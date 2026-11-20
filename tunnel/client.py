"""The tunnel: the one connection an install at home keeps to its relay.

The relay passes each public TLS connection for this install's names
through unopened (docs/protocol.md). The tunnel holds a control
connection to the relay, and for each `open` it makes a join connection
and splices it to the service the host names in `targets`. It also
listens on the `forwards`, plain TCP, for a node's sandbox to reach its
deployment's issuer.

    Tunnel("/state/remote.json").run()       until stopped
    register("relay.example.net", key)      a name and its secret, once
    discover_names("/node/runtime")          the <id>.id.decentai names of a node's certificate
    main(["--config", "/state/remote.json"]) holds the connection: python -m tunnel run

remote.json:

    {"relay": "relay.example.net",          its name, and :port when not 443
     "name": "…", "secret": "…", "domain": "relay.example.net",
     "targets": {"<host>": "<service>:<port>", "*": "<service>:<port>"},
     "forwards": {"<port>": "<host>:<port>"},
     "names": ["<id>.id.decentai"],          exact names to register, besides
     "identity": {"folder": "<folder>",      those of the node certificate in this
                  "target": "<service>:<port>"},  identity folder, which go to this target
     "insecure_ca": "<pem path>"}            trust this CA for the relay, not the system's

Only `relay`, `name` and `secret` are required. A host goes to its own
entry in `targets`; else, when it is one of the identity folder's names,
to the identity's target; else to `targets["*"]` when there is one.
`identity` may also be the folder alone, a string.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import random
import re
import signal
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("tunnel")

VERSION = 1
#: The certificate file of a DecentAI identity folder (communication/identity.py).
NODE_FILE = "node.pem"
ID_SUFFIX = ".id.decentai"
EXACT = re.compile(r"^[a-z0-9-]{1,63}\.id\.decentai$")
LINE = 64 * 1024
CHUNK = 64 * 1024


class TunnelError(RuntimeError):
    """The tunnel cannot run, or the relay refused; the message says why."""


# -- remote.json -------------------------------------------------------------
def endpoint(text: str, default_port: Optional[int] = None) -> tuple[str, int]:
    """("host", port) from "host:port", "[v6]:port", or "host" with a default port."""
    text = str(text).strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        host, port = text, ""
    if not port and default_port is not None:
        return host, default_port
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise TunnelError(f"{text!r} is not host:port")
    return host, int(port)


@dataclass
class Settings:
    relay_host: str
    relay_port: int
    name: str = ""
    secret: str = ""
    domain: str = ""
    targets: dict[str, tuple[str, int]] = field(default_factory=dict)
    forwards: dict[int, tuple[str, int]] = field(default_factory=dict)
    names: list[str] = field(default_factory=list)
    identity: str = ""
    identity_target: Optional[tuple[str, int]] = None
    ca: str = ""

    @classmethod
    def read(cls, path: str | Path) -> "Settings":
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as why:
            raise TunnelError(f"{path} could not be read: {why}") from None
        if not isinstance(raw, dict) or not isinstance(raw.get("relay"), str):
            raise TunnelError(f"{path} names no relay")
        host, port = endpoint(raw["relay"], 443)

        def table(key: str) -> dict:
            value = raw.get(key) or {}
            if not isinstance(value, dict):
                raise TunnelError(f"{path}: {key} is an object")
            return value

        targets = {str(name).lower().rstrip("."): endpoint(value)
                   for name, value in table("targets").items()}
        forwards = {}
        for port_text, value in table("forwards").items():
            if not str(port_text).isdigit() or not 0 < int(port_text) < 65536:
                raise TunnelError(f"{path}: forwards' keys are ports, not {port_text!r}")
            forwards[int(port_text)] = endpoint(value)
        names = raw.get("names") or []
        if not isinstance(names, list):
            raise TunnelError(f"{path}: names is a list")
        identity = raw.get("identity") or ""
        identity_target = None
        if isinstance(identity, dict):
            target = identity.get("target")
            identity_target = endpoint(target) if target else None
            identity = identity.get("folder") or ""
        if not isinstance(identity, str):
            raise TunnelError(f"{path}: identity is a folder, or {{\"folder\", \"target\"}}")
        return cls(
            relay_host=host, relay_port=port,
            name=str(raw.get("name") or ""), secret=str(raw.get("secret") or ""),
            domain=str(raw.get("domain") or ""), targets=targets, forwards=forwards,
            names=sorted({str(name).lower() for name in names if EXACT.match(str(name).lower())}),
            identity=identity, identity_target=identity_target, ca=str(raw.get("insecure_ca") or ""))


def client_context(ca: str = "") -> ssl.SSLContext:
    """TLS to the relay: the system's roots, or the one CA a test or a private relay names."""
    try:
        context = ssl.create_default_context(cafile=ca or None)
    except (OSError, ssl.SSLError) as why:
        raise TunnelError(f"the CA {ca} could not be read: {why}") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


def decode(line: bytes) -> Optional[dict[str, Any]]:
    """A line's JSON object, or None when it is not one."""
    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return message if isinstance(message, dict) else None


# -- registration ------------------------------------------------------------
def register(relay_host: str, key: str = "", ca: str = "", timeout: float = 15.0) -> dict:
    """Registers with a relay, once: {"relay", "name", "secret", "domain"},
    to be kept in remote.json. Raises TunnelError when it is refused or
    cannot be reached."""
    host, port = endpoint(relay_host, 443)
    context = client_context(ca)
    try:
        with socket.create_connection((host, port), timeout=timeout) as plain:
            with context.wrap_socket(plain, server_hostname=host) as tls:
                tls.sendall(encode({"op": "register", "key": key}))
                line = tls.makefile("rb").readline(LINE)
    except (OSError, ssl.SSLError) as why:
        raise TunnelError(f"the relay {relay_host} could not be reached: {why}") from None
    reply = decode(line) or {}
    if reply.get("op") == "registered" and all(
            isinstance(reply.get(name), str) and reply.get(name) for name in ("name", "secret", "domain")):
        return {"relay": relay_host, "name": reply["name"], "secret": reply["secret"],
                "domain": reply["domain"]}
    if reply.get("op") == "error":
        raise TunnelError(f"the relay refused to register: {reply.get('error')}")
    raise TunnelError(f"the relay {relay_host} gave no registration")


# -- a node's names ----------------------------------------------------------
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def discover_names(identity_folder: str | Path) -> list[str]:
    """The <id>.id.decentai names in the certificate of a DecentAI identity
    folder's node.pem (its first certificate: the node's own), sorted; [] when
    there is no readable certificate."""
    try:
        data = (Path(identity_folder) / NODE_FILE).read_bytes()
    except OSError:
        return []
    found = _PEM.search(data)
    if not found:
        return []
    try:
        der = base64.b64decode(b"".join(found.group(1).split()), validate=True)
    except ValueError:
        return []
    try:
        names = _names_with_cryptography(der)
    except ImportError:
        names = None
    except Exception:  # noqa: BLE001 - a certificate cryptography refuses has no names
        return []
    if names is None:
        try:
            names = _names_from_der(der)
        except (ValueError, IndexError):
            return []
    return sorted({name.lower() for name in names if EXACT.match(name.lower())})


def _names_with_cryptography(der: bytes) -> list[str]:
    from cryptography import x509

    certificate = x509.load_der_x509_certificate(der)
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return list(names.get_values_for_type(x509.DNSName))


def _tlv(data: bytes, at: int) -> tuple[int, int, int]:
    """A DER element at ``at``: (tag, where its content begins, where it ends)."""
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        size = length & 0x7F
        if not 0 < size <= 4:
            raise ValueError("a DER length this parser does not read")
        length = int.from_bytes(data[at:at + size], "big")
        at += size
    if at + length > len(data):
        raise ValueError("a DER element longer than its certificate")
    return tag, at, at + length


def _children(data: bytes, start: int, end: int):
    while start < end:
        tag, begin, finish = _tlv(data, start)
        yield tag, begin, finish
        start = finish


def _names_from_der(der: bytes) -> list[str]:
    """The DNS names of a certificate's subjectAltName, read from its DER
    without cryptography: Certificate > TBSCertificate > [3] > Extensions."""
    _, start, end = _tlv(der, 0)
    _, tbs_start, tbs_end = next(_children(der, start, end))
    for tag, begin, finish in _children(der, tbs_start, tbs_end):
        if tag != 0xA3:
            continue
        _, list_start, list_end = _tlv(der, begin)
        for _, ext_start, ext_end in _children(der, list_start, list_end):
            parts = list(_children(der, ext_start, ext_end))
            if not parts or der[parts[0][1]:parts[0][2]] != b"\x55\x1d\x11":
                continue
            _, value_start, _ = parts[-1]
            _, names_start, names_end = _tlv(der, value_start)
            return [der[a:b].decode("ascii") for kind, a, b in _children(der, names_start, names_end)
                    if kind == 0x82]
    return []


# -- byte pipes ---------------------------------------------------------------
async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, EOFError):
        return False
    try:
        if writer.can_write_eof():
            writer.write_eof()
            return True
    except (OSError, RuntimeError):
        pass
    return False


async def splice(a_reader: asyncio.StreamReader, a_writer: asyncio.StreamWriter,
                 b_reader: asyncio.StreamReader, b_writer: asyncio.StreamWriter) -> None:
    """Joins two connections both ways until both end, then closes them."""
    one = asyncio.ensure_future(_pipe(a_reader, b_writer))
    two = asyncio.ensure_future(_pipe(b_reader, a_writer))
    try:
        done, waiting = await asyncio.wait({one, two}, return_when=asyncio.FIRST_COMPLETED)
        if waiting and all(task.result() for task in done):
            await asyncio.wait(waiting)
    finally:
        for task in (one, two):
            task.cancel()
        for writer in (a_writer, b_writer):
            _close(writer)


def _close(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except (OSError, RuntimeError):
        pass


# -- the tunnel ---------------------------------------------------------------
class Tunnel:
    PING_SECONDS = 30.0
    SILENT_SECONDS = 90.0
    NAMES_SECONDS = 60.0
    TIMEOUT = 10.0
    BACKOFF_MAX = 60.0
    #: A connection that lasted this long resets the backoff.
    STEADY_SECONDS = 10.0

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)
        self.settings: Optional[Settings] = None
        self.names: list[str] = []
        #: The names the identity folder's certificate carries, as last read.
        self.identity_names: list[str] = []
        self.hosts: list[str] = []
        self.connected = False
        self._writer: Optional[asyncio.StreamWriter] = None
        self._context: Optional[ssl.SSLContext] = None
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()

    def run(self) -> None:
        """Holds the relay connection and the forwards until SIGTERM or SIGINT."""
        asyncio.run(self._run_until_stopped())

    async def _run_until_stopped(self) -> None:
        serving = asyncio.ensure_future(self.serve())
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(signum, serving.cancel)
            except (NotImplementedError, RuntimeError):
                pass
        try:
            await serving
        except asyncio.CancelledError:
            log.info("stopped")

    async def serve(self) -> None:
        """The forwards, and the relay connection held with backoff, until cancelled."""
        self.settings = Settings.read(self.config_path)
        self._context = client_context(self.settings.ca)
        servers = await self._forwards()
        try:
            if not (self.settings.name and self.settings.secret):
                log.info("no name registered with the relay: only the forwards run")
                await asyncio.Event().wait()
            await self._hold()
        finally:
            for server in servers:
                server.close()
            for task in list(self._tasks):
                task.cancel()

    def _spawn(self, coroutine) -> asyncio.Task:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # -- forwards ---------------------------------------------------------
    async def _forwards(self) -> list[asyncio.base_events.Server]:
        servers = []
        for port, target in self.settings.forwards.items():
            async def forward(reader, writer, target=target):
                await self._forward(reader, writer, target)
            try:
                servers.append(await asyncio.start_server(forward, "0.0.0.0", port))
            except OSError as why:
                log.error("forward :%d could not listen: %s", port, why)
                continue
            log.info("forward :%d -> %s:%d", port, *target)
        return servers

    async def _forward(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       target: tuple[str, int]) -> None:
        try:
            far_reader, far_writer = await asyncio.wait_for(asyncio.open_connection(*target), self.TIMEOUT)
        except (OSError, TimeoutError) as why:
            log.warning("forward to %s:%d failed: %s", *target, why)
            _close(writer)
            return
        try:
            await splice(reader, writer, far_reader, far_writer)
        except Exception:  # noqa: BLE001 - one connection never ends the tunnel
            log.exception("a forwarded connection failed")
            _close(writer)
            _close(far_writer)

    # -- the relay connection ----------------------------------------------
    def current_names(self) -> list[str]:
        """The exact names to register: remote.json's, and the identity folder's."""
        names = set(self.settings.names)
        if self.settings.identity:
            self.identity_names = discover_names(self.settings.identity)
            names.update(self.identity_names)
        return sorted(names)

    def _hello(self) -> dict[str, Any]:
        return {"op": "hello", "v": VERSION, "name": self.settings.name,
                "secret": self.settings.secret, "names": self.names}

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        settings = self.settings
        return await asyncio.wait_for(asyncio.open_connection(
            settings.relay_host, settings.relay_port, ssl=self._context,
            server_hostname=settings.relay_host, limit=LINE), self.TIMEOUT)

    async def _hold(self) -> None:
        delay = 1.0
        while True:
            began = time.monotonic()
            try:
                await self._session()
            except asyncio.CancelledError:
                raise
            except TunnelError as why:
                log.warning("%s", why)
            except (OSError, EOFError, TimeoutError, ValueError) as why:
                log.warning("relay connection lost: %s", why or type(why).__name__)
            except Exception:  # noqa: BLE001 - the tunnel never stops for one failure
                log.exception("relay connection failed")
            finally:
                self.connected = False
                self._writer = None
            if time.monotonic() - began >= self.STEADY_SECONDS:
                delay = 1.0
            wait = random.uniform(delay / 2, delay)
            log.info("reconnecting in %.1f s", wait)
            await asyncio.sleep(wait)
            delay = min(delay * 2, self.BACKOFF_MAX)

    async def send(self, message: dict[str, Any]) -> None:
        writer = self._writer
        if writer is None:
            return
        async with self._lock:
            writer.write(encode(message))
            await asyncio.wait_for(writer.drain(), self.TIMEOUT)

    async def _session(self) -> None:
        reader, writer = await self._connect()
        self._writer = writer
        helpers: list[asyncio.Task] = []
        try:
            self.names = self.current_names()
            await self.send(self._hello())
            line = await asyncio.wait_for(reader.readline(), self.TIMEOUT)
            reply = decode(line) if line else None
            if reply is None:
                raise TunnelError("the relay closed the connection without an answer")
            if reply.get("op") == "error":
                raise TunnelError(f"the relay refused the tunnel: {reply.get('error')}")
            if reply.get("op") != "ready":
                raise TunnelError("the relay did not answer hello with ready")
            self._ready(reply)
            self.connected = True
            helpers = [asyncio.ensure_future(self._ping()), asyncio.ensure_future(self._watch_names())]
            while True:
                line = await asyncio.wait_for(reader.readline(), self.SILENT_SECONDS)
                if not line:
                    raise TunnelError("the relay closed the connection")
                await self.handle(decode(line))
        except TimeoutError:
            raise TunnelError("the relay was silent too long") from None
        finally:
            for helper in helpers:
                helper.cancel()
            _close(writer)

    def _ready(self, reply: dict[str, Any]) -> None:
        hosts = reply.get("hosts")
        self.hosts = [str(host) for host in hosts] if isinstance(hosts, list) else []
        log.info("connected to %s:%d as %s: %s", self.settings.relay_host, self.settings.relay_port,
                 self.settings.name, ", ".join(self.hosts) or "no hosts")

    async def handle(self, message: Optional[dict[str, Any]]) -> None:
        """One message from the relay. Never raises for what the message says."""
        if message is None:
            log.warning("ignored a line from the relay that is not a JSON object")
            return
        op = message.get("op")
        if op == "ping":
            await self.send({"op": "pong"})
        elif op == "open":
            stream, host = message.get("stream"), message.get("host")
            if not isinstance(stream, str) or not isinstance(host, str) \
                    or not 0 < len(stream) <= 256 or not 0 < len(host) <= 253:
                log.warning("ignored an open with no stream or host")
                return
            self._spawn(self._join(stream, host.lower()))
        elif op == "ready":
            self._ready(message)
        elif op == "error":
            log.warning("the relay says: %s", str(message.get("error"))[:300])
        # pong, and anything newer than this tunnel knows, needs nothing.

    async def _ping(self) -> None:
        while True:
            await asyncio.sleep(self.PING_SECONDS)
            try:
                await self.send({"op": "ping"})
            except (OSError, TimeoutError):
                _close(self._writer)
                return

    async def _watch_names(self) -> None:
        while True:
            await asyncio.sleep(self.NAMES_SECONDS)
            names = self.current_names()
            if names != self.names:
                log.info("names changed: %s", ", ".join(names) or "none")
                self.names = names
                try:
                    await self.send(self._hello())
                except (OSError, TimeoutError):
                    _close(self._writer)
                    return

    def target(self, host: str) -> Optional[tuple[str, int]]:
        targets = self.settings.targets
        if host in targets:
            return targets[host]
        if self.settings.identity_target and host in self.identity_names:
            return self.settings.identity_target
        return targets.get("*")

    async def _join(self, stream: str, host: str) -> None:
        """Joins one public connection to its target: a new connection to the
        relay, the join line, then the ClientHello and everything after it."""
        writer = target_writer = None
        try:
            reader, writer = await self._connect()
            writer.write(encode({"op": "join", "name": self.settings.name,
                                 "secret": self.settings.secret, "stream": stream}))
            await writer.drain()
            first = await asyncio.wait_for(reader.read(CHUNK), self.TIMEOUT)
            if not first:
                return
            if first.startswith(b"{"):
                # Not a ClientHello, which begins with 0x16: the relay refused.
                rest = b"" if b"\n" in first else await asyncio.wait_for(reader.readline(), self.TIMEOUT)
                reply = decode((first + rest).split(b"\n")[0]) or {}
                log.warning("the relay refused a join for %s: %s", host, str(reply.get("error"))[:300])
                return
            target = self.target(host)
            if target is None:
                log.warning("no target for %s: its connection is closed", host)
                return
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(*target), self.TIMEOUT)
            target_writer.write(first)
            await splice(reader, writer, target_reader, target_writer)
        except asyncio.CancelledError:
            raise
        except (OSError, EOFError, TimeoutError, ValueError) as why:
            log.warning("a connection for %s failed: %s", host, why or type(why).__name__)
        except Exception:  # noqa: BLE001 - one connection never ends the tunnel
            log.exception("a connection for %s failed", host)
        finally:
            _close(writer)
            _close(target_writer)


# -- the command line -----------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    """python -m tunnel run --config /state/remote.json"""
    parser = argparse.ArgumentParser(prog="tunnel run",
                                     description="Hold this install's connection to its relay.")
    parser.add_argument("--config", default="/state/remote.json", help="remote.json")
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)
    try:
        Tunnel(arguments.config).run()
    except TunnelError as why:
        print(str(why), file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
