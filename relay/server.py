"""The relay's public ports.

    :443   the ClientHello's server name is read and the connection passed
           on unopened: the relay's own name to its control server, an
           install's names to that install's tunnel; anything else closed
    :80    a redirect to https for the same host, and the relay's own
           ACME challenge files, so that its certificate renews by webroot

The control server listens on 127.0.0.1 at a port of its own choosing
and ends TLS with the relay's certificate. A connection for the relay's
name is spliced to it, ClientHello and all, so TLS is ended there and
nowhere else.

    relay = Relay(Config.from_environment())
    await relay.start()
    ...
    await relay.close()
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Mapping, Optional

from relay.control import Control
from relay.sni import MAX_HELLO, HelloError, read_hello
from relay.store import Store
from relay.streams import address, close, splice

log = logging.getLogger("relay")

#: An exact name an install may register: a node's TLS name.
EXACT = re.compile(r"^[a-z0-9-]{1,63}\.id\.decentai$")
#: The label before the relay's domain: <name> or <name>-<word>.
LABEL = re.compile(r"^(?P<name>[a-z0-9]{1,63})(?:-[a-z0-9-]+)?$")
_HOST = re.compile(r"^[a-z0-9.-]{1,253}$")
_TARGET = re.compile(r"^/[!-~]{0,2047}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,255}$")


class ConfigError(ValueError):
    """The relay's settings are missing or wrong; the message says which."""


@dataclass
class Config:
    domain: str
    cert: str
    key: str
    registration: str = "open"
    keys: str = ""
    data: str = "/data"
    public_port: int = 443
    http_port: int = 80
    #: The address the public ports listen on; '' for every address.
    listen: str = ""
    #: Where the relay's own ACME challenges are served from on :80.
    acme: str = ""

    @classmethod
    def from_environment(cls, environ: Optional[Mapping[str, str]] = None) -> "Config":
        env = os.environ if environ is None else environ

        def port(name: str, default: int) -> int:
            value = env.get(name, "") or str(default)
            try:
                number = int(value)
            except ValueError:
                raise ConfigError(f"{name} is not a port number: {value!r}") from None
            if not 0 <= number <= 65535:
                raise ConfigError(f"{name} is not a port number: {value!r}")
            return number

        domain = (env.get("RELAY_DOMAIN") or "").strip().lower().rstrip(".")
        if not domain or not _HOST.match(domain):
            raise ConfigError("RELAY_DOMAIN names the relay, such as relay.example.net")
        data = env.get("RELAY_DATA") or "/data"
        config = cls(
            domain=domain,
            cert=env.get("RELAY_CERT") or "",
            key=env.get("RELAY_KEY") or "",
            registration=(env.get("RELAY_REGISTRATION") or "open").strip().lower(),
            keys=env.get("RELAY_KEYS") or "",
            data=data,
            public_port=port("RELAY_PUBLIC_PORT", 443),
            http_port=port("RELAY_HTTP_PORT", 80),
            listen=env.get("RELAY_LISTEN") or "",
            acme=env.get("RELAY_ACME") or str(Path(data) / "acme"),
        )
        config.check()
        return config

    def check(self) -> None:
        for name, path in (("RELAY_CERT", self.cert), ("RELAY_KEY", self.key)):
            if not path or not Path(path).is_file():
                raise ConfigError(f"{name} names the PEM file of the relay's own "
                                  f"certificate or key; {path or 'none'} was not found")
        if self.registration not in ("open", "key"):
            raise ConfigError("RELAY_REGISTRATION is open or key")
        if self.registration == "key" and not (self.keys and Path(self.keys).is_file()):
            raise ConfigError("RELAY_REGISTRATION=key needs RELAY_KEYS, a file of keys, one per line")


# -- the relay ------------------------------------------------------------
class Relay:
    #: How long a ClientHello may take to arrive.
    HELLO_SECONDS = 10.0
    MAX_HELLO = MAX_HELLO
    HTTP_SECONDS = 10.0
    HTTP_HEAD = 8 * 1024

    def __init__(self, config: Config, store: Optional[Store] = None):
        self.config = config
        self.store = store or Store(Path(config.data) / "relay.db")
        self.control = Control(self)
        self.servers: list[asyncio.base_events.Server] = []
        self.tasks: set[asyncio.Task] = set()
        #: The local port of each splice to the control server, and the
        #: public address it came from: the control server sees only 127.0.0.1.
        self.peers: dict[int, str] = {}
        self.control_port = 0
        self.public_port = 0
        self.http_port = 0

    async def start(self) -> None:
        listen = self.config.listen or None
        control = await asyncio.start_server(
            self._tracked(self.control.handle), "127.0.0.1", 0,
            ssl=self.control.context(), ssl_handshake_timeout=self.HELLO_SECONDS,
            limit=self.control.LINE)
        self.servers.append(control)
        self.control_port = control.sockets[0].getsockname()[1]
        public = await asyncio.start_server(
            self._tracked(self.public), listen, self.config.public_port)
        self.servers.append(public)
        self.public_port = public.sockets[0].getsockname()[1]
        http = await asyncio.start_server(
            self._tracked(self.http), listen, self.config.http_port, limit=self.HTTP_HEAD)
        self.servers.append(http)
        self.http_port = http.sockets[0].getsockname()[1]
        log.info("relay %s: TLS on :%d, http on :%d, registration %s",
                 self.config.domain, self.public_port, self.http_port, self.config.registration)

    async def close(self) -> None:
        for server in self.servers:
            server.close()
        self.control.close()
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.wait(list(self.tasks), timeout=5)
        self.store.close()

    def _tracked(self, handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]):
        """The handler, as a task the relay can end, which never lets an
        error out and always closes its connection."""
        async def run(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                self.tasks.add(task)
            try:
                await handler(reader, writer)
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 - one connection never ends the relay
                log.exception("a connection failed")
            finally:
                if task is not None:
                    self.tasks.discard(task)
                close(writer)
        return run

    # -- :443 -----------------------------------------------------------
    def route(self, host: str) -> str:
        """The install a server name goes to, or '' when none. The relay's
        own name is not routed here."""
        suffix = "." + self.config.domain
        if host.endswith(suffix):
            label = host[:-len(suffix)]
            found = LABEL.match(label) if len(label) <= 63 else None
            return found.group("name") if found else ""
        if EXACT.match(host):
            return self.store.owner(host)
        return ""

    async def public(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = address(writer)
        try:
            raw, host = await asyncio.wait_for(read_hello(reader, self.MAX_HELLO), self.HELLO_SECONDS)
        except HelloError as why:
            log.info("refused %s: %s", peer, why)
            return
        except TimeoutError:
            log.info("refused %s: no ClientHello within %.0f s", peer, self.HELLO_SECONDS)
            return
        except (EOFError, OSError):
            return
        if not host:
            log.info("refused %s: the ClientHello names no server", peer)
            return
        if host == self.config.domain:
            await self._to_control(raw, reader, writer, peer)
            return
        name = self.route(host)
        if not name:
            log.info("refused %s: %s is not a name of this relay", peer, host)
            return
        await self.control.open_stream(name, host, raw, reader, writer, peer)

    async def _to_control(self, raw: bytes, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter, peer: str) -> None:
        self.control.refresh()
        try:
            inner_reader, inner_writer = await asyncio.open_connection("127.0.0.1", self.control_port)
        except OSError as why:
            log.warning("the control server could not be reached: %s", why)
            return
        local = inner_writer.get_extra_info("sockname")[1]
        self.peers[local] = peer
        try:
            inner_writer.write(raw)
            await splice(reader, writer, inner_reader, inner_writer)
        finally:
            self.peers.pop(local, None)
            close(inner_writer)

    # -- :80 ------------------------------------------------------------
    async def http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.HTTP_SECONDS)
        except (TimeoutError, EOFError, OSError, asyncio.LimitOverrunError, ValueError):
            return
        lines = head.decode("latin-1").split("\r\n")
        request = lines[0].split(" ")
        host = ""
        for line in lines[1:]:
            field, _, value = line.partition(":")
            if field.strip().lower() == "host":
                host = value.strip().lower()
                break
        if host.count(":") == 1:
            host, _, port = host.partition(":")
            if not port.isdigit():
                host = ""
        host = host.rstrip(".")
        if len(request) != 3 or not host or not _HOST.match(host):
            await self._answer(writer, "400 Bad Request", b"")
            return
        target = request[1] if _TARGET.match(request[1]) else "/"
        challenge = "/.well-known/acme-challenge/"
        if host == self.config.domain and target.startswith(challenge):
            token = target[len(challenge):]
            path = Path(self.config.acme) / ".well-known" / "acme-challenge" / token
            if _TOKEN.match(token) and path.is_file():
                try:
                    body = path.read_bytes()[:4096]
                except OSError:
                    body = None
                if body is not None:
                    await self._answer(writer, "200 OK", body, "Content-Type: text/plain\r\n")
                    return
            await self._answer(writer, "404 Not Found", b"")
            return
        await self._answer(writer, "301 Moved Permanently", b"",
                           f"Location: https://{host}{target}\r\n")

    @staticmethod
    async def _answer(writer: asyncio.StreamWriter, status: str, body: bytes, headers: str = "") -> None:
        writer.write(f"HTTP/1.1 {status}\r\n{headers}Content-Length: {len(body)}\r\n"
                     f"Connection: close\r\n\r\n".encode("latin-1") + body)
        try:
            await writer.drain()
        except OSError:
            pass

