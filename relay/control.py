"""The control protocol, version 1: newline-delimited JSON over TLS to the relay's own name.

    {"op": "register", "key": "…"}
        -> {"op": "registered", "name": "…", "secret": "…", "domain": "…"}, closed
    {"op": "hello", "v": 1, "name": "…", "secret": "…", "names": ["<id>.id.decentai"]}
        -> {"op": "ready", "hosts": […]}, the connection kept as the install's tunnel
    relay -> {"op": "open", "stream": "<id>", "host": "<sni>"} for each public connection
    {"op": "join", "name": "…", "secret": "…", "stream": "<id>"} on a new connection,
        after which both sides are raw bytes: the relay writes the ClientHello, then splices
    {"op": "ping"} / {"op": "pong"} every 30 s; a tunnel silent for 90 s is dropped

Anything refused is answered {"op": "error", "error": "…"} and closed. The
log says who connected, who left and what was refused; never a secret, and
never a byte of a stream.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from relay.streams import close, splice

if TYPE_CHECKING:
    from relay.server import Relay

log = logging.getLogger("relay")

VERSION = 1
EXACT = re.compile(r"^[a-z0-9-]{1,63}\.id\.decentai$")


@dataclass
class Session:
    """An install's tunnel: its control connection, kept open."""
    name: str
    writer: asyncio.StreamWriter
    peer: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(self, message: dict[str, Any], seconds: float) -> None:
        async with self.lock:
            self.writer.write(encode(message))
            await asyncio.wait_for(self.writer.drain(), seconds)


@dataclass
class Pending:
    """A public connection waiting for its install's join."""
    name: str
    joined: asyncio.Future
    finished: asyncio.Future


@dataclass
class Counts:
    open: int = 0
    pending: int = 0


def encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


def decode(line: bytes) -> Optional[dict[str, Any]]:
    """A line's JSON object, or None when it is not one."""
    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return message if isinstance(message, dict) else None


class Control:
    #: The longest line a control connection may send.
    LINE = 64 * 1024
    FIRST_LINE_SECONDS = 10.0
    PING_SECONDS = 30.0
    SILENT_SECONDS = 90.0
    JOIN_SECONDS = 10.0
    SEND_SECONDS = 10.0
    MAX_OPEN = 256
    MAX_PENDING = 32
    MAX_NAMES = 64
    #: Registrations one address may make in an hour.
    REGISTRATIONS_PER_HOUR = 20
    CERT_CHECK_SECONDS = 60.0

    def __init__(self, relay: "Relay"):
        self.relay = relay
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, Pending] = {}
        self.counts: dict[str, Counts] = {}
        self.registrations: dict[str, list[float]] = {}
        self._context: Optional[ssl.SSLContext] = None
        self._cert_stamp: tuple = ()
        self._cert_checked = 0.0

    # -- TLS -------------------------------------------------------------
    def context(self) -> ssl.SSLContext:
        """The control server's TLS: the relay's own certificate, TLS 1.2 or later."""
        if self._context is None:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.relay.config.cert, self.relay.config.key)
            self._context = context
            self._cert_stamp = self._stamp()
            self._cert_checked = time.monotonic()
        return self._context

    def _stamp(self) -> tuple:
        config = self.relay.config
        try:
            return tuple(os.stat(path).st_mtime_ns for path in (config.cert, config.key))
        except OSError:
            return self._cert_stamp

    def refresh(self) -> None:
        """Loads the certificate again when its files changed, at most once a
        minute: a renewal is taken without a restart."""
        if self._context is None or time.monotonic() - self._cert_checked < self.CERT_CHECK_SECONDS:
            return
        self._cert_checked = time.monotonic()
        stamp = self._stamp()
        if stamp == self._cert_stamp:
            return
        try:
            self._context.load_cert_chain(self.relay.config.cert, self.relay.config.key)
        except (OSError, ssl.SSLError) as why:
            log.warning("the relay's certificate could not be loaded again: %s", why)
            return
        self._cert_stamp = stamp
        log.info("the relay's certificate was loaded again")

    def close(self) -> None:
        for session in list(self.sessions.values()):
            close(session.writer)
        self.sessions.clear()

    # -- a control connection ---------------------------------------------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        local = writer.get_extra_info("peername")
        peer = self.relay.peers.get(local[1], "?") if local else "?"
        message = await self._read(reader, self.FIRST_LINE_SECONDS)
        if message is None:
            await self._refuse(writer, peer, "a control connection begins with one line of JSON")
            return
        op = message.get("op")
        if op == "register":
            await self.register(message, writer, peer)
        elif op == "hello":
            await self.hello(message, reader, writer, peer)
        elif op == "join":
            await self.join(message, reader, writer, peer)
        else:
            await self._refuse(writer, peer, "a control connection begins with register, hello or join")

    async def _read(self, reader: asyncio.StreamReader, seconds: float) -> Optional[dict[str, Any]]:
        try:
            line = await asyncio.wait_for(reader.readline(), seconds)
        except (TimeoutError, ValueError, EOFError, OSError):
            return None
        return decode(line) if line else None

    async def _refuse(self, writer: asyncio.StreamWriter, peer: str, error: str,
                      name: str = "") -> None:
        log.info("refused %s%s: %s", f"{name} at " if name else "", peer, error)
        writer.write(encode({"op": "error", "error": error}))
        try:
            await asyncio.wait_for(writer.drain(), self.SEND_SECONDS)
        except (TimeoutError, OSError):
            pass

    # -- register ----------------------------------------------------------
    def _key_allowed(self, key: Any) -> bool:
        if not isinstance(key, str) or not key:
            return False
        try:
            lines = Path(self.relay.config.keys).read_text(encoding="utf-8").splitlines()
        except OSError as why:
            log.warning("the registration keys could not be read: %s", why)
            return False
        allowed = False
        for line in lines:
            candidate = line.strip()
            if candidate and not candidate.startswith("#"):
                allowed |= hmac.compare_digest(candidate.encode(), key.encode())
        return allowed

    def _under_rate(self, peer: str) -> bool:
        now = time.monotonic()
        recent = [moment for moment in self.registrations.get(peer, []) if now - moment < 3600]
        if len(recent) >= self.REGISTRATIONS_PER_HOUR:
            self.registrations[peer] = recent
            return False
        self.registrations[peer] = recent + [now]
        if len(self.registrations) > 10000:
            self.registrations = {who: moments for who, moments in self.registrations.items()
                                  if moments and now - moments[-1] < 3600}
        return True

    async def register(self, message: dict[str, Any], writer: asyncio.StreamWriter, peer: str) -> None:
        if self.relay.config.registration == "key" and not self._key_allowed(message.get("key")):
            await self._refuse(writer, peer, "this relay registers only with one of its keys, "
                                             "and that key is not one")
            return
        if not self._under_rate(peer):
            await self._refuse(writer, peer, "too many registrations from this address; try in an hour")
            return
        name, secret = self.relay.store.register()
        log.info("registered %s from %s", name, peer)
        writer.write(encode({"op": "registered", "name": name, "secret": secret,
                             "domain": self.relay.config.domain}))
        try:
            await asyncio.wait_for(writer.drain(), self.SEND_SECONDS)
        except (TimeoutError, OSError):
            pass

    # -- hello: the tunnel -----------------------------------------------------
    def _greet(self, message: dict[str, Any], name: str = "") -> tuple[str, str]:
        """Checks a hello and binds its exact names. Returns (install, '') or ('', why not)."""
        if message.get("v") != VERSION:
            return "", f"this relay speaks version {VERSION} of the protocol"
        claimed, secret = message.get("name"), message.get("secret")
        if not isinstance(claimed, str) or not isinstance(secret, str):
            return "", "a hello carries a name and a secret"
        if name and claimed != name:
            return "", "a tunnel keeps the name it said hello with"
        if not self.relay.store.check(claimed, secret):
            return "", "unknown name or wrong secret"
        names = message.get("names") or []
        if not isinstance(names, list) or len(names) > self.MAX_NAMES:
            return "", f"names is a list of at most {self.MAX_NAMES} exact names"
        wanted = []
        for host in names:
            host = host.lower().rstrip(".") if isinstance(host, str) else ""
            if not EXACT.match(host):
                return "", "an exact name is <id>.id.decentai"
            wanted.append(host)
        taken = self.relay.store.bind(claimed, sorted(set(wanted)))
        if taken:
            return "", f"{taken} belongs to another install"
        return claimed, ""

    def _hosts(self, name: str) -> list[str]:
        domain = self.relay.config.domain
        return [f"{name}.{domain}", f"{name}-*.{domain}", *self.relay.store.hosts(name)]

    async def hello(self, message: dict[str, Any], reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter, peer: str) -> None:
        name, why = self._greet(message)
        if not name:
            await self._refuse(writer, peer, why, str(message.get("name"))[:64])
            return
        session = Session(name, writer, peer)
        before = self.sessions.get(name)
        self.sessions[name] = session
        if before is not None:
            log.info("tunnel %s: replaced by a new connection from %s", name, peer)
            close(before.writer)
        self.relay.store.seen(name)
        log.info("tunnel %s: connected from %s", name, peer)
        pinger = asyncio.ensure_future(self._ping(session))
        why = "closed by the tunnel"
        try:
            await session.send({"op": "ready", "hosts": self._hosts(name)}, self.SEND_SECONDS)
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), self.SILENT_SECONDS)
                except TimeoutError:
                    why = f"silent for {self.SILENT_SECONDS:.0f} s"
                    break
                except ValueError:
                    why = "a line too long"
                    break
                if not line:
                    break
                message = decode(line)
                if message is None:
                    await self._refuse(writer, peer, "a line that is not a JSON object", name)
                    why = "a line that is not a JSON object"
                    break
                op = message.get("op")
                if op == "ping":
                    await session.send({"op": "pong"}, self.SEND_SECONDS)
                elif op == "hello":
                    again, refused = self._greet(message, name)
                    if not again:
                        await self._refuse(writer, peer, refused, name)
                        why = "a hello refused"
                        break
                    await session.send({"op": "ready", "hosts": self._hosts(name)}, self.SEND_SECONDS)
                # pong, and anything newer than this relay knows, is only a sign of life.
        except (TimeoutError, OSError, EOFError) as failed:
            why = f"connection lost ({type(failed).__name__})"
        finally:
            pinger.cancel()
            if self.sessions.get(name) is session:
                del self.sessions[name]
            try:
                self.relay.store.seen(name)
            except Exception:  # noqa: BLE001 - the log line matters more
                log.exception("last seen not kept for %s", name)
            log.info("tunnel %s: disconnected (%s)", name, why)

    async def _ping(self, session: Session) -> None:
        try:
            while True:
                await asyncio.sleep(self.PING_SECONDS)
                await session.send({"op": "ping"}, self.SEND_SECONDS)
        except (TimeoutError, OSError):
            close(session.writer)

    # -- streams ---------------------------------------------------------------
    async def open_stream(self, name: str, host: str, raw: bytes, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter, peer: str) -> None:
        """Asks the install's tunnel to join a public connection, and splices
        the two when it does: the ClientHello first, as it was read."""
        session = self.sessions.get(name)
        if session is None:
            log.info("refused %s: %s has no tunnel connected", peer, host)
            return
        counts = self.counts.setdefault(name, Counts())
        if counts.open >= self.MAX_OPEN or counts.pending >= self.MAX_PENDING:
            log.info("refused %s: %s is at its limit of streams", peer, host)
            return
        loop = asyncio.get_running_loop()
        stream = secrets.token_urlsafe(12)
        waiting = Pending(name, loop.create_future(), loop.create_future())
        self.pending[stream] = waiting
        counts.open += 1
        counts.pending += 1
        try:
            try:
                await session.send({"op": "open", "stream": stream, "host": host}, self.SEND_SECONDS)
                join_reader, join_writer = await asyncio.wait_for(waiting.joined, self.JOIN_SECONDS)
            except TimeoutError:
                log.info("refused %s: %s did not join within %.0f s", peer, name, self.JOIN_SECONDS)
                return
            except OSError:
                return
            finally:
                counts.pending -= 1
                self.pending.pop(stream, None)
            join_writer.write(raw)
            await splice(reader, writer, join_reader, join_writer)
        finally:
            counts.open -= 1
            if not counts.open and not counts.pending:
                self.counts.pop(name, None)
            if not waiting.finished.done():
                waiting.finished.set_result(None)
            if not waiting.joined.done():
                waiting.joined.cancel()

    async def join(self, message: dict[str, Any], reader: asyncio.StreamReader,
                   writer: asyncio.StreamWriter, peer: str) -> None:
        name, secret, stream = message.get("name"), message.get("secret"), message.get("stream")
        if not all(isinstance(value, str) for value in (name, secret, stream)):
            await self._refuse(writer, peer, "a join carries a name, a secret and a stream")
            return
        if not self.relay.store.check(name, secret):
            await self._refuse(writer, peer, "unknown name or wrong secret", name[:64])
            return
        waiting = self.pending.get(stream)
        if waiting is None or waiting.name != name or waiting.joined.done():
            await self._refuse(writer, peer, "no such stream", name)
            return
        del self.pending[stream]
        waiting.joined.set_result((reader, writer))
        # The public side splices this connection and closes it.
        await waiting.finished
