"""The server name a TLS ClientHello asks for, read without ending TLS.

The relay reads the first handshake message of a connection, takes the
name from its server_name extension, and keeps every byte it read so
that the connection's real end receives them unchanged.

    raw, name = await read_hello(reader)    HelloError if it is no ClientHello
    server_name(body)                       the name in a ClientHello's body
"""

from __future__ import annotations

import asyncio
import re

#: A ClientHello larger than this, in bytes as read, is refused.
MAX_HELLO = 16 * 1024

HANDSHAKE_RECORD = 22
CLIENT_HELLO = 1
SERVER_NAME_EXTENSION = 0
HOST_NAME = 0

_HOST = re.compile(r"^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$")


class HelloError(ValueError):
    """Not a ClientHello the relay reads: the connection is closed."""


class _Cursor:
    """Reads a byte string front to back, each length checked against what is left."""

    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    @property
    def left(self) -> int:
        return len(self.data) - self.at

    def take(self, count: int) -> bytes:
        if count < 0 or count > self.left:
            raise HelloError("the ClientHello ends early")
        part = self.data[self.at:self.at + count]
        self.at += count
        return part

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, size: int) -> "_Cursor":
        """The next field that is prefixed by its length in ``size`` bytes."""
        return _Cursor(self.take(self.number(size)))


def server_name(body: bytes) -> str:
    """The host name a ClientHello's body (after its four-byte handshake
    header) asks for, lowercased, or '' when it names none. Raises
    HelloError when the body is malformed."""
    cursor = _Cursor(body)
    cursor.take(2 + 32)          # legacy version, random
    cursor.vector(1)             # session id
    cursor.vector(2)             # cipher suites
    cursor.vector(1)             # compression methods
    if not cursor.left:
        return ""
    extensions = cursor.vector(2)
    while extensions.left:
        kind = extensions.number(2)
        data = extensions.vector(2)
        if kind != SERVER_NAME_EXTENSION:
            continue
        names = data.vector(2)
        while names.left:
            name_type = names.number(1)
            name = names.take(names.number(2))
            if name_type == HOST_NAME:
                return _host(name)
        return ""
    return ""


def _host(name: bytes) -> str:
    try:
        host = name.decode("ascii").lower().rstrip(".")
    except UnicodeDecodeError:
        raise HelloError("the server name is not ASCII") from None
    if len(host) > 253 or not _HOST.match(host):
        raise HelloError("the server name is not a host name")
    return host


async def read_hello(reader: asyncio.StreamReader, limit: int = MAX_HELLO) -> tuple[bytes, str]:
    """The bytes of a connection's ClientHello, as read, and the host name it
    asks for ('' when none). Raises HelloError when the connection does not
    begin with one, or when it is larger than ``limit``; IncompleteReadError
    when the connection ends first. The caller sets the time allowed."""
    raw = bytearray()
    handshake = bytearray()
    while True:
        header = await reader.readexactly(5)
        if header[0] != HANDSHAKE_RECORD:
            raise HelloError("the connection does not begin with a TLS handshake")
        length = int.from_bytes(header[3:5], "big")
        if length == 0 or len(raw) + 5 + length > limit:
            raise HelloError("the ClientHello is empty or too large")
        body = await reader.readexactly(length)
        raw += header + body
        handshake += body
        if len(handshake) < 4:
            continue
        if handshake[0] != CLIENT_HELLO:
            raise HelloError("the first handshake message is not a ClientHello")
        needed = 4 + int.from_bytes(handshake[1:4], "big")
        if needed > limit:
            raise HelloError("the ClientHello is too large")
        if len(handshake) >= needed:
            return bytes(raw), server_name(bytes(handshake[4:needed]))
