"""Reading the server name of a ClientHello, and refusing what is not one."""

from __future__ import annotations

import asyncio
import random
import ssl

import pytest

from relay.sni import HelloError, read_hello, server_name


def client_hello(host: str | None) -> bytes:
    """The bytes Python's TLS client sends first, naming ``host``."""
    context = ssl.create_default_context()
    if host is None:
        context.check_hostname = False
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=host)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


async def read(data: bytes):
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await read_hello(reader)


def test_the_name_of_a_real_client_hello():
    raw = client_hello("Abc0123456-api.Relay.Example.net")
    read_raw, name = asyncio.run(read(raw + b"more bytes after it"))
    assert name == "abc0123456-api.relay.example.net"
    assert read_raw == raw


def test_a_client_hello_without_a_name():
    assert asyncio.run(read(client_hello(None)))[1] == ""


def test_a_client_hello_split_across_records():
    raw = client_hello("node.id.decentai")
    body = raw[5:]
    split = b"".join(raw[:3] + len(part).to_bytes(2, "big") + part
                     for part in (body[:7], body[7:100], body[100:]))
    assert asyncio.run(read(split)) == (split, "node.id.decentai")


@pytest.mark.parametrize("data", [
    b"GET / HTTP/1.1\r\n\r\n",
    b"\x17\x03\x03\x00\x01\x00",
    b"\x16\x03\x01\x00\x00",
    b"\x16\x03\x01\x40\x01" + b"\x00" * 16385,
    b"\x16\x03\x01\x00\x04\x02\x00\x00\x00",
])
def test_what_is_not_a_client_hello(data):
    with pytest.raises(HelloError):
        asyncio.run(read(data))


def test_a_connection_that_ends_early():
    with pytest.raises(asyncio.IncompleteReadError):
        asyncio.run(read(client_hello("a.localhost")[:40]))


def test_mangled_client_hellos_are_refused_never_crash():
    raw = client_hello("abc.relay.example.net")
    body = raw[9:]
    chance = random.Random(7)
    for _ in range(3000):
        mangled = bytearray(body)
        for _ in range(chance.randint(1, 8)):
            mangled[chance.randrange(len(mangled))] = chance.randrange(256)
        cut = mangled[:chance.randrange(len(mangled) + 1)] if chance.random() < 0.3 else mangled
        try:
            name = server_name(bytes(cut))
        except HelloError:
            continue
        assert isinstance(name, str)
