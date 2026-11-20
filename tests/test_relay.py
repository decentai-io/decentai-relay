"""The relay end to end: a public client, the relay, a tunnel, and a TLS server at home."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from conftest import (DOMAIN, Home, ask, control, registered, remote_json, start_relay,
                      start_tunnel, until, visit)
from tunnel.client import Tunnel, TunnelError
from relay import streams


def run(coroutine):
    return asyncio.run(asyncio.wait_for(coroutine, 30))


async def closed_quickly(port: int, sni: str, pki) -> bool:
    """Whether a TLS client naming ``sni`` is closed without a handshake."""
    try:
        await visit(port, sni, pki)
    except (ConnectionError, OSError, EOFError, asyncio.IncompleteReadError):
        return True
    return False


def test_a_public_client_reaches_home_through_tls_the_relay_cannot_read(pki, tmp_path, monkeypatch):
    seen = bytearray()
    original = streams.pipe

    async def recording(reader, writer):
        read = reader.read

        async def keep(n=-1):
            data = await read(n)
            seen.extend(data)
            return data
        reader.read = keep
        return await original(reader, writer)

    monkeypatch.setattr(streams, "pipe", recording)

    async def scenario():
        relay = await start_relay(pki, tmp_path)
        install = await registered(relay, pki)
        assert install["domain"] == DOMAIN and len(install["name"]) == 10
        name = install["name"]
        home = await Home(pki, f"{name}.{DOMAIN}", f"{name}-api.{DOMAIN}").start()
        path = remote_json(tmp_path, relay, pki, install,
                           targets={f"{name}.{DOMAIN}": f"127.0.0.1:{home.port}",
                                    "*": f"127.0.0.1:{home.port}"})
        tunnel, task = await start_tunnel(path, relay, name)
        try:
            assert tunnel.hosts[:2] == [f"{name}.{DOMAIN}", f"{name}-*.{DOMAIN}"]
            secret_line = b"a plaintext line only home may read\n"
            answer, der = await visit(relay.public_port, f"{name}.{DOMAIN}", pki, secret_line)
            assert answer == b"home saw: " + secret_line
            # The certificate the client checked is home's, not the relay's.
            assert der == home.der
            assert home.received == [secret_line]
            answer, der = await visit(relay.public_port, f"{name}-api.{DOMAIN}", pki)
            assert answer == b"home saw: hello\n" and der == home.der
            await until(lambda: not relay.control.counts, "the streams are closed")
        finally:
            task.cancel()
            home.close()
            await relay.close()

    run(scenario())
    assert seen, "the relay carried the stream"
    assert b"plaintext line" not in bytes(seen)
    assert b"home saw" not in bytes(seen)


def test_an_unknown_name_or_a_malformed_hello_is_closed_and_the_relay_carries_on(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            install = await registered(relay, pki)
            for sni in ("nobody.localhost", "example.com", f"{install['name']}.{DOMAIN}",
                        "a.b.localhost", "unbound.id.decentai"):
                assert await closed_quickly(relay.public_port, sni, pki), sni
            for garbage in (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                            b"\x16\x03\x01\x00\x05\x01\xff\xff\xff\x00",
                            b"\x16\x03\x01\xff\xff" + b"\x00" * 64,
                            b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c" + b"\x03\x03" + b"\x00" * 42):
                reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
                writer.write(garbage)
                await writer.drain()
                assert await asyncio.wait_for(reader.read(100), 5) == b""
                writer.close()
            # Still serving.
            assert (await registered(relay, pki))["name"] != install["name"]
        finally:
            await relay.close()

    run(scenario())


def test_a_hello_too_slow_is_closed(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        relay.HELLO_SECONDS = 0.3
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
            writer.write(b"\x16\x03\x01")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(100), 5) == b""
            writer.close()
        finally:
            await relay.close()

    run(scenario())


def test_registration_by_key_refuses_a_wrong_key(pki, tmp_path):
    keys = tmp_path / "keys"
    keys.write_text("# one key per line\nthe-right-key\n\n")

    async def scenario():
        relay = await start_relay(pki, tmp_path, registration="key", keys=str(keys))
        try:
            for wrong in ("", "the-wrong-key", "the-right-ke"):
                with pytest.raises(TunnelError, match="key"):
                    await registered(relay, pki, wrong)
            install = await registered(relay, pki, "the-right-key")
            assert install["name"] and install["secret"]
        finally:
            await relay.close()

    run(scenario())


def test_names_are_ten_characters_never_given_twice_and_secrets_are_kept_hashed(pki, tmp_path):
    installs = []

    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            installs.extend([await registered(relay, pki) for _ in range(5)])
        finally:
            await relay.close()

    run(scenario())
    names = [install["name"] for install in installs]
    assert len(set(names)) == 5
    assert all(len(name) == 10 and name.isalnum() and name == name.lower() for name in names)
    kept = b"".join(path.read_bytes() for path in (tmp_path / "data").iterdir())
    assert all(install["name"].encode() in kept for install in installs)
    assert not any(install["secret"].encode() in kept for install in installs)


def test_an_exact_name_belongs_to_the_first_install_that_registers_it(pki, tmp_path):
    exact = "node-one.id.decentai"

    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            first, second = await registered(relay, pki), await registered(relay, pki)
            home = await Home(pki, exact).start()
            # A node's identity folder, as the runtime keeps it: its key, then its certificate.
            node_cert, node_key, _ = pki.issue(exact, "runtime.kind.decentai")
            identity = tmp_path / "identity"
            identity.mkdir()
            (identity / "node.pem").write_bytes(Path(node_key).read_bytes() + Path(node_cert).read_bytes())
            path = remote_json(tmp_path, relay, pki, first, targets={},
                               identity={"folder": str(identity), "target": f"127.0.0.1:{home.port}"})
            tunnel, task = await start_tunnel(path, relay, first["name"])
            try:
                assert exact in tunnel.hosts
                assert relay.store.owner(exact) == first["name"]
                answer, der = await visit(relay.public_port, exact, pki)
                assert answer == b"home saw: hello\n" and der == home.der

                reader, writer = await control(relay, pki)
                reply = await ask(reader, writer, {"op": "hello", "v": 1, "name": second["name"],
                                                   "secret": second["secret"], "names": [exact]})
                assert reply["op"] == "error" and exact in reply["error"]
                assert await asyncio.wait_for(reader.read(10), 5) == b""
                assert relay.store.owner(exact) == first["name"]

                # Not even after the first install has gone.
                task.cancel()
                await until(lambda: first["name"] not in relay.control.sessions, "the tunnel leaves")
                reader, writer = await control(relay, pki)
                reply = await ask(reader, writer, {"op": "hello", "v": 1, "name": second["name"],
                                                   "secret": second["secret"], "names": [exact]})
                assert reply["op"] == "error"
            finally:
                task.cancel()
                home.close()
        finally:
            await relay.close()

    run(scenario())


def test_a_wrong_secret_is_refused_on_hello_and_on_join(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            install = await registered(relay, pki)
            name = install["name"]
            reader, writer = await control(relay, pki)
            reply = await ask(reader, writer, {"op": "hello", "v": 1, "name": name, "secret": "guess"})
            assert reply == {"op": "error", "error": "unknown name or wrong secret"}

            reader, writer = await control(relay, pki)
            reply = await ask(reader, writer, {"op": "hello", "v": 1, "name": name,
                                               "secret": install["secret"], "names": []})
            assert reply["op"] == "ready"
            public = asyncio.ensure_future(visit(relay.public_port, f"{name}.{DOMAIN}", pki))
            opened = json.loads(await asyncio.wait_for(reader.readline(), 5))
            assert opened["op"] == "open" and opened["host"] == f"{name}.{DOMAIN}"

            join_reader, join_writer = await control(relay, pki)
            refused = await ask(join_reader, join_writer, {"op": "join", "name": name, "secret": "guess",
                                                           "stream": opened["stream"]})
            assert refused == {"op": "error", "error": "unknown name or wrong secret"}
            assert await asyncio.wait_for(join_reader.read(10), 5) == b""

            join_reader, join_writer = await control(relay, pki)
            refused = await ask(join_reader, join_writer, {"op": "join", "name": name,
                                                           "secret": install["secret"], "stream": "made-up"})
            assert refused == {"op": "error", "error": "no such stream"}

            # The right join gets the ClientHello, as the client sent it.
            join_reader, join_writer = await control(relay, pki)
            join_writer.write(json.dumps({"op": "join", "name": name, "secret": install["secret"],
                                          "stream": opened["stream"]}).encode() + b"\n")
            await join_writer.drain()
            first = await asyncio.wait_for(join_reader.read(5), 5)
            assert first[:1] == b"\x16"
            join_writer.close()
            with pytest.raises((ConnectionError, OSError, EOFError, asyncio.IncompleteReadError)):
                await public
        finally:
            await relay.close()

    run(scenario())


def test_a_join_not_made_in_time_closes_the_public_connection(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        relay.control.JOIN_SECONDS = 0.3
        try:
            install = await registered(relay, pki)
            reader, writer = await control(relay, pki)
            reply = await ask(reader, writer, {"op": "hello", "v": 1, "name": install["name"],
                                               "secret": install["secret"]})
            assert reply["op"] == "ready"
            assert await closed_quickly(relay.public_port, f"{install['name']}.{DOMAIN}", pki)
            assert not relay.control.pending and not relay.control.counts
        finally:
            await relay.close()

    run(scenario())


def test_the_limit_of_pending_joins(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        relay.control.MAX_PENDING = 2
        relay.control.JOIN_SECONDS = 0.8
        try:
            install = await registered(relay, pki)
            reader, writer = await control(relay, pki)
            await ask(reader, writer, {"op": "hello", "v": 1, "name": install["name"],
                                       "secret": install["secret"]})
            waiting = [asyncio.ensure_future(closed_quickly(relay.public_port,
                                                            f"{install['name']}.{DOMAIN}", pki))
                       for _ in range(2)]
            await until(lambda: len(relay.control.pending) == 2, "two streams wait")
            started = asyncio.get_running_loop().time()
            assert await closed_quickly(relay.public_port, f"{install['name']}.{DOMAIN}", pki)
            assert asyncio.get_running_loop().time() - started < 0.5
            assert all(await asyncio.gather(*waiting))
        finally:
            await relay.close()

    run(scenario())


def test_the_tunnel_answers_pings_and_a_silent_tunnel_is_dropped(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        relay.control.PING_SECONDS = 0.1
        relay.control.SILENT_SECONDS = 0.5
        try:
            install = await registered(relay, pki)
            path = remote_json(tmp_path, relay, pki, install)
            tunnel, task = await start_tunnel(path, relay, install["name"])
            session = relay.control.sessions[install["name"]]
            await asyncio.sleep(1.2)
            assert relay.control.sessions.get(install["name"]) is session
            task.cancel()

            # A raw tunnel that never answers is dropped.
            other = await registered(relay, pki)
            reader, writer = await control(relay, pki)
            await ask(reader, writer, {"op": "hello", "v": 1, "name": other["name"],
                                       "secret": other["secret"]})
            await until(lambda: other["name"] not in relay.control.sessions, "the silent one is dropped")
        finally:
            await relay.close()

    run(scenario())


def test_the_tunnel_says_hello_again_when_its_names_change(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            install = await registered(relay, pki)
            path = remote_json(tmp_path, relay, pki, install)
            tunnel = Tunnel(path)
            tunnel.NAMES_SECONDS = 0.1
            task = asyncio.ensure_future(tunnel.serve())
            await until(lambda: install["name"] in relay.control.sessions, "the tunnel connects")
            tunnel.settings.names = ["later.id.decentai"]
            await until(lambda: relay.store.owner("later.id.decentai") == install["name"], "the name binds")
            await until(lambda: "later.id.decentai" in tunnel.hosts, "the relay says so")
            task.cancel()
        finally:
            await relay.close()

    run(scenario())


def test_the_tunnel_comes_back_when_the_relay_does(pki, tmp_path):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        install = await registered(relay, pki)
        home = await Home(pki, f"{install['name']}.{DOMAIN}").start()
        path = remote_json(tmp_path, relay, pki, install, targets={"*": f"127.0.0.1:{home.port}"})
        tunnel, task = await start_tunnel(path, relay, install["name"])
        port = relay.public_port
        await relay.close()
        await until(lambda: not tunnel.connected, "the tunnel sees the relay go")
        relay = await start_relay(pki, tmp_path, public_port=port)
        try:
            await until(lambda: install["name"] in relay.control.sessions, "the tunnel is back", 10)
            answer, _ = await visit(port, f"{install['name']}.{DOMAIN}", pki)
            assert answer == b"home saw: hello\n"
        finally:
            task.cancel()
            home.close()
            await relay.close()

    run(scenario())


def test_port_80_sends_to_https_and_serves_the_relays_own_challenges(pki, tmp_path):
    challenge = tmp_path / "acme" / ".well-known" / "acme-challenge"
    challenge.mkdir(parents=True)
    (challenge / "tok-en_1").write_text("tok-en_1.thumbprint")

    async def get(port: int, target: str, host: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        return answer

    async def scenario():
        relay = await start_relay(pki, tmp_path)
        try:
            answer = await get(relay.http_port, "/app?x=1", "abc.localhost:80")
            assert answer.startswith(b"HTTP/1.1 301")
            assert b"Location: https://abc.localhost/app?x=1\r\n" in answer
            answer = await get(relay.http_port, "/.well-known/acme-challenge/tok-en_1", DOMAIN)
            assert answer.startswith(b"HTTP/1.1 200") and answer.endswith(b"tok-en_1.thumbprint")
            answer = await get(relay.http_port, "/.well-known/acme-challenge/tok-en_1", "abc.localhost")
            assert answer.startswith(b"HTTP/1.1 301")
            answer = await get(relay.http_port, "/.well-known/acme-challenge/../../relay.db", DOMAIN)
            assert answer.startswith(b"HTTP/1.1 404")
            answer = await get(relay.http_port, "/", "bad host\r\nX: y")
            assert answer.startswith(b"HTTP/1.1 400")
        finally:
            await relay.close()

    run(scenario())


def test_the_configuration_comes_from_the_environment(pki, tmp_path):
    from relay.server import Config, ConfigError

    cert, key, _ = pki.issue(DOMAIN)
    config = Config.from_environment({"RELAY_DOMAIN": "Relay.Example.NET.", "RELAY_CERT": cert,
                                      "RELAY_KEY": key, "RELAY_DATA": str(tmp_path),
                                      "RELAY_PUBLIC_PORT": "8443", "RELAY_HTTP_PORT": "8080"})
    assert (config.domain, config.public_port, config.http_port, config.registration) == \
        ("relay.example.net", 8443, 8080, "open")
    for wrong in ({}, {"RELAY_DOMAIN": "relay.example.net"},
                  {"RELAY_DOMAIN": "r.example", "RELAY_CERT": cert, "RELAY_KEY": key,
                   "RELAY_REGISTRATION": "key"},
                  {"RELAY_DOMAIN": "r.example", "RELAY_CERT": cert, "RELAY_KEY": key,
                   "RELAY_PUBLIC_PORT": "https"}):
        with pytest.raises(ConfigError):
            Config.from_environment(wrong)
