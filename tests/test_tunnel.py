"""The tunnel client on its own: remote.json, a node's names, its forwards, and
messages it does not expect. test_relay.py runs it end to end, with a relay."""

from __future__ import annotations

import asyncio
import datetime
import json
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tunnel import client as tunnel  # noqa: E402
from tunnel.client import Settings, Tunnel, TunnelError, discover_names, endpoint  # noqa: E402


def node_folder(folder: Path, names: list[str]) -> Path:
    """An identity folder as DecentAI's identity.py saves it: node.pem holds
    the key, the node's certificate, then the certificate that signed it."""
    root_key, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)

    def certificate(subject: str, public, signer, alternative: list[str]):
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
                   .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root")]))
                   .public_key(public).serial_number(x509.random_serial_number())
                   .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
        if alternative:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in alternative]), critical=False)
        return builder.sign(signer, None)

    pem = serialization.Encoding.PEM
    node = certificate("node", key.public_key(), root_key, names)
    root = certificate("root", root_key.public_key(), root_key, ["root.id.decentai"])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "node.pem").write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        + node.public_bytes(pem) + root.public_bytes(pem))
    return folder


def test_discover_names_reads_the_nodes_own_certificate(tmp_path):
    folder = node_folder(tmp_path / "runtime",
                         ["3f9c-node.id.decentai", "runtime.kind.decentai", "Other.ID.decentai"])
    assert discover_names(folder) == ["3f9c-node.id.decentai", "other.id.decentai"]
    assert discover_names(tmp_path / "nowhere") == []
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "node.pem").write_text("-----BEGIN CERTIFICATE-----\nnot base64!\n"
                                                   "-----END CERTIFICATE-----\n")
    assert discover_names(tmp_path / "broken") == []
    assert discover_names(node_folder(tmp_path / "plain", [])) == []


def test_the_fallback_reads_the_same_names_without_cryptography(tmp_path, monkeypatch):
    folder = node_folder(tmp_path / "runtime", ["abc.id.decentai", "runtime.kind.decentai"])

    def missing(der):
        raise ImportError("no cryptography here")

    monkeypatch.setattr(tunnel, "_names_with_cryptography", missing)
    assert discover_names(folder) == ["abc.id.decentai"]
    assert discover_names(node_folder(tmp_path / "plain", [])) == []
    with pytest.raises(ValueError):
        tunnel._names_from_der(b"\x30\x84\xff\xff\xff\xff")


def test_endpoints():
    assert endpoint("relay.example.net", 443) == ("relay.example.net", 443)
    assert endpoint("relay.example:8443", 443) == ("relay.example", 8443)
    assert endpoint("caddy:443") == ("caddy", 443)
    assert endpoint("[::1]:8004") == ("::1", 8004)
    for wrong in ("caddy", "caddy:http", "caddy:0", ":443", "a:b:c"):
        with pytest.raises(TunnelError):
            endpoint(wrong)


def test_remote_json(tmp_path):
    path = tmp_path / "remote.json"
    path.write_text(json.dumps({
        "relay": "relay.example.net", "name": "abc0123456", "secret": "s", "domain": "relay.example.net",
        "targets": {"abc0123456.relay.example.net": "caddy:443", "*": "caddy:443"},
        "forwards": {"8004": "issuer.example.com:8004"},
        "names": ["X.id.decentai", "not a name"], "identity": "/node/runtime"}))
    settings = Settings.read(path)
    assert (settings.relay_host, settings.relay_port) == ("relay.example.net", 443)
    assert settings.targets["abc0123456.relay.example.net"] == ("caddy", 443)
    assert settings.forwards == {8004: ("issuer.example.com", 8004)}
    assert settings.names == ["x.id.decentai"] and settings.identity == "/node/runtime"
    assert settings.identity_target is None
    # As the launcher's node mode writes it.
    path.write_text(json.dumps({"relay": "relay.example:8443", "name": "n", "secret": "s", "targets": {},
                                "identity": {"folder": "/identity/runtime", "target": "runtime:8004"}}))
    settings = Settings.read(path)
    assert (settings.relay_port, settings.identity, settings.identity_target) ==         (8443, "/identity/runtime", ("runtime", 8004))
    for wrong in ("not json", json.dumps([]), json.dumps({"name": "x"}),
                  json.dumps({"relay": "r", "forwards": {"http": "a:1"}}),
                  json.dumps({"relay": "r", "targets": {"h": "no-port"}}),
                  json.dumps({"relay": "r", "identity": ["no"]})):
        path.write_text(wrong)
        with pytest.raises(TunnelError):
            Settings.read(path)
    with pytest.raises(TunnelError):
        Settings.read(tmp_path / "missing.json")


class Written:
    """Stands where the relay connection's writer would: keeps what was sent."""

    def __init__(self):
        self.lines = []

    def write(self, data):
        self.lines.append(json.loads(data))

    async def drain(self):
        pass

    def close(self):
        pass


def test_hosts_go_to_their_target_then_the_identitys_then_the_default(tmp_path):
    folder = node_folder(tmp_path / "runtime", ["abc.id.decentai"])
    path = tmp_path / "remote.json"
    path.write_text(json.dumps({"relay": "relay.example", "name": "n", "secret": "s",
                                "targets": {"n.relay.example": "caddy:8443", "*": "fallback:1"},
                                "identity": {"folder": str(folder), "target": "runtime:8004"}}))
    held = Tunnel(path)
    held.settings = Settings.read(path)
    assert held.current_names() == ["abc.id.decentai"]
    assert held.target("n.relay.example") == ("caddy", 8443)
    assert held.target("abc.id.decentai") == ("runtime", 8004)
    assert held.target("other.id.decentai") == ("fallback", 1)


def test_any_message_is_handled_without_raising(tmp_path):
    path = tmp_path / "remote.json"
    path.write_text(json.dumps({"relay": "relay.example", "name": "n", "secret": "s",
                                "targets": {"*": "127.0.0.1:9"}}))

    async def scenario():
        held = Tunnel(path)
        held.settings = Settings.read(path)
        held._writer = Written()
        joins = []

        async def join(stream, host):
            joins.append((stream, host))
        held._join = join
        for message in (None, {}, {"op": None}, {"op": 7}, {"op": "open"},
                        {"op": "open", "stream": 5, "host": "x"}, {"op": "open", "stream": "", "host": "x"},
                        {"op": "open", "stream": "s", "host": "x" * 300}, {"op": "ready", "hosts": "no"},
                        {"op": "error", "error": ["no"]}, {"op": "future-op", "anything": 1}, {"op": "pong"}):
            await held.handle(message)
        await held.handle({"op": "ping"})
        await held.handle({"op": "open", "stream": "st", "host": "ABC.example"})
        await asyncio.sleep(0)
        assert held._writer.lines == [{"op": "pong"}]
        assert joins == [("st", "abc.example")]
        assert held.target("anything") == ("127.0.0.1", 9)

    asyncio.run(scenario())
    assert tunnel.decode(b"\xff\xfe") is None and tunnel.decode(b"[1]") is None


def test_a_forward_pipes_plain_tcp_to_its_target(tmp_path):
    async def scenario():
        async def echo(reader, writer):
            writer.write(b"echo: " + await reader.readline())
            await writer.drain()
            writer.close()

        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()
        path = tmp_path / "remote.json"
        path.write_text(json.dumps({"relay": "relay.example",
                                    "forwards": {str(port): f"127.0.0.1:{target_port}"}}))
        task = asyncio.ensure_future(Tunnel(path).serve())
        try:
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    break
                except OSError:
                    await asyncio.sleep(0.02)
            writer.write(b"through the forward\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.readline(), 5) == b"echo: through the forward\n"
            writer.close()
        finally:
            task.cancel()
            target.close()

    asyncio.run(scenario())


def test_main_says_what_is_wrong_with_the_config(tmp_path, capsys):
    assert tunnel.main(["--config", str(tmp_path / "missing.json")]) == 1
    assert "could not be read" in capsys.readouterr().err
