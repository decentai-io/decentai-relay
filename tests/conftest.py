"""The relay's tests: a real relay on ports of its own choosing, a real tunnel,
a home server behind it, and a throwaway CA for every certificate.

    python -m pytest tests -q

The relay's domain is `localhost`, so that the tunnel finds the relay by
its name with no DNS of its own; the public clients connect to 127.0.0.1
and name `<name>.localhost` in their SNI.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tunnel.client import Tunnel, register  # noqa: E402
from relay.server import Config, Relay  # noqa: E402

DOMAIN = "localhost"


class PKI:
    """A CA made for one test, and the certificates it issues."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Throwaway test CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                           critical=True)
            .sign(self.key, hashes.SHA256()))
        self.ca = str(folder / "ca.pem")
        Path(self.ca).write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))
        self.issued = 0

    def issue(self, *names: str) -> tuple[str, str, bytes]:
        """(certificate path, key path, the certificate's DER) for the names."""
        self.issued += 1
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self.certificate.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
                           critical=False)
            .sign(self.key, hashes.SHA256()))
        cert_path = self.folder / f"leaf{self.issued}.pem"
        key_path = self.folder / f"leaf{self.issued}.key"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        return str(cert_path), str(key_path), certificate.public_bytes(serialization.Encoding.DER)

    def client(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.ca)


@pytest.fixture
def pki(tmp_path) -> PKI:
    return PKI(tmp_path)


async def start_relay(pki: PKI, folder: Path, **changes) -> Relay:
    cert, key, _ = pki.issue(DOMAIN)
    config = Config(domain=DOMAIN, cert=cert, key=key, data=str(folder / "data"),
                    public_port=0, http_port=0, listen="127.0.0.1",
                    acme=str(folder / "acme"))
    for name, value in changes.items():
        setattr(config, name, value)
    config.check()
    relay = Relay(config)
    await relay.start()
    return relay


async def registered(relay: Relay, pki: PKI, key: str = "") -> dict:
    return await asyncio.to_thread(register, f"{DOMAIN}:{relay.public_port}", key, pki.ca)


def remote_json(folder: Path, relay: Relay, pki: PKI, registration: dict, **fields) -> Path:
    import json

    path = folder / f"remote-{registration.get('name', 'none')}.json"
    path.write_text(json.dumps({**registration, "relay": f"{DOMAIN}:{relay.public_port}",
                                "insecure_ca": pki.ca, **fields}))
    return path


async def start_tunnel(path: Path, relay: Relay, name: str) -> tuple[Tunnel, asyncio.Task]:
    tunnel = Tunnel(path)
    task = asyncio.ensure_future(tunnel.serve())
    await until(lambda: name in relay.control.sessions and tunnel.connected, "the tunnel connects")
    return tunnel, task


async def until(condition, what: str, seconds: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + seconds
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timed out waiting until {what}")
        await asyncio.sleep(0.02)


class Home:
    """A TLS server at home: answers each line with 'home saw: <line>', and
    keeps what it received."""

    def __init__(self, pki: PKI, *names: str):
        self.cert, self.key, self.der = pki.issue(*names)
        self.received: list[bytes] = []
        self.server = None
        self.port = 0

    async def start(self) -> "Home":
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert, self.key)
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=context)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _serve(self, reader, writer):
        try:
            line = await reader.readline()
            self.received.append(line)
            writer.write(b"home saw: " + line)
            await writer.drain()
        finally:
            writer.close()

    def close(self):
        self.server.close()


async def visit(port: int, sni: str, pki: PKI, line: bytes = b"hello\n") -> tuple[bytes, bytes]:
    """A public client: connects to the relay naming ``sni``, checks the
    certificate it is shown, and returns (the answer, that certificate's DER)."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        "127.0.0.1", port, ssl=pki.client(), server_hostname=sni), 5)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.write(line)
        await writer.drain()
        return await asyncio.wait_for(reader.readline(), 5), der
    finally:
        writer.close()


async def control(relay: Relay, pki: PKI):
    """A raw control connection to the relay, for the protocol's own tests."""
    return await asyncio.wait_for(asyncio.open_connection(
        "127.0.0.1", relay.public_port, ssl=pki.client(), server_hostname=DOMAIN), 5)


async def ask(reader, writer, message: dict) -> dict:
    import json

    writer.write(json.dumps(message).encode() + b"\n")
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), 5)
    return json.loads(line) if line else {}
