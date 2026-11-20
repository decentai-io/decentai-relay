"""The tunnel's command line against a real relay: register writes remote.json, run reaches home."""

from __future__ import annotations

import asyncio
import json

from conftest import DOMAIN, Home, start_relay, start_tunnel, visit
from tunnel.__main__ import main


def run(coroutine):
    return asyncio.run(asyncio.wait_for(coroutine, 30))


def test_register_then_run_reaches_a_tls_server_of_ones_own(pki, tmp_path, capsys):
    async def scenario():
        relay = await start_relay(pki, tmp_path)
        config = tmp_path / "remote.json"
        relay_address = f"{DOMAIN}:{relay.public_port}"
        asked = ["register", relay_address, "--to", "127.0.0.1:1", "--config", str(config), "--ca", pki.ca]
        assert await asyncio.to_thread(main, asked) == 0
        said = json.loads(config.read_text())
        name = said["name"]
        assert said["relay"] == relay_address and said["targets"] == {"*": "127.0.0.1:1"}
        assert f"Address: https://{name}.{DOMAIN}" in capsys.readouterr().out

        # A second register keeps the name, and only changes where it goes.
        home = await Home(pki, f"{name}.{DOMAIN}").start()
        asked[3] = f"127.0.0.1:{home.port}"
        assert await asyncio.to_thread(main, asked) == 0
        again = json.loads(config.read_text())
        assert again["name"] == name and again["secret"] == said["secret"]

        tunnel, task = await start_tunnel(config, relay, name)
        try:
            answer, der = await visit(relay.public_port, f"{name}.{DOMAIN}", pki)
            assert answer == b"home saw: hello\n" and der == home.der
        finally:
            task.cancel()
            home.close()
            await relay.close()

    run(scenario())


def test_a_target_that_is_not_host_and_port_is_refused(pki, tmp_path, monkeypatch, capsys):
    from tunnel import client

    monkeypatch.setattr(client, "register", lambda relay, key="", ca="": {
        "name": "k3x9abcdef", "secret": "s", "domain": "relay.example.net"})
    config = tmp_path / "remote.json"
    assert main(["register", "relay.example.net", "--to", "nowhere", "--config", str(config)]) == 1
    assert not config.exists()


def test_config_alone_runs(monkeypatch):
    from tunnel import client

    asked = []
    monkeypatch.setattr(client, "main", lambda argv: asked.append(argv) or 0)
    assert main(["--config", "x.json"]) == 0 and main([]) == 0
    assert asked == [["--config", "x.json"], ["--config", "remote.json"]]
