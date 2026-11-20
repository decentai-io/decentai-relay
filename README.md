# decentai-relay

A relay that lets a computer behind NAT be reached at a public HTTPS address, without opening a port
and without the relay ever seeing the traffic. The DecentAI app uses it for **Reach from anywhere**:
your phone, a browser anywhere, or another computer reaches DecentAI running at home.

- **End-to-end TLS.** The relay reads only the server name a connection asks for, and passes the
  connection through unopened to the computer that owns that name. Certificates and keys stay on that
  computer.
- **No port forwarding.** The computer at home keeps one outgoing connection to the relay.
- **Small.** Python's standard library and nothing else; one container, one SQLite file.
- **Yours to run.** DecentAI runs no relay of its own. Run one for yourself, your family, your company
  or anyone, under the Apache License 2.0.

```
relay/              the relay: routing by SNI, the control protocol, its store
tunnel/             the reference client: register once, then hold the connection
tests/              end to end: a real relay, a real tunnel, a TLS server at home
docs/protocol.md    the protocol, version 1
docs/running.md     running a relay
deploy/setup.sh     a relay on a fresh Debian or Ubuntu server, in one go
deploy/docker-compose.yml
Dockerfile          the image: ghcr.io/decentai-io/relay
```

## Run one

Point `relay.example.net` and `*.relay.example.net` at a server with ports 80 and 443 open, then on it:

```sh
git clone https://github.com/decentai-io/decentai-relay.git
cd decentai-relay
sudo bash deploy/setup.sh relay.example.net --email you@example.com
```

Everything else, including running it without the script: [docs/running.md](docs/running.md).

## Use one

In the DecentAI app, **Reach from anywhere**, and type the relay's name. For anything else that speaks
TLS:

```sh
python -m tunnel register relay.example.net --to 127.0.0.1:8443
python -m tunnel run
```

## Tests

Python 3.12, with `pytest` and `cryptography` (the tests make a throwaway CA; the relay needs neither):

```sh
python -m pytest tests -q
```

They start a real relay on ports of its own choosing with `localhost` as its domain, a real tunnel and
a TLS server standing for home, and check that a client reaches home with home's certificate and that
the relay never carries a plaintext byte.

## Licence

Copyright 2026 DECENT INTELLIGENCE ARTIFICIAL SERVICES. Licensed under the Apache License, Version 2.0
([LICENSE](LICENSE)). Security reports: [SECURITY.md](SECURITY.md). Contributions:
[CONTRIBUTING.md](CONTRIBUTING.md).
