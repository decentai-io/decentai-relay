"""The tunnel's command line.

    python -m tunnel register relay.example.net --to 127.0.0.1:8443 [--key KEY] [--config remote.json]
        asks the relay for a name, once, and writes remote.json: every connection for that name
        goes to --to, a TLS server of your own that holds a certificate for it
    python -m tunnel run [--config remote.json]
        holds the connection to the relay until stopped, reconnecting by itself

`python -m tunnel --config remote.json` is `run`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from tunnel import VERSION, client


def register(arguments: argparse.Namespace) -> int:
    path = Path(arguments.config)
    said = {}
    if path.is_file():
        try:
            said = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            print(f"{path} is not JSON: move it away, or name another --config.", file=sys.stderr)
            return 1
    relay = arguments.relay.strip().lower()
    if said.get("name") and said.get("relay") == relay and not arguments.again:
        print(f"{path} already has a name on {relay}: https://{said['name']}.{said['domain']}")
    else:
        try:
            given = client.register(relay, arguments.key or "", arguments.ca or "")
        except Exception as failed:  # the relay's own words, whatever went wrong
            print(f"{relay} gave no name: {failed}", file=sys.stderr)
            return 1
        said = {"relay": relay, "name": given["name"], "secret": given["secret"], "domain": given["domain"]}
    try:
        client.endpoint(arguments.to)
    except client.TunnelError as wrong:
        print(str(wrong), file=sys.stderr)
        return 1
    said["targets"] = {"*": arguments.to}
    if arguments.ca:
        said["insecure_ca"] = arguments.ca
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.incoming")
    staging.write_text(json.dumps(said, indent=1, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(staging, 0o600)  # it holds the secret
    except OSError:
        pass
    staging.replace(path)
    host = f"{said['name']}.{said['domain']}"
    print(f"Address: https://{host}")
    print(f"Written to {path}. Serve TLS for {host} at {arguments.to}, then: python -m tunnel run --config {path}")
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="tunnel", description="The client of a DecentAI relay.")
    top.add_argument("--version", action="version", version=f"tunnel {VERSION}")
    commands = top.add_subparsers(dest="command")
    asked = commands.add_parser("register", help="ask a relay for a name, once, and write remote.json")
    asked.add_argument("relay", help="the relay's name, such as relay.example.net (and :port when not 443)")
    asked.add_argument("--to", required=True,
                       help="host:port of the TLS server every connection goes to, such as 127.0.0.1:8443")
    asked.add_argument("--key", help="the relay's registration key, where it asks for one")
    asked.add_argument("--config", default="remote.json", help="where to write it: remote.json")
    asked.add_argument("--ca", help="trust this CA's PEM file for the relay instead of the system's (tests)")
    asked.add_argument("--again", action="store_true", help="ask for a new name even if one is kept")
    run = commands.add_parser("run", help="hold the connection to the relay")
    run.add_argument("--config", default="remote.json")
    return top


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("--config"):
        argv = ["run", *argv]
    arguments = parser().parse_args(argv)
    if arguments.command == "register":
        return register(arguments)
    return client.main(["--config", arguments.config])


if __name__ == "__main__":
    sys.exit(main())
