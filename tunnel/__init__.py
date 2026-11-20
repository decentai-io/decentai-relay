"""The tunnel: the client half of the DecentAI relay protocol (docs/protocol.md).

An install behind NAT keeps one outgoing connection to a relay; the relay passes each public
TLS connection for the install's names through it, unopened, to a TLS server the install runs.

    client.py    the protocol: register once, then hold the connection (Tunnel)
    __main__.py  the command line: python -m tunnel register | run

Python's standard library and nothing else.
"""

from tunnel.client import Settings, Tunnel, TunnelError, discover_names, endpoint, register

VERSION = "1.0.0"

__all__ = ["Settings", "Tunnel", "TunnelError", "discover_names", "endpoint", "register", "VERSION"]
