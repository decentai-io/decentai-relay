"""The relay: how an install at home is reached from anywhere, behind any NAT (docs/protocol.md).

    sni.py       the server name a TLS ClientHello asks for, read without ending TLS
    server.py    the public ports: :443 passed on by its SNI, :80 sent to https
    control.py   the control protocol: register, hello, ping, and the joins that carry streams
    store.py     what the relay keeps: installs, their hashed secrets, the exact names they own
    __main__.py  the command line: python -m relay, configured from the environment

docs/running.md describes running it.
"""

VERSION = "1.0.0"
