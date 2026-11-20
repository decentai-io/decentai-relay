"""The relay's command line: python -m relay, configured from the environment.

    RELAY_DOMAIN         the relay's name, such as relay.example.net (required)
    RELAY_CERT           the PEM file of its own certificate, for that name alone (required)
    RELAY_KEY            the PEM file of that certificate's key (required)
    RELAY_REGISTRATION   open (the default) or key
    RELAY_KEYS           with key: a file of registration keys, one per line
    RELAY_DATA           where relay.db is kept; /data
    RELAY_PUBLIC_PORT    443
    RELAY_HTTP_PORT      80
    RELAY_LISTEN         the address both listen on; every address when unset
    RELAY_ACME           where certbot's webroot challenges are served from; $RELAY_DATA/acme
    RELAY_LOG            the log's level; INFO
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from relay import VERSION
from relay.server import Config, ConfigError, Relay

log = logging.getLogger("relay")


async def serve(config: Config) -> None:
    """Runs the relay until it is told to stop."""
    relay = Relay(config)
    await relay.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await stop.wait()
    finally:
        log.info("stopping")
        await relay.close()


def main() -> int:
    logging.basicConfig(level=(os.environ.get("RELAY_LOG") or "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    log.info("decentai-relay %s", VERSION)
    try:
        config = Config.from_environment()
    except ConfigError as why:
        log.error("%s", why)
        return 2
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        pass
    except OSError as why:
        log.error("the relay could not start: %s", why)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
