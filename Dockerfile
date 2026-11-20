# The relay, and its reference tunnel client (docs/protocol.md).
#
#   docker build -t decentai-relay .
#   docker run ... decentai-relay                                        the relay (docs/running.md)
#   docker run ... --entrypoint python3 decentai-relay -m tunnel run      the tunnel client
#
# Python's standard library and nothing else. It runs as a user of its own (10001), keeps relay.db in
# /data, and listens on 443 and 80: Docker lets a container's user bind those (its default
# net.ipv4.ip_unprivileged_port_start=0), with no capability.
FROM python:3.12-alpine

RUN addgroup -S -g 10001 relay \
    && adduser -S -D -H -u 10001 -G relay relay \
    && mkdir -p /data \
    && chown relay:relay /data

WORKDIR /relay
COPY relay ./relay
COPY tunnel ./tunnel

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELAY_DATA=/data
VOLUME ["/data"]
EXPOSE 443 80
USER relay
ENTRYPOINT ["python3", "-m", "relay"]
