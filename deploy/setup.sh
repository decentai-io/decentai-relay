#!/usr/bin/env bash
# A DecentAI relay on a fresh Debian or Ubuntu server, in one go (docs/running.md).
#
#   sudo bash setup.sh relay.example.net [--email you@example.com] [--keys] [--image IMAGE | --build]
#
# Before running it: point relay.example.net and *.relay.example.net at this server (A records, and
# AAAA where it has IPv6), and let ports 80 and 443 in. It then:
#   1. installs Docker and certbot from the system's packages;
#   2. gets a Let's Encrypt certificate for the relay's own name (never a wildcard), and renews it by
#      itself, stopping the relay for the few seconds a renewal takes;
#   3. with --keys, makes a registration key, so that only people you give one to can use the relay;
#   4. starts the relay, which restarts with the server.
# Running it again is safe: it keeps the certificate, the keys and the relay's database.
set -euo pipefail

DOMAIN=""
EMAIL=""
KEYS="no"
IMAGE="ghcr.io/decentai-io/decentai-relay:1.0.0"
BUILD="no"
HOME_DIR="/srv/relay"
NAME="decentai-relay"

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\nSetup stopped: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="${2:-}"; shift 2 ;;
    --keys) KEYS="yes"; shift ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --build) BUILD="yes"; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    -*) fail "unknown option $1 (see --help)" ;;
    *) DOMAIN="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"; shift ;;
  esac
done

[ -n "$DOMAIN" ] || fail "name the relay: sudo bash setup.sh relay.example.net"
printf '%s' "$DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' \
  || fail "'$DOMAIN' is not a domain name"
[ "$(id -u)" = 0 ] || fail "run it as root: sudo bash setup.sh $DOMAIN"
command -v apt-get >/dev/null || fail "this script is for Debian and Ubuntu; docs/running.md says how to run the relay elsewhere"

say "Checking DNS for $DOMAIN and *.$DOMAIN"
own=$(getent ahosts "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
probe="dns-check-$RANDOM.$DOMAIN"
wild=$(getent ahosts "$probe" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
[ -n "$own" ] || fail "$DOMAIN does not resolve yet. Add an A record for it pointing at this server, wait a few minutes, and run this again."
[ -n "$wild" ] || fail "*.$DOMAIN does not resolve yet ($probe has no address). Add a wildcard A record for *.$DOMAIN pointing at this server, and run this again."
echo "$DOMAIN -> $own"
echo "*.$DOMAIN -> $wild"
[ "$own" = "$wild" ] || echo "Warning: the two resolve to different addresses. Both must be this server."

say "Installing Docker and certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q docker.io certbot openssl
systemctl enable --now docker >/dev/null 2>&1 || true

mkdir -p "$HOME_DIR/certs" "$HOME_DIR/data/acme"

if [ "$BUILD" = yes ]; then
  here="$(cd "$(dirname "$0")/.." && pwd)"
  [ -f "$here/Dockerfile" ] || fail "--build runs from a checkout of decentai-relay: no Dockerfile in $here"
  say "Building the relay's image from $here"
  docker build -t decentai-relay:local "$here"
  IMAGE="decentai-relay:local"
else
  say "Fetching $IMAGE"
  docker pull "$IMAGE"
fi

say "The relay's certificate"
# The relay holds 80 while it runs; certbot needs it for the few seconds of a renewal.
mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/pre/decentai-relay.sh <<EOF
#!/bin/sh
docker stop $NAME >/dev/null 2>&1 || true
EOF
cat > /etc/letsencrypt/renewal-hooks/post/decentai-relay.sh <<EOF
#!/bin/sh
docker start $NAME >/dev/null 2>&1 || true
EOF
# Copies a new certificate where the relay reads it (it notices within a minute), readable by its user.
cat > /etc/letsencrypt/renewal-hooks/deploy/decentai-relay.sh <<EOF
#!/bin/sh
[ "\$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$DOMAIN" ] || exit 0
install -m 0644 -o 10001 -g 10001 "\$RENEWED_LINEAGE/fullchain.pem" $HOME_DIR/certs/relay.pem
install -m 0600 -o 10001 -g 10001 "\$RENEWED_LINEAGE/privkey.pem"   $HOME_DIR/certs/relay.key
EOF
chmod +x /etc/letsencrypt/renewal-hooks/*/decentai-relay.sh

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
  docker stop "$NAME" >/dev/null 2>&1 || true
  if [ -n "$EMAIL" ]; then account=(-m "$EMAIL"); else account=(--register-unsafely-without-email); fi
  certbot certonly --standalone --non-interactive --agree-tos "${account[@]}" -d "$DOMAIN" \
    || fail "Let's Encrypt did not issue the certificate. Is port 80 open to the internet, and does $DOMAIN point here?"
fi
RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN" sh /etc/letsencrypt/renewal-hooks/deploy/decentai-relay.sh

registration=(-e RELAY_REGISTRATION=open)
if [ "$KEYS" = yes ] || [ -s "$HOME_DIR/certs/keys" ]; then
  if [ ! -s "$HOME_DIR/certs/keys" ]; then
    say "A registration key"
    { echo "# One key per line. Add one: openssl rand -hex 24 >> $HOME_DIR/certs/keys"; openssl rand -hex 24; } \
      > "$HOME_DIR/certs/keys"
  fi
  registration=(-e RELAY_REGISTRATION=key -e RELAY_KEYS=/certs/keys)
fi
chown -R 10001:10001 "$HOME_DIR"

say "Starting the relay"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p 443:443 -p 80:80 \
  -e RELAY_DOMAIN="$DOMAIN" \
  -e RELAY_CERT=/certs/relay.pem -e RELAY_KEY=/certs/relay.key \
  "${registration[@]}" \
  -v "$HOME_DIR/certs:/certs:ro" \
  -v "$HOME_DIR/data:/data" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
  if echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null | grep -q "BEGIN CERTIFICATE" \
  || { docker logs --tail 30 "$NAME" >&2; fail "the relay did not answer on 443"; }

say "Done"
echo "The relay is $DOMAIN. In the DecentAI app: Reach from anywhere, Relay: $DOMAIN"
if [ -s "$HOME_DIR/certs/keys" ]; then
  echo "Registration needs a key. The keys are in $HOME_DIR/certs/keys:"
  grep -v '^#' "$HOME_DIR/certs/keys" | sed 's/^/  /'
  echo "Give one to each person (from the command line: remote on --relay $DOMAIN --key <key>)."
else
  echo "Anyone may register with it. To require a key: sudo bash setup.sh $DOMAIN --keys"
fi
echo "Its log: docker logs $NAME. Its database, to back up: $HOME_DIR/data/relay.db"
