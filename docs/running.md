# Running a relay

A DecentAI relay lets the DecentAI app on someone's computer be reached from their phone, from a
browser anywhere, and from other computers, without opening a port on their router. Their computer
keeps one outgoing connection to the relay; the relay passes each visitor's encrypted connection
through it, unopened. How that works, exactly: [the protocol](protocol.md).

Anyone may run one: for themselves, their family, their company, or for the public.

## What it needs

- A small server with a public IPv4 address: 1 processor and 512 MB of memory are enough for many
  installs; the relay copies bytes and does no encryption of its own except on its control
  connections. Any provider will do.
- Ports **80** and **443** open to the internet, and nothing else listening on them.
- A domain name you control, for example `relay.example.net`. A domain of its own (not a subdomain of
  your main site) is best: see [Let's Encrypt's limit](#lets-encrypts-limit).

Bandwidth is what grows with use: every byte between a visitor and an install crosses the relay twice
(in, then out). Choose a provider whose price includes enough transfer.

## 1. DNS

Two records, both pointing at the server (and the same two as AAAA records if it has IPv6):

```
relay.example.net.      A   203.0.113.10
*.relay.example.net.    A   203.0.113.10
```

`relay.example.net` is the relay's own name: the apps connect to it. Every install gets a name under
it, such as `k3x9q0w2mz.relay.example.net`.

## 2. Setting it up

### On Debian or Ubuntu: one script

On the server, as root:

```sh
git clone https://github.com/decentai-io/decentai-relay.git
cd decentai-relay
sudo bash deploy/setup.sh relay.example.net --email you@example.com
```

It checks the DNS records, installs Docker and certbot, gets the relay's certificate from Let's
Encrypt and sets it to renew by itself, and starts the relay so that it restarts with the server. At
the end it prints the relay's name, to type into the DecentAI app.

| Option | |
|---|---|
| `--email ADDRESS` | Let's Encrypt writes there about the certificate. Without it, no account email. |
| `--keys` | Only people with a registration key may use the relay. It makes one and prints it. |
| `--build` | Build the image from this checkout rather than fetching the published one. |
| `--image IMAGE` | Run another published version. |

Running it again is safe: the certificate, the keys and the relay's database are kept.

### Anywhere else, by hand

The relay is one container. It needs a certificate for its own name only (never a wildcard): each
install gets its own certificate, on its own computer, through the relay.

1. Get the certificate, while port 80 is still free, for example with certbot:
   ```sh
   certbot certonly --standalone -d relay.example.net
   ```
   A DNS-01 plugin for your DNS provider works too, and needs neither port.
2. Put the certificate and its key where the relay reads them, readable by its user (10001):
   ```sh
   mkdir -p /srv/relay/certs /srv/relay/data
   install -m 0644 /etc/letsencrypt/live/relay.example.net/fullchain.pem /srv/relay/certs/relay.pem
   install -m 0600 /etc/letsencrypt/live/relay.example.net/privkey.pem   /srv/relay/certs/relay.key
   chown -R 10001:10001 /srv/relay
   ```
   Do the same after every renewal (a certbot `deploy` hook). The relay notices a changed file within a
   minute; no restart is needed.
3. Start it:
   ```sh
   docker run -d --name decentai-relay --restart unless-stopped \
     -p 443:443 -p 80:80 \
     -e RELAY_DOMAIN=relay.example.net \
     -e RELAY_CERT=/certs/relay.pem -e RELAY_KEY=/certs/relay.key \
     -v /srv/relay/certs:/certs:ro -v /srv/relay/data:/data \
     ghcr.io/decentai-io/decentai-relay:1.0.0
   ```
   Or with [deploy/docker-compose.yml](../deploy/docker-compose.yml):
   `RELAY_DOMAIN=relay.example.net docker compose up -d`, with `certs/` and `data/` beside it.

While the relay runs it answers certbot's HTTP-01 challenges for its own name from
`/data/acme/.well-known/acme-challenge/`, so `certbot renew --webroot -w /srv/relay/data/acme` renews
without stopping it. (`setup.sh` instead stops the relay for the few seconds of a renewal, which needs
no certbot reconfiguration.)

The image runs as user 10001 with no capabilities and binds 443 and 80 inside its container, which
Docker allows by default. With `--network host`, or an engine that does not allow it, map other ports
(`RELAY_PUBLIC_PORT`, `RELAY_HTTP_PORT`) or set `net.ipv4.ip_unprivileged_port_start=0`.

## 3. Using it

In the DecentAI app: **Reach from anywhere**, type the relay's name (`relay.example.net`), **Turn it
on**. The first time, the relay gives that computer a name and the computer gets its own certificate;
the app then shows its address and a QR code for the phone.

Anything else that speaks TLS can be reached the same way, with the tunnel client in this repository:

```sh
python -m tunnel register relay.example.net --to 127.0.0.1:8443   # once: prints the address
python -m tunnel run                                                # keeps the connection
```

The server at `127.0.0.1:8443` must hold a certificate for the printed name, for example from Caddy
with the TLS-ALPN-01 challenge, which reaches it through the relay.

## Registration keys

`RELAY_REGISTRATION=open` (the default) gives a name to anyone who asks, at most 20 an hour from one
address. `RELAY_REGISTRATION=key` gives one only to whoever presents a key from the file `RELAY_KEYS`:
one key per line, blank lines and lines starting with `#` ignored. The file is read at every
registration, so a key is added or withdrawn without a restart:

```sh
openssl rand -hex 24 >> /srv/relay/certs/keys
```

A key is needed only to register; an install that has its name keeps working if its key is withdrawn.
From the DecentAI app's command line, `remote on --relay relay.example.net --key <key>`.

## Settings

| Setting | |
|---|---|
| `RELAY_DOMAIN` | the relay's name (required) |
| `RELAY_CERT`, `RELAY_KEY` | PEM files of its certificate and key (required) |
| `RELAY_REGISTRATION` | `open` (the default) or `key` |
| `RELAY_KEYS` | the file of keys, for `key` |
| `RELAY_DATA` | where `relay.db` is kept; `/data` |
| `RELAY_PUBLIC_PORT`, `RELAY_HTTP_PORT` | `443` and `80` |
| `RELAY_LISTEN` | the address both listen on; every address when unset |
| `RELAY_ACME` | certbot's webroot, served for the relay's own name; `$RELAY_DATA/acme` |
| `RELAY_LOG` | the log's level; `INFO` |

## Keeping it

**Its log.** `docker logs decentai-relay` shows each registration, each tunnel's connection and
disconnection, and each refusal (an unknown name, a wrong secret, a limit reached). It never shows a
secret or a byte of anyone's traffic.

**Its state.** `/srv/relay/data/relay.db` is all of it: the installs (name, a hash of the secret,
created, last seen) and the exact names they own. Back it up. An install whose row is lost must
register again and gets a new name. No row is deleted, so no name is ever given twice.

**Turning an install away.** Empty its secret's hash:

```sh
docker exec decentai-relay python3 -c "import sqlite3; \
  sqlite3.connect('/data/relay.db').execute(\"UPDATE installs SET secret_hash='' WHERE name='k3x9q0w2mz'\").connection.commit()"
```

**Updating.** Run a newer image with the same volume (`setup.sh --image …`, or `docker pull` and
recreate the container). Tunnels reconnect by themselves within a minute.

## What it sees, and what it cannot

The relay reads the server name each connection asks for and passes the connection on, without ending
TLS. It sees who connects to which name, when, for how long and how many bytes; and each install's
name, address and exact names. It cannot see what is said: requests, answers, passwords and files are
encrypted between the visitor and the computer at home, with a key the relay never has.

Whoever runs a relay controls its domain's DNS, and so could have a certificate issued for an
install's name and stand in the middle. Certificate Transparency logs would show such a certificate.
That is the reason to use a relay run by someone you trust, or your own.

## Let's Encrypt's limit

Each install gets its own certificate for `<name>.<relay domain>`. Let's Encrypt allows 50 new
certificates a week per *registered domain* (`example.net` for `relay.example.net`), shared with
everything else under that domain. A relay for many people should have a registered domain of its own
and be added to the [Public Suffix List](https://publicsuffix.org/), after which each install's name
counts on its own. Listing also keeps browsers from treating different installs as one site for
cookies.

## When something does not work

- **The script says the wildcard does not resolve.** Add `*.relay.example.net`, not only
  `relay.example.net`. DNS changes can take some minutes to be seen.
- **Let's Encrypt did not issue the certificate.** Port 80 must reach this server from the internet:
  check the provider's firewall as well as the server's.
- **The app says the relay gave no name.** With `--keys`, registration needs a key. Otherwise check
  `docker logs decentai-relay` for the refusal.
- **An install's address shows a certificate error for a minute.** Its certificate is being made; it
  takes up to a minute the first time.
