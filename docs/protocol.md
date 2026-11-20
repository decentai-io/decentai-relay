# The DecentAI relay protocol, version 1

This document specifies the protocol between a DecentAI relay and its tunnel clients. A relay lets a
TLS server that has no public address (an *install*: typically a computer behind NAT) be reached at a
public name. The relay routes each incoming TLS connection by its Server Name Indication (SNI) and
passes it through, without terminating TLS, over a connection the install opened. End-to-end TLS is
kept between the public client and the install.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

The reference implementations are this repository's `relay/` (the relay) and `tunnel/` (the client).

## 1. Roles and names

- **Relay.** A server with a public address and a DNS name of its own, the *relay domain*, such as
  `relay.example.net`. It holds a certificate for the relay domain only.
- **Install.** A TLS server without a public address, and the tunnel client beside it. An install is
  known to the relay by a *name*: ten characters of `[a-z0-9]`, chosen by the relay.
- **Public client.** Anything that connects to `https://<name>.<relay domain>`: a browser, a phone app.

An install is reached at these hosts:

| Host | Routed to |
|---|---|
| `<name>.<relay domain>` | the install `<name>` |
| `<name>-<label>.<relay domain>`, where `<label>` is `[a-z0-9-]+` | the install `<name>` |
| an *exact name* the install bound (section 4.3) | the install that bound it |
| the relay domain itself | the relay's control server (section 3) |

Any other SNI, and a ClientHello with no SNI, MUST be closed by the relay without a response.

DNS for the relay domain MUST resolve both the relay domain and `*.<relay domain>` to the relay.
Exact names need no DNS: a client that wants one connects to the relay's address and names it in SNI.

## 2. Transport

### 2.1 Port 443: routing by SNI

The relay accepts TCP on port 443 (configurable). For each connection it:

1. reads the first TLS record, which MUST be a handshake record carrying a ClientHello, within
   10 seconds and in at most 16 KiB; otherwise it closes the connection;
2. extracts the `server_name` extension's host name and lower-cases it;
3. routes by section 1, and forwards the ClientHello bytes, unchanged, followed by everything else the
   client sends, to the destination; and the destination's bytes back to the client.

The relay MUST NOT terminate TLS for any host but the relay domain. It cannot read, alter or inject
application data without being detected by the TLS session between the public client and the install.

### 2.2 Port 80

The relay MAY answer plain HTTP on port 80. Version 1 relays answer:

- `GET /.well-known/acme-challenge/<token>` for the relay domain, from a local webroot, so the relay's
  own certificate can renew by HTTP-01;
- anything else with `301 Moved Permanently` to `https://` with the same host and path.

Installs' certificates do not use port 80: they are obtained with the TLS-ALPN-01 challenge (RFC 8737),
which arrives on 443 and is passed through to the install like any other connection.

## 3. The control channel

Control messages travel over TLS to the relay domain on port 443, so the relay's certificate
authenticates the relay. Clients MUST verify that certificate against their trust store.

Messages are JSON objects, one per line, UTF-8, terminated by `\n`. A line MUST NOT exceed 64 KiB.
Every message has a string field `op`. A receiver MUST ignore fields it does not know. The first line
of a connection MUST arrive within 10 seconds.

When the relay refuses anything it sends `{"op": "error", "error": "<reason>"}` and closes the
connection. Reasons are human-readable and not a stable interface.

A control connection carries exactly one of: a registration (4.1), a tunnel (4.2) or a join (4.4).

## 4. Messages

### 4.1 Registration

```
client → {"op": "register", "key": "<key>"}
relay  → {"op": "registered", "name": "<name>", "secret": "<secret>", "domain": "<relay domain>"}
```

The relay then closes the connection. `key` is present only when the relay requires a registration
key. The relay chooses a fresh name, never reused, and a secret of at least 128 bits of entropy. It
stores only a hash of the secret. The client MUST keep the name, the secret and the domain; there is no
way to recover a lost secret, only to register again under a new name.

A relay MAY rate-limit registrations; the reference relay allows 20 per hour per client address.

### 4.2 The tunnel

```
client → {"op": "hello", "v": 1, "name": "<name>", "secret": "<secret>", "names": ["<exact name>", …]}
relay  → {"op": "ready", "hosts": ["<name>.<domain>", "<name>-*.<domain>", "<exact name>", …]}
```

`v` MUST be 1. `names` is optional (section 4.3). On success the connection becomes the install's
*tunnel* and stays open. If the install already has a tunnel, the new one replaces it and the old one
is closed.

On the tunnel:

- **Open.** For each public connection routed to the install the relay sends
  `{"op": "open", "stream": "<stream id>", "host": "<sni>"}`. The stream id is opaque, unguessable and
  single-use.
- **Hello again.** The client MAY send another `hello` on the same connection, with the same name, to
  change its exact names; the relay answers `ready` again, or refuses and closes the tunnel.
- **Liveness.** Each side sends `{"op": "ping"}` every 30 seconds and answers each with
  `{"op": "pong"}`. The relay drops a tunnel from which it has read nothing for 90 seconds.

A client SHOULD reconnect after losing its tunnel, with randomized exponential back-off capped at about
one minute.

### 4.3 Exact names

An exact name has the form `<id>.id.decentai` (`<id>` is `[a-z0-9-]{1,63}`). It lets a server whose
certificate carries a non-public name (such as a DecentAI node, whose name comes from its deployment's
own certificate authority) be reached through the relay with that certificate unchanged.

The first install to say an exact name in a `hello` binds it, permanently. A `hello` naming an exact
name bound to another install MUST be refused. A `hello` names at most 64 exact names.

### 4.4 Join

When the client receives `open`, it opens a **new** TLS connection to the relay domain and sends:

```
client → {"op": "join", "name": "<name>", "secret": "<secret>", "stream": "<stream id>"}
```

The relay sends no reply. From then on the connection carries raw bytes: the relay first writes the
ClientHello it read from the public client, then copies bytes in both directions between the two
connections until either side closes. The client connects the stream to its local TLS server, which
completes the handshake with the public client.

A join that does not arrive within 10 seconds of `open` causes the relay to close the public
connection. A join for an unknown stream, or with a wrong name or secret, is refused.

## 5. Limits

The reference relay applies these per install, to keep one install from exhausting the relay; other
relays MAY choose others.

| | |
|---|---|
| Streams open at once | 256 |
| Opens awaiting their join | 32 |
| Join deadline | 10 s |
| ClientHello deadline and size | 10 s, 16 KiB |
| Tunnel silence before it is dropped | 90 s |
| Control line | 64 KiB |
| Exact names per hello | 64 |
| Registrations per client address | 20 per hour |

There are no quotas on bandwidth, duration or the number of installs.

## 6. Security considerations

**What the relay sees.** For each public connection: the client's IP address, the SNI, the time, the
duration and the byte counts. For each install: its name, its IP address, its exact names, and when it
was last connected. It does not see application data, and does not hold any install's private key.

**What the relay could do.** The relay operator controls DNS for the relay domain and could therefore
obtain a publicly trusted certificate for `<name>.<relay domain>` and intercept connections to that
name. Such a certificate would appear in Certificate Transparency logs. Users who do not trust a
relay's operator should run their own relay. Exact names are not exposed to this, because their
certificates are issued by the deployment's own certificate authority and public clients of those
names trust only it.

**Secrets.** An install's secret authenticates both its tunnel and its joins. The relay stores a hash,
compares in constant time, and never logs it. Anyone holding the secret can take over the install's
name (but cannot impersonate the install's TLS server without its private key).

**Denial of service.** The relay is a shared resource. Per-install limits (section 5) bound the harm
one install can do to the others. Public clients that open connections without completing a
ClientHello are cut off after 10 seconds.

**Cookies and the Public Suffix List.** All installs are subdomains of one relay domain. Browsers treat
them as one site for cookies unless the relay domain is on the Public Suffix List; a relay serving
installs of mutually untrusting people SHOULD be listed there, or its installs should not rely on
cookies scoped above their own host. Listing also gives each install its own Let's Encrypt
rate-limit bucket.

## 7. The client's configuration file

The reference client reads a JSON file (`remote.json`). Only `relay`, `name` and `secret` are required.

```json
{"relay": "relay.example.net",
 "name": "k3x9q0w2mz", "secret": "…", "domain": "relay.example.net",
 "targets": {"k3x9q0w2mz.relay.example.net": "caddy:8443", "*": "127.0.0.1:8443"},
 "forwards": {"8004": "issuer.example.com:8004"},
 "names": ["n0de.id.decentai"],
 "identity": {"folder": "/identity/runtime", "target": "runtime:8004"},
 "insecure_ca": "/path/to/ca.pem"}
```

- `relay`: the relay domain, with `:port` when not 443.
- `targets`: where each host's streams go (`host:port` of a TLS server); `"*"` for every other host.
- `forwards`: plain TCP listeners on `0.0.0.0:<port>` that connect to `host:port`.
- `names`: exact names to bind, besides those read from `identity`.
- `identity`: a DecentAI identity folder whose certificate's `*.id.decentai` names are bound and whose
  streams go to `target`. The client re-reads it every 60 seconds and says `hello` again when it changes.
- `insecure_ca`: trust this CA, instead of the system's, for the relay's certificate. For tests and
  private relays.

## 8. Versioning

This is version 1. A relay MUST refuse a `hello` whose `v` it does not speak. Fields and operations may
be added in a later version only in ways a version 1 peer ignores safely; anything else increments `v`.
