# Security

A relay is trusted to pass people's encrypted connections through without opening them, and to keep
one install's name from being taken by another. A weakness in either matters more than any other bug.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately from the repository's
**Security** tab (*Report a vulnerability*), or email support@decentai.io, with a description, the
steps to reproduce, and the version or commit. You will get an acknowledgement within three days and a
fix or a plan before any public disclosure.

## What counts

- The relay terminating, reading or altering a connection for any host but its own name.
- A connection reaching an install other than the one that owns the name it asked for.
- Taking over another install's name or exact name, or joining its streams, without its secret.
- A secret, or a byte of a stream, written to the relay's log or store in a form that reveals it.
- One install, or anyone on the internet, stopping the relay from serving others with little effort.
- The tunnel client connecting a stream anywhere its configuration does not say.

## Out of scope

- What the relay's operator can do by controlling its domain's DNS (docs/protocol.md, section 6):
  that is a property of the design, and the reason to run one's own relay.
- Traffic volume: the relay sets no bandwidth quotas, by design.
