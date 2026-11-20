# Contributing

Issues and pull requests are welcome.

- Keep the relay and the tunnel to Python's standard library: they run anywhere Python 3.12 does, and
  the image stays small.
- A change to what goes over the wire is a change to [the protocol](docs/protocol.md): update it in the
  same pull request, and keep version 1 peers working, or raise the version.
- Every change comes with a test; `python -m pytest tests -q` passes before review.
- Report security problems privately ([SECURITY.md](SECURITY.md)), not in an issue.

Contributions are made under the Apache License 2.0 (LICENSE), as section 5 of that licence says.
