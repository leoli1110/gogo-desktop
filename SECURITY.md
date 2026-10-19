# Security policy

Gogo Desktop indexes private files, so security reports are welcome and taken
seriously.

## Reporting a problem

Please don't open a public issue for security problems. Instead, use GitHub's
private vulnerability reporting for this repository (Security tab > Report a
vulnerability), or contact the maintainer directly. Include the version
(`gogo --version`), how it's run (Windows or Docker), and steps to reproduce.

You can expect an acknowledgement within 7 days. Fixes for confirmed problems
are released as soon as practical and noted in `CHANGELOG.md`.

## Supported versions

Only the newest release receives security fixes while the project is before
version 1.0.

## Design

The security design is described in [docs/security.md](docs/security.md) and
in section 11 of the [specification](docs/specification.md).
