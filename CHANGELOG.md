# Changelog

All notable changes to Gogo Desktop are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased] - milestone M1 in progress

### Added
- `gogo` server for Windows and Linux (Rust), with the web interface built in.
- Name index: about 18-32 ms per query over 1 million entries (release build,
  2-CPU test machine), with wildcards, phrases, exclusions and filters
  (`ext:`, `type:`, `path:`, `lib:`, `size:`, `modified:`).
- File discovery: directory walk plus inotify on Linux/Synology (falls back to
  scheduled re-checks when the watch limit is too low); NTFS file table
  listing and live change journal on Windows; periodic re-check on both.
- Gogo Desktop accounts: Argon2id passwords, roles (administrator, user),
  sign-in code apps (TOTP) with replay protection, lockout after 5 failures,
  "confirm it's you" before risky changes, emergency recovery with
  `gogo admin reset`, and a rule that the last administrator can't be removed.
- Same-PC Windows sign-in (`gogo signin`) through a local-only named pipe.
- Libraries with per-user and all-users access lists; new libraries are
  visible to administrators only.
- Security: Host allow-list, same-origin check and CSRF token on every change,
  strict Content Security Policy, HSTS on HTTPS, rate limits on sign-in.
- Hash-chained audit log (`gogo audit verify`).
- Docker image (amd64, arm64) and `compose.yaml` for Synology Container Manager.
- Web interface in English and Traditional Chinese.
- Documentation: specification v0.8, architecture, installation, configuration,
  API, security and development guides.
