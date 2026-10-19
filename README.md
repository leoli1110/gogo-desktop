# Gogo Desktop

Fast search for your own files, in your web browser. Gogo Desktop runs on a
Windows PC or as a Docker container on a Synology NAS, keeps everything on
hardware you own, and finds any file by name in milliseconds.

> Status: **milestone M1 in progress** (server, web interface, sign-in, and
> file-name search). Content search, Outlook mail stores, CAD drawings and
> photo metadata come in later milestones; see [docs/milestones.md](docs/milestones.md).

## What works today (M1)

- **Search as you type** over file and folder names, with phrases, wildcards
  (`*`, `?`), exclusions (`-draft`) and filters such as `ext:dwg`,
  `type:folder`, `size:>10m`, `modified:2026-03`, `path:projects` and `lib:Name`.
- **Stays current by itself.** Windows: reads the NTFS file table and follows
  the change journal. Synology/Linux: directory walk plus inotify, with a
  scheduled re-check as a safety net.
- **Accounts and permissions.** Gogo Desktop accounts with roles, sign-in code
  apps (TOTP), lockout and an emergency reset. On Windows, `gogo signin` signs
  you in with your Windows account. Administrators choose who can search each
  library.
- **Secure by default.** Windows listens on `127.0.0.1` only. The container
  serves HTTPS only. Every change needs a same-origin request with a CSRF
  token, and all actions are written to a tamper-evident audit log.
- **English and Traditional Chinese** interface.

## Quick start

### Windows

```powershell
# As administrator, from the folder containing gogo.exe
.\gogo.exe service install
```

Open <http://127.0.0.1:4680>. The first time, the program log shows a one-time
setup code for creating the administrator. Full guide: [docs/install-windows.md](docs/install-windows.md).

### Synology NAS (Container Manager)

1. Create a DSM user `gogo` with read-only access to the folders to search.
2. Copy [docker/compose.yaml](docker/compose.yaml), adjust the paths, and create
   a Container Manager project from it.
3. Open `https://<nas>:4681/setup` and enter the setup code from the container log.

Full guide, including inotify limits and the DSM reverse proxy:
[docs/install-synology.md](docs/install-synology.md).

## Documentation

| Document | Contents |
|---|---|
| [Specification](docs/specification.md) | The full product specification (v0.8) |
| [Architecture](docs/architecture.md) | How the code is organised |
| [Install on Windows](docs/install-windows.md) | Service, libraries, same-PC sign-in |
| [Install on Synology](docs/install-synology.md) | DSM user, permissions, compose, reverse proxy |
| [Configuration](docs/configuration.md) | Every `GOGO_*` setting and `policy.yaml` |
| [API](docs/api.md) | The JSON API used by the web interface |
| [Security](docs/security.md) | Threat model and protections |
| [Milestones](docs/milestones.md) | M1 checklist and what comes next |
| [Development](docs/development.md) | Building, testing, releasing |

## Building from source

```sh
(cd web && npm ci && npm run build)
cargo build --release -p gogo-server     # binary: target/release/gogo(.exe)
docker buildx build -f docker/Dockerfile --platform linux/amd64,linux/arm64 -t gogo-desktop .
```

See [docs/development.md](docs/development.md) for details.

## Background

Gogo Desktop is a clean-room design inspired by the user experience of Google
Desktop. It contains no Google code, data formats or assets.

## License

[MIT](LICENSE). Copyright (c) 2026 Leo Li.
