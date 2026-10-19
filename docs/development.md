# Development

## Tools

- Rust 1.99.1 (pinned in `rust-toolchain.toml`; `rustup` installs it).
- Node.js 22 (20 also works) and npm, for the web interface.
- Optional: `mingw-w64` and the `x86_64-pc-windows-gnu` target to compile-check
  the Windows code from Linux; Docker with Buildx for the image.

## Layout

```
crates/gogo-index       name index and query language
crates/gogo-discovery   folder walk, inotify, NTFS change journal
crates/gogo-auth        accounts, sessions, TOTP, libraries, audit log
crates/gogo-server      the `gogo` binary (HTTP server, CLI, Windows service)
web/                    web interface (TypeScript + Vite), built into web/dist
docker/                 Dockerfile and compose.yaml
docs/                   documentation and the specification
```

## Build and run

```sh
(cd web && npm ci && npm run build)          # must come first: the server embeds web/dist
cargo run -p gogo-server -- serve            # http://127.0.0.1:4680
```

On Linux, development defaults to `GOGO_MODE=standalone` with data in
`./gogo-data`. Add a library from the web interface or with:

```sh
GOGO_LIBRARIES="Home=$HOME/Documents" GOGO_DATA_DIR=./dev-data cargo run -p gogo-server
```

The setup code is printed in the terminal and saved to `<data>/setup-code.txt`.

For interface work, run the server and then `npm run dev` in `web/`
(http://localhost:5173, API calls are proxied to port 4680). Add `localhost`
to the allowed hosts if needed.

## Tests

```sh
cargo test --workspace                                            # all unit and HTTP tests
cargo test --release -p gogo-index -- --ignored --nocapture million   # 1M-entry speed test
cargo test -p gogo-discovery --test ntfs_journal -- --ignored --nocapture   # Windows, as administrator
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo fmt --all --check
(cd web && npm run build)                                         # includes the TypeScript check
```

The HTTP tests in `crates/gogo-server/src/tests.rs` run the real router in
process and cover the security rules in [security.md](security.md).

## Windows build

```powershell
cd web; npm ci; npm run build; cd ..
cargo build --release -p gogo-server     # target\release\gogo.exe
```

## Container image

```sh
docker buildx build -f docker/Dockerfile --platform linux/amd64,linux/arm64 -t gogo-desktop:dev .
```

The Dockerfile cross-compiles on the build machine's architecture, so no
emulation is needed for arm64.

## Releases

1. Update `CHANGELOG.md` and the version in the root `Cargo.toml`.
2. Tag: `git tag v0.1.0 && git push --tags`.
3. CI builds and pushes `ghcr.io/leoli1110/gogo-desktop:<version>` and `:latest`,
   and uploads `gogo.exe` as a build artifact.

## Clean-room rule

Don't add code, data formats or assets from Google Desktop or any other
product, and never commit decompiled output or the ODA SDK. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
