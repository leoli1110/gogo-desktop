# Contributing

Thanks for helping with Gogo Desktop.

## Ground rules

- **Clean room.** Gogo Desktop takes design lessons from Google Desktop, but no
  Google code, decompiled output, data formats or assets may be added to this
  repository. Don't paste code from disassemblers or decompilers.
- **Third-party SDKs.** The ODA SDK (MicroStation DGN) is licensed separately and
  must never be committed. See section 13 of the specification.
- **Privacy.** Nothing may send data outside the user's network: no telemetry,
  no remote crash reports, no online lookups.

## Workflow

1. Read [docs/development.md](docs/development.md) to set up the toolchain.
2. Create a branch, make the change, and add tests.
3. Run the checks:
   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   (cd web && npm run build)
   ```
4. Open a pull request describing what changed and why. CI must pass on Linux
   and Windows.

## Style

- Rust: `rustfmt` settings in `rustfmt.toml`; no `unwrap()` on user input.
- TypeScript: strict mode; never use `innerHTML` with data from the server.
- User-facing text: short, plain sentences. Add new strings to both the English
  and Traditional Chinese dictionaries in `web/src/i18n.ts`.

By contributing you agree that your contributions are licensed under the MIT
License in [LICENSE](LICENSE).
