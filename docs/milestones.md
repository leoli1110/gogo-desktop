# Milestones

The plan follows section 14 of the [specification](specification.md).

## M1 - Server and web search (names): in progress

### Done

- [x] Rust workspace: `gogo-index`, `gogo-discovery`, `gogo-auth`, `gogo-server`.
- [x] Name index with the query language (terms, phrases, wildcards, exclusions,
      `ext:`, `type:`, `path:`, `lib:`, `size:`, `modified:`).
- [x] Directory walk with default exclusions; inotify watching with a watch-limit
      check and fallback; periodic re-check.
- [x] NTFS file table listing and change journal (Windows).
- [x] Web interface: setup, sign-in (with code), search as you type, keyboard
      navigation, copy path and folder, status, users, libraries, account.
      English and Traditional Chinese.
- [x] Gogo Desktop accounts: roles, Argon2id, TOTP with replay protection,
      lockout, "confirm it's you", emergency reset, last-administrator rule.
- [x] Same-PC Windows sign-in through a local-only named pipe.
- [x] Libraries with access lists; administrators only by default.
- [x] Security headers, Host allow-list, Origin check, CSRF token, rate limits.
- [x] Hash-chained audit log with retention and `gogo audit verify`.
- [x] Fail-closed configuration and `policy.yaml`.
- [x] Windows service install/uninstall; data folder restricted to administrators.
- [x] Docker image (amd64, arm64, distroless, non-root) and `compose.yaml`.
- [x] CI: Linux and Windows builds and tests, NTFS integration test, image build.

### Measured so far

| Exit test | Target | Result |
|---|---|---|
| Name search, 1M entries | interactive | 18-32 ms per query, about 38 ms with wildcards (release build, 2-CPU Linux sandbox) |
| Rename visible (Linux, inotify) | < 1 s | 0.3 s in the browser end-to-end test |
| Rename visible (Windows, change journal) | < 1 s | 20 ms in the `ntfs_journal` test on the GitHub `windows-latest` runner |
| 1M files listed on Windows | < 10 s | 5.2 s to read the CI runner's whole C: file table (file count of that volume not yet recorded); still to measure on a PC with a known 1M+ files |
| Security tests (spec section 16) | pass | the M1 subset passes (see [security.md](security.md)) |

### Still to do for M1

- [ ] Measure listing time on a Windows PC with 1M+ files.
- [ ] Test on a real Synology unit (amd64 and arm64) with the published image.
- [ ] Live search updates over Server-Sent Events (the interface re-queries
      as you type for now).
- [ ] Open file / open folder on Windows through the Gogo Companion (needs a
      small helper running as the signed-in user).

### Moved to later milestones

- **Windows file permissions (NTFS ACLs) in results: M2.** Until then, results
  are filtered by library access only.
- Persistent on-disk name index (rebuilt at start in M1).
- Installer (MSI) and settings lock through ADMX: M7.

## Next

| Milestone | Contents |
|---|---|
| M2 - Documents | Worker sandbox, text/PDF/Office/ZIP extraction, Tantivy content index, previews, NTFS permission filtering |
| M3 - Outlook | `.msg`, `.pst`, `.ost` |
| M4a - AutoCAD formats | `.dwg`, `.dxf`, `.dwf` and related formats |
| M4b - MicroStation | DGN V7/V8 through the ODA SDK (`gogo-oda` worker) |
| M5 - Photos and media | EXIF/XMP/RAW, video and audio tags |
| M6 - Synology package and Companion | Synology SSO with mandatory administrator approval, Companion app |
| M7 - Polish | Installer, settings lock, encryption at rest, local crash reports |
