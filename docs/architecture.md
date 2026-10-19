# Architecture

Gogo Desktop is one program, `gogo`, written in Rust. It contains the web
server, the web interface (built from `web/` and embedded at compile time),
the file discovery threads and the in-memory name index.

```
             browser (HTML/JS from the same server, no CDN)
                 |  HTTPS (Docker) or http://127.0.0.1 (Windows)
     +-----------v------------------------------------------------+
     | gogo-server  (axum)                                        |
     |   security.rs  Host allow-list, Origin check, headers      |
     |   api.rs       /api/v1 - sessions, CSRF, permissions       |
     |   web.rs       embedded web interface                      |
     |   winsignin.rs named pipe for same-PC Windows sign-in      |
     +------+----------------------+------------------------------+
            |                      |
   +--------v--------+    +--------v---------+     +--------------------+
   | gogo-auth       |    | gogo-index       |<----| gogo-discovery     |
   | SQLite accounts |    | name tree,       |     | walk + inotify,    |
   | sessions, TOTP, |    | query parser,    |     | NTFS file table +  |
   | libraries,      |    | parallel search  |     | change journal,    |
   | audit log       |    +------------------+     | periodic re-check  |
   +-----------------+                             +--------------------+
```

## Crates

| Crate | Purpose |
|---|---|
| `crates/gogo-index` | The name index: a tree of entries keyed by `(library, key)`, where the key is the inode (Linux), file reference number (NTFS) or a path hash. Renames and moves keep children. `query.rs` parses the search language. Search scans all names in parallel chunks above 200,000 entries and keeps the top results in a heap, scored by match quality, recency and depth. |
| `crates/gogo-discovery` | One thread per library. `scan.rs` walks folders (no symlink following, same file system only, default exclusions for system and Synology folders). `watch.rs` uses the `notify` crate (inotify on Linux, `ReadDirectoryChangesW` on Windows) and batches bursts; it checks the inotify watch limit first and falls back to scheduled re-checks. `ntfs.rs` lists the NTFS file table with `FSCTL_ENUM_USN_DATA` and follows `FSCTL_READ_USN_JOURNAL`, re-listing if the journal wrapped. |
| `crates/gogo-auth` | `store.rs`: SQLite (bundled) tables for users, sessions, libraries, access lists and reset codes. `password.rs`: Argon2id and password rules. `totp.rs`: RFC 6238 codes with replay protection. `audit.rs`: append-only monthly JSON-lines files with a SHA-256 hash chain. |
| `crates/gogo-server` | The `gogo` binary: configuration (`config.rs`), startup (`server.rs`), HTTP security (`security.rs`), API (`api.rs`), TLS (`tls.rs`), health check, Windows service and named-pipe sign-in. |

## Data folder

| Path | Contents |
|---|---|
| `db/accounts.sqlite` | Users, sessions (token hashes only), libraries, access lists, reset codes |
| `audit/audit-YYYY-MM.jsonl` | Audit log |
| `tls/self-signed.crt`, `.key` | Generated certificate when none is configured |

The data folder is `%ProgramData%\GogoDesktop` on Windows and `/data` in the
container. It is never indexed. The name index is held in memory in M1 and
rebuilt at start (fast: the NTFS file table or a directory walk); the
persistent content index arrives with M2.

## Request flow

1. `security::guard` checks the `Host` header against the allow-list, and for
   state-changing methods checks that `Origin` is this site. It adds the
   security headers to every response.
2. The `Auth` extractor reads the session cookie, looks up the SHA-256 hash of
   the token, applies the idle and absolute limits, and checks the
   `X-CSRF-Token` header for any method other than GET/HEAD.
3. Administrator routes use the `Admin` extractor. Risky actions (role
   changes, deletes, library access, adding libraries, passwords) also require
   a "confirm it's you" within the last 5 minutes.
4. Search runs on a blocking thread: the query is parsed, the user's allowed
   libraries are computed from the access lists, and only those libraries are
   searched. Hits without size/time (NTFS listing) are filled in from the
   file system and cached.

## Windows specifics

- The service runs as LocalSystem so it can open volumes for the change journal.
- Same-PC sign-in: `\\.\pipe\gogo-desktop-signin` is created with
  `PIPE_REJECT_REMOTE_CLIENTS` and a DACL that only allows SYSTEM,
  Administrators and interactive users. The client connects with
  `SECURITY_IDENTIFICATION`, so the service can read who it is but can't act
  as it. The service returns a 60-second single-use token; the browser opens
  `http://127.0.0.1:4680/signin#<token>` (the token is in the fragment, so it
  never appears in server logs) and the page exchanges it with a POST.

## Docker specifics

- Distroless runtime image, no shell, runs as a non-root user, read-only root
  file system in the sample compose file.
- Each folder mounted under `/libraries/<Name>` is registered as a library at
  start.
- The container refuses to start if `/config` is writable, if `/data` isn't
  writable, or if any setting tries to switch off administrator approval.
