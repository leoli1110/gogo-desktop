# Security

Google Desktop's local web server was a well-known source of problems: pages
on other websites could drive it, and settings could be changed with simple
`GET` requests. Gogo Desktop is designed around those lessons. The full design
is in section 11 of the [specification](specification.md); this page lists
what milestone M1 implements and how it is tested.

## Threats considered

| Threat | Protection |
|---|---|
| A web page on another site sends requests to the local server (CSRF) | State changes need `POST`/`PUT`/`PATCH`/`DELETE`, a same-origin `Origin` header, and the per-session CSRF token in a custom header. Cookies are `SameSite=Strict`. `GET` never changes anything |
| DNS rebinding (an attacker's host name resolving to 127.0.0.1) | `Host` header allow-list; other names get `421` |
| Clickjacking, injected scripts | CSP `default-src 'self'`, no inline scripts or styles, `frame-ancestors 'none'`, `X-Frame-Options: DENY`. The interface never inserts server text as HTML |
| Password guessing | Argon2id hashes; 10 attempts per minute per address; account locked 15 minutes after 5 failures; same response time for unknown users |
| Stolen session cookie | `HttpOnly`; only a SHA-256 hash is stored; 8-hour idle and 7-day absolute limits; sign out everywhere; password change ends other sessions |
| Stolen administrator password | Sign-in code app (TOTP) required for administrators whenever the server is reachable from the network; codes can't be reused; risky changes need "confirm it's you" within 5 minutes |
| Locked-out owner | `gogo admin reset` on the host prints a 15-minute single-use code for `/recover` |
| Removing the last administrator | Refused for role change, disable and delete |
| Users seeing other people's files | Libraries are visible to administrators only until an administrator grants access. Search only runs over allowed libraries |
| Other local users on a Windows PC | Data folder restricted to SYSTEM and Administrators. Same-PC sign-in uses a named pipe that rejects remote clients and non-interactive logons; the service only identifies the caller (no impersonation of rights) |
| Network eavesdropping | Windows listens on loopback only by default. The container serves HTTPS only; plain HTTP on a network address is refused unless behind a trusted reverse proxy. HSTS over HTTPS |
| Weakening settings from inside the container | `/config` must be read-only; forbidden variables and policy keys stop the container |
| Covering tracks | Hash-chained audit log; `gogo audit verify` finds edited or removed records |
| Data leaving the network | No telemetry, update checks or online services |

## Known limitations in M1

- **NTFS permissions are not applied yet.** Results are filtered by library
  access lists only. Windows ACL filtering arrives with milestone M2. Until
  then, only grant a library to people who may see every name in it.
- Windows NTFS and service code is compile-checked on Linux and exercised by
  CI on `windows-latest`; field testing on real PCs is still needed.
- Same-PC sign-in trusts the first process that creates the named pipe
  (`FILE_FLAG_FIRST_PIPE_INSTANCE`). Start the service at boot so it owns the
  pipe.
- Synology SSO and approvals are not implemented yet (M6); the settings that
  would weaken approval are already refused.

## Automated tests

`cargo test --workspace` runs, among others:

- Host refusal, Origin refusal, missing CSRF token, security headers, `no-store`.
- Setup only once and only with the code; TOTP required for network-reachable
  administrators; administrators without TOTP are held at the setup screen.
- Sign-in rate limit and lockout; code replay refused.
- Users can't reach administrator routes; "confirm it's you" expires; last
  administrator protected; deleted users' sessions stop working.
- Search filtered by library access; the data folder can't become a library.
- Recovery with a reset code; reset codes are single use.
- Audit log tampering (edit and delete) is detected.
- Configuration refuses approval-disabling settings, secrets in variables,
  out-of-range values and typos.

Report problems as described in [SECURITY.md](../SECURITY.md).
