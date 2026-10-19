# API

The web interface uses a JSON API under `/api/v1`. It's documented so you can
script against it, but it may change before version 1.0.

## Rules

- Requests must use an allowed `Host` (see `GOGO_ALLOWED_HOSTS`), otherwise
  `421 bad_host`.
- Every method other than `GET`/`HEAD` needs an `Origin` header for this site
  (`403 bad_origin`) and, when signed in, the session's CSRF token in
  `X-CSRF-Token` (`403 bad_csrf`). The token is returned by sign-in and by
  `GET /api/v1/me`.
- Sessions use an `HttpOnly`, `SameSite=Strict` cookie: `__Host-gogo_session`
  over HTTPS (also `Secure`), `gogo_session` on `http://127.0.0.1`.
- Bodies are limited to 64 KB. Responses have `Cache-Control: no-store`.
- Errors look like `{"error": "human message", "code": "machine_code"}`.
- "Recent" means the session confirmed the password within 5 minutes
  (`POST /auth/reauth`); otherwise `403 reauth_required`.

## Public

| Method and path | Purpose |
|---|---|
| `GET /api/health` | `{"status":"ok"}`. No data, no sign-in |
| `GET /api/v1/bootstrap` | Product, version, whether setup is required, sign-in options |
| `POST /api/v1/setup/totp` `{code, username}` | During setup: returns a new TOTP secret, `otpauth://` URL and QR code |
| `POST /api/v1/setup` `{code, username, password, totp_code?}` | Creates the first administrator and signs in. Only while no administrator exists |
| `POST /api/v1/auth/login` `{username, password, code?}` | Sign in. `401 code_required` means ask for the code. `429 locked` includes `locked_until` |
| `POST /api/v1/auth/onetime` `{token}` | Same-PC Windows sign-in (loopback only) |
| `POST /api/v1/auth/recover` `{code, username, password}` | Emergency reset with a code from `gogo admin reset` |

## Signed in

| Method and path | Purpose |
|---|---|
| `POST /api/v1/auth/logout` | Ends this session |
| `POST /api/v1/auth/reauth` `{password, code?}` | "Confirm it's you" |
| `GET /api/v1/me` | User, CSRF token, searchable libraries, whether TOTP setup is required |
| `POST /api/v1/me/password` `{current, new, code?}` | Change password; other sessions end |
| `POST /api/v1/me/totp/begin` | New secret and QR code (recent, unless setup is required) |
| `POST /api/v1/me/totp/confirm` `{code}` | Turns the sign-in code app on |
| `POST /api/v1/me/totp/disable` | Turns it off (recent; refused for administrators when required) |
| `GET /api/v1/me/sessions` | This user's sessions |
| `POST /api/v1/me/sessions/end-others` | Signs out other sessions |
| `GET /api/v1/search?q=&limit=&lib=` | Name search over the libraries this user may search. `limit` 1-200 (default 50). `lib` restricts to one library by name |
| `GET /api/v1/status` | Library states; settings for administrators |

Search response:

```json
{
  "total": 30,
  "took_ms": 2.1,
  "hits": [
    {
      "id": "1-3f2a",
      "library": "Projects",
      "name": "site-plan-rev22.dwg",
      "rel_path": "2026/plans/site-plan-rev22.dwg",
      "path": "\\\\NAS\\Projects\\2026\\plans\\site-plan-rev22.dwg",
      "folder": "\\\\NAS\\Projects\\2026\\plans",
      "is_dir": false,
      "size": 1048576,
      "mtime": 1792368000
    }
  ]
}
```

## Administrators

| Method and path | Purpose |
|---|---|
| `GET /api/v1/users` | All accounts |
| `POST /api/v1/users` `{username, password, role}` | Create a Gogo Desktop account (recent, for administrators) |
| `PATCH /api/v1/users/{id}` `{role?, disabled?}` | Change role or disable (recent). The last enabled administrator is protected (`409 last_admin`) |
| `DELETE /api/v1/users/{id}` | Delete (recent) |
| `POST /api/v1/users/{id}/password` `{password}` | Set a password (recent); their sessions end |
| `POST /api/v1/users/{id}/unlock` | Clear a lockout |
| `POST /api/v1/users/{id}/sessions/end` | Sign out everywhere |
| `GET /api/v1/libraries` | Libraries with access lists |
| `POST /api/v1/libraries` `{name, path, display_prefix?}` | Add (recent). In Docker the path must be under `/libraries` |
| `PATCH /api/v1/libraries/{id}` `{display_prefix?, excludes?}` | Change the shown path or exclusions |
| `PUT /api/v1/libraries/{id}/access` `{principals}` | Who may search: `"role:user"` (all users) and/or `"user:<id>"` (recent) |
| `POST /api/v1/libraries/{id}/recheck` | Re-check now |
| `DELETE /api/v1/libraries/{id}` `{confirm_name}` | Remove (recent; type the name). Container-mount libraries are removed from `compose.yaml` instead |
| `GET /api/v1/audit?limit=&prefix=` | Newest audit records |

## Example (curl, Windows loopback)

```sh
B=http://127.0.0.1:4680
curl -s -c jar -H "Origin: $B" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"correct horse battery"}' $B/api/v1/auth/login
curl -s -b jar "$B/api/v1/search?q=site%20plan%20ext:dwg&limit=5"
```
