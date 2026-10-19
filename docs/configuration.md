# Configuration

Gogo Desktop reads settings from three places. Higher ones win:

1. **`policy.yaml`** in the config folder (`/config` in the container). Settings
   set here are locked and shown as read-only.
2. **Environment variables** `GOGO_*` (compose `environment:`, or Windows
   system environment variables for the service).
3. Built-in defaults.

Gogo Desktop **fails closed**: it refuses to start on an unknown `GOGO_*`
variable (so typos don't silently do nothing), a value out of range, a secret
placed directly in a variable, or any attempt to switch off administrator
approval of Synology users.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GOGO_MODE` | detected | `windows`, `docker` or `standalone` |
| `GOGO_DATA_DIR` | `%ProgramData%\GogoDesktop`, `/data` | Data folder (accounts, audit log, certificates) |
| `GOGO_CONFIG_DIR` | none, `/config` in Docker | Folder with `policy.yaml`; must be read-only in Docker |
| `GOGO_HTTP_BIND` | `127.0.0.1:4680`; `off` in Docker | Plain HTTP listener. Only loopback, unless `GOGO_TRUST_PROXY=true` |
| `GOGO_HTTPS_BIND` | `off`; `0.0.0.0:4681` in Docker | HTTPS listener |
| `GOGO_TLS_CERT_FILE`, `GOGO_TLS_KEY_FILE` | none | PEM certificate and key. Without them a self-signed certificate is created in `<data>/tls` |
| `GOGO_PUBLIC_URL` | none | Address users type, for example `https://search.example.com`. Must be HTTPS (or loopback) |
| `GOGO_ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` + the public URL's host | Extra host names accepted in the `Host` header, comma separated |
| `GOGO_TRUST_PROXY` | `false` | Behind a reverse proxy on the same machine: trust `X-Forwarded-For`/`X-Forwarded-Proto` and allow HTTP on a network address |
| `GOGO_LOCAL_ACCOUNTS` | `all` | `all`, or `admins_only` (only administrators may use Gogo Desktop accounts) |
| `GOGO_REQUIRE_TOTP_FOR_LOCAL_ADMINS` | `true` if reachable from the network, else `false` | Administrators must use a sign-in code app. Can't be `false` when reachable from the network |
| `GOGO_SESSION_IDLE_HOURS` | `8` (1-72) | Sign out after this much inactivity |
| `GOGO_SESSION_MAX_DAYS` | `7` (1-30) | Sign out after this long regardless |
| `GOGO_RECHECK_HOURS` | `6` (1-168) | Full re-check of every library |
| `GOGO_AUDIT_RETENTION_DAYS` | `365` (90-3650) | Audit log files older than this are deleted (the deletion is itself logged) |
| `GOGO_APPROVAL_PENDING_MAX` | `50` (1-500) | Synology users waiting for approval (M6) |
| `GOGO_APPROVAL_EXPIRY_DAYS` | `30` (1-90) | Pending requests expire after this (M6) |
| `GOGO_SSO_ENABLED`, `GOGO_SSO_WELL_KNOWN_URL`, `GOGO_SSO_CLIENT_ID`, `GOGO_SSO_CLIENT_SECRET_FILE`, `GOGO_SSO_USERNAME_CLAIM`, `GOGO_SSO_GROUPS_CLAIM`, `GOGO_SSO_SESSION_MAX_HOURS` | off | Synology SSO (M6). Accepted and validated now, no effect yet |
| `GOGO_LIBRARIES` | none | Libraries from configuration: `Name=C:\Path;Other=D:\Path` |
| `GOGO_LIBRARIES_DIR` | `/libraries` in Docker | Every sub-folder becomes a library |
| `GOGO_PROFILE` | `windows`, `nas-small` in Docker | `windows`, `nas-small` or `nas-large` |
| `GOGO_LOG` | `info` | Log filter, for example `debug` or `gogo_server=debug` |

Refused on purpose:

- `GOGO_SSO_REQUIRE_APPROVAL`, `GOGO_SSO_AUTO_APPROVE`, `GOGO_APPROVAL_DISABLED`,
  `GOGO_APPROVAL_REQUIRED`, `GOGO_DISABLE_APPROVAL`, `GOGO_AUTO_APPROVE`:
  approval is mandatory and can't be configured away.
- `GOGO_SSO_CLIENT_SECRET`, `GOGO_TLS_KEY`: secrets go in files
  (`..._FILE`), never in environment variables.

## policy.yaml

Only these keys exist. Unknown keys are errors. Approval can only be made
stricter.

```yaml
sign_in:
  local_accounts: admins_only     # all | admins_only
  sso_enabled: true               # takes effect in M6
approval:
  pending_max: 25                 # can lower the environment value, never raise it
  expiry_days: 14
  admin_role_requires_two_admins: true   # M6
users:
  require_totp_for_local_admins: true
```

Keys such as `approval.required`, `approval.enabled`, `approval.disabled`,
`approval.auto_approve` or `approval.mode` are refused with the message
"Administrator approval of Synology users is mandatory and cannot be disabled."

## Startup checks

Gogo Desktop stops with a clear message if:

- the data folder can't be created or written;
- in Docker, the config folder is writable from inside the container;
- both listeners are off;
- HTTP is bound to a network address without `GOGO_TRUST_PROXY=true`;
- any value above is invalid.

On Windows the data folder's permissions are reset to SYSTEM and
Administrators only at every start.
