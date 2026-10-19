# Gogo Desktop — specification (2026)

Product name: **Gogo Desktop** (formerly the working name LocalSearch). Version 0.8, 19 October 2026. Version 0.8 renames the project to Gogo Desktop (`gogo` command, `GOGO_` settings, `ghcr.io/leoli1110/gogo-desktop` image) and marks milestone M1 as in progress (section 14; progress is tracked in `docs/milestones.md`). Version 0.7 updates the Docker configuration for the approval workflow (section 3.3). Version 0.6 required administrator approval for every new Synology SSO user (section 11.2.3). Version 0.5 added sign-in with both Synology SSO and Gogo Desktop accounts (section 11.2). Version 0.4 made Gogo Desktop **web-based, like Google Desktop**, and added two ways to run it: **Windows** or a **Docker container on a Synology NAS**.

Status: specification for a new, clean-room product. It takes only **design lessons** from the Google Desktop 5.9 analysis (feature set, user experience, and the security mistakes to avoid). No Google code, data formats or assets are reused.

---

## 1. Goal and scope

A search engine for your own files that you use **in a web browser**, like Google Desktop. It finds any file **by name within milliseconds** and **by content within a second**, including inside Outlook mail stores, CAD drawings and photo libraries. Everything runs on hardware you own. Nothing is sent to the internet.

### Two ways to run it

| | **Windows host** | **Synology NAS host** |
|---|---|---|
| Runs as | Windows service + web server | Docker container in Synology **Container Manager** |
| Indexes | The PC's own NTFS drives (and chosen network shares) | The NAS's shared folders, mounted into the container |
| Open in a browser at | `http://127.0.0.1:4680` on the same PC (default); optionally `https://<pc-name>:4681` from the local network | `https://<nas-name>:4681`, or a DSM reverse-proxy address such as `https://search.<your-domain>` |
| Change tracking | NTFS change journal (instant) | Linux file notifications (inotify) plus scheduled checks |
| Who can sign in | The Windows user at the PC (automatic), **Gogo Desktop accounts**, and optionally Synology SSO in LAN mode | **Gogo Desktop accounts and Synology SSO, side by side** (section 11.2) |
| Best for | One PC with local files and Outlook | Shared office files, CAD projects, photo archives and mail archives on the NAS |

Both run **the same program and the same web interface**. Only file discovery and sign-in differ. A small optional Windows helper, the **Gogo Companion** (section 9.3), adds the Google Desktop-style hotkey and opening files on the PC for either host.

### In scope (v1)

| Area | Included |
|---|---|
| File names and paths | Every file and folder in the chosen locations; changes picked up in near real time |
| Document content | Plain text and code, PDF, Office (Word, Excel, PowerPoint — modern and legacy), RTF, HTML, ZIP contents |
| **Outlook items** | **`.msg`** files; **`.ost`** offline caches from classic Outlook; `.pst` (same file family as `.ost`, little extra work) |
| **CAD drawings** | **`.dwg`**, **`.dxf`** and the related AutoCAD family: `.dwt`, `.dws`, `.dxb`, `.dwf`, `.dwfx`, backups (`.bak`, `.sv$`), AutoCAD support text files (section 5.1); **MicroStation `.dgn` V7 and V8 with full content**, plus `.dgnlib`, `.cel` and `.rdl` (section 5.2, ODA SDK) |
| **Digital photos and media** | Photo, video and audio metadata (EXIF, XMP, camera RAW including Sony `.ARW`), so you can search by date, camera, lens, GPS and settings |
| **Web interface** | Search page with results as you type, filters, previews, timeline, index status and settings, all in the browser |
| Windows Companion | Hotkey quick-search box, "open on this PC", tray icon |

"Digital" is interpreted here as **digital photos and media**. If you meant something else, such as digitally signed PDFs or a specific file extension, that's one row to add in section 5.

### Out of scope

- Gmail, Google Earth, Google Talk, gadgets, sidebar, web-history capture, and any cloud account sign-in.
- Network sending outside your own network: no usage reports, no update checks unless the user turns them on.
- Access from the internet. Gogo Desktop is meant for the local network. Remote access should go through a VPN; section 11.6 explains why.
- New Outlook for Windows: it doesn't keep mail in `.ost` files ([Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5979623/where-does-the-modern-outlook-store-its-cache)). Users of new Outlook can export to `.pst`, which v1 reads.
- Optical character recognition (OCR) of scanned images, and semantic/AI search. Both are planned for later (section 15).
- One search box covering several Gogo Desktop servers at once (for example the PC and the NAS together). Planned for later (section 15).

---

## 2. Lessons from Google Desktop

Google Desktop's search interface was a web page served by the program itself. Gogo Desktop keeps that idea, but fixes each security weakness found in the analysis.

| Google Desktop 5.9 did | Gogo Desktop does instead |
|---|---|
| Local HTTP server on port 4664, protected only by secret values in signed URLs (key likely only 56 bits) | Web server with **real sign-in and sessions**. Every request is checked for a signed-in user; there are no secret URLs |
| Allowed actions such as "delete index" through a plain GET link | **State changes only through POST/PUT/DELETE**, each with a CSRF token. GET never changes anything |
| Its settings form switched off anything missing from the request | Settings are changed **one field at a time** (`PATCH`), each validated and logged |
| A single request deleted the whole index after a restart | Rebuilding the index needs an administrator, **fresh password confirmation** and a typed confirmation |
| Checked the `Host` header against DNS rebinding — good | Kept: strict `Host` and `Origin` allow-lists, plus a strict content security policy |
| Accepted connections from `127.0.0.1` only — good for one PC | Kept as the **Windows default**. Network access is an explicit option, and always uses HTTPS and sign-in |
| Opened most file types with no prompt from search results | The server **never runs files**. Opening happens on the user's PC through the Companion, with a confirmation for executable and script types |
| Loaded its DLLs into Explorer and Windows Sidebar | **No code injection** into other processes |
| A global keyboard hook for double-tap Ctrl | Same feature in the Companion, optional, watching modifier keys only |
| Sent usage statistics by default | **No outside network sending** at all in v1 |
| File parsing inside the main process | **Parsers run in separate, limited worker processes** (section 8) |

Kept from Google Desktop: web search page, per-type indexing switches, folder exclusions, "remove deleted files", cached text previews, timeline view, administrator policy that locks individual settings, optional index encryption.

---

## 3. Architecture

### 3.1 Components

```
 Browser (any device on the LAN, or the same PC)          Gogo Companion (Windows, optional)
        │  HTTPS (or HTTP on 127.0.0.1 only)                 hotkey · quick box · "open on this PC"
        ▼                                                          │
┌────────────────────────────────────────────────────────────────┴─────────┐
│ Gogo Desktop Server  (Windows service  or  Linux process in Docker)         │
│  ┌──────────────────────────────┐   ┌────────────────────────────────────┐ │
│  │ Web layer                     │   │ Search core                        │ │
│  │  web UI (static files)        │──►│  name index · content index         │ │
│  │  REST API + live search stream│   │  query parser · ranking · previews  │ │
│  │  sign-in, sessions, CSRF      │   └──────────────┬─────────────────────┘ │
│  └──────────────────────────────┘                  │                        │
│  ┌──────────────────────────────┐   ┌──────────────▼─────────────────────┐ │
│  │ Discovery                     │──►│ Change queue → scheduler             │ │
│  │  Windows: MFT + change journal│   └──────────────┬─────────────────────┘ │
│  │  Linux:   scan + inotify       │                  │ jobs (one file each)   │
│  └──────────────────────────────┘                  ▼                        │
└──────────────────────────────────────────────────────┬─────────────────────┘
                                                       ▼
            Extractor workers (separate, limited processes; restartable)
            text · pdf · office · msg · ost/pst · media · dwg/dxf (LibreDWG) · dgn (gogo-oda)
```

| Component | Role |
|---|---|
| **Server** | One program (Rust) containing the web layer, search core, discovery and scheduler. On Windows it runs as a service; in Docker it's the container's main process. |
| **Web layer** | Serves the web interface and a JSON API (section 9.4) over HTTP/HTTPS. Handles sign-in, sessions, permissions and security headers. |
| **Search core** | Name index, content index (Tantivy), query parser, ranking, highlighted previews. |
| **Discovery** | Finds files and changes. Different code per platform (section 4); everything after it is shared. |
| **Scheduler** | Decides what to parse and when: priority folders first, pauses when the machine is busy or (on laptops) on battery, limits disk input/output. |
| **Extractor workers** | Separate processes that turn one file into text and fields (section 8). A crash or hang affects only that one file. |
| **Companion** | Optional Windows tray app (section 9.3). |

### 3.2 Same build, two targets

| Part | Windows build | Docker build (Linux) |
|---|---|---|
| Server binary | `gogo.exe` (x86_64; ARM64 later) | `gogo` (amd64 and arm64 images) |
| Discovery | NTFS file table and change journal | Directory scan + inotify + periodic re-check |
| Worker limits | Restricted token + Windows job object | Separate processes with cgroup memory/CPU limits, seccomp, no network |
| Outlook stores | Local `.ost`/`.pst`, including files Outlook has open (section 8) | `.ost`/`.pst` copies kept on NAS shares |
| DGN worker | `gogo-oda.exe` (ODA Windows libraries) | `gogo-oda` (ODA Linux x86_64 or ARM64 libraries) |
| Sign-in | Windows user (automatic on the same PC) + Gogo Desktop accounts (+ Synology SSO in LAN mode) | Gogo Desktop accounts + Synology SSO (OIDC), with optional account linking |
| Per-user access to files | Real Windows file permissions | Library permissions set by the administrator (section 11.4) |
| Data folder | `%ProgramData%\GogoDesktop` | `/data` volume (`/volume1/docker/gogo-desktop/data`), plus read-only `/config` and `/run/secrets` (section 3.3) |

### 3.3 Synology container layout

| Item | Setting |
|---|---|
| **NAS requirement** | DSM 7.2 or later with **Container Manager**, on an Intel/AMD or ARM64 model. Container Manager covers x86 models and many ARMv8 models such as the DS223, DS220j and DS120j ([Synology release notes](https://www.synology.com/en-global/releaseNote/ContainerManager)). 32-bit ARM models can't run it. |
| **Image** | `ghcr.io/leoli1110/gogo-desktop:<version>`, multi-architecture (amd64, arm64). Two variants: `-oda` with the DGN worker (needs your ODA licence files; you build it yourself, section 13.1) and the default one without it. |
| **Volumes** | `/volume1/docker/gogo-desktop/data` → `/data` (indexes, accounts, approvals, audit log; read-write). `/volume1/docker/gogo-desktop/config` → `/config`, **read-only** (administrator policy). Each shared folder to search → `/libraries/<name>`, **read-only**, for example `/volume1/Projects:/libraries/Projects:ro`. |
| **Secrets** | `/volume1/docker/gogo-desktop/secrets/*` → `/run/secrets/*`, read-only, through Compose `secrets:` (section 3.3.2). Never put secrets in environment variables. |
| **User** | Runs as a dedicated DSM user (for example `gogo`, set with `user:`). Give that user **read-only** permission to the shared folders it should index, **read-only** permission to `config` and `secrets`, and read-write only to `data`. |
| **Ports** | `4681/tcp` (HTTPS). Port 4680 (HTTP) is disabled in the container unless it's only used behind the DSM reverse proxy. |
| **Network** | Bridge network. Outgoing connections are needed **only to the Synology SSO Server**, on the NAS itself or the LAN. No internet access is needed; it can be blocked with the DSM firewall. |
| **Time** | ID-token checks depend on the clock (section 11.2.4). Keep DSM's time synchronization (NTP) turned on; the container uses the NAS clock. |
| **Resources** | Memory limit set in Container Manager (section 3.4 profiles). |
| **Healthcheck** | Built-in `gogo healthcheck` command, which calls `GET /api/health`. That endpoint returns only "ok" or "not ready", with no sign-in required, and never shows pending-user counts or other data. |
| **Updates** | Pull a new image tag. Accounts, approvals and the audit log are kept, and their database is upgraded in place after an automatic copy (`/data/db/backup-<version>/`). Indexes are upgraded or rebuilt when the format version changes. |

#### Folder layout on the NAS

```
/volume1/docker/gogo-desktop/
├── config/                    owner: admin (root), mode 755  → /config (ro)
│   └── policy.yaml            owner: admin (root), mode 644  locked settings
├── secrets/                   owner: admin (root), mode 750, group = gogo
│   └── sso_client_secret      mode 640, readable by the gogo group only
└── data/                      owner: gogo, mode 700   → /data (rw)
    ├── db/accounts.sqlite     users, Pending/Rejected lists, sessions, API tokens
    ├── audit/                 append-only audit log (section 3.3.4)
    ├── index/                 search indexes (can be rebuilt)
    └── logs/                  service logs (no secrets, no search terms)
```

Because `config` and `secrets` are mounted **read-only** and owned by the NAS administrator, a compromised container can't loosen its own policy, read other secrets, or change the SSO secret.

#### 3.3.1 Example `compose.yaml` (Container Manager → Project)

```yaml
services:
  gogo-desktop:
    image: ghcr.io/leoli1110/gogo-desktop:0.1
    container_name: gogo-desktop
    user: "1030:100"                 # UID:GID of the DSM user 'gogo'
    ports:
      - "4681:4681"
    volumes:
      - /volume1/docker/gogo-desktop/data:/data
      - /volume1/docker/gogo-desktop/config:/config:ro
      - /volume1/Projects:/libraries/Projects:ro
      - /volume1/Photos:/libraries/Photos:ro
      - /volume1/MailArchive:/libraries/MailArchive:ro
    secrets:
      - sso_client_secret
    environment:
      TZ: Europe/London
      GOGO_PROFILE: nas-small          # nas-small | nas-large
      GOGO_PUBLIC_URL: https://search.example.lan   # must be HTTPS for SSO
      # --- sign-in (section 11.2) ---
      GOGO_LOCAL_ACCOUNTS: admins_only # all | admins_only
      GOGO_SSO_ENABLED: "true"
      GOGO_SSO_WELL_KNOWN_URL: https://sso.example.lan/webman/sso/.well-known/openid-configuration
      GOGO_SSO_CLIENT_ID: "<Application ID from SSO Server>"
      GOGO_SSO_CLIENT_SECRET_FILE: /run/secrets/sso_client_secret
      GOGO_SSO_USERNAME_CLAIM: sub
      GOGO_SSO_GROUPS_CLAIM: ""        # set only if SSO Server sends groups
      GOGO_SSO_SESSION_MAX_HOURS: "8"
      # --- approval workflow (section 11.2.3) ---
      GOGO_APPROVAL_PENDING_MAX: "50"  # 1-500
      GOGO_APPROVAL_EXPIRY_DAYS: "30"  # 1-90
      GOGO_AUDIT_RETENTION_DAYS: "365" # 90-3650
    mem_limit: 2g
    restart: unless-stopped
    read_only: true                  # container file system read-only except /data and /tmp
    tmpfs: [/tmp]
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    healthcheck:
      test: ["CMD", "/usr/local/bin/gogo", "healthcheck"]
      interval: 60s
      timeout: 5s
      retries: 3

secrets:
  sso_client_secret:
    file: /volume1/docker/gogo-desktop/secrets/sso_client_secret
```

The `GOGO_SSO_WELL_KNOWN_URL` value above is only an example. **Copy the real Well-known URL from SSO Server → Service → OIDC** (section 11.2.5).

#### 3.3.2 Settings for sign-in and approval

| Variable | Default | Allowed values | Meaning |
|---|---|---|---|
| `GOGO_PUBLIC_URL` | — | `https://…` | Address users open; used to build the SSO redirect URI `…/auth/oidc/callback`. Required for SSO |
| `GOGO_LOCAL_ACCOUNTS` | `all` | `all`, `admins_only` | Which Gogo Desktop accounts may sign in. `admins_only` is recommended once SSO works |
| `GOGO_SSO_ENABLED` | `false` | `true`, `false` | Turns Synology SSO on |
| `GOGO_SSO_WELL_KNOWN_URL` | — | `https://…` | From SSO Server → Service → OIDC |
| `GOGO_SSO_CLIENT_ID` | — | text | Application ID from SSO Server → Application |
| `GOGO_SSO_CLIENT_SECRET_FILE` | — | path under `/run/secrets/` | Application secret, read from a file. **There's no variable that takes the secret directly** |
| `GOGO_SSO_USERNAME_CLAIM` | `sub` | claim name | Identifies the user. `sub` is the stable OIDC subject ID; check which claims your SSO Server sends during setup |
| `GOGO_SSO_GROUPS_CLAIM` | empty | claim name | DSM groups, used **only as suggestions** when approving and applied after approval |
| `GOGO_SSO_SESSION_MAX_HOURS` | `8` | 1–24 | Maximum session length for Synology users |
| `GOGO_APPROVAL_PENDING_MAX` | `50` | 1–500 | Most Pending requests at once |
| `GOGO_APPROVAL_EXPIRY_DAYS` | `30` | 1–90 | Days before an unhandled request expires |
| `GOGO_AUDIT_RETENTION_DAYS` | `365` | 90–3650 | How long audit records are kept |

- **Approval can't be turned off.** There's deliberately no variable for it. If the container sees `GOGO_SSO_REQUIRE_APPROVAL`, `GOGO_SSO_AUTO_APPROVE` or a similar setting, or an `approval:` override in `policy.yaml`, it **refuses to start** and logs: `Administrator approval of Synology users is mandatory and cannot be disabled.` Ignoring the setting silently could leave someone believing approval was off, or on.
- **Values outside the ranges** stop the container from starting, with an error naming the variable.
- **Order of precedence:** `policy.yaml` > environment variables > values saved in the web settings. Values set by the first two are shown **read-only** on the settings page, marked "Set by the NAS administrator".

#### 3.3.3 Administrator policy file (`/config/policy.yaml`)

```yaml
# Owned by the NAS administrator; mounted read-only into the container.
sign_in:
  local_accounts: admins_only     # lock: users must use Synology SSO
  sso_enabled: true
approval:
  pending_max: 25                 # may tighten, never disables approval
  expiry_days: 14
  admin_role_requires_two_admins: true   # optional: granting Administrator needs a second admin
users:
  require_totp_for_local_admins: true
```

- **Tighten only:** `policy.yaml` can make the approval workflow stricter (lower limits, shorter expiry, two administrators to grant the Administrator role), but it can't remove it.
- **Bad policy file:** an unknown key or invalid value stops the container from starting, so a typo can't quietly weaken the policy.

#### 3.3.4 Startup checks (fail closed)

At every start the container checks, and reports on the status page and in the log:

| Check | If it fails |
|---|---|
| `GOGO_SSO_ENABLED=true` but `GOGO_PUBLIC_URL` isn't `https://` | SSO stays **off**; Gogo Desktop accounts still work so an administrator can fix it |
| Secret file missing, empty, or readable by everyone (`o+r`) | SSO stays **off**, with the reason shown |
| Well-known URL unreachable, or its issuer doesn't match | SSO stays **off** and is retried every 5 minutes; Pending, approved and rejected records are untouched |
| No Gogo Desktop administrator exists | **Setup mode:** a one-time setup code is printed in the container log (Container Manager → Container → gogo-desktop → Log). Only `/setup` is served until the first administrator is created |
| `/data` not writable, or `/config` writable | The container refuses to start. A writable `/config` means the policy could be changed from inside |
| Database upgraded from an older version | The automatic copy is kept; the audit log records the upgrade |

#### 3.3.5 Approving from the NAS command line

The web page (Settings → Users → Pending) is the normal place to approve users. The same actions are available from the NAS, for when the web interface can't be used, for example during an SSO fault with no Gogo Desktop administrator able to sign in. They require SSH access to the NAS as an administrator (`sudo docker exec …`).

```sh
sudo docker exec gogo-desktop gogo users list --status pending
sudo docker exec gogo-desktop gogo users show <user-id>
sudo docker exec gogo-desktop gogo users approve <user-id> --role user --libraries Projects,Photos
sudo docker exec gogo-desktop gogo users reject  <user-id> --reason "Not staff"
sudo docker exec gogo-desktop gogo users disable <user-id>
sudo docker exec gogo-desktop gogo audit tail --type approval
sudo docker exec gogo-desktop gogo admin reset     # one-time reset code (section 11.2.2)
```

- **Same rules as the web page:** limits, expiry and audit records apply. Granting `--role admin` asks for a typed confirmation, and with `admin_role_requires_two_admins` it records a request that a second administrator must confirm in the web interface.
- **Recorded as "NAS console":** each command is logged with the NAS user who ran `sudo`, if the container can see it, or "host console" otherwise. Anyone with administrator SSH access to the NAS already controls the container, so the command line doesn't add new access. It only makes that access visible in the audit log.

#### 3.3.6 Audit log, backups and restores

- **Audit log:** `/data/audit/` holds append-only JSON-lines files. Each record includes a hash of the previous one, so edits or deletions are detectable (`gogo audit verify`). It's kept for `GOGO_AUDIT_RETENTION_DAYS`. Records cover requests, approvals, rejections, expiries, disables, role changes, links and command-line actions.
- **Backups (Hyper Backup):** back up `/volume1/docker/gogo-desktop/data/db`, `data/audit` and `config`. `data/index` can be left out, because it's rebuilt from the files. Back up `secrets` separately, encrypted, or re-create it from SSO Server.
- **Restoring a backup:** an older backup could bring back approvals that were revoked after it was made. After a restore is detected (the database is older than the newest audit record), Gogo Desktop therefore:
  1. ends all sessions, API tokens and Companion pairings
  2. marks every Synology account **"Review"**, which works like Pending, so they can't search until re-approved
  3. shows a banner asking an administrator to review the user list. Approved accounts can be re-approved in one step after checking.

### 3.4 Resource profiles

| Profile | For | Workers | Memory budget | Name index |
|---|---|---|---|---|
| `windows` | Desktop PC | Half the CPU cores (max 8) | Up to 4 GB | In memory |
| `nas-small` | NAS with 2–4 GB RAM (for example DS224+, DS223) | 1–2 | ~1.5 GB total | **On disk (memory-mapped)**, so it doesn't fill RAM |
| `nas-large` | NAS with 8 GB+ RAM (for example DS923+, DS1821+) | 4 | ~4 GB | In memory |

In `nas-small`, the DGN and DWG workers run one at a time, and indexing pauses while the NAS is busy with backups or scrubbing (high input/output wait).

---

## 4. File discovery

### 4.1 Windows host: NTFS volumes

1. **First listing:** enumerate the file table with `FSCTL_ENUM_USN_DATA`. The Rust crate [usn-journal-rs](https://crates.io/crates/usn-journal-rs) (v0.5.0) wraps this and the change journal, and needs Windows plus administrator rights. An alternative reads the raw `$MFT` directly ([ntfs-reader](https://docs.rs/ntfs-reader/latest/ntfs_reader/)), which also sees locked files.
2. **Live changes:** read the volume's change journal from the last saved position. Reasons handled: create, delete, rename, data change, security change.
3. **Resume after downtime:** store the journal ID and last position per volume. If the journal was reset or wrapped around, fall back to a full re-listing of that volume, comparing against the stored snapshot.
4. **Journal missing:** offer to create one (`fsutil usn createjournal`) or fall back to the slower watcher below.
5. **Network shares, FAT/exFAT and removable drives:** directory scan plus `ReadDirectoryChangesW`; rescan on reconnect. Network shares are off by default. For files on a NAS, running Gogo Desktop **on the NAS** is faster and more reliable than indexing the share from a PC.
6. **Excluded by default:** `C:\Windows`, `Program Files`, the recycle bin, temporary folders, and Gogo Desktop's own data folder.

### 4.2 Synology host: shared folders in Docker

1. **First listing:** parallel directory walk of each `/libraries/<name>` mount, keeping name, size, times, inode and device number.
2. **Live changes:** Linux inotify watches on every folder. Each watched folder uses one watch, and the default limit on older kernels is 8,192 ([Syncovery notes](https://www.syncovery.com/documentation/raising-inotify-limits/)). The limit can't be raised from inside a container; it must be raised on the NAS itself. On Synology that's done with a boot-time scheduled task such as `sh -c '(sleep 90 && echo 524288 > /proc/sys/fs/inotify/max_user_watches)&'` ([Syncthing forum](https://forum.syncthing.net/t/partial-success-on-increasing-inotify-limits-on-synology-nas/20677)). The setup guide and the status page show how many watches are needed and whether the limit is enough.
3. **Safety net:** inotify can drop events (queue overflow), and changes made over SMB/AFP from other machines can arrive late. So a **re-check runs every 6 hours by default**, comparing size, modified time and inode, and immediately after any overflow. Libraries can be set to "re-check only" if watches are short.
4. **Synology folders skipped by default:** `#recycle`, `@eaDir` (thumbnails made by DSM), `#snapshot`, `@tmp`, `.SynologyWorkingDirectory`.
5. **Paths shown to users:** each library has a display mapping so results show familiar paths. For example `/libraries/Projects/A/plan.dwg` is shown as `\\NAS\Projects\A\plan.dwg` for Windows users and `smb://nas/Projects/A/plan.dwg` for Mac users, and can be opened in DSM File Station.

### 4.3 Performance targets

| Metric | Windows host | Synology host |
|---|---|---|
| First listing of 1 million files | < 10 s (SSD) | < 3 min (HDD array, nas-large), < 8 min (nas-small) |
| New or renamed file visible in name search | < 1 s | < 5 s with inotify; ≤ re-check interval without |
| Name-index memory per 1 million files | < 150 MB | < 150 MB in memory, or < 40 MB resident when memory-mapped (nas-small) |

---

## 5. Supported formats and extractors

Each extractor turns a file (or an item inside it) into: **text** (searchable body), **fields** (structured values such as author or camera), and optionally **child items** (emails inside an `.ost`, files inside a ZIP).

| Format | Approach (v1) | Text indexed | Fields | Notes |
|---|---|---|---|---|
| Text, code, CSV, JSON, logs | Built-in; detect encoding (UTF-8/16, legacy code pages) | Full text, first 10 MB | Line count, language | Skip binary files by content sniffing |
| PDF | pdfium (via Rust bindings) | Text per page | Title, author, subject, keywords, page count, created/modified | Encrypted PDFs: metadata only |
| Word/Excel/PowerPoint (.docx/.xlsx/.pptx) | Built-in reader of the ZIP and XML parts | Body, comments, notes, sheet cell text | Core and app properties | |
| Legacy Office (.doc/.xls/.ppt) | Compound-file reader (`cfb` crate) plus format-specific text extraction | Body text | Summary properties | Optional fallback: Windows' built-in document filters (IFilter) |
| RTF, HTML | Built-in | Visible text | Title | |
| ZIP | Built-in; nested depth ≤ 2, size cap | Contents of supported files inside | Inner path | Each inner file is a child item |
| **`.msg`** | **[msg_parser](https://docs.rs/msg_parser/latest/msg_parser/struct.Outlook.html)** (Rust; reads the [MS-OXMSG](https://learn.microsoft.com/ms-my/openspecs/exchange_server_protocols/ms-oxmsg/cd44ec9f-01bb-4ea3-b335-87cfeb827594) compound-file format) | Subject, body (plain text; else HTML converted to text; else decompressed RTF), attachment names and supported attachment contents | From, To, Cc, Bcc, sent/received time, message class (mail, meeting, contact, task), importance, attachment count | Attachments are child items, sent to the matching extractor |
| **`.ost`** | **[libpff](https://github.com/libyal/libpff)** (C, LGPL-3.0+), which reads PST and OST, including the 4 KB-page compressed OST format | Same as `.msg`, per item | Same as `.msg`, plus folder path inside the store and store owner | One child item per message, contact, appointment, task. Best effort: an OST is a cache and may be incomplete ([email-collection-toolkit notes](https://github.com/simsong/email-collection-toolkit/blob/main/doc/PST_IMPORTER.md)) |
| `.pst` | **[outlook-pst](https://github.com/microsoft/outlook-pst-rs)** (Microsoft's MIT-licensed Rust reader, experimental API); libpff as fallback | Same as `.ost` | Same as `.ost` | |
| **CAD family** (`.dwg`, `.dxf`, `.dwt`, `.dws`, `.dxb`, `.dwf`, `.dwfx`, …) | See **section 5.1** | | | |
| **MicroStation** (`.dgn`, `.dgnlib`, `.cel`, `.rdl`) | See **section 5.2** | | | |
| **Digital photos and media** | **[nom-exif](https://github.com/mindeng/nom-exif)** (pure Rust: JPEG, PNG, WebP, HEIC/HEIF, AVIF, TIFF, several RAW formats; MP4, MOV, MKV, WebM); fallback to ExifTool for formats it doesn't parse | XMP title, description, keywords, IPTC captions | Date taken, camera make/model, lens, focal length, aperture, shutter speed, ISO, GPS position, image size, orientation, video duration and codec, audio tags (MP3/FLAC/M4A via a tag library) | **Sony `.ARW`** isn't on nom-exif's published list. ARW is TIFF-based, so it may parse, but **that must be tested on real files**. ExifTool is the fallback. Sidecar `.xmp` files are merged with their photo |

### 5.1 CAD formats (DWG, DXF and related)

Every CAD file is recognized by its **content signature first**, then its extension. For example, a DWG starts with a version code such as `AC1032`, and DWF v6+/DWFx start with the ZIP signature `PK`. A renamed file is still handled correctly.

| Format | What it is | Extractor | Text indexed | Fields | v1 level |
|---|---|---|---|---|---|
| **`.dwg`** | AutoCAD drawing (R1.x up to the 2018+ format, `AC1032`) | **[LibreDWG](https://github.com/LibreDWG/libredwg)** (C, GPL-3.0), run as a separate tool process. It reads all DWG versions, though some advanced R2010+ objects are skipped | TEXT, MTEXT (formatting codes removed), block attribute tags and values, attribute definitions, dimension text overrides, MLEADER text, table cells, layer names, block names, layout names, text style names, entity hyperlinks, external reference (xref) paths, raster image and PDF underlay paths | DWG version code, drawing properties (title, subject, author, keywords, comments, custom properties), last saved by, created/edited times, total editing time, drawing units, entity counts by type, layout count, embedded thumbnail | **Full** |
| **`.dwt`** | Drawing template | Same as `.dwg` (same file format) | Same as `.dwg` | Same, plus `template = yes` | Full |
| **`.dws`** | CAD standards file | Same as `.dwg` (same file format) | Layer, text-style, dimension-style and line-type names | Same, plus `standards = yes` | Full |
| **`.dxf`** (ASCII) | Drawing Exchange Format | **Built-in streaming parser** that reads group code/value pairs without loading the whole file | Same entity text as `.dwg` | HEADER variables (`$ACADVER`, `$TDCREATE`, `$TDUPDATE`, `$LASTSAVEDBY`, `$INSUNITS`, `$DWGCODEPAGE`), layers, blocks | Full |
| **`.dxf`** (binary), **`.dxb`** | Binary DXF / Drawing Interchange Binary | LibreDWG, which reads both ([LibreDWG NEWS](https://github.com/mlightcad/libredwg-web/blob/master/NEWS)) | Same as `.dxf` | Same as `.dxf` | Full |
| **`.dwf`** (v6+, ZIP) | Design Web Format: a published, view-only package with a manifest, W2D sheets and properties ([format notes](https://file-extensions.com/docs/dwf)) | **Built-in ZIP reader**: manifest and descriptor XML, object-property XML | Sheet names and titles, published object properties, block attributes, layer names, hyperlinks | Publisher, source drawing name, sheet count, created time, thumbnail | Full for metadata and properties. Text that exists **only as geometry inside W2D streams** isn't extracted in v1 |
| **`.dwf`** (v5 and older) | Legacy, non-ZIP DWF (`(DWF V` header) | Header reader | Header text | Version | Name and metadata only |
| **`.dwfx`** | DWF inside an XPS/OPC (ZIP) package ([format notes](https://file-extensions.com/docs/dwfx)) | **Built-in OPC/XPS reader**: `Glyphs` `UnicodeString` text from each FixedPage, plus the DWF metadata and property parts | Visible page text, sheet names, published object properties and block attributes | Same as `.dwf` | Full |
| **`.bak`**, **`.sv$`** | AutoCAD backup and autosave (DWG inside) | Same as `.dwg`, detected by signature | Same as `.dwg` | `backup = yes`; linked to the original drawing by name | **Off by default** to avoid duplicate results |
| **`.dgn`**, `.dgnlib`, `.cel`, `.rdl` | MicroStation V7 and V8 | **ODA Drawings SDK** worker — see **section 5.2** | Full | Full | **Full** |
| `.lsp`, `.scr`, `.dcl`, `.lin`, `.pat`, `.mnl` | AutoLISP, scripts, dialog definitions, line types, hatch patterns | Text extractor | Full text | — | Full |
| `.cuix` | AutoCAD customization (ZIP of XML) | Built-in ZIP/XML | Command names, macros, labels | — | Full |
| `.ctb`, `.stb`, `.pc3`, `.pmp`, `.shx` | Plot styles, plotter configs, compiled fonts | — | — | Name, size, dates | Name only |

#### CAD-specific behavior

- **Text clean-up:**
  - MTEXT formatting codes (`\P` new paragraph, `\f…;` font, `\H…;` height, `{…}` groups) are removed.
  - The special symbols `%%c`, `%%d` and `%%p` become ⌀, ° and ±.
  - Fields such as `%<\AcVar …>%` keep their last displayed value.
- **Text encodings:** drawings from before AutoCAD 2007 store text in a code page (`$DWGCODEPAGE`, for example ANSI_950 for Traditional Chinese, ANSI_936, ANSI_932). Text is converted to Unicode using that code page, so Chinese, Japanese and Korean notes are searchable. Later DWG versions are already Unicode.
- **Block attributes as fields:** attribute tags become searchable fields, for example `attr:DWG_NO=A-101` or `attr:DRAWN_BY:lee`. Title-block values such as drawing number, revision and client can be filtered directly.
- **Reference map:** every xref, raster image, PDF underlay and font a drawing points to is stored. That answers "**which drawings reference `site_base.dwg`**" and "**which drawings have missing references**" (the target path doesn't exist).
- **Thumbnails:** taken from the preview image stored inside DWG, DXF and DWF files. Gogo Desktop doesn't draw drawings itself in v1.
- **Large drawings:** DXF is parsed as a stream. DWG parsing runs under the 1 GB worker memory limit and a 60-second CAD time limit. Drawings over either limit are indexed with metadata only and marked "partial".
- **Published copies:** a `.dwg` with the same name as a `.dwf`, `.dwfx` or `.pdf` in the same folder is shown as one result with its published copies.
- **Unsupported content is flagged, not hidden:** items marked "partial" or "name only" show that status in the results and the index-status page.

#### CAD query examples

| Query | Meaning |
|---|---|
| `kind:drawing "fire exit"` | Drawings containing that text anywhere |
| `kind:drawing layer:E-LIGHT` | Drawings with a layer of that name |
| `attr:DWG_NO=A-10*` | Drawings whose title block drawing number starts with A-10 |
| `kind:drawing xref:site_base.dwg` | Drawings that reference `site_base.dwg` |
| `kind:drawing has:missing-xref` | Drawings with broken references |
| `ext:dwg acadver:<AC1027 modified:2026` | Older-format drawings changed this year |
| `ext:dwfx sheet:"Ground Floor"` | Published sheets with that title |

### 5.2 MicroStation DGN (full support through the ODA SDK)

**Engine:** the [ODA Drawings SDK](https://www.opendesign.com/products/drawings) (C++). ODA describes it as giving access to 100% of the data in DWG and DGN files, and its product material lists **DGN V7 and V8 read and write** ([Teigha Drawings brochure](https://www.opendesign.com/files/upload/wp/pdf/brochure_Drawings.pdf)). Every ODA membership level includes the DGN SDK ([ODA pricing](https://www.opendesign.com/pricing?language=en)). It replaces both DGNLib and the earlier "name only" limit. Gogo Desktop only **reads** DGN files; it never saves them.

#### How it fits the architecture

- The ODA SDK is C++. It runs inside its own sandboxed worker, **`gogo-oda`** (`gogo-oda` on Windows; a Linux x86_64 or ARM64 binary in the Docker image), under the same rules as every extractor (section 8): no network, fixed memory and time limits, one file per job.
- The worker loads the drawing **read-only** into an `OdDgDatabase` (via the SDK's file-reading call, [`DgDatabase.h`](https://github.com/DF-OUTSIDER/TeighaExporter/blob/master/Common/Teigha/Dgn/include/DgDatabase.h)). It walks the control and graphic elements of every model, then sends results to the service as a stream of JSON records. The record schema is shared with the DWG worker, so drawings from both systems land in the same fields.
- **Settings for reading:**
  - Reference files are **not loaded** while indexing a drawing; their paths are read only.
  - Font substitution is quiet: a missing font never stops extraction, and the text is still indexed.
  - Nothing is ever written back to disk.
- **Licensing material:** the ODA activation details, if the SDK build requires them, are compiled into `gogo-oda` only and kept out of the source repository.
- **Fallback:** if `gogo-oda` isn't installed (a build without an ODA licence), V7 files go through DGNLib and V8 files fall back to name and Windows properties, marked "name only".

#### DGN file types

Files are detected by content first:
- DGN V7 starts with a type-9 design-file header element.
- DGN V8 is an OLE compound file, the same container type as `.msg`, holding DGN streams.

| Extension | What it is | Handling |
|---|---|---|
| **`.dgn`** V7 | MicroStation SE/J and earlier | ODA worker, full |
| **`.dgn`** V8 | MicroStation V8, V8 XM, V8i and CONNECT Edition (all store the V8 file format) | ODA worker, full |
| **`.dgnlib`** | DGN library (levels, text styles, cells, item type definitions) | ODA worker, full; marked `library = yes` |
| **`.cel`** | Cell library (V7 format or V8 DGN format) | ODA worker; every cell name and description becomes searchable |
| **`.rdl`** | Redline file (DGN format) | ODA worker, full; marked `redline = yes` |
| `.dgn.bak`, `.dgn~`, `*.bak` with a DGN signature | Backups | Same as `.dgn`; **off by default** (avoids duplicate results) |
| `.i.dgn` (i-model) | Published, read-only DGN | Attempted with the ODA worker; marked "partial" if some content isn't readable. **Test with real files** |
| `.dscript`, `.ucf`, `.pcf`, `.cfg`, `.mvba` names | Configuration and macro files | Text files indexed as text; `.mvba` by name only |

#### What's extracted from a DGN

| Area | DGN source (ODA classes) | Indexed as |
|---|---|---|
| **Text** | `OdDgText2d` / `OdDgText3d` text elements | `body` |
| **Multi-line text** | `OdDgTextNode2d` / `OdDgTextNode3d`, which group several text elements ([ODA blog](https://www.opendesign.com/blog/2017/july/creating-table-elements-dgn-files)) | `body`, lines joined in order |
| **Tables** | `OdDgTableElement` cells, which hold text nodes ([ODA blog](https://www.opendesign.com/blog/2017/july/creating-table-elements-dgn-files)) | `body`, plus `table` rows in the preview |
| **Dimensions and notes** | Dimension text overrides and prefixes/suffixes; note elements (cell + leader + text) | `body` |
| **Fields in text** | Text fields that point to properties | Their last displayed value |
| **Cells** | `OdDgCellHeader2d/3d`, `OdDgSharedCellDefinition`, `OdDgSharedCellReference` | Cell names → `blocks`; cell descriptions → `body` |
| **Tags (older attribute data)** | Tag set definitions and tag elements | `attr.<tagset>.<tag> = value`, same filtering as DWG block attributes |
| **Item types (newer attribute data)** | Item types and attached items, which replace tags ([MicroStation help](https://docs.bentley.com/LiveContent/web/MicroStation%20Help-v21/en/GUID-5662137D-989D-4E16-AE90-1A1D7D390245.html)). Read through ODA's common data access layer, which covers DGN models, property tables and styles ([ODA white paper](https://www.opendesign.com/files/white-papers/ODA%20Drawings%20SDK.pdf)) | `attr.<itemtype>.<property> = value`. **Exact API coverage to confirm** against the SDK during M4b |
| **Models** | Design, sheet and drawing models; 2D/3D; model names and descriptions | `layouts` (shared field with DWG layouts), `sheets` |
| **Levels** | Level names, descriptions, level filters | `layers` (shared field with DWG layers) |
| **Styles and resources** | Text styles, dimension styles, line styles, fonts used | `styles`, `fonts` |
| **Saved views, named groups** | Names and descriptions | `body` (low weight) |
| **References** | `OdDgReferenceAttachmentHeader` (type 90): file name, model name, logical name, description, nesting. Supported targets are DGN, DWG and DXF, plus raster attachments to image and PDF files ([ODA FAQ](https://www.opendesign.com/faq/examples)), with `OdDgRasterFrame` (type 94) for raster details ([ODA blog](https://www.opendesign.com/blog/2017/june/raster-reference-element-feature-dgn-files)) | `refs`, `missing_refs`, joined into the **same reference map as DWG xrefs**. So "which drawings use `site_base.dgn`" works across DGN and DWG |
| **Hyperlinks** | Engineering links on elements | `links` |
| **File properties** | Title, subject, author, keywords, comments, last saved by, application name and version, created/modified times | Standard document fields |
| **File facts** | DGN version (V7/V8), master/sub units, 2D or 3D, model count, element counts by type | Fields for filtering |
| **Preview** | Embedded thumbnail if the file has one. Otherwise an optional small image rendered by the SDK's raster export (Drawings SDK exports raster formats, [ODA FAQ](https://www.opendesign.com/faq/product-descriptions)), **off by default** because it's slow | Preview pane |

Recent SDK releases also give access to elements in DGN "Nd" streams ([ODA SDK updates](https://www.opendesign.com/blog/2025/may/recent-sdk-updates)). Gogo Desktop reads their text and properties the same way when present.

#### Text encodings

- V8 text is normally Unicode, and the SDK returns it as Unicode strings.
- V7 text, and V8 text in older MicroStation shape fonts, may be stored as 8-bit or double-byte text tied to the font. The worker converts it using the font's code page (for example Big5 for Traditional Chinese fonts). If the font isn't known, it uses the code page set for the drawing or the system. Traditional Chinese notes in older drawings are part of the acceptance tests.

#### Limits and performance

| Limit | DGN default |
|---|---|
| Time per file | 120 s; over that, metadata only and marked "partial" |
| Memory per worker | 2 GB |
| Parallel ODA workers | Half the CPU cores, at most 4 |
| Target speed (SSD, typical 2–20 MB V8 file) | ≥ 60 drawings per minute per worker, to be benchmarked in M4b |

#### DGN query examples

| Query | Meaning |
|---|---|
| `ext:dgn "pump room"` | DGN drawings containing that text |
| `kind:drawing level:E-LIGHT` | DGN levels or DWG layers named E-LIGHT (same field) |
| `ext:dgn attr.TitleBlock.DrawingNo=A-10*` | Drawings whose title-block item or tag starts with A-10 |
| `ext:cel cell:DOOR*` | Cell libraries containing door cells |
| `kind:drawing ref:site_base.dgn` | DGN and DWG drawings that reference `site_base.dgn` |
| `ext:dgn dgnver:V7` | Old V7 files (candidates for upgrade) |
| `ext:dgn model.type:sheet "Rev C"` | Sheet models showing revision C |

### Size, time and safety limits (per file)

| Limit | Default |
|---|---|
| Maximum text kept per item | 10 MB |
| Extractor time limit | 30 s (DWG/DXF: 60 s; DGN: 120 s; OST/PST: per item, not per store) |
| Extractor memory limit | 1 GB (Windows job object or Linux cgroup; nas-small: 768 MB, except CAD workers) |
| Files skipped above | 2 GB (except OST/PST, which are processed item by item) |

---

## 6. Index design

### 6.1 Name index (in memory, or memory-mapped on small NAS units)

- One record per file or folder: file reference number and parent reference (Windows) or inode, device and parent (Linux), plus name (kept compactly), size, modified time, attributes, volume or library.
- Full paths are built from parent links when needed. A compact sorted name array plus a trigram index allows fast substring search.
- A snapshot is saved to disk every few minutes and on shutdown, so restarts take seconds.

### 6.2 Content index ([Tantivy](https://github.com/quickwit-oss/tantivy/releases), current release 0.26.x)

| Field | Type | Used for |
|---|---|---|
| `id` | key | Stable item ID: volume + file reference (Windows) or library + inode (NAS), plus inner path for child items |
| `kind` | facet | file, email, contact, appointment, task, drawing, photo, video, audio, archive-entry |
| `path`, `name`, `ext` | text + keyword | Path and name search, type filters |
| `title`, `body` | text (stemmed + exact) | Main search |
| `from`, `to`, `cc` | text + keyword | Mail search |
| `folder` | keyword | Outlook folder path |
| `author`, `last_saved_by` | text | Documents, drawings |
| `camera`, `lens` | keyword | Photos |
| `taken`, `sent`, `received`, `modified`, `created` | date | Date ranges, timeline |
| `iso`, `focal`, `aperture`, `exposure` | number | Photo filters |
| `geo` | latitude/longitude | "Near" filter (later) |
| `layers`, `blocks`, `layouts`, `sheets` | keyword | Drawings |
| `attr.*` | dynamic keyword | Block attribute tags and values (title blocks) |
| `refs`, `missing_refs` | keyword | Xref, image and underlay paths; broken ones |
| `acadver`, `dgnver` | keyword | DWG/DXF version code; DGN V7/V8 |
| `cells`, `styles`, `fonts`, `links` | keyword | DGN cells (shared with DWG blocks where useful), styles, fonts, engineering links |
| `model.type` | keyword | design, sheet, drawing |
| `size` | number | Size filters |
| `library` | keyword | Library ID, used to filter results by permission (section 11.4) |
| `acl_sid_hash` | keyword | Windows host: fast pre-filter before the per-user file-permission check |

- **Languages:** a standard tokenizer plus stemming for English. For Chinese, Japanese and Korean, a character n-gram tokenizer so Traditional Chinese text is searchable without word segmentation.
- **Updates:** commits every few seconds (near-real-time), plus background segment merging.
- **Text previews:** the extracted text is stored compressed so the preview can show highlighted matches without reopening the original.

---

## 7. Queries and ranking

### Query syntax

| Example | Meaning |
|---|---|
| `invoice 2025` | All words, anywhere (name or content) |
| `"site plan"` | Exact phrase |
| `name:*.dwg revision` | Name pattern plus content word |
| `ext:msg from:alice` | `.msg` files from Alice |
| `kind:email folder:Inbox received:2026-09..2026-10` | Mail in a folder and date range |
| `kind:drawing layer:ELEC` | Drawings containing a layer named ELEC (more CAD examples in section 5.1) |
| `kind:photo camera:"ILCE-7M4" iso:>3200` | Photos from a given camera with high ISO |
| `size:>100MB modified:last-week` | Large, recently changed files |
| `-draft` | Exclude a word |

### Ranking

1. BM25 text relevance, boosted for matches in name or title, and in email subject.
2. Recency boost (recently modified or received).
3. Location boost: on Windows, the user's Documents, Desktop and Downloads folders; on the NAS, libraries marked as priority. Folders the user often opens results from also get a boost, which is kept per user on the server only.
4. Exact filename match always comes first.

### Speed targets

| Query (1M files, 200k emails, 50k drawings) | Windows host | NAS (nas-large / nas-small) |
|---|---|---|
| Name search, first results | < 20 ms | < 50 ms / < 150 ms |
| Content search, first page | < 200 ms (p95) | < 300 ms / < 800 ms (p95) |
| Typing-as-you-search updates | Every keystroke; earlier requests cancelled | Same |

Times are measured at the server. On the local network, browser display adds typically 5–30 ms.

---

## 8. Reliability and safety of parsing

File parsers are the riskiest code. LibreDWG, for example, had fixes in 2026 for crashes and an overflow in thumbnail handling ([OSV advisory](https://osv.dev/vulnerability/openSUSE-SU-2026:21346-1)). Rules for both hosts:

- **Separate worker processes** with no network access and fixed limits.
  - Windows: restricted token and job object.
  - Docker: separate processes with cgroup memory/CPU limits, a seccomp filter and no network namespace access. Libraries are mounted read-only.
- **One job = one file or one store item.** A crash marks just that item as "failed", records the extractor version, and retries only after an extractor upgrade.
- OST/PST stores are processed **item by item with a checkpoint**, so a 40 GB store resumes where it stopped.
- **Outlook files in use (Windows host):** classic Outlook keeps its `.ost` open. Order of attempts:
  1. Open read-only with full sharing.
  2. Else read from a Volume Shadow Copy snapshot (the service has the rights).
  3. Else wait until Outlook closes.

  **Never write to Outlook files.** On the NAS, `.ost`/`.pst` files are copies or archives on shares; if one is being copied, the worker waits until its size and modified time are stable for 5 minutes.
- **Original files are never changed.** Workers open files read-only. On Windows, the "last accessed" time is left unchanged where Windows allows. On the NAS, library mounts are read-only.
- Library versions are pinned, and security advisories for each library are tracked. The Docker image is rebuilt when its base image gets security fixes.

---

## 9. User interface (web)

### 9.1 Web pages

| Page | Contents |
|---|---|
| **Search** (`/`) | One search box, results as you type, grouped tabs: All, Files, Emails, Drawings, Photos. Filters on the side (type, date, folder/library, sender, camera, layer). Keyboard-first: arrows, Enter to open, Ctrl+Enter for folder |
| **Result preview** (side panel) | Highlighted text excerpt; email header and body; drawing thumbnail with text, layers and references; photo thumbnail with EXIF and map position (map tiles **off by default**, since they'd need the internet) |
| **Timeline** (`/timeline`) | Items by day: files changed, emails received, photos taken, drawings saved |
| **Drawing references** (`/refs`) | For a drawing: what it references and what references it (DWG and DGN together); missing references highlighted |
| **Index status** (`/status`) | Progress per library and format, failed items with reason, inotify watch usage (NAS), pause/resume |
| **Settings** (`/settings`) | Libraries, formats, exclusions, accounts and permissions, resource profile, security. Locked settings are shown read-only |
| **Sign-in** (`/login`) | "Sign in with Synology" and a Gogo Desktop username/password form (with code if set). Either can be hidden by the administrator |
| **Users** (`/settings/users`, administrators) | User list (Local / Synology / linked), roles, library access, DSM group mapping, **pending Synology users waiting for approval** (with a count badge on the menu), active sessions |
| **My account** (`/account`) | Linked sign-ins, password and second factor (Gogo Desktop accounts), API tokens, Companion pairings, sessions |

- **Technology:** a single-page app (TypeScript, built with Vite), served as static files by the server. No outside CDN; everything is bundled. It works in current Chrome, Edge, Firefox and Safari, and adapts to phone screens for searching on the move within the LAN.
- **Install as an app:** the site is a Progressive Web App, so it can be pinned to the Start menu or a phone home screen.
- **Languages:** English and Traditional Chinese interface text in v1.

### 9.2 What happens when you click a result

The server **never runs a file**. Options depend on where you are:

| Action | Behavior |
|---|---|
| **Open** (with Companion installed) | The page asks the Companion on your PC to open the file (section 9.3). The Companion uses the local path (Windows host) or the network path such as `\\NAS\Projects\A\plan.dwg` (NAS host). It applies the confirmation list for executable and script types |
| **Open** (no Companion) | Windows host, same PC: copies the path and shows "open folder". NAS host: offers download, or "open in File Station" |
| **Download / view** | Streamed by the server **only** if the signed-in user has access (section 11.4). Sent as a download with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, never shown inline as HTML |
| **Email body** | HTML emails are cleaned (scripts, forms and event handlers removed) and shown inside a sandboxed frame. **Remote images are blocked by default** so tracking pixels can't report that you looked |
| **Copy path / copy link** | Copies the display path, or a Gogo Desktop link that only works for signed-in users with access |

**Confirmation list** for opening (Companion), maintained as a setting: `exe, msi, bat, cmd, com, scr, pif, cpl, hta, js, jse, vbs, vbe, wsf, wsh, ps1, psm1, lnk, url, reg, jar, py, msc, appx, msix, application, chm, inf, iso, img, vhd, vhdx, …`

### 9.3 Gogo Companion (Windows, optional)

A small tray app for each Windows PC. It works with a Windows host or a NAS host.

| Feature | Behavior |
|---|---|
| **Hotkey** | Default `Ctrl+Space` (`RegisterHotKey`). Optional double-tap Ctrl, using a low-level hook that only looks at modifier keys and never stores keystrokes |
| **Quick search box** | A small window (WebView2) showing the server's search page in compact mode |
| **Open on this PC** | Registers a `gogo-open:` link handler. The web page sends a **one-time, signed open request** (valid 30 s, single use, bound to the signed-in user and the Companion's pairing key). The Companion checks it, maps the path, asks for confirmation if the type is on the list, then opens the file with the normal Windows handler |
| **Pairing** | First run: the user signs in to the server once, and the server issues a Companion key, which the Companion stores with Windows DPAPI. Keys can be revoked on the settings page |
| **Sign-in on the same PC** | With a Windows host, the Companion proves the Windows user to the server over a local named pipe and gets a one-time sign-in link, so there's no password prompt |
| **Not done** | No code injection, no browser extension, no reading of other apps' windows |

### 9.4 API

- **Style:** JSON REST API under `/api/v1`, described in OpenAPI so scripts and other tools can use it.
- **Live search:** results stream over Server-Sent Events (`/api/v1/search/stream`), with results replaced as you type.
- **Main endpoints:**

  | Method | Endpoint |
  |---|---|
  | `GET` | `/search`, `/items/{id}`, `/items/{id}/preview`, `/items/{id}/content` (download), `/timeline`, `/refs/{id}`, `/status` |
  | `PATCH` | `/settings/{key}` (one setting per request) |
  | `POST` | `/libraries`, `/libraries/{id}/recheck`, `/index/rebuild` (admin, re-authentication), `/tokens` |
- **Rules:**
  - Every `GET` is read-only.
  - Every state change needs a session plus a CSRF token, or an API token with the right scope.
- **API tokens:** for scripts and automation. Each one is scoped (`search:read`, `content:read`, `admin`), has an expiry date, is shown once, stored only as a hash, and can be revoked.

---

## 10. Settings and policy

- **Libraries (what to index):**
  - Windows: drives and folders.
  - NAS: the mounted `/libraries/*` folders.
  - Each library has a name, display-path mapping, permissions (section 11.4), formats and exclusions.
- **Per-format switches:** text, PDF, Office, `.msg`, `.ost`, `.pst`, `.dwg/.dxf` family, DGN family, media metadata, ZIP contents.
- **Exclusions:** folders and patterns (wildcards). Synology system folders are excluded by default (section 4.2).
- **Outlook stores (Windows host):** auto-detect stores in `%LOCALAPPDATA%\Microsoft\Outlook` and `Documents\Outlook Files`, with a per-store switch. Mail is indexed **only for the Windows user who owns it**, unless an administrator shares it.
- **Resource use:** profile (section 3.4), CPU cap, "only when idle", quiet hours.
- **Privacy:** remove deleted files from the index right away (default on); "forget" a folder or library.
- **Index encryption:** optional encryption of index files at rest.
  - Windows: key protected with DPAPI (machine scope).
  - NAS: key held in a secret file under `/run/secrets` (section 3.3), readable only by the container user. Or use an encrypted DSM shared folder for `/data`.
- **Administrator lock:** each setting can be locked. Windows: Group Policy (ADMX). NAS: `/config/policy.yaml`, owned by the NAS administrator and mounted read-only (section 3.3.3).
- **Sign-in:** allowed methods (Gogo Desktop accounts: all or administrators only; Synology SSO: on or off), DSM group mapping, session lengths, second-factor rules (section 11.2).
- **Changing settings:** one field per request, checked against policy, recorded in the audit log. **A missing field never means "off".**

---

## 11. Security design

### 11.1 Network exposure

| Host | Default | Optional |
|---|---|---|
| Windows | **Listens only on `127.0.0.1:4680`** (HTTP is acceptable because traffic never leaves the PC) | LAN mode: HTTPS on `:4681` for chosen networks, with Windows Firewall rules created for "Private" networks only |
| Synology | HTTPS on `:4681` inside the LAN | Behind the **DSM reverse proxy** (Control Panel → Login Portal → Advanced) using the NAS's certificate, for example Let's Encrypt for `search.<your-domain>` |

- **HTTPS certificates:** use a certificate you provide, the DSM certificate through the reverse proxy, or a self-signed certificate created on first run (its fingerprint is shown for checking).
- **Internet access:** not supported. If you need it from outside, use a VPN to your network (for example the VPN on your router or Synology VPN Server). Don't forward the port.

### 11.2 Sign-in

**Decision:** both hosts support **Gogo Desktop accounts** and **Synology SSO** side by side. The sign-in page offers both, and an administrator chooses which are allowed.

#### 11.2.1 Sign-in methods

| Method | Where | Details |
|---|---|---|
| **Same-PC automatic** | Windows host | The Companion or tray icon proves the Windows user through a local named pipe and gets a one-time sign-in link (valid 60 s, single use) |
| **Gogo Desktop accounts** | Both hosts | Username and password stored by Gogo Desktop (Argon2id hash). Optional or required second factor with time-based codes (TOTP). Lockout after repeated failures |
| **Synology SSO (OpenID Connect)** | NAS host; also Windows LAN mode | Gogo Desktop is an OIDC client of **Synology SSO Server**, which supports OIDC and SAML 2.0. The SSO Server address must be a domain name with a valid HTTPS certificate, not an IP address ([Synology SSO Server specs](https://www.synology.com/en-global/dsm/7.4/software_spec/sso_server)) |
| **API tokens** | Both hosts | For scripts (section 9.4); each token belongs to one account |

#### 11.2.2 How the two account types work together

| Topic | Rule |
|---|---|
| **Sign-in page** | Shows **"Sign in with Synology"** and a username/password form. Either can be hidden by the administrator (see "Allowed methods" below) |
| **Account identity** | **Gogo Desktop accounts** are identified by username. **SSO accounts** are identified by the SSO Server's issuer plus the user's subject ID (`iss` + `sub`), never by display name. Both live in one user list, marked "Local" or "Synology" |
| **No automatic merging** | A Gogo Desktop account named `alice` and a Synology user `alice` are **not merged automatically**, because matching by name would let someone take over another account. They can be **linked** deliberately: the user signs in with one method, then confirms the other on the "Linked sign-ins" page. An administrator can also link or unlink them. Linking a Synology sign-in to an existing account **also needs administrator approval**, just like a new Synology user. A linked account keeps one set of permissions, history and API tokens |
| **First SSO sign-in** | **Always needs administrator approval** (section 11.2.3). This is a fixed rule, not a setting, so it can't be turned off by mistake. Until approved, the account is "Pending" and can't search, see results, create API tokens or pair a Companion |
| **Groups from Synology** | If the SSO Server's ID token includes group membership, DSM groups can be mapped to Gogo Desktop roles and libraries, for example DSM group `cad-team` → library "Projects", DSM group `administrators` → Gogo Desktop administrator. Mapping is applied **only after the account has been approved**, and is then re-applied at every sign-in. Group membership never approves an account, and never grants the administrator role to an account that isn't yet approved. **Whether Synology SSO Server sends group claims is to be confirmed during M6.** If it doesn't, group membership is managed in Gogo Desktop instead |
| **Roles** | **Administrator** (settings, libraries, users, rebuilds) and **User** (search within permitted libraries). Either account type can hold either role |
| **Allowed methods** (setting) | `local_accounts`: `all` / `admins_only`. `synology_sso`: `on` / `off`. The common NAS setup is **SSO for everyone, Gogo Desktop accounts for administrators only** |
| **Emergency administrator** | At least **one Gogo Desktop administrator account always exists**; the last one can't be deleted or disabled. That keeps administration possible if the SSO Server is down, its certificate expires, or DSM settings change |
| **If SSO is unavailable** | Gogo Desktop accounts keep working. SSO users already signed in stay signed in until their session ends. New SSO sign-ins show a clear "Synology sign-in is unavailable" message, with no fallback to a weaker method |
| **Account disabled in DSM** | Takes effect at the user's next sign-in. To make that quick, SSO sessions have a shorter maximum length (8 hours by default, adjustable). Administrators can end any session immediately |
| **Signing out** | Ends the Gogo Desktop session. If the SSO Server supports sign-out requests from apps, Gogo Desktop also signs the user out there; otherwise the page says the Synology session may still be active |
| **Confirming identity for risky actions** | Gogo Desktop accounts re-enter their password (and code, if set). SSO accounts are sent back through Synology sign-in with a forced fresh login. Gogo Desktop checks the token's sign-in time is within the last 5 minutes |
| **Second factor** | Gogo Desktop accounts: TOTP **required for administrators** when the server is reachable from the network, optional for users. SSO accounts: whatever DSM requires; DSM supports two-factor sign-in |
| **Password rules** (Gogo Desktop accounts) | At least 12 characters; checked against a built-in list of common passwords; no forced periodic changes |
| **Account recovery** | Administrators reset Gogo Desktop users' passwords and second factors. If every administrator is locked out, `gogo admin reset` run on the host (container shell, or an administrator command prompt on Windows) issues a one-time reset code. On the NAS: `sudo docker exec gogo-desktop gogo admin reset` (section 3.3.5). This needs NAS or PC administrator access |
| **Companion and API tokens** | Work with either account type. They stop working when their account is disabled or unlinked |
| **Audit log** | Records method used (Local / Synology / same-PC), linking and unlinking, role changes from group mapping, failed sign-ins |

#### 11.2.3 Approving new Synology users

Every Synology SSO identity that signs in to Gogo Desktop for the first time must be approved by a Gogo Desktop administrator. That includes linking a Synology sign-in to an existing account.

| Step | What happens |
|---|---|
| **1. First sign-in** | The user signs in through Synology SSO. Gogo Desktop checks the ID token (section 11.2.4), then creates a **Pending** account recording the Synology user name, display name, email address (if sent), DSM groups (if sent), the time, and the address the request came from |
| **2. User sees** | A "Waiting for approval" page: "Your Synology account has been recorded. An administrator needs to approve it before you can search." No search box, results, library names or file counts are shown. Signing in again shows the same page until a decision is made |
| **3. Administrators see** | A count badge on the **Users** menu and a banner on the status page. The **Pending** list shows each request with its details and any **suggested** role and libraries from DSM group mapping. Suggestions are never applied automatically |
| **4. Decision** | The administrator chooses **Approve** or **Reject**. Approving means choosing a role (User by default) and library access, starting from the suggestions. Granting the **Administrator** role on approval needs the administrator's own fresh sign-in (section 11.3) |
| **5. After approval** | The user's next sign-in goes straight to search. Group mapping now applies at every sign-in |
| **6. After rejection** | The user sees "Access to Gogo Desktop was not approved." The identity is kept on a **Rejected** list so repeated sign-ins don't create new requests. An administrator can later approve it from that list |

| Rule | Detail |
|---|---|
| **Who can approve** | Any Gogo Desktop administrator (Gogo Desktop account or already-approved Synology account). An administrator can't approve their own request: a Synology identity linked to an administrator's own account needs a different administrator. If only one administrator exists, they confirm with their Gogo Desktop account password and second factor |
| **Expiry** | Pending requests that aren't handled within **30 days** (`GOGO_APPROVAL_EXPIRY_DAYS`, 1–90) expire. The next sign-in creates a fresh request |
| **Flood protection** | At most **50 pending requests** at a time (`GOGO_APPROVAL_PENDING_MAX`, 1–500), and one per Synology identity. Over the limit, new requests are refused with "Too many access requests — contact your administrator" |
| **Notifications** | Shown inside Gogo Desktop only (badge, banner, status page), plus `gogo users list --status pending` on the NAS (section 3.3.5). Nothing is sent outside your network, keeping section 11 intact. Optional email through a mail server on your own network is a later item (section 15) |
| **Re-approval** | An approved account stays approved. If its Synology identity changes (a different issuer or subject, for example after rebuilding the SSO Server), Gogo Desktop treats it as a **new** identity needing approval |
| **Disabling** | Administrators can move any approved Synology account back to **Disabled**; its sessions, API tokens and Companion pairings end immediately |
| **Audit log** | Records every request, approval, rejection, expiry and disabling, with who decided, when, and the role and libraries granted |
| **API** | `GET /api/v1/users?status=pending`, `POST /api/v1/users/{id}/approve` (body: role, libraries), `POST /api/v1/users/{id}/reject`. Administrators only, with CSRF protection |

#### 11.2.4 OpenID Connect details

- **Flow:** authorization code flow with PKCE, plus `state` and `nonce`. No implicit flow.
- **Checks on every ID token:** signature (keys from the SSO Server's published key set), issuer, audience (`client_id`), expiry and issue time (2 minutes' allowance for clock differences), and `nonce`.
- **Settings:**
  - the SSO Server's **Well-known URL**, **Application ID** and **Application secret**
  - username claim (default `sub`)
  - optional groups claim
- **Storage:** the secret is read from a read-only secret file (`GOGO_SSO_CLIENT_SECRET_FILE`, section 3.3.2) on the NAS, or protected with DPAPI (Windows), never in the settings export.
- **Redirect URI:** exactly `https://<gogo-desktop-address>/auth/oidc/callback`. Gogo Desktop's public address (`GOGO_PUBLIC_URL`) must be HTTPS, because Synology SSO Server requires a proper domain name and certificate.
- **"Test connection" button:** on the settings page; it checks the well-known URL, key set and redirect before the method is turned on.

#### 11.2.5 Setting up Synology SSO (for the setup guide)

1. **In DSM, SSO Server:**
   - Set the server URL under **General Settings**.
   - Turn on **OIDC** under **Service**, and copy the **Well-known URL** ([Synology KB](https://kb.synology.com/en-global/DSM/help/SSOServer/sso_server_service?version=7)).
2. **Under Application:** add an **OIDC** application named "Gogo Desktop" with the redirect URI above. Then open it with **Edit** and copy the **Application ID** and **Application secret** ([Synology KB](https://kb.synology.com/en-global/DSM/help/SSOServer/sso_server_application_list?version=7)).
3. **In Gogo Desktop:**
   - Go to **Settings → Sign-in → Synology SSO**, paste the three values, and choose the username claim and optional groups claim.
   - Click **Test connection**, then turn the method on.
4. **Check it works:** open a private browser window, choose "Sign in with Synology", and sign in with a DSM user who is allowed to use SSO.
5. **Approve yourself:** the test sign-in creates a Pending request. Approve it from **Settings → Users → Pending** while signed in as the Gogo Desktop administrator.
6. **Optional:** set "Gogo Desktop accounts: administrators only", and map DSM groups to libraries (used as suggestions when approving, and applied after approval).

The first administrator account is a Gogo Desktop account, created with a one-time setup code printed in the container log or the Windows service log. **There's no default password.** SSO can be configured only after that.

### 11.3 Web protections (lessons from Google Desktop's port 4664)

| Protection | Rule |
|---|---|
| Sessions | Random 256-bit session ID in a cookie marked `HttpOnly`, `Secure` (HTTPS) and `SameSite=Strict`. Idle timeout 8 h, absolute 7 days, renewed at sign-in |
| CSRF | Every state change needs a per-session token in a header; the server also checks the `Origin` header |
| DNS rebinding | Requests are rejected unless the `Host` header is on the allow-list (`127.0.0.1`, `localhost`, and configured names) |
| Content Security Policy | `default-src 'self'`; no inline scripts; `frame-ancestors 'none'`; email frames use `sandbox` with no scripts |
| Methods | `GET` and `HEAD` never change state. State changes need `POST`/`PUT`/`PATCH`/`DELETE` |
| Destructive actions | Rebuilding the index, deleting a library, or changing security settings need an administrator who re-enters their password (or re-does SSO) within the last 5 minutes, plus a typed confirmation |
| Rate limits | Sign-in attempts and API tokens are rate-limited |
| Headers | `Strict-Transport-Security` (HTTPS), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Input | All query and path input validated. File access only by item ID, **never by a path supplied by the user**, so nobody can request files outside the libraries |
| Audit log | Sign-ins, settings changes, downloads, rebuilds and token use are recorded locally. Search terms aren't logged unless debug logging is on |

### 11.4 Who can see what

| Host | Rule |
|---|---|
| Windows (same-PC sign-in) | Results are filtered by the **user's real Windows file permissions**. The service checks access using the user's identity, so nobody finds names or text of files they couldn't open themselves |
| Windows (LAN accounts) | Library permissions, as on the NAS. Optionally a LAN account can be linked to a Windows account to use real file permissions |
| Synology | Each library lists the users (Gogo Desktop or Synology accounts) and groups allowed to search it. Groups are either DSM groups from SSO group mapping, or groups managed in Gogo Desktop. Results, previews and downloads are filtered by that list. The container reads files as its own read-only user, so **DSM's own share permissions aren't checked automatically**. The administrator sets library permissions to match. A library's permissions default to **administrators only** until set |

Index records carry the library ID, so filtering is done inside the search query and is fast.

### 11.5 Data protection

- Index and settings files are readable only by SYSTEM and administrators (Windows) or the container user (NAS), and optionally encrypted (section 10).
- Extracted text previews live only in the index, never in temporary files outside the data folder.
- Backups of `/data` contain extracted text and must be protected like the original files.

### 11.6 Why no internet exposure

The server holds extracted text of every document, email and drawing it indexes. Even with sign-in and HTTPS, putting it on the internet makes it a valuable target. A VPN keeps the same convenience with far less risk.

---

## 12. Technology choices

| Part | Choice | Reason |
|---|---|---|
| Server language | **Rust** | Speed, memory safety for parsing code, builds for Windows and Linux (amd64/arm64) |
| Web server | `axum` + `tokio`, with `rustls` for HTTPS | Mature, fast, no OpenSSL dependency |
| Web interface | TypeScript single-page app (Vite), bundled into the server | One interface for both hosts; no outside CDN |
| Companion | Rust or C#, using WebView2 for the quick box | Small Windows tray app |
| Full-text engine | Tantivy 0.26.x | Lucene-style engine in Rust, actively maintained |
| Sign-in | `argon2` password hashing; `totp-rs` for second-factor codes; `openidconnect` crate (code flow + PKCE) for Synology SSO | Standard, well-reviewed building blocks |
| HTML cleaning | `ammonia` | Safe HTML cleaning for emails |
| NTFS (Windows) | usn-journal-rs / ntfs-reader | File-table listing and change journal |
| Linux watching | inotify (`notify` crate) + periodic re-check | Works inside Docker on Synology |
| `.msg` | msg_parser | MS-OXMSG reader in Rust |
| `.pst` | outlook-pst (Microsoft, MIT) | Reader based on the published spec, Rust |
| `.ost` | libpff (LGPL-3.0+) | Mature reader with compressed-OST support; builds on Windows and Linux |
| `.dwg`, `.dwt`, `.dws`, `.bak`, binary `.dxf`, `.dxb` | LibreDWG (GPL-3.0), separate tool process | Free; wide version coverage |
| ASCII `.dxf`, `.dwf`, `.dwfx`, `.cuix` | Built-in Rust parsers | No outside dependency |
| `.dgn` V7/V8, `.dgnlib`, `.cel`, `.rdl` | **ODA Drawings SDK** in the `gogo-oda` worker (C++). Linux builds exist for x86_64 and ARM64; ARM64 since ODA 2025.3 ([ODA supported platforms](https://www.opendesign.com/supported-platforms/drawings), [ODA platform policy](https://docs.opendesign.com/page/supported-platform-lifecycle)) | Full DGN V7 and V8 read support on both hosts. DGNLib (MIT) stays as the V7 fallback for builds without ODA |
| `.dwg` (optional switch to ODA) | The same ODA worker can also read DWG/DXF/DXB/DWF ([ODA FAQ](https://www.opendesign.com/faq/product-descriptions)) | Removes the GPL question around LibreDWG. Decision in section 17 |
| Media metadata | nom-exif; ExifTool fallback | Pure Rust for common formats; ExifTool for the long tail (Sony ARW to be confirmed) |
| PDF | pdfium | Accurate text extraction; Windows and Linux builds |
| Container base image | **Ubuntu 22.04 (glibc 2.35)** for the `-oda` image; distroless or Debian slim for the default image | ODA's Linux libraries are built against specific GCC/glibc versions; ARM64 builds list GCC 10.2/11 (glibc up to 2.35), so 22.04 matches both architectures |

---

## 13. Licensing notes

| Library | License | Effect on Gogo Desktop |
|---|---|---|
| Tantivy, axum, msg_parser, outlook-pst, nom-exif, usn-journal-rs, ammonia | MIT / Apache-style | No restrictions beyond notices |
| libpff | LGPL-3.0+ | Fine if dynamically linked or run as a separate process; keep the library replaceable and publish any changes to it |
| LibreDWG | **GPL-3.0** | Run as a **separate tool process** that exchanges plain data with Gogo Desktop, rather than linking it in. Ship its source or offer. **Get legal advice** before selling a closed-source product that bundles it; ODA is the alternative |
| DGNLib | MIT | Notices only (fallback only) |
| **ODA Drawings SDK** | **ODA membership (annual subscription)** | See section 13.1 |
| ExifTool | Perl Artistic / GPL | Run as a separate tool |
| pdfium | BSD-style | Notices only |

### 13.1 ODA membership (needed for DGN)

| Level | First year / renewal | Distribution | Notes |
|---|---|---|---|
| **Commercial** | **US$3,000 / US$2,250** | Up to **100 copies**, counting free and trial copies | Includes DWG and DGN SDKs; **no web/SaaS use** ([ODA membership](https://www.opendesign.com/oda-membership)) |
| **Sustaining** | US$7,500 / US$4,500 | Unlimited | Adds web/SaaS use ([ODA membership](https://www.opendesign.com/oda-membership)) |
| **Founding** | US$37,500 / US$18,000 | Unlimited | Adds source code ([ODA membership](https://www.opendesign.com/oda-membership)) |

- **Web interface and ODA — needs written confirmation from ODA:** Gogo Desktop is web-based, and the Commercial level excludes "Web/SaaS use". Running the server on your own PC or NAS for your own network is not a hosted service, but the wording is broad. **Before choosing Commercial, ask ODA in writing whether a self-hosted, LAN-only web interface counts as web use.** If it does, Sustaining is needed.
- **Personal or in-house use:** ODA's pricing FAQ says a non-commercial membership is possible, but the product can't then be sold ([ODA pricing](https://www.opendesign.com/pricing?language=en)).
- **Giving it away is still distribution:** distributing even for free needs Commercial or higher, and the 100-copy limit includes trial copies ([ODA business FAQ](https://staging.opendesign.com/faq/business-questions)).
- **Subscription:** the licence is a yearly subscription. If it ends, **the right to distribute the ODA-based product ends too**, even for versions built while it was active ([ODA pricing](https://www.opendesign.com/pricing?language=en)).
- **Docker images with ODA:** don't publish a public `-oda` image. ODA libraries are only for members, so each licensee builds the `-oda` image from a Dockerfile that copies in their own ODA files, or receives it privately within their copy limit.
- **Packaging:** the ODA libraries ship only inside the `gogo-oda` worker's folder. The main Gogo Desktop program stays usable without them (DGN then falls back as described in section 5.2).

This is not legal advice. Check licenses again before release.

---

## 14. Delivery plan

| Milestone | Contents | Exit test |
|---|---|---|
| **M1 — Server and web search (names)** (in progress, see `docs/milestones.md`) | Rust server for Windows and Linux; web UI shell; sign-in with Gogo Desktop accounts (roles, TOTP, lockout, emergency administrator) and same-PC Windows sign-in; security headers and CSRF; Windows MFT listing and change journal; NAS directory walk and inotify; name search | Windows: 1M files listed < 10 s and renames visible < 1 s. NAS (Docker on a test DS-series unit): 1M files listed within section 4.3 targets. Security tests in section 16 pass |
| **M2 — Documents** | Worker sandbox on both hosts; text/PDF/Office/ZIP extractors; Tantivy index; previews; timeline | Search a 100k-document test set; p95 < 200 ms on Windows, < 500 ms on nas-small |
| **M3 — Outlook** | `.msg`, `.pst`, `.ost` (item by item, checkpointed, shadow-copy fallback on Windows); mail fields and filters; safe HTML email view | Correct item counts versus Outlook on test stores; Outlook kept running throughout (Windows) |
| **M4a — AutoCAD formats** | `.dwg`/`.dwt`/`.dws` via LibreDWG worker; streaming `.dxf`; binary DXF and `.dxb`; `.dwf`/`.dwfx`; CAD support text files; attribute fields, reference map, thumbnails, published-copy grouping | Text and attributes match AutoCAD's own data extraction on a sample set from R14 to 2018+; Traditional Chinese notes in pre-2007 drawings found; broken xrefs reported correctly |
| **M4b — MicroStation (ODA)** | ODA membership in place; `gogo-oda` worker for Windows and Linux (amd64/arm64); DGN V7/V8, `.dgnlib`, `.cel`, `.rdl`; tags, item types, cells, levels, models, references in the shared reference map | Text, tags and item-type values match MicroStation's own reports on a sample set from V7 to CONNECT Edition; DGN↔DWG references resolved both ways; ≥ 60 typical drawings per minute per worker on Windows |
| **M5 — Photos and media** | EXIF/XMP/RAW (incl. Sony ARW check), video/audio tags, photo filters | Search by camera, lens, date and ISO across a mixed library |
| **M6 — Synology package and Companion** | Multi-arch Docker images; `compose.yaml`; setup guide (user, permissions, inotify task, reverse proxy, SSO); Synology SSO sign-in alongside Gogo Desktop accounts (account linking, **administrator approval of every new Synology user and every link**, pending-request expiry and limits, container settings for SSO and approval, read-only `/config` policy and `/run/secrets`, fail-closed startup checks, NAS command-line approval, tamper-evident audit log, restore review, DSM group mapping if group claims are available, SSO-down behavior); library permissions; Companion (hotkey, quick box, open on this PC, pairing) | Fresh install on an x86 and an ARM64 Synology from the guide in < 30 minutes; SSO and Gogo Desktop sign-in both work, and administration still works with the SSO Server stopped; opening a NAS result from a PC opens the file over SMB |
| **M7 — Polish** | Settings lock (ADMX and `policy.yaml`), encryption at rest, audit log, installer, crash reports **saved locally only** | Security checklist (section 11) passes, including an outside review of the web layer |

---

## 15. Later (not v1)

- **One search across several servers:** for example, search the PC and the NAS from one box.
- **Search by meaning:** semantic search using a small local embedding model, still fully offline.
- OCR for scanned PDFs and images (Tesseract or Windows OCR).
- Native Synology package (`.spk`) instead of Docker, if demand justifies it.
- Reading DSM share permissions automatically instead of setting library permissions by hand.
- Optional email to administrators about pending Synology users, through a mail server on your own network.
- macOS host support.
- New Outlook offline data, if Microsoft documents it.

---

## 16. Test and acceptance plan

- **Test sets:**
  - a 1M-file synthetic volume (NTFS) and a 1M-file Btrfs share on a Synology test unit
  - real Office/PDF documents
  - `.msg` samples covering mail, meeting, contact and task
  - OST files from classic Outlook (compressed 4 KB-page format)
  - PST files of ANSI and Unicode types
  - DWG files from R14, 2000, 2004, 2007, 2010, 2013 and 2018 formats, including drawings with Chinese text, many xrefs and large title blocks
  - matching DXF (ASCII and binary), DWF, DWFx and DXB files
  - DGN samples from V7, V8 2004, V8 XM, V8i and CONNECT Edition; `.dgnlib`, `.cel` and `.rdl` files; drawings with tags, item types, tables, Big5 fonts, and references to both DGN and DWG files
  - photos from Sony (ARW + JPEG), iPhone (HEIC), Android, and video files
- **Hosts:** Windows 11 (x86_64); Synology on one Intel/AMD and one ARM64 model, each at the lowest supported memory.
- **Accuracy:** for each format, count items found against the source application, such as Outlook item counts and AutoCAD/MicroStation reports.
- **Robustness:** feed deliberately broken files (fuzzing) to each extractor, which must not crash the server. Pull the NAS power during indexing and check that the index recovers.
- **Performance:** benchmarks for listing, indexing rate (items/min per format) and query latency, per host and profile.
- **Web security tests:**
  - CSRF: a page on another site can't change settings or start a rebuild.
  - DNS rebinding: requests with a foreign `Host` header are rejected.
  - No state change happens through `GET`, checked for every endpoint automatically.
  - Session cookies have the right flags; sessions expire.
  - Users without permission get "not found" for items, previews and downloads (no difference in timing or error text).
  - Path tricks (`..`, absolute paths, symbolic links out of a library) can't reach files outside the libraries.
  - HTML emails can't run scripts or load remote content.
  - Companion open requests can't be replayed or forged.
  - **Sign-in:**
    - A Synology user and a Gogo Desktop user with the same name stay separate unless linked deliberately.
    - ID tokens with the wrong issuer, audience, `nonce` or signature, or expired, are rejected.
    - A replayed or changed `state` is rejected.
    - The last Gogo Desktop administrator can't be removed.
    - With "administrators only", non-admin Gogo Desktop accounts can't sign in.
    - A user disabled in DSM can't sign in again.
    - A Pending or Rejected Synology user gets no search results, library names, file counts, previews or downloads, through the web page or the API.
    - DSM group mapping never approves an account or grants the administrator role before approval.
    - Linking a Synology sign-in to an existing account stays inactive until approved.
    - An administrator can't approve their own Synology identity.
    - The 51st pending request is refused; requests expire after 30 days.
  - **Container configuration:**
    - The container refuses to start with any variable or policy that tries to turn off approval, an unknown policy key, an out-of-range value, or a writable `/config`.
    - SSO stays off with a non-HTTPS `GOGO_PUBLIC_URL` or a world-readable secret file.
    - The SSO secret never appears in `docker inspect`, logs, settings export or the status page.
    - Command-line approvals follow the same rules and appear in the audit log.
    - `gogo audit verify` detects an edited or deleted audit record.
    - Restoring an older `/data` backup ends all sessions and puts every Synology account into Review.
    - Risky actions require a fresh sign-in by either method.
  - Windows default mode opens no port other than `127.0.0.1:4680`; the container opens only `4681`.
  - An automated scan (for example OWASP ZAP) shows no high-risk findings.

---

## 17. Open questions

1. **"Digital" files:** confirm that this means digital photos and media, or name the exact file types.
2. **ODA level and web use:** ask ODA whether a self-hosted, LAN-only web interface is allowed at the Commercial level, or whether Sustaining (US$7,500 first year) is needed.
3. **Use ODA for DWG as well?** One engine for DWG and DGN would remove the LibreDWG GPL question and simplify testing. LibreDWG would then be kept only as a fallback, or dropped.
4. **Your NAS model and memory:** this sets the default profile (nas-small or nas-large), the architecture to test first, and whether DGN/DWG indexing is practical on it.
5. **Which host first:** Windows or Synology? The other follows in the same release, but one is tested first.
6. **Synology SSO certificate** (sign-in decided: both methods, with administrator approval for every new Synology user). Do you have a domain name and valid certificate for SSO Server?
7. **Companion:** needed in v1, or is the web page alone enough at first?
8. **CAD content depth:** is text, attributes and metadata enough, or do you need text that exists only as geometry in DWF sheets? That would need a W2D decoder.
9. **Distribution:** personal use only, or a product for others (affects licensing and code signing)?
10. **Outlook:** is classic Outlook (OST) the main client, or do you also need new Outlook? New Outlook would need `.pst` export.
11. **Index size budget:** roughly 10–20% of the indexed text size, on `%ProgramData%\GogoDesktop` or `/volume1/docker/gogo-desktop`. Is that acceptable?
