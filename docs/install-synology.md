# Install on a Synology NAS

Gogo Desktop runs as a Docker container through **Container Manager** (DSM 7.2
or later). Container Manager can run multi-container "projects" from a
`compose.yaml` file ([Synology Container Manager release notes](https://www.synology.com/en-global/releaseNote/ContainerManager)).

Images are published for `amd64` (Intel/AMD models) and `arm64` (for example
Realtek RTD1619B models). Check your model's processor before you start.

## 1. Create a DSM user for Gogo Desktop

Control Panel > **User & Group** > Create:

- Name: `gogo`. Give it a long random password; nobody signs in with it.
- Groups: `users` only (not `administrators`).
- Shared folder permissions: **Read only** on each folder you want to search.
  No access to anything else.
- Applications: deny all.

Find its user ID (SSH, as an administrator):

```sh
id gogo        # for example: uid=1030(gogo) gid=100(users)
```

## 2. Create the folders

```sh
sudo mkdir -p /volume1/docker/gogo-desktop/data /volume1/docker/gogo-desktop/config
sudo chown -R gogo:users /volume1/docker/gogo-desktop/data
sudo chmod 700 /volume1/docker/gogo-desktop/data
```

`config` stays owned by an administrator. It is mounted read-only; Gogo
Desktop refuses to start if it can write there. Put `policy.yaml` in it if you
want to lock settings (see [configuration.md](configuration.md)).

## 3. Raise the inotify watch limit

Gogo Desktop needs one inotify watch per folder to see changes immediately.
DSM's default limit is low. Add a boot-time task: Control Panel > **Task
Scheduler** > Create > Triggered Task > User-defined script, user `root`,
event **Boot-up**:

```sh
echo 524288 > /proc/sys/fs/inotify/max_user_watches
echo 1024 > /proc/sys/fs/inotify/max_user_instances
```

Run it once now. This approach is the one commonly used for Synology
([Syncovery guide](https://www.syncovery.com/documentation/raising-inotify-limits/),
[Syncthing forum](https://forum.syncthing.net/t/partial-success-on-increasing-inotify-limits-on-synology-nas/20677)).
If the limit is still too low, Gogo Desktop keeps working with scheduled
re-checks and shows a warning on the Status page.

## 4. Create the project

Container Manager > **Project** > Create. Path: `/volume1/docker/gogo-desktop`.
Use [`docker/compose.yaml`](../docker/compose.yaml) and change:

- `user:` to the IDs from step 1, for example `"1030:100"`.
- the `/libraries/...` lines: one per shared folder, always `:ro`.
- `GOGO_PUBLIC_URL` and `GOGO_ALLOWED_HOSTS` to the names you'll type in the
  browser (NAS name, IP address, or reverse-proxy name).

Each folder mounted under `/libraries/<Name>` becomes a library called `<Name>`.

## 5. Create the administrator

Open Container Manager > **Container** > `gogo-desktop` > **Log** and find:

```
==================== Gogo Desktop setup ====================
...
    XXXX-XXXX-XXXX
```

Open `https://<nas>:4681/setup`. The browser warns about the self-signed
certificate; the log shows its SHA-256 fingerprint so you can check it before
continuing. Enter the setup code, a username and a password, then scan the QR
code with an authenticator app. Administrators on a NAS always need a sign-in
code app because the server is reachable from the network.

Then go to **Libraries** and choose who can search each one. New libraries are
visible to administrators only.

## 6. Optional: a proper address with the DSM reverse proxy

Control Panel > **Login Portal** > Advanced > **Reverse Proxy** > Create:

- Source: HTTPS, host `search.<your-domain>`, port 443, HSTS on. Use a DSM
  certificate for that name (for example Let's Encrypt).
- Destination: HTTP, `localhost`, port `4680`.

Then change the project:

```yaml
    ports:
      - "127.0.0.1:4680:4680"     # only the reverse proxy can reach it
    environment:
      GOGO_HTTP_BIND: "0.0.0.0:4680"
      GOGO_HTTPS_BIND: "off"
      GOGO_TRUST_PROXY: "true"
      GOGO_PUBLIC_URL: "https://search.<your-domain>"
      GOGO_ALLOWED_HOSTS: "search.<your-domain>"
```

Gogo Desktop refuses plain HTTP on a network address unless
`GOGO_TRUST_PROXY=true`, and only then trusts `X-Forwarded-For` and
`X-Forwarded-Proto`. Don't publish port 4680 on the LAN.

## Commands on the NAS

```sh
sudo docker exec gogo-desktop gogo users list
sudo docker exec gogo-desktop gogo audit verify
sudo docker exec gogo-desktop gogo audit tail -n 50 --type auth.
sudo docker exec gogo-desktop gogo admin reset      # emergency reset code, then open /recover
```

## Synology sign-in (SSO)

Signing in with DSM accounts through Synology SSO Server, with administrator
approval of every new user, is planned for milestone M6 (see
[milestones.md](milestones.md) and section 11.2 of the
[specification](specification.md)). SSO Server supports OpenID Connect
([Synology SSO Server specifications](https://www.synology.com/en-global/dsm/7.4/software_spec/sso_server),
[SSO Server help](https://kb.synology.com/en-global/DSM/help/SSOServer/sso_server_service?version=7)).
Settings that would switch approval off are already refused today.

## Backups

With Hyper Backup, back up `/volume1/docker/gogo-desktop/data/db`,
`data/audit` and `config`. The name index is rebuilt from the files at start.

## Updating

Container Manager > Project > `gogo-desktop` > Action > **Build** (pulls the
new image). Accounts and settings are kept in `/data`.
