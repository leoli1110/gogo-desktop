# Install on Windows

Gogo Desktop runs as a Windows service and is used from your browser at
<http://127.0.0.1:4680>. By default it only listens on this PC.

Requirements: Windows 10 or 11 (64-bit), or Windows Server 2019 or later.
Administrator rights are needed to install the service. Fast listing and live
updates need NTFS drives; other drives (exFAT, FAT32, network drives) work with
a folder walk and change notifications instead.

## 1. Get `gogo.exe`

There is no installer yet (planned for milestone M7). Either:

- download the `gogo-windows-x64` artifact from the latest successful
  [CI run](../.github/workflows/ci.yml) (Actions tab on GitHub), or
- build it yourself: see [development.md](development.md).

Copy `gogo.exe` to `C:\Program Files\Gogo Desktop\`.

## 2. Install the service

Open **PowerShell as administrator**:

```powershell
cd "C:\Program Files\Gogo Desktop"
.\gogo.exe service install
```

This creates and starts the **Gogo Desktop** service (automatic start,
LocalSystem account, which is needed to read the NTFS change journal).

The data folder `%ProgramData%\GogoDesktop` is created and restricted to
SYSTEM and Administrators. The log is at `%ProgramData%\GogoDesktop\logs\gogo.log`.

## 3. Create the administrator

The first time, Gogo Desktop has no administrator. It saves a one-time setup
code in the data folder. In the administrator PowerShell window:

```powershell
Get-Content "$env:ProgramData\GogoDesktop\setup-code.txt"
```

Open <http://127.0.0.1:4680/setup>, enter the code, and choose a username and
password (at least 12 characters). The setup code stops working once the
administrator exists, and the file is deleted.

## 4. Add libraries

A library is a folder that Gogo Desktop indexes. Go to **Libraries**, then
**Add a library**:

- **Name**: shown to users, for example `Projects`.
- **Folder path**: for example `D:\Projects`.
- **Path shown to users** (optional): what users copy, for example
  `\\FILESERVER\Projects` when the folder is also shared on the network.

New libraries are visible to **administrators only**. Under **Who can search**,
tick **All signed-in users** or choose people, then **Save**.

The **Status** page shows each library's state and how it's being watched
(`ntfs-journal` for NTFS drives).

## 5. Sign in as yourself (same PC)

Any user signed in to this PC can open a Command Prompt and run:

```cmd
"C:\Program Files\Gogo Desktop\gogo.exe" signin
```

The browser opens and signs in with your Windows account. The link works once,
within 60 seconds. Windows accounts start as **users** with no libraries until
an administrator grants access on the Libraries page.

> **M1 limitation:** results are filtered by library access lists only.
> Windows file permissions (NTFS ACLs) are applied from milestone M2, so only
> grant a library to people who may see every file name in it.

## Other Gogo Desktop accounts

Administrators can create Gogo Desktop accounts (username and password) on the
**Users** page, for people who don't sign in to this PC.

## Settings

The service reads `GOGO_*` settings from **system** environment variables. For
example, to also register a library from configuration:

```powershell
[Environment]::SetEnvironmentVariable("GOGO_LIBRARIES", "Projects=D:\Projects;Docs=C:\Users\Public\Documents", "Machine")
Restart-Service GogoDesktop
```

All settings are in [configuration.md](configuration.md). Opening Gogo Desktop
to the local network (HTTPS on port 4681) is possible with `GOGO_HTTPS_BIND`,
and then a sign-in code app is required for administrators.

## Emergency access

If every administrator is locked out, in an administrator PowerShell window:

```powershell
& "C:\Program Files\Gogo Desktop\gogo.exe" admin reset
```

Open <http://127.0.0.1:4680/recover>, enter the code, the administrator's
username and a new password. This also clears that administrator's sign-in
code app and lockout, and signs out their sessions.

## Uninstall

```powershell
& "C:\Program Files\Gogo Desktop\gogo.exe" service uninstall
```

The data folder is kept. Delete `%ProgramData%\GogoDesktop` to remove accounts
and the audit log as well.
