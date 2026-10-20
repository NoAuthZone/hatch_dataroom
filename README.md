<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="hatch_dataroom-wordmark.svg">
    <img src="hatch_dataroom-wordmark-light.svg" alt="hatch_dataroom" width="420">
  </picture>
</p>

# hatch_dataroom

**Version 1.0.0** · [github.com/NoAuthZone/hatch_dataroom](https://github.com/NoAuthZone/hatch_dataroom/)

A small encrypted file-exchange server for moving files between machines (for example macOS ⇄ Windows) over HTTPS (encrypted, no SMB).

- Single file: `hatch_dataroom.py`, Python 3 standard library only, no third-party code
- HTTPS with a self-signed certificate (TLS 1.2+), password only (no user name)
- **Local network only by default**, everyone else is refused before the TLS handshake
- A **fresh folder per start**, named `hatch-YYYYMMDD-HHMMSS`
- Dark web UI: login page, **Log out**, drag-and-drop upload with progress, folder upload
- **Rename, delete, new folder** with confirmation dialogs
- **ZIP download** of a folder or of selected items
- **SHA-256** for every file (list, upload response, `?sha256`)
- **Auto-shutdown** (`--idle-minutes`, `--once`), **audit log**, **QR code** in the terminal
- Default port **9001**, password **generated automatically** at every start
- **Protections on by default:** executable upload types blocked, connection and request limits, hidden files and the server's own key/certificate/log never served (optional: `--read-only`)

## Get it

```bash
git clone https://github.com/NoAuthZone/hatch_dataroom.git
cd hatch_dataroom
python3 hatch_dataroom.py --version     # hatch_dataroom 1.0.0
```

Or download `hatch_dataroom.py` alone; it is a single file with no dependencies.

## Requirements

- Python 3.8 or newer
- `openssl` on the PATH (preinstalled on macOS; on Windows it ships with Git for Windows), **or** `pip install cryptography` as a fallback. Only needed for the first start, when the certificate is generated.

## Quick start

On the machine that holds the files:

```bash
python3 hatch_dataroom.py          # Windows: python hatch_dataroom.py
```

```
     ________
    /   o    \     hatch_dataroom v1.0.0
   /__________\    encrypted file exchange
   | .  ===== |    https://github.com/NoAuthZone/hatch_dataroom/
   | .  ===   |
   | .  ====  |
   '----------'

Folder:   /path/to/hatch-20261020-143005
          new folder for this start; kept if it contains files, use --dir to reuse a folder
Address:  https://192.168.1.20:9001/
Password: gVXie-Br7Xi-MFiF6-nz4ef   (generated, new on every start)
Access:   local network only + this machine
          allowed: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
          everyone else is refused; change with --allow NET, open to all with --allow any
SHA-256:  05:E9:3E:...
          (compare it with the browser warning, don't just click through)
Options:  log /path/to/hatch.log

Scan to open on your phone:
<QR code>

Stop with Ctrl+C
```

The terminal tells you where the files go, the password, who may connect, and the certificate fingerprint. On first start the script also creates `cert.pem` and `key.pem` next to it.

## Data folder

Every start creates a new folder `hatch-YYYYMMDD-HHMMSS` (for example `hatch-20261020-143005`) next to the script, so each session is separate and easy to archive.

- If the folder is **still empty** when the server stops, it is removed again.
- If it **contains files**, it is kept and its path is printed on exit.
- `--dir FOLDER` uses a fixed folder instead (created if needed, never removed). Use this to keep working in the same data room.

## Network access

By default only the **local network** can connect: private address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`) and the IPv6 equivalents, plus this machine itself. If the machine's own address is neither private nor public (for example a `100.64.x.x` VPN network), its own `/24` is added. Everything else is closed before any TLS handshake and logged as `DENIED`.

| Option | Effect |
|---|---|
| *(nothing)* | Local network only |
| `--allow 192.168.1.0/24` | Only this subnet (repeatable or comma separated, single IPs work too) |
| `--allow any` | Everyone who can reach the machine. The terminal shows a red warning. |

The terminal also warns if this machine's own address is public.

## Password

| How | When to use |
|---|---|
| Generated automatically (default) | Normal use. 20 random characters, printed once at startup, new on every start. |
| `--prompt` | You want to type your own password. |
| `TRANSFER_PASSWORD` environment variable | Scripts or a fixed password. Takes priority over the other two. |

A custom password must have at least 8 characters.

## Using it

**Browser:** open the address, enter the password, then:

- **Upload:** drop files on the page, or use *choose files* / *choose folder*. Each file shows a progress bar and its SHA-256 when done.
- **Download:** click a file name.
- **Rename / Delete:** buttons on each row, both ask for confirmation. Deleting a folder removes everything inside it and cannot be undone.
- **New folder:** button above the list.
- **ZIP:** tick rows and use *Download selected as ZIP*, click *ZIP* on a folder row, or *This folder as ZIP*. Hidden files (names starting with `.`) and symlinks are left out.
- **Checksum:** the full 64-character SHA-256 appears under each file name after the page loads. Click it to copy.
- **Sort:** click *Name*, *Size* or *Modified* in the table header (click again to reverse). Folders always stay on top.
- **Log out** (top right) ends the session immediately. Sessions also expire after 8 hours without activity (`--session-hours`).

The browser warns about the self-signed certificate. Compare the SHA-256 fingerprint in the warning with the one printed by the server before accepting.

**Command line** (HTTP Basic auth; the user name is ignored, so leave it empty):

```bash
# upload (response contains the SHA-256)
curl --cacert cert.pem -u :PASSWORD -T file.zip https://<ip>:9001/file.zip

# download
curl --cacert cert.pem -u :PASSWORD -O https://<ip>:9001/file.zip

# checksum of a file on the server
curl --cacert cert.pem -u :PASSWORD "https://<ip>:9001/file.zip?sha256"

# folder (or whole data room) as ZIP, or selected items
curl --cacert cert.pem -u :PASSWORD -o docs.zip "https://<ip>:9001/docs/?zip"
curl --cacert cert.pem -u :PASSWORD -o some.zip "https://<ip>:9001/?zip=a.txt&zip=docs"
```

Windows PowerShell: use `curl.exe` instead of `curl`. Copy `cert.pem` (the **certificate only, never `key.pem`**) to the client once; with `--cacert` the connection is verified properly, `-k` skips verification and should be a last resort.

**Verify a transferred file locally:**

```bash
shasum -a 256 file.zip                  # macOS
sha256sum file.zip                      # Linux
certutil -hashfile file.zip SHA256      # Windows
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--dir FOLDER` | new `hatch-YYYYMMDD-HHMMSS` per start | Data room folder |
| `--port PORT` | `9001` | Port |
| `--bind ADDRESS` | `0.0.0.0` | Listen address (`127.0.0.1` = this machine only) |
| `--allow NET` | local network only | Allowed IPs/subnets, or `any` (see above) |
| `--idle-minutes N` | off | Stop automatically after N minutes without activity |
| `--once` | off | Stop after the first completed transfer, once things have been quiet for 10 seconds (so a multi-file upload can finish) |
| `--prompt` | off | Ask for the password instead of generating one |
| `--max-mb N` | `2048` | Maximum upload size in MB |
| `--read-only` | off | Downloads only: no upload, rename, delete or new folder (buttons are hidden, the server answers 403) |
| `--block-ext LIST` | `exe,msi,bat,cmd,com,scr,pif,ps1,vbs,vbe,wsf,hta,jar,dll,lnk` | Upload/rename to these file types is refused (HTTP 415). Comma separated, case-insensitive. `--block-ext none` turns it off. |
| `--max-conn N` | `20` | Open connections per client address (`0` = no limit). Extra connections are closed before TLS. |
| `--rate N` | `30` | Requests per second per client address after a burst of 100 (`0` = no limit). Extra requests get HTTP 429. |
| `--session-hours N` | `8` | Browser session lifetime (sliding) |
| `--log FILE` | `./hatch.log` | Audit log file |
| `--no-log` | off | Disable the audit log file |
| `--no-qr` | off | Do not print the QR code |
| `--new-cert` | off | Regenerate the certificate |
| `--version` | | Print the version and the project URL |

Examples:

```bash
# default: local network only, new folder, stop when done
python3 hatch_dataroom.py --once

# only my subnet, leave it running but not forever
python3 hatch_dataroom.py --allow 192.168.1.0/24 --idle-minutes 15

# keep using the same folder
python3 hatch_dataroom.py --dir ~/Transfer

# download-only share
python3 hatch_dataroom.py --read-only --once

# allow everything to be uploaded (tools, scripts)
python3 hatch_dataroom.py --block-ext none
```

Stopping with Ctrl+C, `kill` (SIGTERM) or by closing the terminal all shut down cleanly, including the empty-folder cleanup.

## Audit log

Every file operation and login event is appended to `hatch.log` (also shown in the terminal), one line each:

```
2026-10-20T14:03:11+02:00 192.168.1.5 UPLOAD docs/a.zip 10485760 bytes sha256=ab12...
2026-10-20T14:03:40+02:00 192.168.1.5 DOWNLOAD docs/a.zip 10485760 bytes
2026-10-20T14:04:02+02:00 192.168.1.5 RENAME docs/a.zip -> docs/b.zip
```

Actions: `START`, `STOP`, `LOGIN_OK`, `LOGIN_FAIL`, `LOCKED`, `LOGOUT`, `UPLOAD`, `DOWNLOAD`, `ZIP`, `MKDIR`, `RENAME`, `DELETE`, `DENIED`, `BLOCKED` (refused file type), `LIMIT` (connection or rate limit hit). Passwords are never logged, and file names are sanitized so they cannot forge log lines. The log file is created with mode 600 and is shared by all sessions.

## Security notes

- Traffic is encrypted with TLS 1.2 or newer. The certificate is self-signed and contains the server IP as a SAN, so it is only valid for the IP it was created for. **IP changed?** Run once with `--new-cert` and copy the new `cert.pem` to the clients.
- Access is limited to the local network by default (see above). This is an extra layer, not a replacement for the password or a firewall.
- Browser sessions use a cookie that is `HttpOnly`, `Secure` and `SameSite=Strict`, kept only in server memory (a restart logs everyone out). Rename, delete and new-folder requests additionally need a custom header, which other websites cannot send.
- `curl -u` sends the password with every request and has no session, so there is nothing to log out of.
- **Brute-force protection:** after 5 failed logins an IP is locked for 60 seconds (HTTP 429), which also blocks the correct password during the lock.
- Only files inside the data room folder are reachable. Path traversal (`../`, encoded variants) is rejected, and symlinks that point outside the folder are refused and never included in ZIPs.
- Uploads are written to a temporary file and renamed when complete, so aborted uploads leave no partial files. A file with the same name is overwritten.
- Responses carry strict security headers (CSP, `X-Frame-Options: DENY`, `nosniff`, no referrer). Names are HTML-escaped everywhere.
- The generated password is shown in the terminal and may remain in scrollback. Passwords on the command line (`-u :PASSWORD`) end up in shell history and the process list; for regular use prefer a `curl` config file.
- **The server's own files are protected.** `key.pem`, `cert.pem` and the log are never served. If one of them lies inside the shared folder (for example `--dir .` next to the script), the server **refuses to start** and says why. Use a separate folder for `--dir`.
- **Hidden files** (names starting with `.`, such as `.htaccess`, `.env`, `.git/`) are not listed, not zipped, cannot be downloaded or uploaded, and any path containing one is rejected.
- **File-type block:** uploads and renames to executable/script types (`.exe`, `.msi`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.jar`, `.dll`, `.lnk`, ...) are refused by default. This checks the last extension and ignores trailing dots/spaces. It is a name filter, not a malware scan. Change with `--block-ext`, disable with `--block-ext none` (for example when you really need to move a tool).
- **Read-only mode** (`--read-only`) turns the data room into a download-only share. It is opt-in, because the tool exists to move files in both directions.
- **Limits:** at most 20 simultaneous connections and 30 requests/s (burst 100) per client address, 200 connections in total. Hitting a limit is logged as `LIMIT` (once per minute per address). Idle clients are dropped after 30 seconds.
- `key.pem` is the private key. Keep it private and do not put it in a synced or shared folder; never copy it to clients (only `cert.pem`).
- Do not expose it directly to the internet.
- Windows: allow Python through the firewall for the private network on first start.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Could not generate a certificate` | Install `openssl` or run `pip install cryptography`, then start again |
| `Cannot listen on ...` | Port 9001 is in use; pick another with `--port` |
| Certificate error in curl | Use `--cacert cert.pem`; after an IP change run `--new-cert` and copy the new `cert.pem` |
| Cannot connect from a device | Check IP, port and firewall. The device must be in the local network, otherwise add it with `--allow`. Refused attempts show up as `DENIED` in the terminal. |
| QR code looks garbled or is missing | The terminal must support ANSI colors and Unicode block characters; use `--no-qr` otherwise. It is only printed in an interactive terminal. |
| Password lost | Stop the server and start it again; a new one is generated |
| Folder disappeared | An empty auto-named folder is removed on exit; use `--dir` for a fixed folder |
| `413 File too large` | Raise `--max-mb` |
| `415 This file type is not allowed` | The type is on the block list; use `--block-ext none` or a custom list, or zip the file first |
| `Refusing to start: the private key ... is inside the shared folder` | Pick a `--dir` that does not contain the script, `key.pem`, `cert.pem` or the log |
| `403 Read-only mode` | The server was started with `--read-only` |
| `429 Too many requests` | Slow down, or raise `--rate` / `--max-conn` |
| `429 Too many failed attempts` | Wait 60 seconds |
| `401` | Wrong password, or the session expired |

## Typical workflow (re-setup every few weeks)

Keep `hatch_dataroom.py`, `cert.pem` and `key.pem` together in a safe place. After setting up a machine, start the server (`--once` is handy), note the printed password, transfer the files, check the SHA-256 if you like, log out, and let it stop on its own. Because the certificate is reused, the fingerprint stays the same; only the password and the folder change.


## Version

Current version: **1.0.0** (`__version__` in `hatch_dataroom.py`, shown in the terminal banner, in the web UI footer and by `--version`). The HTTP server header deliberately does not reveal the version. Releases, issues and updates: <https://github.com/NoAuthZone/hatch_dataroom/>
