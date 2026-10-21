#!/usr/bin/env python3
"""
hatch_dataroom - encrypted file exchange over HTTPS, Python standard library only.
Runs on macOS, Windows and Linux.

Version:  1.2.0
Project:  https://github.com/NoAuthZone/hatch_dataroom/

Start:    python3 hatch_dataroom.py
          A random password is generated and printed at startup.

Options:  --dir FOLDER         Data room folder. Default: a new folder hatch-YYYYMMDD-HHMMSS next to
                               this script for every start (removed again if it stays empty)
          --port PORT          Default 9001
          --bind ADDRESS       Default 0.0.0.0
          --allow NET          Only accept clients from this IP/subnet, e.g. 192.168.1.0/24
                               (repeatable or comma separated; this machine is always allowed).
                               Default: local network only (private ranges, see LOCAL_NETS).
                               Use --allow any to accept every address.
                               Without --allow, an interactive start asks for the other machine's IP
                               (Enter = whole local network); --no-ask skips that question.
          --no-ask             Do not ask for the client IP at startup
          --tls12              Also allow TLS 1.2 (default: TLS 1.3 only, if this Python supports it)
          --on-conflict MODE   Upload to an existing name: rename (default, "name (2).ext"),
                               fail (HTTP 409) or overwrite
          --idle-minutes N     Stop automatically after N minutes without activity (default 30, 0 = off)
          --once               Stop after the first completed transfer (once things go quiet)
          --read-only          Downloads only: no upload, rename, delete or new folder
          --block-ext LIST     Refuse these upload types (default: exe,msi,bat,cmd,ps1,...; 'none' = off)
          --max-conn N         Open connections per client address (default 20, 0 = off)
          --rate N             Requests per second per client address (default 30, 0 = off)
          --prompt             Ask for the password instead of generating one
          --max-mb N           Maximum upload size in MB (default 2048)
          --session-hours N    Browser session lifetime in hours (default 8)
          --log FILE           Audit log (default: ./hatch.log), --no-log to disable
          --no-qr              Do not print the QR code
          --new-cert           Regenerate the certificate (e.g. after an IP change)
Password: generated at startup, or taken from TRANSFER_PASSWORD, or asked with --prompt.

Usage:
  Browser:  https://IP:9001   (password only; upload, download, rename, delete, ZIP)
  Upload:   curl --cacert cert.pem -u :PW -T file.zip https://IP:9001/file.zip
  Download: curl --cacert cert.pem -u :PW -O https://IP:9001/file.zip
  Checksum: curl --cacert cert.pem -u :PW "https://IP:9001/file.zip?sha256"
There is no user name; with curl leave it empty (-u :PW). Any name sent is ignored.
"""
import argparse
import base64
import datetime
import functools
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = "hatch_dataroom"
__version__ = "1.2.0"
REPO = "https://github.com/NoAuthZone/hatch_dataroom/"
HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")
TMP_PREFIX = ".upload-"
CHUNK = 1024 * 1024
DEFAULT_PORT = 9001
ONCE_GRACE = 10          # seconds of quiet after the first transfer before --once stops the server
MAX_FAILS, LOCK_SECONDS = 5, 60
LOCK_MAX = 3600          # the lockout doubles with every repeated lockout (60s, 120s, 240s, ...) up to this
LEVEL_DECAY = 3600       # seconds without failed logins until an address starts again at the first level
DEFAULT_IDLE_MINUTES = 30
# Upload types refused by default (executables, scripts, installers, macro documents, shortcut/link files that can
# trigger network connections when a folder is opened); change with --block-ext, turn off with --block-ext none
DEFAULT_BLOCK_EXT = (
    "exe,msi,msp,mst,bat,cmd,com,scr,pif,cpl,msc,gadget,"
    "ps1,psm1,psd1,ps1xml,vbs,vbe,js,jse,wsf,wsh,wsc,sct,hta,jar,jnlp,dll,inf,reg,"
    "lnk,url,scf,library-ms,searchconnector-ms,chm,msix,msixbundle,appx,appxbundle,iso,"
    "docm,dotm,xlsm,xlam,pptm,sh,bash,command,app,dmg,pkg")
# "Local network": private address ranges (RFC 1918), link-local, and IPv6 unique-local/link-local.
LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"]

CFG = {}                 # filled in main()
FAILS = {}               # ip -> (failed attempts, locked until, lockout level, time of last failure)
SESSIONS = {}            # session id -> expiry timestamp
HASHES = {}              # (path, mtime_ns, size) -> sha256 hex
STATE = {"last": time.time(), "active": 0, "transfers": 0}
SLOCK = threading.Lock()
LOGLOCK = threading.Lock()
DENIED_SEEN = {}         # ip -> last time a DENIED line was logged
CONNS = {}               # ip -> open connections
CONN_OF = {}             # id(socket) -> ip (so a closed connection can be counted down)
RATE = {}                # ip -> [tokens, last refill time]
LIMIT_SEEN = {}          # (kind, ip) -> last time a LIMIT line was logged
CLOCK = threading.Lock()
TLS_SEEN = {}            # ip -> last time a TLS_FAIL line was logged
TOTAL_CONN_MAX = 200     # hard cap on simultaneous connections from everybody
RATE_BURST = 100         # requests an IP may send in a burst before --rate applies

# No look-alike characters (I, O, l, 0, 1)
PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def generate_password(groups=4, size=5):
    return "-".join("".join(secrets.choice(PW_ALPHABET) for _ in range(size)) for _ in range(groups))


# ------------------------------------------------------------------ Audit log
def clean(s):
    return "".join(ch if ch.isprintable() else "?" for ch in str(s))


def audit(ip, action, detail="", console=True):
    now = datetime.datetime.now().astimezone()
    line = f"{now.isoformat(timespec='seconds')} {ip} {action} {clean(detail)}".rstrip()
    with LOGLOCK:
        path = CFG.get("log")
        if path:
            try:
                new = not os.path.exists(path)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                if new:
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
            except OSError:
                pass
        if console:
            print(f"{now:%H:%M:%S}  {ip:<15} {action:<9} {clean(detail)}", flush=True)


# ---------------------------------------------------------------- Certificate
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _cert_openssl(ip):
    exe = shutil.which("openssl")
    if not exe:
        return False
    r = subprocess.run(
        [exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-pkeyopt", "ec_param_enc:named_curve",  # some openssl/LibreSSL builds write explicit EC parameters, which browsers reject
         "-nodes", "-keyout", KEY, "-out", CERT, "-days", "397", "-subj", "/CN=hatch_dataroom",
         "-addext", f"subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost",
         "-addext", "extendedKeyUsage=serverAuth",
         "-addext", "keyUsage=digitalSignature"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0 and os.path.exists(CERT) and os.path.exists(KEY)


def _cert_cryptography(ip):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        print("openssl not found and 'cryptography' is not installed -> pip install cryptography")
        return False
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, APP)])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.ip_address(ip)),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.DNSName("localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(san, critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return True


def ensure_cert(ip, force):
    if os.path.exists(CERT) and os.path.exists(KEY) and not force:
        return
    print(f"Generating self-signed certificate for {ip} (397 days) ...")
    if not (_cert_openssl(ip) or _cert_cryptography(ip)):
        sys.exit("Could not generate a certificate.")
    try:
        os.chmod(KEY, 0o600)
    except OSError:
        pass


def fingerprint():
    with open(CERT, "r") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# --------------------------------------------------------- QR code (terminal)
def qr_matrix(text):
    """Minimal QR encoder: byte mode, error correction L, versions 1-5 (up to 106 bytes)."""
    data = text.encode("utf-8")
    versions = {1: (19, 7), 2: (34, 10), 3: (55, 15), 4: (80, 20), 5: (108, 26)}  # data cw, ec cw
    for ver, (dcw, ecw) in versions.items():
        if len(data) <= dcw - 2:
            break
    else:
        return None

    bits = []

    def put(val, n):
        bits.extend((val >> i) & 1 for i in range(n - 1, -1, -1))

    put(0b0100, 4)
    put(len(data), 8)
    for b in data:
        put(b, 8)
    put(0, min(4, dcw * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    pad, i = (0xEC, 0x11), 0
    while len(bits) < dcw * 8:
        put(pad[i % 2], 8)
        i += 1
    cw = [int("".join(map(str, bits[k:k + 8])), 2) for k in range(0, len(bits), 8)]

    # Reed-Solomon over GF(256), primitive polynomial 0x11D
    exp, log, x = [0] * 512, [0] * 256, 1
    for k in range(255):
        exp[k], log[x] = x, k
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for k in range(255, 512):
        exp[k] = exp[k - 255]

    def gmul(a, b):
        return 0 if a == 0 or b == 0 else exp[log[a] + log[b]]

    gen = [1]
    for k in range(ecw):
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= gmul(c, exp[k])
        gen = nxt
    rem = [0] * ecw
    for b in cw:
        f = b ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(ecw):
            rem[j] ^= gmul(gen[j + 1], f)
    stream = [(b >> k) & 1 for b in cw + rem for k in range(7, -1, -1)]

    n = 17 + 4 * ver
    M = [[0] * n for _ in range(n)]
    fixed = [[False] * n for _ in range(n)]

    def setf(r, c, v):
        if 0 <= r < n and 0 <= c < n:
            M[r][c], fixed[r][c] = v, True

    def finder(r0, c0):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                inside = 0 <= dr <= 6 and 0 <= dc <= 6
                v = 1 if inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4)) else 0
                setf(r0 + dr, c0 + dc, v)

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    for k in range(8, n - 8):
        setf(6, k, 1 if k % 2 == 0 else 0)
        setf(k, 6, 1 if k % 2 == 0 else 0)
    if ver >= 2:
        p = 4 * ver + 10
        for dr in range(-2, 3):
            for dc in range(-2, 3):
                setf(p + dr, p + dc, 0 if max(abs(dr), abs(dc)) == 1 else 1)
    setf(n - 8, 8, 1)
    for k in range(9):
        fixed[8][k] = fixed[k][8] = True
    for k in range(8):
        fixed[8][n - 1 - k] = fixed[n - 1 - k][8] = True

    # data placement (zig-zag, right to left, skipping the vertical timing column)
    idx, c, up = 0, n - 1, True
    while c > 0:
        if c == 6:
            c -= 1
        for r in (range(n - 1, -1, -1) if up else range(n)):
            for cc in (c, c - 1):
                if not fixed[r][cc]:
                    M[r][cc] = stream[idx] if idx < len(stream) else 0
                    idx += 1
        up = not up
        c -= 2

    masks = [lambda i, j: (i + j) % 2 == 0, lambda i, j: i % 2 == 0, lambda i, j: j % 3 == 0,
             lambda i, j: (i + j) % 3 == 0, lambda i, j: (i // 2 + j // 3) % 2 == 0,
             lambda i, j: (i * j) % 2 + (i * j) % 3 == 0, lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
             lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0]

    def with_mask(mask):
        m = [row[:] for row in M]
        for r in range(n):
            for cc in range(n):
                if not fixed[r][cc] and masks[mask](r, cc):
                    m[r][cc] ^= 1
        d = (1 << 3) | mask                       # error correction level L = 0b01
        rm = d
        for _ in range(10):
            rm = (rm << 1) ^ ((rm >> 9) * 0x537)
        fb = ((d << 10) | rm) ^ 0x5412
        bit = lambda k: (fb >> k) & 1
        for k in range(6):
            m[k][8] = bit(k)
        m[7][8], m[8][8], m[8][7] = bit(6), bit(7), bit(8)
        for k in range(9, 15):
            m[8][14 - k] = bit(k)
        for k in range(8):
            m[8][n - 1 - k] = bit(k)
        for k in range(8, 15):
            m[n - 15 + k][8] = bit(k)
        return m

    def penalty(m):
        p = 0
        for grid in (m, [list(col) for col in zip(*m)]):
            for row in grid:
                run = 1
                for k in range(1, n):
                    if row[k] == row[k - 1]:
                        run += 1
                    else:
                        p += run - 2 if run >= 5 else 0
                        run = 1
                p += run - 2 if run >= 5 else 0
        for r in range(n - 1):
            for cc in range(n - 1):
                if m[r][cc] == m[r][cc + 1] == m[r + 1][cc] == m[r + 1][cc + 1]:
                    p += 3
        dark = sum(map(sum, m))
        return p + (abs(dark * 20 - n * n * 10) // (n * n)) * 10

    return min((with_mask(k) for k in range(8)), key=penalty)


def qr_ansi(text, quiet=2):
    """QR code as ANSI half-blocks with a forced white background (readable on dark terminals)."""
    m = qr_matrix(text)
    if m is None:
        return None
    n = len(m)
    size = n + 2 * quiet

    def dark(r, c):
        r, c = r - quiet, c - quiet
        return 0 <= r < n and 0 <= c < n and m[r][c] == 1

    lines = []
    for r in range(0, size, 2):
        s = "".join(f"\x1b[38;5;{16 if dark(r, c) else 231};48;5;{16 if dark(r + 1, c) else 231}m▀"
                    for c in range(size))
        lines.append(s + "\x1b[0m")
    return "\n".join(lines)


# ----------------------------------------------------------------------- HTML
CSS = """
:root{color-scheme:dark;--bg:#0b0e14;--panel:#131822;--panel2:#1a2130;--line:#252d3d;--text:#e6e9ef;
--muted:#8a94a7;--accent:#38d9a9;--accent-ink:#06261d;--danger:#ff6b6b}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:920px;margin:0 auto;padding:1.5rem 1rem 5rem}
header{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1rem}
.brand{display:flex;align-items:center;gap:.65rem;font-weight:700;font-size:1.3rem;letter-spacing:.2px}
.brand b{color:var(--accent)}.brand svg{flex:none}
.crumb{color:var(--muted);font:13px ui-monospace,Menlo,Consolas,monospace;margin:0 0 1rem;word-break:break-all}
button,.btn{font:inherit;font-size:14px;background:var(--panel2);color:var(--text);border:1px solid var(--line);
border-radius:8px;padding:.4rem .8rem;cursor:pointer;display:inline-block;line-height:1.4}
button:hover,.btn:hover{border-color:var(--accent);text-decoration:none}
button.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent);font-weight:600}
button.danger{background:var(--danger);color:#2b0a0a;border-color:var(--danger);font-weight:600}
button.ghost{background:transparent}
.sm{padding:.15rem .5rem;font-size:12px}.sm.del:hover{border-color:var(--danger);color:var(--danger)}
.drop{border:2px dashed var(--line);border-radius:12px;padding:1.2rem;text-align:center;color:var(--muted);
margin-bottom:.8rem;transition:.15s}.drop.over{border-color:var(--accent);background:#38d9a914;color:var(--text)}
.tools{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
#log{margin-bottom:1rem}.up{font-size:13px;color:var(--muted);margin:.25rem 0}.up.ok{color:var(--accent)}.up.bad{color:var(--danger)}
.up progress{display:block;width:100%;height:5px;margin-top:3px;accent-color:var(--accent)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td,th{padding:.55rem .7rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--panel2)}
.r{text-align:right}.chk{width:2rem}.name{word-break:break-all}
.hash{font:11.5px ui-monospace,Menlo,Consolas,monospace;color:var(--muted);cursor:copy;margin-top:3px;word-break:break-all;line-height:1.35}
.hash:hover{color:var(--accent)}
footer{margin-top:1.2rem;text-align:center;font-size:12px;color:var(--muted)}
th.sortable{cursor:pointer;user-select:none;-webkit-user-select:none}th.sortable:hover{color:var(--text)}
th .arr{display:inline-block;width:1em;color:var(--accent)}
.size,.mod{white-space:nowrap;color:var(--muted)}.act{white-space:nowrap;text-align:right}.act>*{margin-left:.3rem}
.empty{text-align:center;color:var(--muted);padding:2rem}
dialog{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:14px;padding:1.2rem;
width:min(26rem,92vw)}dialog::backdrop{background:#000a}
dialog h3{margin:0 0 .4rem}dialog p{margin:0 0 .8rem;color:var(--muted);word-break:break-word}
dialog input{width:100%;font:inherit;background:var(--bg);color:var(--text);border:1px solid var(--line);
border-radius:8px;padding:.5rem;margin-bottom:.8rem}dialog input:focus,.login input:focus{outline:2px solid var(--accent)}
.row{display:flex;gap:.5rem;justify-content:flex-end;flex-direction:row-reverse}
#toast{position:fixed;left:50%;bottom:1.5rem;transform:translateX(-50%);background:var(--panel2);border:1px solid var(--line);
padding:.5rem 1rem;border-radius:10px;opacity:0;pointer-events:none;transition:.2s;max-width:90vw;word-break:break-all}
#toast.show{opacity:1}#toast.bad{border-color:var(--danger);color:var(--danger)}
.login{max-width:21rem;margin:12vh auto 0;padding:1.5rem;background:var(--panel);border:1px solid var(--line);border-radius:14px}
.login .logo{text-align:center;margin-bottom:.6rem}.login .brand{justify-content:center;margin-bottom:1.1rem}.login input{width:100%;font:inherit;background:var(--bg);color:var(--text);
border:1px solid var(--line);border-radius:8px;padding:.6rem;margin-bottom:.8rem}.login button{width:100%;padding:.6rem}
.err{color:var(--danger);min-height:1.4em;margin:.8rem 0 0;font-size:14px}
body.ro .drop,body.ro [data-act=mkdir],body.ro [data-act=rename],body.ro [data-act=delete]{display:none}
@media(max-width:640px){.mod,th.mod{display:none}}
"""

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>hatch_dataroom</title><link rel="icon" href="@@FAVICON@@"><style>@@CSS@@</style></head>
<body class="@@RO@@" data-dir="@@DIR@@"><div class="wrap">
<header><div class="brand">@@LOGOS@@<span>hatch<b>_</b>dataroom</span></div>
<form method="post" action="/__logout"><button type="submit" class="ghost">Log out</button></form></header>
<div class="crumb">@@PATH@@</div>
<div class="drop" id="drop">Drop files here, or
<button type="button" id="pick">choose files</button> <button type="button" id="pickdir">choose folder</button>
<input type="file" id="f" multiple hidden><input type="file" id="fd" webkitdirectory hidden></div>
<div id="log"></div>
<div class="tools">
<button type="button" data-act="mkdir">New folder</button>
<button type="button" data-act="zip-selected">Download selected as ZIP</button>
<a class="btn" href="?zip">This folder as ZIP</a>
</div>
<div class="card"><table><thead><tr><th class="chk"><input type="checkbox" id="all" aria-label="select all"></th>
<th class="sortable" data-sort="name" title="Sort by name">Name <span class="arr"></span></th><th class="r sortable" data-sort="size" title="Sort by size">Size <span class="arr"></span></th><th class="r mod sortable" data-sort="mtime" title="Sort by date">Modified <span class="arr"></span></th><th></th></tr></thead>
<tbody>@@ROWS@@</tbody></table></div>
<footer>hatch_dataroom v@@VER@@ &middot; <a href="@@REPO@@" target="_blank" rel="noopener noreferrer">@@REPO@@</a></footer>
</div>
<dialog id="dlg"><form method="dialog"><h3 id="dlg-title"></h3><p id="dlg-text"></p>
<input id="dlg-input" autocomplete="off" spellcheck="false">
<div class="row"><button id="dlg-ok" value="ok">OK</button><button value="cancel" class="ghost">Cancel</button></div>
</form></dialog>
<div id="toast"></div>
<script>
const $=s=>document.querySelector(s);
const dir=document.body.dataset.dir;
let tt;
function toast(m,bad){const t=$('#toast');t.textContent=m;t.className='show'+(bad?' bad':'');clearTimeout(tt);tt=setTimeout(()=>{t.className='';},3500);}
function ask(title,text,opts){opts=opts||{};return new Promise(res=>{
  const d=$('#dlg'),inp=$('#dlg-input'),ok=$('#dlg-ok');
  $('#dlg-title').textContent=title;$('#dlg-text').textContent=text||'';
  inp.hidden=opts.input===undefined;inp.value=opts.input||'';
  ok.textContent=opts.ok||'OK';ok.className=opts.danger?'danger':'primary';
  d.returnValue='';
  d.onclose=()=>res(d.returnValue==='ok'?(inp.hidden?true:inp.value.trim()):null);
  d.showModal();if(!inp.hidden){inp.focus();inp.select();}
});}
async function api(action,body){
  let r;
  try{r=await fetch('/__api/'+action,{method:'POST',headers:{'X-Requested-With':'hatch','Content-Type':'application/json'},body:JSON.stringify(body)});}
  catch(e){toast('Network error',true);return null;}
  if(r.status===401){location.reload();return null;}
  let j={};try{j=await r.json();}catch(e){}
  if(!r.ok){toast(j.error||('Error '+r.status),true);return null;}
  return j;
}
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-act]');if(!b)return;
  const tr=b.closest('tr'),name=tr?tr.dataset.name:'',act=b.dataset.act;
  if(act==='delete'){
    const msg='Delete "'+name+'"'+(tr.dataset.dir==='1'?' and everything inside it':'')+'? This cannot be undone.';
    if(await ask('Delete',msg,{ok:'Delete',danger:true})&&await api('delete',{path:dir+name}))location.reload();
  }else if(act==='rename'){
    const n=await ask('Rename','New name for "'+name+'"',{input:name,ok:'Rename'});
    if(n&&n!==name&&await api('rename',{path:dir+name,name:n}))location.reload();
  }else if(act==='mkdir'){
    const n=await ask('New folder','Name of the new folder',{input:'',ok:'Create'});
    if(n&&await api('mkdir',{path:dir,name:n}))location.reload();
  }else if(act==='zip-selected'){
    const names=[...document.querySelectorAll('.sel:checked')].map(c=>c.closest('tr').dataset.name);
    if(!names.length){toast('Select files first',true);return;}
    location.href=location.pathname+'?'+names.map(n=>'zip='+encodeURIComponent(n)).join('&');
  }
});
let sortKey=null,sortDir=1;
function sortRows(key){
  sortDir=(sortKey===key)?-sortDir:1;sortKey=key;
  const tb=document.querySelector('tbody'),rows=[...tb.querySelectorAll('tr[data-name]')];
  rows.sort((a,b)=>{
    if(a.dataset.dir!==b.dataset.dir)return b.dataset.dir-a.dataset.dir;   // folders stay first
    let r;
    if(key==='name')r=a.dataset.name.localeCompare(b.dataset.name,undefined,{numeric:true,sensitivity:'base'});
    else r=(+a.dataset[key])-(+b.dataset[key]);
    return r*sortDir||a.dataset.name.localeCompare(b.dataset.name);
  });
  rows.forEach(r=>tb.append(r));
  document.querySelectorAll('th.sortable').forEach(th=>{th.querySelector('.arr').textContent=th.dataset.sort===key?(sortDir>0?'\u25B2':'\u25BC'):'';});
}
document.querySelectorAll('th.sortable').forEach(th=>{th.onclick=()=>sortRows(th.dataset.sort);});
$('#all').onchange=e=>document.querySelectorAll('.sel').forEach(c=>{c.checked=e.target.checked;});

const log=$('#log');
function line(text){
  const d=document.createElement('div'),s=document.createElement('span'),p=document.createElement('progress');
  d.className='up';s.textContent=text;p.max=100;p.value=0;d.append(s,p);log.append(d);return {d:d,s:s,p:p};
}
async function upload(items){
  let bad=0;
  for(const it of items){
    const ui=line(it.rel);
    const path=dir+it.rel.split('/').map(encodeURIComponent).join('/');
    const x=await new Promise(res=>{
      const r=new XMLHttpRequest();
      r.open('PUT',path);
      r.upload.onprogress=e=>{if(e.lengthComputable)ui.p.value=Math.round(e.loaded*100/e.total);};
      r.onload=()=>res(r);r.onerror=()=>res(null);
      r.send(it.file);
    });
    if(x&&x.status===401){location.reload();return;}
    if(x&&x.status===201){
      ui.p.value=100;ui.d.classList.add('ok');
      const sa=x.getResponseHeader('X-Saved-As');
      ui.s.textContent=(sa?it.rel+' -> saved as '+decodeURIComponent(sa)+' (name existed)':it.rel)+'  sha256 '+(x.getResponseHeader('X-SHA256')||'').slice(0,16)+'...';
    }else{
      bad++;ui.d.classList.add('bad');ui.s.textContent=it.rel+'  failed ('+(x?x.status:'network')+')';
    }
  }
  if(!bad)setTimeout(()=>location.reload(),900);
}
$('#pick').onclick=()=>$('#f').click();
$('#pickdir').onclick=()=>$('#fd').click();
$('#f').onchange=e=>{const a=[...e.target.files].map(f=>({file:f,rel:f.name}));e.target.value='';upload(a);};
$('#fd').onchange=e=>{const a=[...e.target.files].map(f=>({file:f,rel:f.webkitRelativePath||f.name}));e.target.value='';upload(a);};
const drop=$('#drop');
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over');};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');
  upload([...e.dataTransfer.files].map(f=>({file:f,rel:f.name})));};

(async()=>{
  for(const td of document.querySelectorAll('.hash[data-href]')){
    try{
      const r=await fetch(td.dataset.href+'?sha256');if(!r.ok)continue;
      const h=(await r.text()).trim();
      td.textContent=h;td.title='click to copy';
      td.onclick=async()=>{try{await navigator.clipboard.writeText(h);toast('SHA-256 copied');}catch(e){toast(h);}};
    }catch(e){}
  }
})();
</script></body></html>"""

LOGIN = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>hatch_dataroom</title><link rel="icon" href="@@FAVICON@@"><style>@@CSS@@</style></head>
<body><form class="login" method="post" action="/__login">
<div class="logo">@@LOGOL@@</div><div class="brand">hatch<b>_</b>dataroom</div>
<input name="password" type="password" placeholder="Password" autocomplete="current-password" autofocus>
<button type="submit" class="primary">Unlock</button>
<p class="err">@@MSG@@</p></form>
<footer>hatch_dataroom v@@VER@@ &middot; <a href="@@REPO@@" target="_blank" rel="noopener noreferrer">@@REPO@@</a></footer></body></html>"""

HTML = "text/html; charset=utf-8"

# ----------------------------------------------------------------------- Logo
# Same artwork as hatch-logo.svg: an open hatch above a room full of stored files.
LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">'
    '<defs><linearGradient id="hg-a" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5eead4"/>'
    '<stop offset="1" stop-color="#2fc99a"/></linearGradient>'
    '<linearGradient id="hg-g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#38d9a9" stop-opacity=".38"/>'
    '<stop offset="1" stop-color="#38d9a9" stop-opacity="0"/></linearGradient></defs>'
    '<rect x="4" y="4" width="248" height="248" rx="56" fill="#0b0e14" stroke="#252d3d" stroke-width="2"/>'
    '<rect x="52" y="92" width="152" height="116" rx="18" fill="#080b10"/>'
    '<rect x="52" y="92" width="152" height="116" rx="18" fill="url(#hg-g)"/>'
    '<g fill="url(#hg-a)">'
    '<rect x="72" y="115" width="10" height="10" rx="3"/><rect x="92" y="115" width="92" height="10" rx="5"/>'
    '<rect x="72" y="141" width="10" height="10" rx="3"/><rect x="92" y="141" width="64" height="10" rx="5" opacity=".85"/>'
    '<rect x="72" y="167" width="10" height="10" rx="3"/><rect x="92" y="167" width="78" height="10" rx="5" opacity=".7"/></g>'
    '<rect x="52" y="92" width="152" height="116" rx="18" fill="none" stroke="url(#hg-a)" stroke-width="9"/>'
    '<path d="M56 90 L78 46 H178 L200 90 Z" fill="#131822" stroke="url(#hg-a)" stroke-width="9" stroke-linejoin="round"/>'
    '<circle cx="128" cy="68" r="8" fill="url(#hg-a)"/></svg>')
FAVICON = "data:image/svg+xml," + urllib.parse.quote(LOGO_SVG)


def logo_html(size):
    return LOGO_SVG.replace("<svg ", f'<svg width="{size}" height="{size}" aria-hidden="true" ', 1)


LOGO_ART = [r"     ________",
            r"    /   o    \ ",
            r"   /__________\ ",
            r"   | .  ===== |",
            r"   | .  ===   |",
            r"   | .  ====  |",
            r"   '----------'"]
LOGO_TEXT = {1: f"hatch_dataroom v{__version__}", 2: "encrypted file exchange", 3: REPO}


def paint(code, text):
    """Colorize for terminals (ANSI), plain text when output is redirected."""
    return f"\x1b[{code}m{text}\x1b[0m" if sys.stdout.isatty() else text


def print_logo():
    for i, art in enumerate(LOGO_ART):
        text = LOGO_TEXT.get(i, "")
        if i == 1:
            text = paint("1", text)
        elif i == 2:
            text = paint("2", text)
        print(paint("38;5;79", art.ljust(19)) + text)


def render(template, **vals):
    vals.update(VER=__version__, REPO=REPO, CSS=CSS, FAVICON=FAVICON, LOGOS=logo_html(34), LOGOL=logo_html(72))
    return re.sub(r"@@(\w+)@@", lambda m: vals.get(m.group(1), ""), template)


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# -------------------------------------------------------------------- Helpers
def password_ok(pw):
    return hmac.compare_digest(hashlib.sha256(pw.encode()).digest(), CFG["pwhash"])


def valid_name(n):
    return (isinstance(n, str) and 0 < len(n) <= 255 and n not in (".", "..") and not n.startswith(".")
            and n == n.strip() and not any(c in n for c in "/\\\x00") and all(c.isprintable() for c in n))


def inside_root(path):
    root = CFG["root"]
    return path == root or path.startswith(root + os.sep)


def inside(path, folder):
    path, folder = os.path.realpath(path), os.path.realpath(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def is_protected(full):
    """The server's own private files (key, certificate, log) are never served, even from inside the data room."""
    for p in CFG.get("protected", ()):
        try:
            if full == p or os.path.samefile(full, p):
                return True
        except OSError:
            pass
    return False


def parse_ext(values):
    """'exe, .BAT;ps1' -> {'exe', 'bat', 'ps1'}"""
    out = set()
    for v in values or []:
        for part in re.split(r"[,; ]+", v):
            part = part.strip().lstrip(".*").lower()
            if part == "none":
                return set()
            if part:
                out.add(part)
    return out


def blocked_name(name):
    """True if the file name has a blocked extension (last extension; trailing dots/spaces are ignored,
    because Windows strips them, so 'a.exe.' is really 'a.exe')."""
    exts = CFG.get("block_ext")
    if not exts:
        return False
    base = name.rstrip(". ").lower()
    return "." in base and base.rsplit(".", 1)[1] in exts


def limit_log(kind, ip, detail):
    now = time.time()
    with CLOCK:
        if now - LIMIT_SEEN.get((kind, ip), 0) <= 60:
            return
        LIMIT_SEEN[(kind, ip)] = now
        if len(LIMIT_SEEN) > 2000:
            for k in [k for k, t in LIMIT_SEEN.items() if now - t > 60]:
                LIMIT_SEEN.pop(k, None)
    audit(ip, "LIMIT", detail)


def rate_ok(ip):
    """Token bucket per IP: RATE_BURST requests at once, then --rate per second."""
    rate = CFG.get("rate", 0)
    if not rate:
        return True
    now = time.time()
    with CLOCK:
        tokens, last = RATE.get(ip, (RATE_BURST, now))
        tokens = min(RATE_BURST, tokens + (now - last) * rate)
        if tokens < 1:
            RATE[ip] = [tokens, now]
            return False
        RATE[ip] = [tokens - 1, now]
        if len(RATE) > 2000:
            for k in [k for k, v in RATE.items() if now - v[1] > 120]:
                RATE.pop(k, None)
    return True


def sha256_file(path):
    st = os.stat(path)
    key = (path, st.st_mtime_ns, st.st_size)
    h = HASHES.get(key)
    if h:
        return h
    d = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            d.update(chunk)
    if len(HASHES) > 5000:
        HASHES.clear()
    HASHES[key] = d.hexdigest()
    return HASHES[key]


def default_allow(ip):
    """Default access: the local network. Private ranges, plus this machine's own /24 when its
    address is neither private nor public (e.g. 100.64.x.x VPN/CGNAT networks)."""
    nets = [ipaddress.ip_network(n) for n in LOCAL_NETS]
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global and not addr.is_loopback and not any(addr in n for n in nets):
            nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        pass
    return nets


def ip_allowed(ip):
    nets = CFG.get("allow")
    if not nets:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_loopback or any(a in n for n in nets)


def tracked(fn):
    """Mark a request as active (for --idle-minutes / --once)."""
    @functools.wraps(fn)
    def wrapper(self):
        ip = self.client_address[0]
        if not rate_ok(ip):  # flooding does not count as activity (idle timer) either
            limit_log("rate", ip, f"more than {CFG['rate']:g} requests/s")
            return self.reply(429, "Too many requests, slow down.\n", extra={"Retry-After": "5"}, close=True)
        with SLOCK:
            STATE["active"] += 1
            STATE["last"] = time.time()
        try:
            return fn(self)
        finally:
            with SLOCK:
                STATE["active"] -= 1
                STATE["last"] = time.time()
    return wrapper


def transfer_done():
    with SLOCK:
        STATE["transfers"] += 1


def watchdog(srv):
    while True:
        time.sleep(1)
        with SLOCK:
            idle, active, done = time.time() - STATE["last"], STATE["active"], STATE["transfers"]
        if active:
            continue
        if CFG["idle_seconds"] and idle >= CFG["idle_seconds"]:
            reason = f"idle for {CFG['idle_seconds'] / 60:g} minutes"
        elif CFG["once"] and done and idle >= ONCE_GRACE:
            reason = "transfer finished (--once)"
        else:
            continue
        audit("-", "STOP", reason)
        srv.shutdown()
        return


class ChunkedWriter:
    """File-like object that sends everything as HTTP chunked encoding (for streamed ZIPs)."""

    def __init__(self, wfile):
        self.w, self.buf = wfile, bytearray()

    def write(self, data):
        self.buf += bytes(data)
        if len(self.buf) >= 65536:
            self.flush()
        return len(data)

    def flush(self):
        if self.buf:
            self.w.write(b"%x\r\n" % len(self.buf) + bytes(self.buf) + b"\r\n")
            self.buf = bytearray()

    def finish(self):
        self.flush()
        self.w.write(b"0\r\n\r\n")


# -------------------------------------------------------------------- Handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hatch_dataroom"  # no version number in HTTP headers on purpose
    sys_version = ""

    def log_message(self, fmt, *args):
        pass  # we write our own audit log

    # -- responses
    def security_headers(self, page=True):
        """Security headers for every response; downloads (page=False) get a sandboxed, script-less CSP."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy",
                         "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), "
                         "payment=(), usb=(), interest-cohort=()")
        if page:
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "img-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
        else:
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'")

    def reply(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None, close=False):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def json(self, code, obj, close=False):
        self.reply(code, json.dumps(obj), "application/json", close=close)

    # -- brute-force protection
    def locked(self, ip):
        rec = FAILS.get(ip)
        if not rec:
            return False
        fails, until, level, last = rec
        now = time.time()
        if until > now:
            return True
        if now - last > LEVEL_DECAY:  # quiet for long enough: forget this address
            FAILS.pop(ip, None)
        elif until:                   # lockout over: count attempts again, but keep the escalation level
            FAILS[ip] = (0, 0, level, last)
        return False

    def fail(self, ip):
        fails, _, level, _ = FAILS.get(ip, (0, 0, 0, 0))
        now = time.time()
        fails += 1
        if fails >= MAX_FAILS:
            secs = min(LOCK_SECONDS * 2 ** level, LOCK_MAX)  # 60s, 120s, 240s, ... up to LOCK_MAX
            FAILS[ip] = (0, now + secs, level + 1, now)
            audit(ip, "LOCKED", f"{secs}s lockout")
        else:
            FAILS[ip] = (fails, 0, level, now)
            audit(ip, "LOGIN_FAIL", "")
        time.sleep(1)

    # -- sessions
    def session_id(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            morsel = SimpleCookie(raw).get("sid")
        except Exception:
            return None
        return morsel.value if morsel else None

    def session_valid(self):
        sid = self.session_id()
        if not sid:
            return False
        exp = SESSIONS.get(sid)
        if exp and exp > time.time():
            SESSIONS[sid] = time.time() + CFG["session_seconds"]  # sliding expiry
            return True
        SESSIONS.pop(sid, None)
        return False

    @staticmethod
    def cookie_header(sid, max_age):
        return f"sid={sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"

    # -- authentication (session cookie for browsers, Basic for curl)
    def authed(self):
        ip = self.client_address[0]
        if self.locked(ip):
            self.reply(429, "Too many failed attempts, try again later.\n", close=True)
            return False
        if self.session_valid():
            return True
        hdr = self.headers.get("Authorization", "")
        ok = False
        if hdr.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")  # user name ignored
                ok = password_ok(pw)
            except Exception:
                ok = False
        if ok:
            FAILS.pop(ip, None)
            return True
        if hdr:  # only count real failed attempts, not requests without credentials
            self.fail(ip)
        self.deny()
        return False

    def deny(self):
        wants_html = "text/html" in self.headers.get("Accept", "") and self.command in ("GET", "HEAD")
        if wants_html:  # browser: show the login page (no Basic dialog)
            self.reply(401, render(LOGIN, MSG=""), HTML, close=True)
        else:
            self.reply(401, "Authentication required.\n",
                       extra={"WWW-Authenticate": f'Basic realm="{APP}", charset="UTF-8"'}, close=True)

    def login(self):
        ip = self.client_address[0]
        if self.locked(ip):
            return self.reply(429, "Too many failed attempts, try again later.\n", close=True)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            return self.reply(400, "Bad request.\n", close=True)
        data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        if password_ok(data.get("password", [""])[0]):
            FAILS.pop(ip, None)
            now = time.time()
            for k in [k for k, v in SESSIONS.items() if v <= now]:
                SESSIONS.pop(k, None)
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = now + CFG["session_seconds"]
            audit(ip, "LOGIN_OK")
            return self.reply(303, extra={"Location": "/",
                                          "Set-Cookie": self.cookie_header(sid, CFG["session_seconds"])})
        self.fail(ip)
        self.reply(401, render(LOGIN, MSG="Wrong password."), HTML)

    def logout(self):
        sid = self.session_id()
        if sid and SESSIONS.pop(sid, None):
            audit(self.client_address[0], "LOGOUT")
        self.reply(303, extra={"Location": "/", "Set-Cookie": self.cookie_header("", 0)})

    # -- paths
    @staticmethod
    def resolve_path(raw):
        """Unquoted URL path -> real path inside the data room, or None."""
        if "\x00" in raw or "\\" in raw:
            return None
        parts = [p for p in raw.split("/") if p not in ("", ".")]
        # hidden files (.htaccess, .env, .git, ...) and our temp files are neither listed nor reachable
        if any(p.startswith(".") for p in parts):
            return None
        full = os.path.realpath(os.path.join(CFG["root"], *parts))
        if not inside_root(full) or is_protected(full):
            return None
        return full

    def resolve(self):
        raw = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        return self.resolve_path(raw), raw

    def rel(self, full):
        r = os.path.relpath(full, CFG["root"])
        return "/" if r == "." else r.replace(os.sep, "/")

    # -- GET / HEAD
    @tracked
    def do_GET(self):
        self.handle_read()

    @tracked
    def do_HEAD(self):
        self.handle_read()

    def handle_read(self):
        if not self.authed():
            return
        full, raw = self.resolve()
        if full is None:
            return self.reply(400, "Invalid path.\n")
        split = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(split.query, keep_blank_values=True)
        ip = self.client_address[0]
        if os.path.isdir(full):
            if not raw.endswith("/"):
                loc = urllib.parse.quote(raw) + "/" + ("?" + split.query if split.query else "")
                return self.reply(301, extra={"Location": loc})
            if "zip" in q:
                return self.zip_download(full, [n for n in q["zip"] if n])
            return self.listing(full, raw)
        if not os.path.isfile(full):
            return self.reply(404, "Not found.\n")
        if "sha256" in q:
            return self.reply(200, sha256_file(full) + "\n")
        size = os.path.getsize(full)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         "attachment; filename*=UTF-8''" + urllib.parse.quote(os.path.basename(full)))
        self.security_headers(page=False)
        self.end_headers()
        if self.command == "HEAD":
            return
        sent = 0
        with open(full, "rb") as f:
            for buf in iter(lambda: f.read(CHUNK), b""):
                self.wfile.write(buf)
                sent += len(buf)
        audit(ip, "DOWNLOAD", f"{self.rel(full)} {sent} bytes")
        transfer_done()

    def listing(self, full, raw):
        rows = []
        if full != CFG["root"]:
            rows.append('<tr><td></td><td class="name"><a href="../">..</a></td><td></td><td></td><td></td></tr>')
        entries = sorted(os.scandir(full), key=lambda e: (not e.is_dir(), e.name.lower()))
        for e in entries:
            if e.name.startswith(".") or is_protected(e.path):
                continue
            try:
                st = e.stat()
                isdir = e.is_dir()
            except OSError:
                continue
            href = urllib.parse.quote(e.name) + ("/" if isdir else "")
            mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
            label = html.escape(e.name) + ("/" if isdir else "")
            if isdir:
                hashdiv = ""
                zipbtn = f'<a class="btn sm" href="{href}?zip" title="Download folder as ZIP">ZIP</a>'
            else:
                hashdiv = f'<div class="hash" data-href="{href}"></div>'
                zipbtn = ""
            rows.append(
                f'<tr data-name="{html.escape(e.name, quote=True)}" data-dir="{1 if isdir else 0}" '
                f'data-size="{0 if isdir else st.st_size}" data-mtime="{int(st.st_mtime)}">'
                f'<td class="chk"><input type="checkbox" class="sel" aria-label="select"></td>'
                f'<td class="name"><a href="{href}">{label}</a>{hashdiv}</td>'
                f'<td class="r size">{"" if isdir else human(st.st_size)}</td>'
                f'<td class="r mod">{mtime}</td>'
                f'<td class="act">{zipbtn}<button class="sm" data-act="rename">Rename</button>'
                f'<button class="sm del" data-act="delete">Delete</button></td></tr>')
        if not any("data-name=" in r for r in rows):
            rows.append('<tr><td colspan="5" class="empty">This folder is empty.</td></tr>')
        self.reply(200, render(PAGE, DIR=html.escape(raw, quote=True), PATH=html.escape(raw),
                               ROWS="".join(rows), RO="ro" if CFG.get("read_only") else ""), HTML)

    # -- ZIP download (streamed, chunked)
    def zip_download(self, full, names):
        root = CFG["root"]
        entries = []

        def add(p, arc):
            if os.path.isdir(p):
                entries.append((p, arc, True))
                for dp, dns, fns in os.walk(p):
                    dns[:] = sorted(d for d in dns
                                    if not d.startswith(".") and not os.path.islink(os.path.join(dp, d)))
                    rel = os.path.relpath(dp, p)
                    base = arc if rel == "." else arc + "/" + rel.replace(os.sep, "/")
                    if rel != ".":
                        entries.append((dp, base, True))
                    for f in sorted(fns):
                        fp = os.path.join(dp, f)
                        if not f.startswith(".") and not os.path.islink(fp) and not is_protected(fp):
                            entries.append((fp, base + "/" + f, False))
            else:
                entries.append((p, arc, False))

        if names:
            for n in names:
                p = os.path.realpath(os.path.join(full, n)) if valid_name(n) else None
                if p is None or not inside_root(p) or not os.path.exists(p):
                    return self.reply(404, "Item not found.\n")
                add(p, n)
            zipname = os.path.basename(full if full != root else root) + "-selection.zip"
        else:
            top = os.path.basename(full)  # for the root this is the hatch-YYYYMMDD-HHMMSS folder name
            add(full, top)
            zipname = top + ".zip"

        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(zipname))
        self.security_headers(page=False)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if self.command == "HEAD":
            return
        out = ChunkedWriter(self.wfile)
        try:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for p, arc, isdir in entries:
                    if isdir:
                        zi = zipfile.ZipInfo(arc + "/")
                        zi.external_attr = (0o40755 << 16) | 0x10
                        zf.writestr(zi, b"")
                    else:
                        zf.write(p, arc)
            out.finish()
        except Exception as e:
            self.close_connection = True  # no terminating chunk: the client sees an incomplete download
            audit(self.client_address[0], "ZIP_FAIL", f"{self.rel(full)} {e}")
            return
        files = sum(1 for _, _, d in entries if not d)
        audit(self.client_address[0], "ZIP", f"{self.rel(full)} ({files} files)")
        transfer_done()

    # -- PUT (upload)
    @tracked
    def do_PUT(self):
        if not self.authed():
            return
        if CFG.get("read_only"):
            return self.reply(403, "Read-only mode: uploads are disabled.\n", close=True)
        full, raw = self.resolve()
        if full is None or full == CFG["root"] or raw.endswith("/"):
            return self.reply(400, "Invalid file name.\n", close=True)
        if blocked_name(os.path.basename(full)):
            audit(self.client_address[0], "BLOCKED", f"upload {self.rel(full)} (file type)")
            return self.reply(415, "This file type is not allowed.\n", close=True)
        if os.path.isdir(full):
            return self.reply(409, "Target is a folder.\n", close=True)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.reply(411, "Content-Length required.\n", close=True)
        if length < 0 or length > CFG["max_bytes"]:
            return self.reply(413, "File too large.\n", close=True)
        renamed_from = None
        if os.path.lexists(full):  # never replace an existing file silently
            mode = CFG.get("on_conflict", "rename")
            if mode == "fail":
                audit(self.client_address[0], "EXISTS", f"upload {self.rel(full)} refused (file exists)")
                return self.reply(409, "A file with that name already exists.\n", close=True)
            if mode == "rename":
                stem, ext = os.path.splitext(os.path.basename(full))
                n = 2
                while True:
                    cand = os.path.join(os.path.dirname(full), f"{stem} ({n}){ext}")
                    if not os.path.lexists(cand):
                        break
                    n += 1
                renamed_from = self.rel(full)
                full = cand
        parent = os.path.dirname(full)
        os.makedirs(parent, exist_ok=True)
        tmp = os.path.join(parent, TMP_PREFIX + secrets.token_hex(6))
        digest, got = hashlib.sha256(), 0
        try:
            with open(tmp, "wb") as f:
                while got < length:
                    buf = self.rfile.read(min(CHUNK, length - got))
                    if not buf:
                        break
                    f.write(buf)
                    digest.update(buf)
                    got += len(buf)
            if got != length:
                raise ConnectionError("Upload aborted")
            os.replace(tmp, full)
        except Exception as e:
            if os.path.exists(tmp):
                os.remove(tmp)
            audit(self.client_address[0], "UP_FAIL", f"{raw} {e}")
            return self.reply(400, "Upload failed.\n", close=True)
        hexd = digest.hexdigest()
        try:
            st = os.stat(full)
            HASHES[(full, st.st_mtime_ns, st.st_size)] = hexd
        except OSError:
            pass
        note = f" (name existed, was {renamed_from})" if renamed_from else ""
        audit(self.client_address[0], "UPLOAD", f"{self.rel(full)} {got} bytes sha256={hexd}{note}")
        transfer_done()
        extra = {"X-SHA256": hexd}
        msg = f"Saved ({human(got)}) sha256:{hexd}\n"
        if renamed_from:
            extra["X-Saved-As"] = urllib.parse.quote(os.path.basename(full))
            msg = f"Saved as {os.path.basename(full)} because {renamed_from} already exists ({human(got)}) sha256:{hexd}\n"
        self.reply(201, msg, extra=extra)

    # -- POST (login, logout, file operations)
    @tracked
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/__login":
            return self.login()
        if path == "/__logout":
            return self.logout()
        if path.startswith("/__api/"):
            return self.api(path[len("/__api/"):])
        self.reply(405, "Not allowed.\n", close=True)

    def api(self, action):
        if not self.authed():
            return
        if action not in ("mkdir", "rename", "delete"):
            return self.reply(404, "Unknown action.\n", close=True)
        if self.headers.get("X-Requested-With") != "hatch":
            return self.reply(403, "Forbidden.\n", close=True)
        if CFG.get("read_only"):
            return self.reply(403, "Read-only mode: changes are disabled.\n", close=True)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = 0
        if not 0 < length <= 8192:
            return self.reply(400, "Bad request.\n", close=True)
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            assert isinstance(data, dict)
        except Exception:
            return self.json(400, {"error": "Bad request"})
        root, ip = CFG["root"], self.client_address[0]
        full = self.resolve_path(str(data.get("path", "")))
        if full is None:
            return self.json(400, {"error": "Invalid path"})
        name = data.get("name")
        try:
            if action == "mkdir":
                if not valid_name(name):
                    return self.json(400, {"error": "Invalid folder name"})
                if not os.path.isdir(full):
                    return self.json(404, {"error": "Parent folder not found"})
                target = os.path.join(full, name)
                if os.path.lexists(target):
                    return self.json(409, {"error": "Already exists"})
                os.mkdir(target)
                audit(ip, "MKDIR", self.rel(target))
            else:
                if full == root:
                    return self.json(400, {"error": "Cannot change the data room folder itself"})
                if not os.path.lexists(full):
                    return self.json(404, {"error": "Not found"})
                if action == "rename":
                    if not valid_name(name):
                        return self.json(400, {"error": "Invalid name"})
                    if blocked_name(name) and not os.path.isdir(full):
                        audit(ip, "BLOCKED", f"rename {self.rel(full)} -> {name} (file type)")
                        return self.json(415, {"error": "This file type is not allowed"})
                    target = os.path.join(os.path.dirname(full), name)
                    if os.path.lexists(target) and target.lower() != full.lower():
                        return self.json(409, {"error": "A file with that name already exists"})
                    old = self.rel(full)
                    os.rename(full, target)
                    audit(ip, "RENAME", f"{old} -> {self.rel(target)}")
                else:
                    old = self.rel(full)
                    if os.path.isdir(full) and not os.path.islink(full):
                        shutil.rmtree(full)
                    else:
                        os.remove(full)
                    audit(ip, "DELETE", old)
        except OSError as e:
            return self.json(400, {"error": f"Failed: {e.strerror or e}"})
        self.json(200, {"ok": True})

    def do_other(self):
        self.reply(405, "Not allowed.\n", close=True)

    do_DELETE = do_PATCH = do_OPTIONS = do_other


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    ssl_context = None

    def verify_request(self, request, client_address):
        cip = client_address[0]
        if not ip_allowed(cip):
            now = time.time()
            if now - DENIED_SEEN.get(cip, 0) > 60:  # don't flood the log
                DENIED_SEEN[cip] = now
                audit(cip, "DENIED", "outside the allowed network (see --allow)")
            return False  # connection is closed before any TLS handshake
        per_ip = CFG.get("max_conn", 0)
        with CLOCK:
            if (per_ip and CONNS.get(cip, 0) >= per_ip) or len(CONN_OF) >= TOTAL_CONN_MAX:
                over = True
            else:
                over = False
                CONNS[cip] = CONNS.get(cip, 0) + 1
                CONN_OF[id(request)] = cip
        if over:
            limit_log("conn", cip, f"too many open connections (max {per_ip} per address, {TOTAL_CONN_MAX} total)")
            return False
        return True

    def shutdown_request(self, request):
        with CLOCK:
            cip = CONN_OF.pop(id(request), None)
            if cip is not None:
                CONNS[cip] = CONNS.get(cip, 1) - 1
                if CONNS[cip] <= 0:
                    CONNS.pop(cip, None)
        super().shutdown_request(request)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(30)
        # Handshake happens in the handler thread, so hanging clients cannot block the server
        return self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]  # no tracebacks, but log TLS handshake failures
        if isinstance(exc, ssl.SSLError):
            ip, now = client_address[0], time.time()
            if now - TLS_SEEN.get(ip, 0) > 10:
                TLS_SEEN[ip] = now
                audit(ip, "TLS_FAIL", getattr(exc, "reason", None) or str(exc))


# ----------------------------------------------------------------------- main
def parse_allow(values):
    """None = not given (use the local-network default), [] = 'any' (no restriction), else networks."""
    nets = []
    for v in values or []:
        for part in v.split(","):
            part = part.strip()
            if not part:
                continue
            if part.lower() in ("any", "all", "*"):
                return []
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                sys.exit(f"Invalid --allow value: {part}")
    return nets or None


def ask_peer():
    """Interactive start: limit access to the other machine. Enter = the whole local network (None)."""
    while True:
        try:
            text = input("IP of the other machine (several separated by commas, Enter = whole local network): ")
        except EOFError:
            return None
        except KeyboardInterrupt:
            print()
            sys.exit(1)
        nets, bad = [], None
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if part.lower() in ("any", "all", "*"):
                return []
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                bad = part
                break
        if bad:
            print(f"  '{bad}' is not a valid IP address or network, try again.")
            continue
        return nets or None


def new_data_dir():
    """hatch-YYYYMMDD-HHMMSS next to this script (numbered if it already exists)."""
    base = os.path.join(HERE, datetime.datetime.now().strftime("hatch-%Y%m%d-%H%M%S"))
    path, n = base, 1
    while os.path.exists(path):
        n += 1
        path = f"{base}-{n}"
    return path


def main():
    ap = argparse.ArgumentParser(description=f"{APP} v{__version__} - encrypted file exchange (HTTPS + password)",
                                 epilog=f"Project: {REPO}")
    ap.add_argument("--version", action="version", version=f"{APP} {__version__}  {REPO}")
    ap.add_argument("--dir", default=None,
                    help="data room folder (default: a new hatch-YYYYMMDD-HHMMSS folder for every start)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--allow", action="append", metavar="NET",
                    help="only accept clients from this IP/subnet (repeatable, comma separated); "
                         "default: local network only; 'any' = everyone")
    ap.add_argument("--no-ask", action="store_true",
                    help="do not ask for the other machine's IP at an interactive start")
    ap.add_argument("--tls12", action="store_true",
                    help="also allow TLS 1.2 (default: TLS 1.3 only when this Python supports it)")
    ap.add_argument("--on-conflict", choices=("rename", "fail", "overwrite"), default="rename",
                    help="upload to an existing file name: rename = keep both as 'name (2).ext' (default), "
                         "fail = refuse (HTTP 409), overwrite = replace the old file")
    ap.add_argument("--idle-minutes", type=float, default=DEFAULT_IDLE_MINUTES,
                    help=f"stop after N minutes without activity (default {DEFAULT_IDLE_MINUTES}, 0 = never)")
    ap.add_argument("--once", action="store_true", help="stop after the first completed transfer")
    ap.add_argument("--prompt", action="store_true", help="ask for the password instead of generating one")
    ap.add_argument("--max-mb", type=int, default=2048, help="maximum upload size in MB")
    ap.add_argument("--read-only", action="store_true",
                    help="downloads only: no uploads, no rename/delete/new folder")
    ap.add_argument("--block-ext", action="append", metavar="EXT",
                    help="refuse uploads/renames of these file types (repeatable, comma separated); "
                         "default: Windows executables/scripts, 'none' = allow everything")
    ap.add_argument("--max-conn", type=int, default=20,
                    help="open connections allowed per client address (default 20, 0 = no limit)")
    ap.add_argument("--rate", type=float, default=30,
                    help="requests per second allowed per client address after a burst of 100 (default 30, 0 = no limit)")
    ap.add_argument("--session-hours", type=float, default=8, help="browser session lifetime in hours")
    ap.add_argument("--log", default=os.path.join(HERE, "hatch.log"), help="audit log file")
    ap.add_argument("--no-log", action="store_true", help="disable the audit log file")
    ap.add_argument("--no-qr", action="store_true", help="do not print the QR code")
    ap.add_argument("--new-cert", action="store_true", help="regenerate the certificate")
    a = ap.parse_args()

    generated = False
    pw = os.environ.get("TRANSFER_PASSWORD")
    if not pw:
        if a.prompt:
            pw = getpass.getpass("Password: ")
        else:
            pw = generate_password()
            generated = True
    if len(pw) < 8:
        sys.exit("Password must be at least 8 characters.")

    ip = local_ip()
    auto_dir = a.dir is None
    data_dir = new_data_dir() if auto_dir else a.dir
    os.makedirs(data_dir, exist_ok=True)

    allow_arg = parse_allow(a.allow)
    if allow_arg is None and not a.no_ask and sys.stdin.isatty() and sys.stdout.isatty():
        allow_arg = ask_peer()
    if allow_arg is None:
        allow, mode = default_allow(ip), "local"
    elif not allow_arg:
        allow, mode = [], "any"
    else:
        allow, mode = allow_arg, "custom"

    CFG.update(root=os.path.realpath(data_dir), pwhash=hashlib.sha256(pw.encode()).digest(),
               max_bytes=a.max_mb * 1024 * 1024, session_seconds=int(a.session_hours * 3600),
               allow=allow, idle_seconds=int(a.idle_minutes * 60), once=a.once,
               log=None if a.no_log else os.path.abspath(a.log),
               read_only=a.read_only, block_ext=parse_ext(a.block_ext if a.block_ext is not None else [DEFAULT_BLOCK_EXT]),
               max_conn=max(0, a.max_conn), rate=max(0.0, a.rate), on_conflict=a.on_conflict)

    # The private key, certificate and log must never sit inside the shared folder.
    for what, path in (("private key", KEY), ("certificate", CERT), ("audit log", CFG["log"])):
        if path and inside(path, CFG["root"]):
            if auto_dir and not os.listdir(CFG["root"]):
                os.rmdir(CFG["root"])
            sys.exit(f"Refusing to start: the {what} ({path}) is inside the shared folder {CFG['root']}.\n"
                     f"Use a different --dir (not the folder that contains the script), "
                     f"or move the file out of it.")
    CFG["protected"] = [p for p in (KEY, CERT, CFG["log"]) if p]

    ensure_cert(ip, a.new_cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if a.tls12 or not ssl.HAS_TLSv1_3:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")  # TLS 1.2 suites: forward secrecy + AEAD only
        except ssl.SSLError:
            pass
        tls_text = "TLS 1.2+" if a.tls12 else "TLS 1.2+ (this Python/OpenSSL has no TLS 1.3)"
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_text = "TLS 1.3 only (--tls12 also allows TLS 1.2)"
    ctx.load_cert_chain(CERT, KEY)

    TLSServer.ssl_context = ctx
    try:
        srv = TLSServer((a.bind, a.port), Handler)
    except OSError as e:
        sys.exit(f"Cannot listen on {a.bind}:{a.port}: {e}")

    url = f"https://{ip}:{a.port}/"
    if os.name == "nt" and sys.stdout.isatty():
        os.system("")  # enables ANSI escape codes in the Windows console
    print()
    print_logo()
    print()
    print(f"Folder:   {CFG['root']}")
    print("          " + ("new folder for this start; kept if it contains files, use --dir to reuse a folder"
                          if auto_dir else "existing/explicit folder (--dir), never removed"))
    print(f"Address:  {url}")
    if generated:
        print(f"Password: {paint('1', pw)}   (generated, new on every start)")
    if mode == "local":
        v4 = [str(n) for n in allow if n.version == 4]
        print(f"Access:   {paint('38;5;79', 'local network only')} + this machine")
        print("          allowed: " + ", ".join(v4))
        print("          everyone else is refused; change with --allow NET, open to all with --allow any")
    elif mode == "custom":
        print(f"Access:   only {', '.join(str(n) for n in allow)} + this machine")
    else:
        print(paint("1;31", "Access:   OPEN to every address that can reach this machine (--allow any)"))
    try:
        if ipaddress.ip_address(ip).is_global:
            print(paint("1;31", f"WARNING:  this machine's address {ip} is public - make sure a firewall protects "
                                f"port {a.port}"))
    except ValueError:
        pass
    print(f"SHA-256:  {fingerprint()}")
    print("          (compare it with the browser warning, don't just click through)")
    extras = [tls_text]
    if CFG["idle_seconds"]:
        extras.append(f"stops after {a.idle_minutes:g} min idle")
    else:
        extras.append("no idle timeout (--idle-minutes 0)")
    extras.append({"rename": "existing names are kept (new upload becomes 'name (2).ext')",
                   "fail": "existing names are refused (HTTP 409)",
                   "overwrite": "uploads OVERWRITE existing files"}[CFG["on_conflict"]])
    if a.once:
        extras.append("stops after the first transfer")
    if a.read_only:
        extras.append("READ-ONLY (downloads only)")
    if CFG["block_ext"]:
        exts = sorted(CFG["block_ext"])
        extras.append("blocked upload types: " + (", ".join("." + e for e in exts) if len(exts) <= 12 else
                      f"{len(exts)} types (.exe, .ps1, .js, .lnk, .iso, macro documents, ...; "
                      f"change with --block-ext, 'none' = off)"))
    lim = []
    if CFG["max_conn"]:
        lim.append(f"{CFG['max_conn']} connections")
    if CFG["rate"]:
        lim.append(f"{CFG['rate']:g} requests/s")
    if lim:
        extras.append("limits per address: " + ", ".join(lim))
    extras.append(f"log {CFG['log']}" if CFG["log"] else "log off")
    print("Options:  " + "; ".join(extras))
    if not a.no_qr and sys.stdout.isatty():
        qr = qr_ansi(url)
        if qr:
            try:
                print(f"\nScan to open on your phone:\n{qr}")
            except UnicodeEncodeError:
                pass
    print("\nStop with Ctrl+C\n", flush=True)
    audit("-", "START", f"{url} dir={CFG['root']} access={mode}", console=False)

    def _stop(signum, frame):
        raise KeyboardInterrupt  # same clean shutdown as Ctrl+C (log entry, empty-folder cleanup)

    for sig in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), _stop)
            except (ValueError, OSError):
                pass
    with SLOCK:
        STATE["last"] = time.time()  # idle timer starts now, not at process start
    if CFG["idle_seconds"] or a.once:
        threading.Thread(target=watchdog, args=(srv,), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        audit("-", "STOP", "Ctrl+C", console=False)
        print("\nStopped.")
    else:
        print("Stopped.")
    finally:
        srv.server_close()
        if auto_dir and os.path.isdir(CFG["root"]):
            if not os.listdir(CFG["root"]):
                os.rmdir(CFG["root"])
                print("Data room folder was empty and has been removed.")
            else:
                print(f"Files are kept in: {CFG['root']}")


if __name__ == "__main__":
    main()
