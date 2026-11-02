#!/usr/bin/env python3
"""service_greeting.py — read the line a server sends the moment you connect. Sends nothing.

KB 12 job 4k (4d stage 1, D-073). Many services announce themselves before the
client says a word: an SSH server sends "SSH-2.0-...", an FTP or mail server
"220 ...", a POP3 server "+OK ...", an IMAP server "* OK ...". This module opens
one connection to a port, SENDS NOTHING (no username, no password, no key, not
even an SSH hello), reads that first line for a few seconds, and hangs up.

It replaces fingerprintx, removed in job 4l (2026-11-02) because its SSH check
logs in as admin/admin. Proven first on Howie's Mac (the 4k trial, 2026-11-02
12:19 ET): both Command SSH servers named themselves with nothing sent.

What a greeting can name, with its public source (product_of()). Every name is
"going by its greeting: confirm it's patched", never proof of the installed
version and never "vulnerable" (Howie's standing rule on version-only evidence).

Used by run_heavy.py (deep scan) and, as a command, by scanner/asm-discover.sh
(discovery):  python3 service_greeting.py --naabu <naabu.json>  ->  JSON lines.
Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time

SKIP_PORTS = frozenset({80, 443})     # web: covered by httpx and the medium tier; a web server never speaks first
CONNECT_S = 5.0
READ_S = 5.0
MAX_READ = 1024                        # RFC 4253 lets an SSH server send a few lines before its "SSH-" line
MAX_LINE = 255
MAX_PORTS = 12                         # per host, per scan
BUDGET_S = 90.0                        # per host, per scan

_PRINTABLE = re.compile(r"[^\x20-\x7e]")

# Globalscape documents its EFT file-transfer server's SSH libraries:
#   KB 11439 "Switch to Legacy (Bitvise) SSH Library": EFT before v7.4.11 used the
#     Bitvise library "1.82_sshlib"; v7.4.11 and later use "v7.7.1.0_openssh"; the
#     Bitvise library could be switched back on through v8.0.5 and was removed in v8.0.6.
#     https://kb.globalscape.com/Print11439.aspx
#   EFT Specifications (8.3.2): "EFT v8.3.0 uses OpenSSH v9.8", "EFT v8.2.1 uses OpenSSH v9.5".
#     https://hstechdocs.helpsystems.com/manuals/globalscape/eft832/Content/Installing/BeforeYouBegin/EFTSpecifications.htm
_SRC_EFT_KB = "Globalscape KB 11439"
_SRC_EFT_SPEC = "Globalscape EFT Specifications (8.3.2)"
EFT_BY_OPENSSH = {
    "9.8": ("8.3.x", _SRC_EFT_SPEC),
    "9.5": ("8.2.1", _SRC_EFT_SPEC),
    "7.7": ("7.4.11 or later", _SRC_EFT_KB),
}

_RE_EFT_BITVISE = re.compile(r"^SSH-2\.0-1\.82_sshlib(?:\s|$)")
_RE_EFT_OPENSSH = re.compile(r"^SSH-2\.0-(\d+)\.(\d+)\.\d+\.\d+_openssh(?:\s|$)")
_RE_OPENSSH = re.compile(r"^SSH-2\.0-OpenSSH_(\d+\.\d+(?:p\d+)?)")


def product_of(greeting: str | None) -> dict | None:
    """What the greeting names, with its source; None when it names nothing we can tie
    to a product. Always a hint ("going by its greeting"), never proof."""
    g = greeting or ""
    if _RE_EFT_BITVISE.match(g):
        return {"product": "Globalscape EFT", "version": "8.0.5 or older",
                "basis": "its SSH library, Bitvise 1.82", "source": _SRC_EFT_KB}
    m = _RE_EFT_OPENSSH.match(g)
    if m:
        lib = "%s.%s" % (m.group(1), m.group(2))
        ver, src = EFT_BY_OPENSSH.get(lib, (None, _SRC_EFT_KB))
        return {"product": "Globalscape EFT", "version": ver,
                "basis": "its OpenSSH-based library %s" % lib, "source": src}
    m = _RE_OPENSSH.match(g)
    if m:
        return {"product": "OpenSSH", "version": m.group(1),
                "basis": "the greeting names it (Linux distributions patch without changing this number)",
                "source": "the greeting"}
    return None


def protocol_of(greeting: str | None, port: int) -> str | None:
    g = greeting or ""
    if g.startswith("SSH-"):
        return "ssh"
    if g.startswith("+OK"):
        return "pop3"
    if g.startswith("* OK") or g.startswith("* PREAUTH"):
        return "imap"
    if g.startswith("220"):
        low = g.lower()
        if "smtp" in low or "mail" in low or port in (25, 587):
            return "smtp"
        if "ftp" in low or port == 21:
            return "ftp"
        return "unknown-220"
    return None


def describe(p: dict | None) -> str:
    """One plain phrase for a title or a line: 'Globalscape EFT 8.0.5 or older (going by its greeting)'."""
    if not p:
        return ""
    name = p["product"] + (" " + p["version"] if p.get("version") else "")
    return "%s (going by its greeting)" % name


def clean(text: str) -> str:
    return _PRINTABLE.sub("?", text)[:MAX_LINE]


def read_greeting(host: str, port: int, connect_s: float = CONNECT_S, read_s: float = READ_S) -> dict:
    """Connect, SEND NOTHING, read until a recognised first line or the time runs out, close.
    Returns {"port", "connected", "greeting", "protocol", "product", "error"}."""
    r = {"port": int(port), "connected": False, "greeting": None, "protocol": None,
         "product": None, "error": None}
    try:
        s = socket.create_connection((host, int(port)), timeout=connect_s)
    except socket.timeout:
        r["error"] = "no answer"
        return r
    except ConnectionRefusedError:
        r["error"] = "refused"
        return r
    except OSError as e:
        r["error"] = type(e).__name__
        return r
    try:
        r["connected"] = True
        buf = b""
        deadline = time.monotonic() + read_s
        while len(buf) < MAX_READ:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            s.settimeout(left)
            try:
                chunk = s.recv(MAX_READ - len(buf))
            except socket.timeout:
                break
            except OSError as e:
                r["error"] = type(e).__name__
                break
            if not chunk:
                break
            buf += chunk
            done = [l for l in buf.split(b"\n")[:-1]]
            if any(l.startswith((b"SSH-", b"220", b"+OK", b"* OK", b"* PREAUTH")) for l in done):
                break
        first = None
        for raw in buf.split(b"\n"):
            text = raw.rstrip(b"\r").decode("latin-1")
            if text.startswith(("SSH-", "220", "+OK", "* OK", "* PREAUTH")):
                first = text
                break
        if first is None and buf.strip():
            first = buf.split(b"\n")[0].rstrip(b"\r").decode("latin-1")
        if first:
            r["greeting"] = clean(first)
            r["protocol"] = protocol_of(r["greeting"], int(port))
            r["product"] = product_of(r["greeting"])
        elif r["error"] is None:
            r["error"] = "no greeting"
        return r
    finally:
        try:
            s.close()
        except OSError:
            pass


def read_greetings(host: str, ports, *, max_ports: int = MAX_PORTS, budget_s: float = BUDGET_S,
                   connect_s: float = CONNECT_S, read_s: float = READ_S) -> list[dict]:
    """One look per port, in order, web ports skipped, at most max_ports and budget_s."""
    want = sorted({int(p) for p in ports if int(p) not in SKIP_PORTS})[:max_ports]
    out, start = [], time.monotonic()
    for p in want:
        if time.monotonic() - start > budget_s:
            out.append({"port": p, "connected": False, "greeting": None, "protocol": None,
                        "product": None, "error": "time budget used up"})
            continue
        out.append(read_greeting(host, p, connect_s, read_s))
    return out


def _naabu_targets(path: str) -> dict:
    """naabu -json lines -> {address: [ports]} (ip preferred, else host)."""
    by: dict[str, set] = {}
    try:
        lines = open(path, errors="replace").read().splitlines()
    except OSError:
        return {}
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        addr = rec.get("ip") or rec.get("host")
        port = rec.get("port")
        if addr and isinstance(port, int):
            by.setdefault(addr, set()).add(port)
    return {a: sorted(ps) for a, ps in by.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read each server's first line; send nothing.")
    ap.add_argument("--naabu", required=True, help="naabu -json output (one open port per line)")
    a = ap.parse_args(argv)
    for addr, ports in sorted(_naabu_targets(a.naabu).items()):
        for r in read_greetings(addr, ports):
            r["host"] = addr
            print(json.dumps(r, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
