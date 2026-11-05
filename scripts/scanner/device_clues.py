#!/usr/bin/env python3
"""device_clues.py — what a web address shows anyone about the device behind it (KB 12 job 4y).

Howie, 2026-11-04 19:10: "I'd really love to get something in terms of a deeper scan or a
better recognition of what these security devices are." Earned by trial 4w (run on Howie's
Mac 2026-11-05 08:33 ET, bar met): these clues named Globalscape EFT, Microsoft IIS running
classic ASP and Pressable's servers where Sentry said "web firewall" or "unknown", and told
which addresses share one make and set-up. This module is that trial's program
(trial4w.py, 45 checks), turned into one scan step.

LOOK-ONLY, the trial's exact requests, per address the host's name points at (port 443):
  four secure handshakes, nothing sent after them:
    normal; TLS 1.2 only; TLS 1.2 with the cipher list reversed; TLS 1.2, older ciphers
  GET /             as an ordinary browser visitor; no Cookie header, ever
  one redirect      at most: same host, https, port 443, as a GET
  GET /favicon.ico
STEP_S seconds between connections. No login, no form, no POST, no other path, no other port.

KEPT (the production schema, smaller than the trial's): handshake version / cipher / chosen
protocol; the certificate's SHA-256, serial, subject, issuer and at most 20 names; the path
the visitor lands on and its parameter NAMES; the landed page's title (120 characters,
cleaned: the only page text kept); Set-Cookie NAMES; header NAMES in order; the Server and
X-Powered-By lines; the icon's status, murmur3 hash and SHA-256; a "same make and set-up"
key. NEVER kept: page text other than the title, the generator tag, cookie values,
parameter values.

The artifact (one per scan run, tool_name 'device_clues', JSON):
  {"schema": 1, "collected_at", "tier", "hostname",
   "addresses": {"<ip>": {"outcome": "answered" | "no_answer" | "error" | "cut_short", ...}},
   "landing_paths": [...] | null,     # the classifier's landing_path; null = no address
                                      # answered GET / on this host (did not look)
   "cert_subject": "..." | null,      # the first answering address's certificate subject
   "set_cookie_names": [...]}         # every cookie NAME any address set
An address that gave no answer, or that the host's time limit cut short, carries no clues,
so a timeout is "did not look" and can never strip a class the classifier gave on an
earlier pass. The whole host takes BUDGET_S at most, however slowly a server answers.

Rules: D-056/D-067/D-076 (look-only, detection-only); lesson 58 (no answer is "no answer",
never "blocked"); Howie's rule on his own scans (nothing from his Mac enters Sentry: Sentry
learns this from its own light and deep scans).

Standard library only. Pure except the wire functions, which tests replace.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import html
import json
import re
import select
import socket
import ssl
import threading
import time
import zlib
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

TOOL_NAME = "device_clues"          # the artifact's tool_name; device_class_runner reads it by this name
SCHEMA = 1
PORT = 443
STEP_S = 2                          # between connections (the trial's spacing)
CONNECT_S = 10
READ_S = 10
MAX_BODY = 262144                   # bytes read from any one answer, at most
MAX_TITLE = 120
MAX_NAMES = 20
MAX_HEADERS = 40
MAX_ADDRESSES = 4                   # per host, per scan
# A HARD deadline, not a hint (code review 2026-11-05 11:52, must-fix 1): every wait inside
# every connection (connect, each step of the handshake, each read) is cut to what is left
# of BOTH the connection's own limit and the host's, so a server that trickles a byte at a
# time can hold neither one connection past PER_CONN_S nor the host past BUDGET_S.
BUDGET_S = 150.0                    # per host, name lookup included
PER_CONN_S = 30.0                   # one connection: connect + handshake + request + answer
RESOLVE_S = 10.0                    # the name lookup, at most
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/17.0 Safari/605.1.15")     # the trial's visitor
OLDER_CIPHERS = ("ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:"
                 "ECDHE-ECDSA-AES256-SHA384:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES128-SHA:"
                 "ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:@SECLEVEL=1")
PROBES = ("normal", "tls12", "tls12-reversed", "tls12-older")
REDIRECTS = (301, 302, 303, 307, 308)

ANSWERED, NO_ANSWER, ERROR, CUT_SHORT = "answered", "no_answer", "error", "cut_short"

# History (asset_tech_history): one row when an address's set-up key, landing path or
# certificate changes from this host's previous artifact. The table's CHECK allows five
# change types; 'attribute_changed' is the one the live asset page leaves out of its
# "Recent stack changes" panel, so nothing new shows on the portal until its own push.
HISTORY_CATEGORY = "device_clues"
HISTORY_CHANGE = "attribute_changed"
HISTORY_CONFIDENCE = "medium"
HISTORY_FIELDS = ("group_key", "landing_path", "cert_sha256")

_PRINTABLE = re.compile(r"[^\x20-\x7e]")


# ── small helpers (pure) ───────────────────────────────────────────────────────

def clean(text, n=MAX_TITLE):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return _PRINTABLE.sub("?", " ".join(str(text).split()))[:n]


def mmh3_32(data, seed=0):
    """MurmurHash3 x86 32-bit, signed, as the mmh3 library (and public icon lists) give."""
    c1, c2, m = 0xcc9e2d51, 0x1b873593, 0xffffffff
    h, n = seed & m, len(data)
    r = n & ~3
    for i in range(0, r, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        k = (k * c2) & m
        h ^= k
        h = ((h << 13) | (h >> 19)) & m
        h = (h * 5 + 0xe6546b64) & m
    k, t = 0, n & 3
    if t == 3:
        k ^= data[r + 2] << 16
    if t >= 2:
        k ^= data[r + 1] << 8
    if t >= 1:
        k ^= data[r]
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        k = (k * c2) & m
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85ebca6b) & m
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & m
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def icon_hash(data):
    """The public favicon hash: murmur3 of the base64 text with a newline every 76 chars."""
    return mmh3_32(base64.encodebytes(data))


# ── the certificate, read from its bytes (nothing is judged) ───────────────────

def _tlv(b, i):
    tag = b[i]
    ln = b[i + 1]
    i += 2
    if ln & 0x80:
        nb = ln & 0x7f
        ln = int.from_bytes(b[i:i + nb], "big")
        i += nb
    if i + ln > len(b):
        raise ValueError("short")
    return tag, i, i + ln


def _kids(b, s, e):
    out, i = [], s
    while i < e:
        t, vs, ve = _tlv(b, i)
        out.append((t, vs, ve))
        i = ve
    return out


_OIDS = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU", b"\x55\x04\x06": "C"}


def _name(b, s, e):
    parts = []
    for _, rs, re_ in _kids(b, s, e):              # SET
        for _, as_, ae in _kids(b, rs, re_):       # SEQUENCE {OID, value}
            kv = _kids(b, as_, ae)
            if len(kv) >= 2 and kv[0][0] == 0x06:
                key = _OIDS.get(bytes(b[kv[0][1]:kv[0][2]]))
                if key:
                    parts.append("%s=%s" % (key, clean(bytes(b[kv[1][1]:kv[1][2]]), 80)))
    return ", ".join(parts)


def read_cert(der):
    """{sha256, serial, subject, issuer, names[<=20]} from a DER certificate. PURE.
    Unreadable fields leave only the sha256 (and unreadable: true)."""
    info = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        _, cs, ce = _tlv(der, 0)
        _, ts, te = _kids(der, cs, ce)[0]
        f = _kids(der, ts, te)
        if f[0][0] == 0xa0:
            f = f[1:]
        info["serial"] = bytes(der[f[0][1]:f[0][2]]).lstrip(b"\x00").hex()
        info["issuer"] = _name(der, f[2][1], f[2][2])
        info["subject"] = _name(der, f[4][1], f[4][2])
        names = []
        for t, s, e in f[6:]:
            if t != 0xa3:
                continue
            for _, xs, xe in _kids(der, *_kids(der, s, e)[0][1:]):
                x = _kids(der, xs, xe)
                if bytes(der[x[0][1]:x[0][2]]) != b"\x55\x1d\x11":
                    continue
                _, gs, ge = _tlv(der, x[-1][1])
                for gt, vs, ve in _kids(der, gs, ge):
                    if gt == 0x82:
                        names.append(clean(bytes(der[vs:ve]), 80))
                    elif gt == 0x87 and ve - vs == 4:
                        names.append("IP " + ".".join(str(c) for c in der[vs:ve]))
        info["names"] = names[:MAX_NAMES]
    except (ValueError, IndexError):
        info["unreadable"] = True
    return info


# ── the wire (tests replace these) ─────────────────────────────────────────────

def _client_ctx(probe):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                # we read the certificate; we don't judge it
    if probe == "normal":
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        return ctx
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if probe == "tls12":
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    elif probe == "tls12-reversed":
        names = [c["name"] for c in ctx.get_ciphers() if c.get("protocol") == "TLSv1.2"]
        ctx.set_ciphers(":".join(reversed(names)))
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    elif probe == "tls12-older":
        ctx.set_ciphers(OLDER_CIPHERS)
        ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def _err(e):
    """A short, stable reason. Lesson 58: what was seen, never a guess at why."""
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, ssl.SSLError):
        return "tls:" + clean(getattr(e, "reason", None) or type(e).__name__, 40)
    return clean(type(e).__name__, 40)


def _left(end):
    return end - time.monotonic()


def _wait(end, cap):
    """How long the next single wait may take: the smaller of `cap` and what is left before
    `end`. Raises socket.timeout when nothing is left."""
    w = min(cap, _left(end))
    if w <= 0:
        raise socket.timeout("out of time")
    return w


def _open_tls(ip, sni, ctx, port, end):
    """Connect and finish the TLS handshake before `end` (time.monotonic()), or raise.
    The handshake runs non-blocking, so each of its waits is bounded by `end`, not only
    each single read. Returns the connected SSL socket, blocking, for the caller to close."""
    s = socket.create_connection((ip, port), timeout=_wait(end, CONNECT_S))
    try:
        ss = ctx.wrap_socket(s, server_hostname=sni, do_handshake_on_connect=False)
    except BaseException:
        s.close()
        raise
    try:
        ss.setblocking(False)
        while True:
            try:
                ss.do_handshake()
                break
            except ssl.SSLWantReadError:
                if not select.select([ss], [], [], _wait(end, READ_S))[0]:
                    raise socket.timeout("handshake")
            except ssl.SSLWantWriteError:
                if not select.select([], [ss], [], _wait(end, READ_S))[1]:
                    raise socket.timeout("handshake")
        ss.setblocking(True)
        return ss
    except BaseException:
        ss.close()
        raise


def handshake(ip, sni, probe, port=PORT, budget_s=PER_CONN_S):
    """One secure handshake; nothing is sent after it. Returns the record and the DER cert.
    Never longer than min(budget_s, PER_CONN_S)."""
    end = time.monotonic() + min(budget_s, PER_CONN_S)
    r = {"probe": probe, "ok": False}
    try:
        ctx = _client_ctx(probe)
    except (ssl.SSLError, ValueError) as e:
        r["error"] = "not possible here (%s)" % clean(type(e).__name__, 40)
        return r, None
    der = None
    ss = None
    try:
        ss = _open_tls(ip, sni, ctx, port, end)
        r.update(ok=True, version=ss.version(),
                 cipher=(ss.cipher() or [None])[0], alpn=ss.selected_alpn_protocol())
        der = ss.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as e:
        r["error"] = _err(e)
    finally:
        if ss is not None:
            try:
                ss.close()
            except OSError:
                pass
    return r, der


def _decode_body(body, headers):
    te = ",".join(v.lower() for k, v in headers if k.lower() == "transfer-encoding")
    if "chunked" in te:
        out, i = b"", 0
        while True:
            j = body.find(b"\r\n", i)
            if j < 0:
                break
            try:
                size = int(body[i:j].split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                break
            out += body[j + 2:j + 2 + size]
            i = j + 2 + size + 2
        body = out
    ce = ",".join(v.lower() for k, v in headers if k.lower() == "content-encoding")
    try:
        if "gzip" in ce:
            body = gzip.decompress(body)
        elif "deflate" in ce:
            body = zlib.decompress(body)
    except (OSError, zlib.error, EOFError):
        pass
    return body


def http_get(ip, sni, path, port=PORT, budget_s=PER_CONN_S):
    """One GET, as an ordinary browser visitor, no Cookie header. Returns
    (status, [(name, value), ...], body_bytes, None), or (None, None, None, reason).
    Never longer than min(budget_s, PER_CONN_S): reading stops at the deadline, keeping
    what had arrived."""
    end = time.monotonic() + min(budget_s, PER_CONN_S)
    hosthdr = sni or ip
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
           "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
           "Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
           % (path, hosthdr, UA)).encode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = b""
    ss = None
    try:
        ss = _open_tls(ip, sni, ctx, port, end)
        ss.settimeout(_wait(end, READ_S))
        ss.sendall(req)
        while len(raw) < MAX_BODY:
            try:
                ss.settimeout(_wait(end, READ_S))
                chunk = ss.recv(65536)
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            raw += chunk
    except (OSError, ssl.SSLError, ValueError) as e:
        return None, None, None, _err(e)
    finally:
        if ss is not None:
            try:
                ss.close()
            except OSError:
                pass
    if not raw:
        return None, None, None, "no answer"
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not m:
        return None, None, None, "not a web answer"
    headers = []
    for ln in lines[1:]:
        k, sep, v = ln.partition(b":")
        if sep:
            headers.append((k.decode("latin-1").strip(), v.decode("latin-1").strip()))
    return int(m.group(1)), headers, _decode_body(body, headers), None


def resolve_v4(hostname, timeout=RESOLVE_S):
    """The IPv4 addresses the name points at, sorted, at most MAX_ADDRESSES. An IP asset is
    itself. The lookup gets `timeout` seconds (it runs in a helper thread, since the system
    lookup has no timeout of its own); a lookup that has not answered by then counts as no
    address, and nothing is sent."""
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname or ""):
        return [hostname]
    box = {}

    def look():
        try:
            box["infos"] = socket.getaddrinfo(hostname, PORT, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            box["infos"] = []

    t = threading.Thread(target=look, daemon=True)
    t.start()
    t.join(max(0.0, timeout))
    return sorted({i[4][0] for i in box.get("infos") or []})[:MAX_ADDRESSES]


# ── reading one answer (pure) ──────────────────────────────────────────────────

def same_host_location(loc, hosthdr):
    """(path_only, param_names, follow_target) for a Location on the same host over https
    port 443; (None, None, None) for anywhere else (not followed). PURE."""
    if not loc:
        return None, None, None
    u = urlsplit(loc)
    try:
        port = u.port
    except ValueError:
        return None, None, None
    same = (not u.netloc) or ((u.hostname or "").lower() == (hosthdr or "").lower()
                              and u.scheme in ("", "https") and port in (None, 443))
    if not same:
        return None, None, None
    path = urljoin("/", u.path or "/")
    names = [clean(p.split("=", 1)[0], 30) for p in u.query.split("&") if p] if u.query else []
    target = path + ("?" + u.query if u.query else "")
    return clean(path, 200), names, target


def page_title(body):
    text = (body or b"")[:MAX_BODY].decode("utf-8", "replace")
    t = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return clean(html.unescape(t.group(1)), MAX_TITLE) if t else None


def _cookie_names(headers):
    return [clean(v.split("=", 1)[0], 40) for k, v in headers or () if k.lower() == "set-cookie"]


def _header(headers, name):
    for k, v in headers or ():
        if k.lower() == name:
            return clean(v, 80)
    return None


def setup_key(tls, header_names, server, icon_mmh3, icon_status):
    """'Same make and set-up', as far as these clues tell (trial4w.setup_key, unchanged):
    every handshake answer, the front page's header order, the Server line, the icon hash
    and status. NO certificate: a certificate is installed, not built in. One box with two
    internet lines can't be told from two identical boxes, so the words never claim more."""
    key = [[[t.get("ok"), t.get("version"), t.get("cipher"), t.get("alpn")] for t in tls],
           list(header_names or ()), server, icon_mmh3, icon_status]
    return hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()


def address_record(tls, cert, front, landed, icon):
    """One address's kept clues from what came back. PURE.
    tls: [{probe, ok, version, cipher, alpn, error}]; cert: read_cert() or None;
    front / landed / icon: {"status", "headers", "body", "error", "location"} or None
    (landed = the followed same-host redirect, None when not followed)."""
    answered_tls = any(t.get("ok") for t in tls)
    front_ok = bool(front and front.get("status") is not None)
    if not answered_tls and not front_ok:
        errs = {t.get("error") for t in tls} | {(front or {}).get("error")}
        quiet = errs <= {"timeout", "refused", "no answer", None}
        return {"outcome": NO_ANSWER if quiet else ERROR}
    rec = {"outcome": ANSWERED,
           "tls": [{k: t.get(k) for k in ("probe", "ok", "version", "cipher", "alpn")} for t in tls]}
    if cert:
        rec["cert"] = {k: cert[k] for k in ("sha256", "serial", "subject", "issuer", "names") if k in cert}
    landing, params, title = None, [], None
    if front_ok:
        fh = front.get("headers") or []
        if front["status"] in REDIRECTS:
            path, names, _ = same_host_location(_header_raw(fh, "location"), front.get("host"))
            landing, params = path, (names or [])     # None: sent elsewhere, not followed
        else:
            landing = "/"
        page = landed if (landed and landed.get("status") is not None) else front
        title = page_title(page.get("body"))
        rec.update(header_names=[clean(k, 40) for k, _ in fh][:MAX_HEADERS],
                   server=_header(fh, "server"), x_powered_by=_header(fh, "x-powered-by"))
    rec["landing_path"] = landing
    rec["landing_param_names"] = params
    if title:
        rec["title"] = title
    cookies = []
    for r in (front, landed, icon):
        for n in _cookie_names((r or {}).get("headers")):
            if n and n not in cookies:
                cookies.append(n)
    rec["set_cookie_names"] = cookies[:MAX_NAMES]
    ic = {}
    if icon and icon.get("status") is not None:
        ic["status"] = icon["status"]
        body = icon.get("body") or b""
        if icon["status"] == 200 and body:
            ic["mmh3"] = icon_hash(body)
            ic["sha256"] = hashlib.sha256(body).hexdigest()
    rec["icon"] = ic or None
    rec["group_key"] = setup_key(tls, rec.get("header_names"), rec.get("server"),
                                 ic.get("mmh3"), ic.get("status"))
    return rec


def _header_raw(headers, name):
    for k, v in headers or ():
        if k.lower() == name:
            return v
    return None


def artifact(hostname, tier, addresses, collected_at=None):
    """The one artifact per scan run. PURE.
    landing_paths: every answering address's landing path; null when none answered GET /
    on this host (the classifier's capability rule: null = did not look, so a timeout never
    strips a class). cert_subject: the first answering address's (sorted by address)."""
    answered = [addresses[ip] for ip in sorted(addresses) if addresses[ip].get("outcome") == ANSWERED]
    paths = sorted({a["landing_path"] for a in answered if a.get("landing_path")})
    subject = next((a["cert"].get("subject") for a in answered
                    if (a.get("cert") or {}).get("subject")), None)
    cookies = []
    for a in answered:
        for n in a.get("set_cookie_names") or []:
            if n not in cookies:
                cookies.append(n)
    return {"schema": SCHEMA,
            "collected_at": collected_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tier": tier, "hostname": hostname, "addresses": addresses,
            "landing_paths": paths or None, "cert_subject": subject,
            "set_cookie_names": cookies[:MAX_NAMES]}


def summary(art):
    """One log line. PURE."""
    a = (art or {}).get("addresses") or {}
    n = sum(1 for r in a.values() if r.get("outcome") == ANSWERED)
    paths = ", ".join(art.get("landing_paths") or []) or "none"
    groups = len({r.get("group_key") for r in a.values() if r.get("group_key")})
    return "%d address(es), %d answered; landing %s; %d set-up key(s)" % (len(a), n, paths, groups)


# ── one host ───────────────────────────────────────────────────────────────────

def collect(hostname, tier, *, resolve=resolve_v4, shake=handshake, get=http_get,
            sleep=time.sleep, clock=time.monotonic, log=None):
    """Collect the clues for every address the name points at. The wire functions and the
    clock are injected so tests send nothing. Never raises for a target's behaviour.

    The whole host, name lookup included, is done within BUDGET_S (code review 2026-11-05,
    must-fix 1): each connection is given only what is left of it, and none starts once
    nothing is. An address cut short keeps NO clues ({"outcome": "cut_short"}): half a
    reading is not a reading, and to the classifier it is "did not look"."""
    sni = None if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname or "") else hostname
    hosthdr = sni or hostname
    deadline = clock() + BUDGET_S
    addresses = {}
    sent = 0
    first = True

    def left():
        return deadline - clock()

    def pause():
        w = min(STEP_S, left())
        if w > 0:
            sleep(w)

    def conn(fn, *args):
        """One connection with what is left, or None when nothing is."""
        nonlocal sent
        w = left()
        if w <= 0:
            return None
        sent += 1
        return fn(*args, budget_s=w)

    for ip in resolve(hostname, timeout=max(0.0, min(RESOLVE_S, left()))):
        if left() <= 0:
            if log:
                log("  %s: out of time before %s; not sent" % (TOOL_NAME, ip))
            break
        tls, cert, front, landed, icon, cut = [], None, None, None, None, False
        for probe in PROBES:
            if not first:
                pause()
            first = False
            res = conn(shake, ip, sni, probe)
            if res is None:
                cut = True
                break
            r, der = res
            tls.append(r)
            if der and cert is None:
                cert = read_cert(der)
        if not cut:
            pause()
            res = conn(get, ip, sni, "/")
            cut = res is None
            front = None if cut else _page(res, hosthdr)
        if not cut and front.get("status") in REDIRECTS:
            _, _, target = same_host_location(_header_raw(front.get("headers"), "location"), hosthdr)
            if target:
                pause()
                res = conn(get, ip, sni, target)
                cut = res is None
                landed = None if cut else _page(res, hosthdr)
        if not cut:
            pause()
            res = conn(get, ip, sni, "/favicon.ico")
            cut = res is None
            icon = None if cut else _page(res, hosthdr)
        if cut:
            addresses[ip] = {"outcome": CUT_SHORT}
            if log:
                log("  %s: %s cut short at the host's %ss limit; kept nothing from it"
                    % (TOOL_NAME, ip, int(BUDGET_S)))
            break
        addresses[ip] = address_record(tls, cert, front, landed, icon)
    return artifact(hostname, tier, addresses), sent


def _page(res, hosthdr):
    status, headers, body = res[0], res[1], res[2]
    err = res[3] if len(res) > 3 else None
    return {"status": status, "headers": headers or [], "body": body, "error": err, "host": hosthdr}


# ── history (asset_tech_history) ───────────────────────────────────────────────

def history_values(addr):
    """The three values a change is judged on, for one answering address. PURE."""
    return {"group_key": addr.get("group_key"), "landing_path": addr.get("landing_path"),
            "cert_sha256": (addr.get("cert") or {}).get("sha256")}


def plan_history_rows(prev, cur):
    """Rows for addresses that answered in BOTH this artifact and the host's previous one and
    whose set-up key, landing path or certificate changed. A first artifact, a new address or
    a gone one writes nothing (names and addresses moving is the DNS job's, 5a). PURE."""
    rows = []
    pa = (prev or {}).get("addresses") or {}
    ca = (cur or {}).get("addresses") or {}
    for ip in sorted(ca):
        a, b = pa.get(ip) or {}, ca[ip]
        if a.get("outcome") != ANSWERED or b.get("outcome") != ANSWERED:
            continue
        old, new = history_values(a), history_values(b)
        changed = [f for f in HISTORY_FIELDS if old.get(f) != new.get(f)]
        if changed:
            rows.append({"item_key": ip, "prior_value": dict(old), "new_value": dict(new, changed=changed)})
    return rows


SELECT_PREVIOUS_SQL = """
SELECT a.content_jsonb::text AS blob
  FROM public.scan_run_artifacts a
  JOIN public.scan_run r ON r.scan_run_id = a.scan_run_id
 WHERE r.asset_id = %(asset_id)s AND a.tool_name = %(tool)s
   AND r.scan_run_id::text <> %(scan_run_id)s
 ORDER BY r.completed_at DESC NULLS LAST, r.started_at DESC NULLS LAST
 LIMIT 1
"""

# scan_id is deliberately absent (software_inventory's reason: it references the legacy
# scans table); the scan_run id goes in notes.
INSERT_HISTORY_SQL = """
INSERT INTO public.asset_tech_history
    (asset_id, category, item_key, name, version, prior_value, new_value,
     change_type, confidence, source, notes)
VALUES (%(asset_id)s, %(category)s, %(item_key)s, %(name)s, NULL, %(prior_value)s,
        %(new_value)s, %(change_type)s, %(confidence)s, %(source)s, %(notes)s)
"""


def current_artifact(artifacts):
    """This run's device_clues artifact (a dict) from ctx.artifacts, or None. PURE."""
    for item in artifacts or ():
        try:
            name, _fmt, content = item
        except (TypeError, ValueError):
            continue
        if name == TOOL_NAME:
            try:
                obj = json.loads(content)
            except (TypeError, ValueError):
                return None
            return obj if isinstance(obj, dict) else None
    return None


def record_history(cur, asset_id, scan_run_id, artifacts, tier, Json, log=None) -> int:
    """Write the change rows. Returns how many, or -1 if the write failed (rolled back to its
    savepoint: the caller's transaction and its findings are untouched). Never raises."""
    art = current_artifact(artifacts)
    if not art:
        return 0
    made = False
    try:
        # Inside the try (code review minor 3): a savepoint that cannot be made is a failed
        # history write too, never an exception in the writer.
        cur.execute("SAVEPOINT device_clues_history")
        made = True
        cur.execute(SELECT_PREVIOUS_SQL, {"asset_id": asset_id, "tool": TOOL_NAME,
                                          "scan_run_id": str(scan_run_id)})
        row = cur.fetchone()
        blob = (row.get("blob") if isinstance(row, dict) else (row[0] if row else None)) if row else None
        prev = json.loads(blob) if blob else None
        rows = plan_history_rows(prev if isinstance(prev, dict) else None, art)
        for r in rows:
            cur.execute(INSERT_HISTORY_SQL, {
                "asset_id": asset_id, "category": HISTORY_CATEGORY, "item_key": r["item_key"],
                "name": "web answer at %s" % r["item_key"],
                "prior_value": Json(r["prior_value"]), "new_value": Json(r["new_value"]),
                "change_type": HISTORY_CHANGE, "confidence": HISTORY_CONFIDENCE,
                "source": tier, "notes": "scan_run %s" % scan_run_id})
        cur.execute("RELEASE SAVEPOINT device_clues_history")
        if log and rows:
            log("  device clues: %d change row(s)" % len(rows))
        return len(rows)
    except Exception as e:  # noqa: BLE001 — never let the history cost the findings
        if made:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT device_clues_history")
            except Exception:
                pass
        if log:
            log("  ⚠ device clues history not saved: %s: %s" % (type(e).__name__, str(e)[:200]))
        return -1


def record_from_ctx(cur, ctx, tier, Json, log=None) -> int:
    """The one call each tier's writer makes (software_inventory.record_from_artifacts'
    shape): this run's device_clues artifact against the host's previous one. A run that
    collected no clues writes nothing and touches nothing."""
    artifacts = getattr(ctx, "artifacts", None)
    if not current_artifact(artifacts):
        return 0
    return record_history(cur, ctx.asset_id, ctx.scan_run_id, artifacts, tier, Json, log=log)
