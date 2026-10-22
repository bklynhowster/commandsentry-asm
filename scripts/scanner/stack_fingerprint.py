#!/usr/bin/env python3
"""stack_fingerprint.py — name a VPN gateway / edge firewall and read its version
from what it shows anyone, before login (KB 12 job 3c, plan 2026-10-22 0745).

Howie, 2026-10-22 07:28: "the fingerprinting of anything that's called the security
stack whether it's a Cisco VPN product or a Fortinet product and then to understand
what its individual respective unique vulnerabilities potentially could be".
Rulings (handoff 004, 2026-10-22 09:01, "Yes to all four."): the Cisco pre-login
hello is allowed; a FortiGate known only by its firmware build date gets a
"built <month>; N advisories since — confirm it's patched" finding.

Core rule ("proved by a harmless reaction"): every request below is one a normal
visitor or the vendor's own VPN client sends before anyone logs in. No username,
no password, no exploit, nothing that changes the device. Three GETs at most per
port, no retries, no redirects followed.

The checks are the requests of three reviewed public nuclei templates
(projectdiscovery/nuclei-templates @ 388f6de, all `severity: info`), sent by our
own code so the light tier needs no template corpus:

  * cisco-asa-detect       GET /  with `X-Aggregate-Auth: 1` (the AnyConnect
                           client's hello). An ASA answers 200 with an XML
                           <config-auth client="vpn"> document whose
                           <version who="sg"> is its software version.
  * cisco-asa-panel        GET /+CSCOE+/logon.html — the ASA's own WebVPN login
                           page (it links /+CSCOU+/portal.css).
  * fortinet-fortigate-panel  GET / — a FortiGate SSL-VPN answers 200 with
                           `top.location="/remote/login"`; the last 8 hex digits
                           of its ETag are the firmware build time (unix seconds).

Two artifacts, because the classifier counts DIFFERENT artifacts as independent
tells (4.7 R4-revised): the hello in `stack_id_vpn_hello`, the two page checks in
`stack_id_vpn_portal`. Both are written on every light HTTPS pass, matched or not:
"we looked and saw nothing" is a real verdict; a check that got no answer at all is
null ("did not look"), so the classifier's capability rule is key-not-null.

Pure except fetch(), which run_light passes in (tests pass a fake).
"""
from __future__ import annotations

import http.client
import re
import ssl
from datetime import datetime, timezone

HELLO_ARTIFACT = "stack_id_vpn_hello"
PORTAL_ARTIFACT = "stack_id_vpn_portal"
TOOL_NAME = "stack_fingerprint"
SCHEMA = 1

# 443 always; these only when the light port scan saw them open (FortiGate SSL-VPN
# is often moved off 443). 10443 is not in naabu's top-100, so it is checked only
# when something else opened it.
ALT_VPN_PORTS = (4443, 8443, 10443)
MAX_BODY = 65536
TIMEOUT_S = 10

ASA_HELLO_HEADERS = {"X-Aggregate-Auth": "1"}
ASA_HELLO_BODY = "TESTME"                       # exactly as cisco-asa-detect sends it
ASA_LOGON_PATH = "/+CSCOE+/logon.html"

_ASA_VERSION_RE = re.compile(r'<version who="sg">(.*?)</version>', re.S)
_ASA_RAW_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})(?:\((\d{1,4})\)(\d{1,4})?)?$")
_FGT_ETAG_RE = re.compile(r'"[\w\d]*-([0-9a-fA-F]{8})"')
_EARLIEST_BUILD = datetime(2010, 1, 1, tzinfo=timezone.utc)


# ── parsing (pure) ─────────────────────────────────────────────────────────────

def asa_version_dotted(raw):
    """ASA's own spelling -> NVD's. '9.16(4)48' -> '9.16.4.48'; '9.8(4)' -> '9.8.4';
    '9.18' -> '9.18'. Anything else -> None (never guessed). PURE."""
    if not isinstance(raw, str):
        return None
    m = _ASA_RAW_RE.match(raw.strip())
    if not m:
        return None
    return ".".join(p for p in m.groups() if p is not None)


def parse_asa_hello(status, body):
    """{'matched', 'version_raw', 'version'} from the hello's reply. PURE.
    Matched only on status 200 AND the AnyConnect config-auth document — a page
    that merely mentions Cisco is not the device answering its own client."""
    body = body or ""
    matched = status == 200 and 'config-auth client="vpn"' in body
    raw = None
    if matched:
        m = _ASA_VERSION_RE.search(body)
        raw = m.group(1).strip()[:40] if m else None
    return {"matched": matched, "status": status, "version_raw": raw,
            "version": asa_version_dotted(raw)}


def parse_asa_logon(status, body):
    """The ASA WebVPN login page (cisco-asa-panel's matchers). PURE."""
    body = body or ""
    matched = status == 200 and ("/+CSCOU+/portal.css" in body or "SSL VPN Service" in body)
    return {"matched": matched, "status": status}


def fortigate_build_date(etag, now=None):
    """ETag '"5f2-65d4c0a1"' -> '2024-02-20' (UTC). The last 8 hex digits are the
    build time in unix seconds (fortinet-fortigate-panel's extractor). Out of
    range (before 2010, or in the future) -> None. PURE."""
    if not isinstance(etag, str):
        return None
    m = _FGT_ETAG_RE.search(etag)
    if not m:
        return None
    try:
        when = datetime.fromtimestamp(int(m.group(1), 16), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    now = now or datetime.now(timezone.utc)
    if when < _EARLIEST_BUILD or when > now:
        return None
    return when.strftime("%Y-%m-%d")


def parse_fortigate_landing(status, body, etag, now=None):
    """A FortiGate SSL-VPN landing page and its build date. PURE."""
    body = body or ""
    matched = status == 200 and 'top.location="/remote/login";' in body
    return {"matched": matched, "status": status,
            "release_date": fortigate_build_date(etag, now) if matched else None}


# ── artifacts (pure) ───────────────────────────────────────────────────────────

def hello_artifact(hostname, asa):
    return {"schema": SCHEMA, "hostname": hostname, "asa_hello": asa}


def portal_artifact(hostname, asa_logon, fortigate):
    """fortigate: the first matched port's result, else the 443 result."""
    return {"schema": SCHEMA, "hostname": hostname,
            "asa_logon": asa_logon, "fortigate_sslvpn": fortigate}


def identified(hello, portal):
    """What the two artifacts name, for the log line. PURE."""
    out = []
    asa = (hello or {}).get("asa_hello") or {}
    if asa.get("matched"):
        v = asa.get("version_raw")
        out.append(f"Cisco ASA{(' ' + v) if v else ''} (VPN hello)")
    if ((portal or {}).get("asa_logon") or {}).get("matched"):
        out.append("Cisco ASA (WebVPN login page)")
    fg = (portal or {}).get("fortigate_sslvpn") or {}
    if fg.get("matched"):
        d = fg.get("release_date")
        out.append(f"FortiGate SSL-VPN{(' built ' + d) if d else ''}")
    return out


# ── the wire ───────────────────────────────────────────────────────────────────

def https_get(hostname, port, path, headers, body=None, timeout=TIMEOUT_S, user_agent=None):
    """One GET. Returns (status, body_text, etag) or (0, '', None) on any transport
    failure. No redirects, no retries, certificate not verified (we are reading
    what the device shows, not trusting it)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=ctx)
        h = {"Accept-Encoding": "identity"}
        if user_agent:
            h["User-Agent"] = user_agent
        h.update(headers or {})
        conn.request("GET", path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read(MAX_BODY)
        return resp.status, data.decode("utf-8", "replace"), resp.getheader("ETag")
    except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
        return 0, "", None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def run_checks(hostname, open_ports, fetch, now=None):
    """Send the checks; return (hello_artifact, portal_artifact, requests_sent).
    fetch(port, path, headers, body) -> (status, body, etag); status 0 = no answer.

    A check that got NO answer is recorded as null, not as "not matched": null
    means "did not look" to the classifier (capability = key not null), so a
    timeout can never demote a gateway identified on an earlier pass."""
    st, body, _ = fetch(443, "/", ASA_HELLO_HEADERS, ASA_HELLO_BODY)
    hello = hello_artifact(hostname, parse_asa_hello(st, body) if st else None)
    st, body, _ = fetch(443, ASA_LOGON_PATH, {}, None)
    asa_logon = parse_asa_logon(st, body) if st else None
    sent = 2
    fortigate = None
    ports = (443,) + tuple(p for p in ALT_VPN_PORTS if p in (open_ports or ()))
    for port in ports:
        st, body, etag = fetch(port, "/", {}, None)
        sent += 1
        if not st:
            continue
        res = dict(parse_fortigate_landing(st, body, etag, now), port=port)
        if fortigate is None or res["matched"]:
            fortigate = res
        if res["matched"]:
            break
    return hello, portal_artifact(hostname, asa_logon, fortigate), sent
