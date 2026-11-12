#!/usr/bin/env python3
"""signin_door.py — name the sign-in in front of a site and read its version. LOOK-ONLY.

Howie, 2026-11-12 13:15: "we want to identify a vulnerability, not exploit it. That's the
key." 13:19: "If we're able to identify a security device that is protecting an asset, we
should know what its vulnerabilities are." Decision D-077 (same day) allows the deep scan
at most TWO plain page loads on a site that redirects to its own /oauth2/start:

  request 1   GET <prefix>/sign_in
  request 2   GET <prefix>/callback   with NOTHING attached, and only when
                - request 1 looked like or said OAuth2 Proxy,
                - request 1 showed no version of any kind, and
                - a person switched this site's attack tests on
                  (assets.active_probe_authorized; D-064 made that switch the place a
                  person confirms the server is ours).

Nothing is submitted, no cookie is sent, no redirect is followed, no other host is
contacted, no flaw is tried. Neither request is a sign-in attempt: a sign-in needs a code
from the identity provider and none is sent. Request 2 deliberately draws the sign-in's
own ERROR page, because OAuth2 Proxy prints "Secured with OAuth2 Proxy version vX.Y.Z" on
its sign-in page and its error page unless the owner turned that footer off.

TWO GRADES OF EVIDENCE, NEVER MIXED (plan-name-the-sign-in, outside review point 2):
  "says"        the page's own footer wording: product name and version side by side.
                Only this names the product. Even then the page says what it DISPLAYS:
                everything downstream says "shows", never "runs" as a proven fact.
  "looks_like"  a response cookie whose NAME begins _oauth2_proxy, or the product's name
                somewhere on the page without the footer wording. Another program could
                do either. Never stated as fact, never a finding. Its one use is to
                justify request 2.

RULE 3r (Howie, 2026-10-22; "Keep the rule." 2026-11-12): a version must be SEEN before
any published flaw is listed. This module only records what was seen. It lists no flaw and
writes no finding; advisory_watch.py does that from the artifact, in a later push.

WHEN AN ARTIFACT IS WRITTEN: one `signin_door` artifact per deep scan of a site whose
home page redirects to its own /oauth2/start (also when the phase is switched off, saying
so). A site that does not qualify gets none, and neither does a run where the phase
itself failed: a missing artifact means "nothing was looked at", never "nothing there".

WHAT IS KEPT (artifact `signin_door`): the grade, the evidence for it, the version or
None, which page showed it, the HOST the sign-in hands off to, each request's path and
status, and the matched footer line. NOT the page, NOT a cookie value, nothing after a "?".

PURE: no network, no subprocess, no clock, no database. run_heavy.py does the I/O.
Byte-identical in both scanner repos.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

SCHEMA = 1
PRODUCT = "OAuth2 Proxy"
PRODUCT_KEY = "oauth2_proxy"

GRADE_SAYS = "says"
GRADE_LOOKS_LIKE = "looks_like"
GRADE_NONE = "none"

# The only redirect shape that qualifies: OAuth2 Proxy's default prefix. A site that
# moved the prefix (--proxy-prefix) is simply not looked at; guessing prefixes would be
# address guessing, and that is not what D-077 allows.
START_PATH = "/oauth2/start"
PREFIX = "/oauth2"
SIGN_IN = PREFIX + "/sign_in"
CALLBACK = PREFIX + "/callback"
ECHO_PARAM = "rd"

COOKIE_PREFIX = "_oauth2_proxy"
MAX_BODY_BYTES = 200_000          # a sign-in or error page is a few KB; never read more
MAX_FOOTER_CHARS = 160
MAX_VERSION_RAW_CHARS = 40
PACING_S = 5.0                    # between request 1 and request 2

# "OAuth2 Proxy</a> version v7.15.5" (or without the link). Product name and a
# version-looking token (it must start with a digit, after an optional v) SIDE BY SIDE: a
# version anywhere else on the page (another product's, or one in a link) is never taken
# (trial 2's outside review, must-fix 1), and "OAuth2 Proxy version of our portal" in an
# owner's own footer is a mention, not the product's footer.
_FOOTER = re.compile(
    r"oauth2[ -]?proxy(?:\s*</a>)?\s{0,3}version\s{0,3}(v?\d[0-9A-Za-z.+_-]{0,39})",
    re.I)
_RELEASE = re.compile(r"^v?(\d{1,3}\.\d{1,3}\.\d{1,3})$")
_MENTION = re.compile(r"oauth2[ -]?proxy", re.I)
_PRINTABLE = re.compile(r"[^\x20-\x7e]")
_AFTER_QUERY = re.compile(r"\?[^\"'<>]*")


def clean(text, limit: int) -> str:
    """Printable ASCII only, one line, nothing after a '?', at most `limit` characters.
    Everything a site sends passes through here before it is kept or logged. PURE."""
    s = str(text or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    s = _PRINTABLE.sub("", s)
    s = _AFTER_QUERY.sub("?<cut>", s)
    return re.sub(r" {2,}", " ", s).strip()[:limit]


def flatten(body) -> str:
    """The page as one printable line, capped. Tabs and line ends become spaces first, so
    a footer broken across lines still reads as one. PURE."""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body[:MAX_BODY_BYTES]).decode("utf-8", "replace")
    s = str(body or "")[:MAX_BODY_BYTES]
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return re.sub(r" {2,}", " ", _PRINTABLE.sub("", s))


def qualifies(location, hostname) -> bool:
    """Does the home page's redirect go to THIS host's own /oauth2/start, carrying rd=?
    HTTPS only; the same host only (a path-only Location is the same host); the default
    prefix only. Anything else: no request is sent. PURE."""
    loc = str(location or "").strip()
    host = str(hostname or "").strip().lower().rstrip(".")
    if not loc or not host:
        return False
    try:
        u = urlsplit(loc)
    except ValueError:
        return False
    if u.scheme or u.netloc:
        if u.scheme.lower() != "https":
            return False
        try:
            target = (u.hostname or "").lower().rstrip(".")
            port = u.port
        except ValueError:
            return False
        if target != host or port not in (None, 443):
            return False
    # No scheme and no host: a path-only Location, which is this same host. Anything
    # that is not exactly the start path (a relative "oauth2/start" included) fails below.
    if u.path != START_PATH:
        return False
    return ECHO_PARAM in parse_qs(u.query, keep_blank_values=True)


def _loads(payload):
    if isinstance(payload, dict):
        return payload
    try:
        v = json.loads(payload)
    except (TypeError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def home_location(artifacts) -> str | None:
    """The Location the home page redirected to, from what THIS scan already collected
    (httpx's record, or the methods check's raw headers). No new request. Returns the
    first redirect found, or None. PURE."""
    for item in (artifacts or []):
        try:
            name, _kind, payload = item
        except (TypeError, ValueError):
            continue
        if name in ("httpx", "httpx_tech"):
            for line in str(payload or "").splitlines() if isinstance(payload, str) else [payload]:
                rec = _loads(line)
                if not rec:
                    continue
                try:
                    status = int(rec.get("status_code") or 0)
                except (TypeError, ValueError):
                    status = 0
                if 300 <= status <= 399 and rec.get("location") and str(rec.get("path") or "/") == "/":
                    return str(rec["location"])
        elif name == "methods_check":
            rec = _loads(payload)
            raw = str((rec or {}).get("raw") or "")
            first = raw.splitlines()[0] if raw.strip() else ""
            m = re.match(r"HTTP/[\d.]+\s+(\d{3})", first)
            if m and m.group(1).startswith("3"):
                for ln in raw.splitlines()[1:]:
                    if ln[:9].lower() == "location:":
                        return ln.split(":", 1)[1].strip()
    return None


def curl_args(hostname: str, path: str, body_path: str, user_agent: str) -> list[str]:
    """The ONE request, as argv. Headers to stdout, body to a file. PURE (unit-tested).

    What is deliberately NOT here: --location (a redirect is recorded, never followed),
    --cookie / --cookie-jar (no cookie sent or kept), --data / --request (a plain GET,
    nothing submitted), --user or any --header (no credential, no header of ours),
    --insecure (the certificate is checked: a version read through a broken certificate
    is not one to repeat)."""
    if path not in (SIGN_IN, CALLBACK):
        raise ValueError(f"signin_door sends only {SIGN_IN} and {CALLBACK}, not {path!r}")
    # --disable FIRST: curl must not read a .curlrc, which could add a cookie, a body, a
    # credential or a second address that this list never shows (outside review of this
    # push, must-fix 1). Long option names only, so the test can hold this list to an
    # exact allowlist.
    return ["curl", "--disable", "--silent", "--show-error", "--max-time", "15", "--max-redirs", "0",
            "--max-filesize", str(MAX_BODY_BYTES * 10),
            "--proto", "=https", "--proto-redir", "=https",
            "--user-agent", user_agent, "--output", body_path, "--dump-header", "-",
            f"https://{hostname}{path}"]


def parse_headers(raw) -> dict:
    """Status, cookie NAMES, and the HOST a redirect points at, from a raw header block.
    Keeps the LAST response block. No cookie value and nothing of a Location but its host
    ever leaves this function. PURE."""
    status, names, to_host = 0, [], None
    for line in str(raw or "").splitlines():
        line = line.rstrip("\r")
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", line, re.I)
        if m:
            status, names, to_host = int(m.group(1)), [], None
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "set-cookie":
            name = _PRINTABLE.sub("", val.split("=", 1)[0]).strip()[:80]
            if name and name not in names:
                names.append(name)
        elif key == "location":
            try:
                u = urlsplit(val)
                to_host = (u.hostname or "").lower() or None
            except ValueError:
                to_host = None
    return {"status": status, "cookie_names": names, "location_host": to_host}


def read_page(body) -> dict:
    """What the page says about itself. PURE.
    footer_line   the matched footer wording, cleaned, or None
    version       a plain release number (7.15.5), or None
    version_raw   what stood where the version goes, when it is NOT a plain release
                  number (a development build, "undefined"): shown, but not a version
                  rule 3r can use
    mention       the product's name appears somewhere, without the footer wording"""
    page = flatten(body)
    m = _FOOTER.search(page)
    if not m:
        return {"footer_line": None, "version": None, "version_raw": None,
                "mention": bool(_MENTION.search(page))}
    token = m.group(1).rstrip(".")
    rel = _RELEASE.match(token)
    return {"footer_line": clean(m.group(0), MAX_FOOTER_CHARS),
            "version": rel.group(1) if rel else None,
            "version_raw": None if rel else clean(token, MAX_VERSION_RAW_CHARS),
            "mention": True}


def looked_at(path: str, curl_rc, raw_headers, body) -> dict:
    """One request's outcome, reduced to what may be kept. PURE.
    A request with no HTTP answer is `answered: False`. It is never called blocked
    (lesson 58): silence is "no answer"."""
    hdr = parse_headers(raw_headers)
    answered = bool(hdr["status"])
    page = read_page(body) if answered else {"footer_line": None, "version": None,
                                             "version_raw": None, "mention": False}
    evidence = []
    if page["footer_line"]:
        evidence.append("footer")
    elif page["mention"]:
        evidence.append("page_mention")
    if any(n.lower().startswith(COOKIE_PREFIX) for n in hdr["cookie_names"]):
        evidence.append("cookie_name")
    grade = (GRADE_SAYS if "footer" in evidence
             else GRADE_LOOKS_LIKE if evidence else GRADE_NONE)
    return {"path": path, "answered": answered, "status": hdr["status"] or None,
            "curl_rc": curl_rc if isinstance(curl_rc, int) else None,
            "grade": grade, "evidence": evidence,
            "cookie_names": hdr["cookie_names"][:10],
            "hands_off_to": hdr["location_host"],
            "footer_line": page["footer_line"], "version": page["version"],
            "version_raw": page["version_raw"]}


def wants_second(first: dict) -> bool:
    """Is request 2 worth asking for? Only when request 1 looked like or said OAuth2
    Proxy and showed NO version of any kind. D-077 says "without showing a version": a
    development build's version is still a version shown, so it also means no request 2
    (outside review of this push, must-fix 2). PURE."""
    return (bool(first) and first.get("answered") is True
            and first.get("grade") in (GRADE_SAYS, GRADE_LOOKS_LIKE)
            and not first.get("version") and not first.get("version_raw"))


def second_decision(first: dict, authorized: bool, policy_reason: str = "") -> tuple[bool, str]:
    """(send request 2?, why). Fail closed: an unreadable policy is not a yes. PURE."""
    if not wants_second(first):
        if not first or first.get("answered") is not True:
            return False, "first_request_no_answer"
        return False, ("version_already_shown"
                       if (first.get("version") or first.get("version_raw"))
                       else "first_request_named_nothing")
    if policy_reason == "__unreadable__":
        return False, "policy_unreadable"
    if not authorized:
        return False, "site_not_switched_on"
    return True, "sent"


def build_record(hostname: str, checked_at: str, live: bool, redirect: bool,
                 first: dict | None = None, second: dict | None = None,
                 second_why: str | None = None) -> dict:
    """The `signin_door` artifact. The better grade of the two requests wins; a version
    comes only from a "says" page. PURE."""
    rec = {"schema": SCHEMA, "hostname": hostname, "checked_at": checked_at,
           "live_flag": bool(live), "qualifying_redirect": bool(redirect),
           "product": None, "product_key": None, "grade": GRADE_NONE, "evidence": [],
           "version": None, "version_raw": None, "version_from": None,
           "hands_off_to": None, "footer_line": None,
           "requests": [], "second_request": second_why}
    looks = [r for r in (first, second) if r]
    for r in looks:
        rec["requests"].append({"path": r["path"], "answered": r["answered"],
                                "status": r["status"], "curl_rc": r["curl_rc"]})
        for e in r["evidence"]:
            if e not in rec["evidence"]:
                rec["evidence"].append(e)
        # Who the sign-in hands off to: the HOST only, and only when it is another host
        # (a redirect back to this site says nothing about an identity provider).
        if (r.get("hands_off_to") and not rec["hands_off_to"] and r["path"] == SIGN_IN
                and r["hands_off_to"] != str(hostname or "").lower().rstrip(".")):
            rec["hands_off_to"] = r["hands_off_to"]
    says = [r for r in looks if r["grade"] == GRADE_SAYS]
    if says:
        best = next((r for r in says if r["version"]), says[0])
        rec.update(grade=GRADE_SAYS, product=PRODUCT, product_key=PRODUCT_KEY,
                   version=best["version"], version_raw=best["version_raw"],
                   footer_line=best["footer_line"],
                   version_from=("sign_in" if best["path"] == SIGN_IN else "error_page")
                   if (best["version"] or best["version_raw"]) else None)
    elif any(r["grade"] == GRADE_LOOKS_LIKE for r in looks):
        # Looks like it. NOT named: product stays None so nothing downstream can treat
        # a cookie name as a fact.
        rec["grade"] = GRADE_LOOKS_LIKE
    return rec
