"""plain_http.py — does a site's plain http:// address send visitors to https? (KB 12 job 4f)

WHY THIS EXISTS (2026-11-01). Howie's ZAP GUI scan of commandcompanies.com (10:20) showed the
plain address http://www.commandcompanies.com answering 200 with the whole page (9 of 9
responses), not a redirect to https. Sentry never asked port 80 that question: the quick scan's
header check, the deep scan's httpx and testssl all start at https://. Howie, 10:30: "How do we
incorporate that and quantify its risk going forward?" Claude's plan followed; Howie: "That's
fine. I agree completely." 11:38: "Go 4F."

WHAT IT SENDS: ordinary GET requests on port 80 to the site's own name. The first is
http://<site>/. At most two more follow a redirect ONLY while it stays on plain http inside the
same domain (http://apex -> http://www.apex -> https://www.apex is a common, harmless chain).
Nothing is requested after a redirect to https, and no redirect off the domain or to another
port is followed. At most 3 requests. No credentials, nothing submitted, no other paths.

THE VERDICT, per site:
  * sent to https (a 3xx whose Location is https://...)                   -> no finding
  * no answer on port 80, or an error status (4xx/5xx, not a login prompt) -> no finding
  * a redirect that leaves the domain, or the port, over plain http       -> no finding (not
    our page to grade; recorded in the artifact)
  * a page served over plain http (2xx)                                    -> finding
  * a login prompt over plain http (401 with WWW-Authenticate)             -> finding

THE RATING (D-074: High only when exploitable; this needs an attacker on the visitor's own
network, so it is never High):
  * LOW by default. Someone on the same network as a visitor (public Wi-Fi, say) can read or
    change that page. Browsers try https first for a typed name more and more, and a site with
    HSTS sends anyone who has visited before straight to https.
  * MODERATE when the plain-http page has a password box, asks for a login, or has a form that
    collects personal details (an email, phone or message box); or when the https site sends no
    working Strict-Transport-Security header (absent, or max-age=0), so nothing ever moves a
    returning visitor to https.

NOT JUDGED (stated, not hidden): a site with no https at all (the quick scan's https suite, which
runs this, doesn't run there; that is the TLS checks' business); ports other than 80; a search
box alone (a search form doesn't collect personal details).

Pure apart from http_get(): follow() takes the fetch function, so the tests drive it with a fake.
"""
import http.client
import json
import re
from urllib.parse import urljoin, urlsplit

TOOL_NAME = "plain_http"
ARTIFACT = "plain_http"
CHECK_NAME = "http-not-sent-to-https"
TITLE = "Plain http:// does not send visitors to https"
MODERATE = "MODERATE"
LOW = "LOW"
MAX_REQUESTS = 3
TIMEOUT_S = 10
MAX_BODY = 262144

FINDING_OUTCOMES = ("serves_page", "login_prompt")

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_TWO_LEVEL = {"co.uk", "org.uk", "com.au", "net.au", "co.nz", "co.za", "com.br", "co.jp",
              "com.mx", "co.in", "com.cn"}
_PASSWORD = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.I)
_FORM = re.compile(r"<form\b", re.I)
_PERSONAL = re.compile(
    r"<input\b[^>]*\btype\s*=\s*[\"']?(email|tel)\b"
    r"|<textarea\b"
    r"|<input\b[^>]*\bname\s*=\s*[\"']?[^\"'>\s]*(e-?mail|phone)", re.I)
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.I)

_WHY_LOGIN = "it asks for a user name and password without encryption"
_WHY_PASSWORD = "the plain-http page has a password box"
_WHY_FORM = "the plain-http page has a form that collects personal details (an email, phone or message box)"
_WHY_NO_HSTS = ("the https site sends no working Strict-Transport-Security header, so browsers "
                "never learn to go straight to https")


# ── the wire ───────────────────────────────────────────────────────────────────
def http_get(host, path, timeout=TIMEOUT_S, user_agent=None):
    """One GET over plain http on port 80. Returns (status, headers, body) with header names in
    lower case, or (0, {}, "") on any transport failure. http.client never follows redirects."""
    conn = None
    try:
        conn = http.client.HTTPConnection(host, 80, timeout=timeout)
        h = {"Accept-Encoding": "identity", "Accept": "text/html,*/*;q=0.8"}
        if user_agent:
            h["User-Agent"] = user_agent
        conn.request("GET", path or "/", headers=h)
        resp = conn.getresponse()
        data = resp.read(MAX_BODY)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, data.decode("utf-8", "replace")
    except (OSError, ValueError, http.client.HTTPException):
        return 0, {}, ""
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# ── following the answer ───────────────────────────────────────────────────────
def site_domain(host):
    """The domain a redirect may stay inside: the last two labels (three under co.uk-style
    suffixes); an IP address is its own domain."""
    host = (host or "").lower().rstrip(".")
    if _IPV4.match(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _inside(host, domain):
    host = (host or "").lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def known_ports(open_ports):
    """The open ports a scan already knows, as ints. The quick scan keeps a set of ints; the deep
    scan keeps a list of dicts (port + protocol). Empty set = not known (ask anyway)."""
    out = set()
    for p in open_ports or ():
        if isinstance(p, dict):
            p = p.get("port")
        try:
            out.add(int(p))
        except (TypeError, ValueError):
            continue
    return out


def page_signals(body):
    """What on a plain-http page raises the rating: 'password', 'personal_form'."""
    out = []
    if _PASSWORD.search(body or ""):
        out.append("password")
    if _FORM.search(body or "") and _PERSONAL.search(body or ""):
        out.append("personal_form")
    return out


def follow(hostname, fetch, max_requests=MAX_REQUESTS):
    """Ask http://<hostname>/ and follow plain-http redirects inside the same domain.
    fetch(host, path) -> (status, headers, body); status 0 = no answer.
    Returns {'outcome', 'hops': [{url, status, location}], 'final_url', 'final_status',
             'signals'}. Outcomes: sent_to_https, serves_page, login_prompt, no_answer,
    error_status, left_over_http, redirect_without_location, redirect_loop, too_many_redirects."""
    domain = site_domain(hostname)
    url = "http://%s/" % hostname
    hops, seen = [], set()

    def done(outcome, **kw):
        res = {"outcome": outcome, "hops": hops, "final_url": url,
               "final_status": hops[-1]["status"] if hops else 0, "signals": []}
        res.update(kw)
        return res

    while True:
        parts = urlsplit(url)
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        status, headers, body = fetch(parts.hostname or hostname, path)
        headers = headers or {}
        location = headers.get("location")
        hops.append({"url": url, "status": status, "location": location})
        seen.add(url)
        if not status:
            return done("no_answer")
        if 300 <= status < 400:
            if not location:
                return done("redirect_without_location")
            nxt = urljoin(url, location.strip())
            p = urlsplit(nxt)
            if p.scheme == "https":
                return done("sent_to_https", target=nxt)
            if p.scheme != "http" or not _inside(p.hostname, domain) or p.port not in (None, 80):
                return done("left_over_http", target=nxt)
            if nxt in seen:
                return done("redirect_loop", target=nxt)
            if len(hops) >= max_requests:
                return done("too_many_redirects", target=nxt)
            url = nxt
            continue
        if 200 <= status < 300:
            return done("serves_page", signals=page_signals(body))
        if status == 401 and "www-authenticate" in headers:
            return done("login_prompt")
        return done("error_status")


# ── the rating and the words ───────────────────────────────────────────────────
def hsts_state(value):
    """The https site's Strict-Transport-Security, as the header check saw it: True when it tells
    browsers to remember https (max-age > 0), False when absent or max-age=0, None when unknown
    (the https header check didn't get an answer)."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    m = _MAX_AGE.search(str(value))
    return bool(m and int(m.group(1)) > 0)


def assess(result, hsts_value):
    """None (no finding) or {'severity', 'reasons'}."""
    if result.get("outcome") not in FINDING_OUTCOMES:
        return None
    reasons = []
    if result["outcome"] == "login_prompt":
        reasons.append(_WHY_LOGIN)
    if "password" in result.get("signals", []):
        reasons.append(_WHY_PASSWORD)
    if "personal_form" in result.get("signals", []):
        reasons.append(_WHY_FORM)
    if hsts_state(hsts_value) is False:
        reasons.append(_WHY_NO_HSTS)
    return {"severity": MODERATE if reasons else LOW, "reasons": reasons}


def _join(items):
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def artifact(hostname, result):
    """What every run records, finding or not ("looked, it redirects" is a real verdict)."""
    a = {"schema": 1, "hostname": hostname, "outcome": result.get("outcome"),
         "hops": result.get("hops", []), "signals": result.get("signals", [])}
    if result.get("target"):
        a["target"] = result["target"]
    return a


def finding_fields(hostname, result, hsts_value):
    """None, or the fields of the one finding for this site:
    {'check_name', 'title', 'severity', 'description', 'tags', 'raw_excerpt'}."""
    v = assess(result, hsts_value)
    if v is None:
        return None
    hops = result.get("hops", [])
    what = "a login prompt" if result["outcome"] == "login_prompt" else "the page itself"
    via = ""
    if len(hops) > 1:
        n = len(hops) - 1
        via = " after %d redirect%s that stayed on plain http" % (n, "" if n == 1 else "s")
    text = ("Asking for http://%s/ got %s (HTTP %s%s at %s) instead of being sent to https://. "
            "Anyone on the same network as a visitor (public Wi-Fi, for example) can read or change "
            "what that visitor sees and sends. " % (hostname, what, result.get("final_status"), via,
                                                     result.get("final_url")))
    hsts = hsts_state(hsts_value)
    if v["severity"] == MODERATE:
        text += "This rates Moderate because %s. " % _join(v["reasons"])
    elif hsts is True:
        text += ("It rates Low: an attacker has to be on the visitor's network, and the https "
                 "site's Strict-Transport-Security header sends returning visitors straight to https. ")
    else:
        text += ("It rates Low: an attacker has to be on the visitor's network. Whether the https "
                 "site sends Strict-Transport-Security is unknown (the https header check got no "
                 "answer). ")
    text += "The fix: answer every http:// request with a redirect to the same address on https://."
    tags = ["http", "cleartext", "no-https-redirect"]
    if result["outcome"] == "login_prompt":
        tags.append("login-over-http")
    if "password" in result.get("signals", []):
        tags.append("password-over-http")
    if "personal_form" in result.get("signals", []):
        tags.append("form-over-http")
    if hsts is False:
        tags.append("no-hsts")
    return {
        "check_name": CHECK_NAME,
        "title": TITLE,
        "severity": v["severity"],
        "description": text,
        "tags": tags,
        "raw_excerpt": json.dumps({"hops": hops, "signals": result.get("signals", [])})[:1500],
    }
