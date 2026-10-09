"""nuclei_auth_guard.py — D-056, FAIL-CLOSED: no login-type attack reaches a target.

⛔ D-056 (Howie, 2026-09-29, ABSOLUTE): no authentication-type attacks on any
asset at any tier. That means no default-credential or hardcoded-credential
logins, no password guessing, and no login- or auth-bypass probes, whether or
not the template sends a credential.
Confirmed scope, Howie 2026-10-08: "make sure that there are no credentials in
any scans", widened to bypass tricks and guessing. The separate authenticated-
scan option (an owner-supplied account) is NOT covered here.

WHY THIS FILE EXISTS. Relay 549 (#46, 2026-10-07) excluded login templates by
TAG. A tag denylist over an externally maintained library FAILS OPEN: a login
template the library forgot to tag still runs. Measured the same day: 51
templates TITLED "Authentication Bypass" / "Hardcoded Credentials" (46 of them
critical/high, so in every heavy scan) carried none of the excluded tags. One
of them is Fortinet CVE-2024-55591, which fires at Command's FortiGate fleet.

WHAT IT DOES. Before nuclei is pointed at a target, every template it would
run is opened and READ. A template is refused if ANY of these is true:
  1. its tags carry a login-attack tag (belt and braces over -exclude-tags);
  2. it lives under a default-login(s) directory;
  3. its name, description or impact says it is an authentication/login
     bypass, a default/hardcoded/weak credential, or a brute force;
  4. its CWE is an authentication-weakness CWE (list below);
  5. its REQUESTS carry a credential or claim an identity: a password field
     (even an empty one), a credential payload list, a log-in-first
     {{username}}/{{password}} variable, a literal Basic/Bearer Authorization
     header, a custom auth header, a cookie that says who you are (admin=,
     user=, auth=, role=), a login or password-reset endpoint, a USER/PASS/AUTH
     line on a raw socket (hex inputs decoded first), or a password in a
     javascript template or its flow;
  6. it cannot be read or parsed at all.
Rule 6 is what makes it FAIL-CLOSED: when in doubt, the template does not run.

WHAT IT DOES NOT DO. It reads REQUESTS, never matchers or extractors. A
template that only LOOKS FOR the word "password" in a response, for example
an exposed .env file or a config leak, is exposure detection and stays. So
does fetching a login page to fingerprint a product (exposed-panels). That is
attack-surface mapping, which is the product.

The caller (run_medium.py) runs nuclei ONLY with `-t <the allowed list>`.
It never runs a bare severity/tag filter. If this module cannot produce a
list, the chunk is refused and recorded as degraded. It does not fall back to
the full corpus.

PURE except for reading files. Stdlib + PyYAML (already in the scanner image,
docker/Dockerfile). Byte-identical in both repos.
"""
from __future__ import annotations

import os
import re
import tempfile

try:  # pragma: no cover - import guard exercised by test_guard_refuses_without_yaml
    import yaml
    _LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
except Exception:  # noqa: BLE001 — any import failure must refuse, not crash
    yaml = None
    _LOADER = None

# ── rule 1: tags. Superset of run_medium.NUCLEI_AUTH_EXCLUDE_TAGS (a test pins
# that), plus the library's own bruteforce tag.
AUTH_TAGS = frozenset("""
default-login default-logins auth-bypass authbypass auth-bupass login-bypass
authorization-bypass authz-bypass creds-stuffing token-spray authenticated
login-check hardcoded-credentials default-jwt default-secret broken-auth
bruteforce brute-force default-credentials default-password weak-password
weak-credentials
""".split())

# ── rule 2: directories that hold nothing but login attempts.
AUTH_DIR_RE = re.compile(r"(?:^|/)default-logins?(?:/|$)", re.I)

# ── rule 3: what the template says it is (name, description, impact).
_AUTH_NOUN = (r"(?:auth(?:entication|entification|orization|orisation|n)?|login|log[- ]?in|"
              r"sign[- ]?in|admin(?:istrator)?|access[- ]control|password|2fa|mfa|otp|sso|"
              r"saml|jwt|session)")
TEXT_RULES = (
    ("auth bypass", re.compile(
        r"\b" + _AUTH_NOUN + r"\s*(?:check\s*|validation\s*|verification\s*|protection\s*)?by-?pass", re.I)),
    ("auth bypass", re.compile(
        r"\bby-?pass(?:es|ed|ing)?\s+(?:the\s+|of\s+|an?\s+)?(?:[\w./'’-]+\s+){0,3}?"
        r"(?:auth\w*|login|log[- ]?in|sign[- ]?in|password|2fa|mfa)\b", re.I)),
    ("auth bypass", re.compile(
        r"\bauth(?:entication|orization)?\s+override\b|\boverrid(?:e|es|ing)\s+(?:the\s+)?auth\w*", re.I)),
    ("account takeover", re.compile(
        r"\b(?:account|admin(?:istrator)?|user)\s+take-?over\b", re.I)),
    ("account creation", re.compile(
        r"\b(?:arbitrary|unauthori[sz]ed|unauthenticated)\s+(?:admin(?:istrator)?\s+)?(?:user|account)\s+"
        r"(?:creation|registration)|\bcreat\w*\s+(?:an?\s+|new\s+)?admin(?:istrator)?\s+(?:user|account)s?|"
        r"\b(?:import|creat\w*|register\w*|add)\s+(?:new\s+)?(?:users?|accounts?)\s+with\s+"
        r"(?:arbitrary|any|admin\w*)\s+(?:roles?|privileges?)|\bregister\w*\s+as\s+(?:an?\s+)?admin", re.I)),
    ("password reset or change", re.compile(
        r"\bpassword\s+(?:reset|change|recovery)\b|\b(?:reset|chang\w*)\s+(?:the\s+|an?\s+|any\s+)?"
        r"(?:admin(?:istrator)?\s+|user\s+|victim\s+)?password", re.I)),
    ("default/hardcoded credential", re.compile(
        r"\b(?:default|hard[- ]?coded|weak|static|built[- ]?in|backdoor|blank|empty|"
        r"known|insecure)\s+(?:admin(?:istrator)?\s+|user\s+|root\s+|ssh\s+|admin\s+user\s+)?"
        r"(?:credential|password|passwd|login|account|creds|username)s?\b", re.I)),
    ("brute force or credential guessing", re.compile(
        r"\b(?:brute[- ]?forc\w*|credential[- ]?stuffing|password[- ]?spray\w*|"
        r"dictionary attack|(?:credential|user(?:name)?|account|login)\s+enumeration)", re.I)),
)

# A credential the template says it DISCLOSES ("may expose hardcoded
# credentials", "leaks the default password") is what an exposure check finds,
# not what an attack sends. Only the credential rule honours this; a bypass is
# a bypass however it is described.
_DISCLOSURE_RE = re.compile(
    r"(?:disclos\w*|expos\w*|leak\w*|reveal\w*|retriev\w*|obtain\w*|steal\w*|"
    r"read\w*|dump\w*|extract\w*|contain\w*|stor(?:e|es|ed|ing)|plain-?text|"
    r"clear-?text)\W+(?:\w+\W+){0,4}$", re.I)


def _is_disclosure(text: str, m) -> bool:
    if not m.group(0).lower().startswith(("default", "hard", "weak", "static", "built",
                                          "backdoor", "blank", "empty", "known", "insecure")):
        return False
    return bool(_DISCLOSURE_RE.search(text[max(0, m.start() - 60):m.start()]))


# ── rule 4: CWEs that ARE an authentication weakness, plus the authorization-
# bypass family (285, 639, 863) the run's own tags already treat as in scope.
# CWE-306 (missing authentication) and CWE-284 (access control, very broad)
# are deliberately NOT here: reaching something that should have required a
# login, without trying to defeat one, is exposure detection.
AUTH_CWES = frozenset("""
CWE-255 CWE-259 CWE-287 CWE-288 CWE-289 CWE-290 CWE-291 CWE-294 CWE-302
CWE-303 CWE-304 CWE-305 CWE-307 CWE-308 CWE-309 CWE-521 CWE-620 CWE-640
CWE-798 CWE-1390 CWE-1391 CWE-1392 CWE-1393
CWE-285 CWE-639 CWE-863
""".split())

# ── rule 5: what the REQUESTS send.
# A password FIELD is any parameter, JSON key or XML element whose name ends in
# one of these, optionally after a prefix (userPsw, inputpwd, adminpass) and
# before a digit or _confirm-style suffix (password_1). Empty values count: a
# login with an empty password is still a login.
_PW_CORE = r"(?:password|passwd|passwrd|passphrase|pass|pwd|psw|pw|credentials?)"
_PW_NAME_RE = re.compile(r"^[a-z0-9_.-]{0,24}?" + _PW_CORE + r"(?:[_-]?(?:\d+|confirm\w*|again|hash|md5|old|new))?$", re.I)
_NOT_PW = frozenset({"bypass", "compass", "passive", "passport", "passthrough", "pass_through",
                     "surpass", "trespass", "overpass", "underpass", "grass", "class", "pw_length"})
_FIELD_RES = (
    re.compile(r"(?:^|[?&\s;,{(])([A-Za-z0-9_.\-\[\]]{1,48})\s*="),        # form / query
    re.compile(r"[\"']([A-Za-z0-9_.\-\[\]]{1,48})[\"']\s*:"),             # JSON / dict
    re.compile(r"<\s*([A-Za-z0-9_.\-]{1,48})\s*>"),                        # XML element
)


def _has_password_field(text: str) -> bool:
    for rx in _FIELD_RES:
        for m in rx.finditer(text):
            for part in re.split(r"[\[\]]+", m.group(1).lower()):
                if part and part not in _NOT_PW and _PW_NAME_RE.match(part):
                    return True
    return False


# A cookie that SAYS who the caller is (admin=, user=, auth=, role=) is a
# forged identity, not a session we were given.
_COOKIE_LINE_RE = re.compile(r"(?im)^\s*cookie\s*:\s*(.*)$")
_IDENTITY_TOKENS = frozenset("""admin administrator auth authtoken authgroup authorization
superuser isadmin role login loggedin haslogin uid userid username uname account priv
privilege rememberme""".split())
# A cookie value that is just a {{variable}} is a session an earlier request was
# GIVEN. A {{function(...)}} value is built here, so it is checked like a literal.
_PLAIN_VAR_RE = re.compile(r"^\{\{\s*[A-Za-z_][\w.]*\s*\}\}")
_USER_ONLY = frozenset({"user", "username", "user_name", "userid", "user_id", "uname", "uid", "login"})


def _cookie_tokens(name: str) -> set:
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    toks = [t.lower() for t in re.split(r"[\s_.\-]+", parts) if t]
    joined = set()
    for i in range(len(toks) - 1):
        joined.add(toks[i] + toks[i + 1])        # "user","name" -> "username"
    return set(toks) | joined


def _has_identity_cookie(text: str) -> bool:
    for line in _COOKIE_LINE_RE.findall(text):
        for pair in line.split(";"):
            if "=" not in pair:
                continue
            name, value = (x.strip() for x in pair.split("=", 1))
            if not name or name.startswith("{{") or _PLAIN_VAR_RE.match(value):
                continue   # a session handed back by an earlier request, not a forged one
            if name.lower() in _USER_ONLY or (_cookie_tokens(name) & _IDENTITY_TOKENS):
                return True
    return False


REQUEST_RULES = (
    ("log-in-first variable", re.compile(
        r"\{\{\s*(?:username|pass(?:word|wd)?|pwd)\s*\}\}", re.I)),
    ("login endpoint", re.compile(
        r"j_security_check|j_spring_security_check|authenticatebyname|/users/authenticate\b", re.I)),
    # A password-RESET submission. POST only: fetching a reset page to see that
    # it exists is detection; submitting it is the attack.
    ("password-reset submission", re.compile(
        r"(?im)^\s*POST\s+\S*(?:action=(?:lostpassword|rp|resetpass)\b|forgot-?password|"
        r"reset-?password|password/reset|lostpassword)")),
    ("literal Basic credential", re.compile(
        r"authorization\s*:\s*basic\s+(?:[A-Za-z0-9+/]{6,}={0,2}|\{\{\s*base64)", re.I)),
    ("literal Bearer token", re.compile(
        r"authorization\s*:\s*bearer\s+(?!\{\{)[A-Za-z0-9\-_.=+/]{20,}", re.I)),
    ("custom auth header", re.compile(
        r"(?im)^\s*(?:auth|x-auth[\w-]*|x-(?:remote|forwarded|original|authenticated)-user|"
        r"remote-user|x-user(?:name|-id)?|x-api-key|api-key|x-access-token)\s*:\s*"
        r"(?!\{\{\s*[A-Za-z_][\w.]*\s*\}\}\s*$)\S")),
)
SOCKET_RULE = ("socket login line", re.compile(r"(?im)^\s*(?:USER|PASS|AUTH|LOGIN)\s+\S"))
JS_RULE = ("password in a javascript template", re.compile(r"\bpass(?:word|wd)s?\b|\.login\s*\(|\bauth\s*\(", re.I))
CRED_PAYLOAD_KEY = re.compile(
    r"^(?:user(?:name)?s?|pass(?:word|wd)?s?|pwds?|logins?|creds?|credentials?|"
    r"usernames?|passwords?)$", re.I)

HTTP_KEYS = ("http", "requests", "headless", "websocket")
SOCKET_KEYS = ("network", "tcp")
JS_KEYS = ("javascript",)
REQUEST_FIELDS = ("path", "raw", "body", "headers", "steps", "inputs", "address")

# A chunk whose corpus mostly cannot be read is not "mostly safe". It means the
# guard is looking in the wrong place, so the chunk is refused, not shrunk.
MAX_UNREADABLE_FRACTION = 0.10


def _flat(x) -> str:
    """Every string inside x, joined. Dict KEYS are included (header names)."""
    out = []
    stack = [x]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for k, vv in v.items():
                if isinstance(vv, (str, int, float)):
                    out.append(f"{k}: {vv}")
                else:
                    out.append(str(k))
                    stack.append(vv)
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
        elif v is not None:
            out.append(str(v))
    return "\n".join(out)


_LOGINISH_PATH_RE = re.compile(r"log-?[io]n|logon|sign-?in|session|auth|passw|pwd", re.I)
_RAW_POST_LINE_RE = re.compile(r"^\s*POST\s+(\S+)", re.I)


def _posts_to_a_login_path(blk: dict) -> bool:
    """A POST WITH A BODY to a path that names a login, sign-in, session, auth or
    password resource is a login submission, whatever its fields are called."""
    for raw in _as_list(blk.get("raw")):
        head, _, body = str(raw).lstrip().partition("\n\n") if "\r\n\r\n" not in str(raw) \
            else str(raw).lstrip().partition("\r\n\r\n")
        m = _RAW_POST_LINE_RE.match(head)
        if m and body.strip() and _LOGINISH_PATH_RE.search(m.group(1)):
            return True
    if str(blk.get("method", "")).upper() == "POST" and str(blk.get("body") or "").strip():
        return any(_LOGINISH_PATH_RE.search(str(p)) for p in _as_list(blk.get("path")))
    return False


def _check_request(req: str, reasons: list) -> None:
    if _has_password_field(req):
        reasons.append("request carries a password field")
    if _has_identity_cookie(req):
        reasons.append("request carries an identity cookie")
    for label, rx in REQUEST_RULES:
        if rx.search(req):
            reasons.append(f"request carries a {label}")


def _decoded_hex_inputs(inputs) -> str:
    """network inputs of `type: hex`, decoded, so a USER/PASS sent as hex is read."""
    out = []
    for inp in _as_list(inputs):
        if isinstance(inp, dict) and str(inp.get("type", "")).lower() == "hex":
            try:
                out.append(bytes.fromhex(re.sub(r"\s+", "", str(inp.get("data", "")))).decode("latin-1"))
            except ValueError:
                pass
    return "\n".join(out)


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [v]


def classify_doc(doc, relpath: str = "") -> list[str]:
    """Reasons a parsed template is refused. [] means it may run. PURE."""
    reasons: list[str] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        return ["unparseable (no info block)"]
    info = doc["info"]

    tags = info.get("tags") or ""
    tagset = {t.strip().lower() for t in (tags.split(",") if isinstance(tags, str) else _as_list(tags))
              if isinstance(t, str) and t.strip()}
    hit = sorted(tagset & AUTH_TAGS)
    if hit:
        reasons.append("tag " + ",".join(hit))

    if relpath and AUTH_DIR_RE.search(relpath.replace(os.sep, "/")):
        reasons.append("default-login directory")

    # Rules 3 and 4 read what the template SAYS about itself. nuclei's own
    # convention is that severity "info" is detection, not an attack: a panel
    # detect whose description mentions "default credentials", or a plugin
    # whose name is "... Brute Force Protection". So rules 3 and 4 skip info.
    # Rules 1, 2, 5 and 6 still apply to info: an info template that SENDS a
    # credential is refused like any other.
    severity = str(info.get("severity") or "").strip().lower()
    if severity != "info":
        text = "\n".join(str(info.get(k) or "") for k in ("name", "description", "impact"))
        for label, rx in TEXT_RULES:
            if any(not _is_disclosure(text, m) for m in rx.finditer(text)):
                reasons.append(f"says it is a {label}")
                break

        cls = info.get("classification") or {}
        cwes = set()
        if isinstance(cls, dict):
            for c in _as_list(cls.get("cwe-id")):
                for part in str(c).split(","):
                    if part.strip():
                        cwes.add(part.strip().upper())
        bad_cwe = sorted(cwes & AUTH_CWES)
        if bad_cwe:
            reasons.append("CWE " + ",".join(bad_cwe))

    for key in HTTP_KEYS:
        for blk in _as_list(doc.get(key)):
            if not isinstance(blk, dict):
                continue
            payloads = blk.get("payloads")
            if isinstance(payloads, dict) and any(
                    isinstance(k, str) and CRED_PAYLOAD_KEY.match(k) for k in payloads):
                reasons.append("credential payload list")
            _check_request(_flat({f: blk.get(f) for f in REQUEST_FIELDS if blk.get(f) is not None}), reasons)
            if _posts_to_a_login_path(blk):
                reasons.append("request posts to a login path")
    for key in SOCKET_KEYS:
        for blk in _as_list(doc.get(key)):
            if not isinstance(blk, dict):
                continue
            req = _flat(blk.get("inputs")) + "\n" + _decoded_hex_inputs(blk.get("inputs"))
            if SOCKET_RULE[1].search(req):
                reasons.append(f"request carries a {SOCKET_RULE[0]}")
            _check_request(req, reasons)
    for key in JS_KEYS:
        for blk in _as_list(doc.get(key)):
            if not isinstance(blk, dict):
                continue
            req = _flat({"code": blk.get("code"), "args": blk.get("args"), "pre": blk.get("pre-condition")})
            if JS_RULE[1].search(req):
                reasons.append(JS_RULE[0])
    # flow: is JavaScript that orchestrates the requests above; read it too.
    flow = doc.get("flow")
    if isinstance(flow, str) and flow.strip():
        if JS_RULE[1].search(flow):
            reasons.append(JS_RULE[0] + " (flow)")
        _check_request(flow, reasons)
    # variables: blocks that define a username/password a request then uses
    variables = doc.get("variables")
    if isinstance(variables, dict) and any(
            isinstance(k, str) and CRED_PAYLOAD_KEY.match(k) for k in variables):
        reasons.append("defines credential variables")

    seen, out = set(), []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def classify_file(path: str, relpath: str = "") -> list[str]:
    """Reasons the template at `path` is refused. Unreadable = refused."""
    if yaml is None:
        return ["PyYAML unavailable"]
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            doc = yaml.load(fh, Loader=_LOADER)  # noqa: S506 — SafeLoader/CSafeLoader only
    except Exception as e:  # noqa: BLE001
        return [f"unreadable ({type(e).__name__})"]
    return classify_doc(doc, relpath or path)


_CACHE: dict = {}


def _resolve(line: str, templates_dir: str) -> tuple[str, str]:
    """(absolute path, path relative to the corpus) for one `nuclei -tl` line."""
    p = line.strip()
    if os.path.isabs(p):
        rel = os.path.relpath(p, templates_dir) if templates_dir else p
        return p, rel
    return os.path.join(templates_dir or "", p), p


def screen(lines, templates_dir: str):
    """Split `nuclei -tl` lines into (allowed, refused).

    allowed: the listed lines, unchanged and in order, that may run.
    refused: [(line, [reasons])].
    Fail-closed per line: a line that cannot be resolved, read or parsed is refused.
    """
    allowed, refused = [], []
    for raw in lines or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        line = raw.strip()
        absp, rel = _resolve(line, templates_dir)
        try:
            st = os.stat(absp)
            key = (absp, st.st_mtime_ns, st.st_size)
        except OSError:
            refused.append((line, ["unreadable (missing)"]))
            continue
        reasons = _CACHE.get(key)
        if reasons is None:
            reasons = classify_file(absp, rel)
            _CACHE[key] = reasons
        if reasons:
            refused.append((line, list(reasons)))
        else:
            allowed.append(line)
    return allowed, refused


def refusal_reason(listed: int, allowed, refused) -> str | None:
    """Why a whole chunk must not run, or None. PURE."""
    if yaml is None:
        return "PyYAML is not installed, so no template can be read"
    if listed <= 0:
        return "nuclei listed no templates for this chunk"
    unreadable = sum(1 for _, rs in refused if any(r.startswith("unreadable") for r in rs))
    if unreadable / listed > MAX_UNREADABLE_FRACTION:
        return (f"{unreadable} of {listed} listed templates could not be read — "
                f"the guard is not looking at the corpus nuclei uses")
    if not allowed:
        return f"all {listed} listed templates were refused"
    return None


def _abs(line: str, templates_dir: str) -> str:
    return line if os.path.isabs(line) else os.path.join(templates_dir or "", line)


def write_list(lines, templates_dir: str, prefix: str = "nuclei-allowed-") -> str:
    """Write the allowed list for `nuclei -t <file>`, as ABSOLUTE paths.

    Absolute because nuclei resolves a relative -t entry against the working
    directory before its template folder, and the guard only read the folder.
    Refuses (raises) on an empty list: nuclei given an empty -t list may fall
    back to its whole library, which is the one outcome this file exists to stop.
    """
    lines = [ln for ln in lines if ln and ln.strip()]
    if not lines:
        raise ValueError("refusing to write an empty nuclei -t list")
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(_abs(ln.strip(), templates_dir) + "\n")
    return path


def finalize_list_file(path: str, allowed, templates_dir: str):
    """Make a list file someone else wrote (the coverage cursor's slice) safe to
    hand to nuclei: every line must be on the ALLOWED list, the file must not be
    empty, and the lines are rewritten as absolute paths. Returns a refusal
    reason, or None when the file is safe."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
    except OSError as e:
        return f"the slice file could not be read ({e!r})"
    if not lines:
        return "the slice file is empty"
    ok = {a.strip() for a in allowed} | {_abs(a.strip(), templates_dir) for a in allowed}
    stray = [ln for ln in lines if ln not in ok]
    if stray:
        return f"the slice names {len(stray)} template(s) the guard did not allow, e.g. {stray[0]}"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(_abs(ln, templates_dir) + "\n")
    except OSError as e:
        return f"the slice file could not be rewritten ({e!r})"
    return None


def refused_report(refused, limit: int = 2000) -> str:
    """Plain-text artifact: one refused template per line, with its reasons."""
    rows = [f"{line}\t{'; '.join(rs)}" for line, rs in refused[:limit]]
    if len(refused) > limit:
        rows.append(f"... and {len(refused) - limit} more")
    return "\n".join(rows)
