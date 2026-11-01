"""csp_policy.py — does a site's Content-Security-Policy actually limit scripts? (KB 12 job 3z)

WHY THIS EXISTS (2026-10-31). Howie's ZAP trials (10-30 and 10-31, on his Mac, under D-075)
showed docs.prodexlabs.com and uat.prodexlabs.com sending a Content-Security-Policy that lets
injected scripts run. Sentry said nothing: the quick scan's header check only asks whether the
header is THERE (run_light.SECURITY_HEADERS). The old Mac-era nuclei caught this class
(`weak-csp-detect`, March 2026, still open on vpn.sciimage.com and vpn2.sciimage.com), but the
cloud scanner runs nuclei only at critical, high and medium, and that template is filed as info,
so it quietly stopped running. Howie, 10:24: "Yes" (build it).

WHAT IT READS: the header value the quick scan already fetched (no new request). Pure: a string
in, a verdict out.

THE RULE. Scripts are governed by `script-src`, or by `default-src` when there is no
`script-src`. A policy does NOT limit scripts when that rule:
  * allows 'unsafe-inline' with no nonce, no hash and no 'strict-dynamic'
    (with any of those, CSP2+ browsers ignore 'unsafe-inline': ZAP flags it anyway, which is a
    false positive this rule does not repeat);
  * allows any site: `*`, `https:`, `http:`, `https://*`, `http://*`, or `data:` URLs
    (ignored when 'strict-dynamic' is present: CSP3 browsers then drop host and scheme lists);
  * does not exist (neither directive).
That is rated MODERATE, the same as a missing Content-Security-Policy, because it protects as
much as no policy. 'unsafe-eval' on a rule that is otherwise tight is LOW. 'style-src' is not
judged (little harm, very common). Precedent: ftp.sciimage.com F-04, kept MODERATE on 2026-05-25
("Trust ZAP"), which was exactly the default-src fallback case.

Several policies in one header (comma-joined) must ALL allow a script for it to run, so the
verdict is the TIGHTEST policy's.

NOT READ (stated, not hidden): `script-src-elem` / `script-src-attr` (CSP3; neither fleet sends
them, read 2026-10-31), a policy set in a <meta> tag, and Content-Security-Policy-Report-Only
(it enforces nothing; with no enforcing header the missing-header finding already fires).
"""
import re

MODERATE = "MODERATE"
LOW = "LOW"

CHECK_NOT_LIMITED = "csp-scripts-not-limited"
CHECK_EVAL_ONLY = "csp-allows-eval"
TITLE_NOT_LIMITED = "Content-Security-Policy does not limit scripts"
TITLE_EVAL_ONLY = "Content-Security-Policy allows eval()"

_NONCE_OR_HASH = re.compile(r"^'(nonce-|sha256-|sha384-|sha512-)", re.I)
_ANY_SITE = {
    "*": "scripts from any website ('*')",
    "https:": "scripts from any https website ('https:')",
    "http:": "scripts from any http website ('http:')",
    "https://*": "scripts from any https website ('https://*')",
    "http://*": "scripts from any http website ('http://*')",
    "data:": "scripts carried inside data: links ('data:')",
}
_INLINE = "scripts written straight into the page ('unsafe-inline')"
_NO_RULE = "scripts from anywhere: there is no rule for scripts (neither script-src nor default-src)"
_EVAL = "turning text into code with eval() ('unsafe-eval')"


def directives(policy):
    """{name: [sources]} for one policy. The first occurrence of a directive wins (CSP spec)."""
    out = {}
    for chunk in (policy or "").split(";"):
        tokens = chunk.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in out:
            out[name] = tokens[1:]
    return out


def assess_policy(policy):
    """One policy -> None (scripts are limited, eval not allowed) or
    {'severity', 'reasons', 'eval', 'rule', 'sources'}."""
    d = directives(policy)
    rule = "script-src" if "script-src" in d else ("default-src" if "default-src" in d else None)
    if rule is None:
        return {"severity": MODERATE, "reasons": [_NO_RULE], "eval": False, "rule": None, "sources": []}
    sources = d[rule]
    low = [s.lower() for s in sources]
    strict_dynamic = "'strict-dynamic'" in low
    nonce_or_hash = any(_NONCE_OR_HASH.match(s) for s in sources)
    reasons = []
    if "'unsafe-inline'" in low and not (nonce_or_hash or strict_dynamic):
        reasons.append(_INLINE)
    if not strict_dynamic:
        for s in low:
            why = _ANY_SITE.get(s)
            if why and why not in reasons:
                reasons.append(why)
    allows_eval = "'unsafe-eval'" in low
    if reasons:
        return {"severity": MODERATE, "reasons": reasons, "eval": allows_eval, "rule": rule, "sources": sources}
    if allows_eval:
        return {"severity": LOW, "reasons": [], "eval": True, "rule": rule, "sources": sources}
    return None


_RANK = {None: 0, LOW: 1, MODERATE: 2}


def script_weakness(header_value):
    """The header value as received (None when the header is absent) -> None when the policy
    limits scripts or there is no policy (that is the missing-header check's job), else the
    tightest policy's verdict. Several comma-joined policies all apply, so the tightest wins."""
    if header_value is None:
        return None
    if isinstance(header_value, (list, tuple)):        # a repeated header, if a tool lists it
        header_value = ", ".join(str(h) for h in header_value)
    policies = [p for p in str(header_value).split(",") if p.strip()]
    if not policies:
        return None
    verdicts = [assess_policy(p) for p in policies]
    return min(verdicts, key=lambda v: _RANK[v["severity"] if v else None])


def _join(items):
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def finding_fields(hostname, header_value):
    """None, or the fields of the one finding for this site:
    {'check_name', 'title', 'severity', 'description', 'tags'}."""
    v = script_weakness(header_value)
    if v is None:
        return None
    rule_text = f"{v['rule']} {' '.join(v['sources'])}".strip() if v["rule"] else "(no script rule)"
    if v["severity"] == MODERATE:
        allows = list(v["reasons"]) + ([_EVAL] if v["eval"] else [])
        return {
            "check_name": CHECK_NOT_LIMITED,
            "title": TITLE_NOT_LIMITED,
            "severity": MODERATE,
            "description": (
                f"The Content-Security-Policy header from {hostname} allows {_join(allows)}. "
                f"A policy like this stops about as few injected scripts as no policy at all, so it "
                f"is rated the same as a missing Content-Security-Policy. The rule that governs "
                f"scripts: {rule_text}"),
            "tags": ["headers", "csp", "csp-weak", v["rule"] or "no-script-rule"],
        }
    return {
        "check_name": CHECK_EVAL_ONLY,
        "title": TITLE_EVAL_ONLY,
        "severity": LOW,
        "description": (
            f"The Content-Security-Policy header from {hostname} limits where scripts come from, "
            f"but allows {_EVAL}. That matters only if an attacker can already get text into a "
            f"script, so it is a smaller weakness. The rule that governs scripts: {rule_text}"),
        "tags": ["headers", "csp", "csp-eval", v["rule"]],
    }
