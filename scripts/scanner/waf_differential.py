"""Pure differential WAF-presence logic — 4.7 Cloud Armor rulings Q1/Q2/Q3.

Decides, from a benign baseline response + attack-payload responses, whether a
payload-INSPECTING WAF is BLOCKING in front of an asset. PRESENCE ONLY — this
module never names a vendor (Q3). No I/O: the run_heavy collector does the HTTP
(benign + payload requests, safe-by-default per Q4) and hands the captured
responses here. Byte-identical both repos.

The empirical bar (the GFE / wafw00f-"Cloud Armor" lesson): a claim of "WAF
present" must be earned by BEHAVIOR, and only when it's genuinely a WAF acting —
not the app's own input validation, and not an edge quirk. Hence the two guards:

  Q1 — >=2 of 3 INDEPENDENT payload classes (SQLi / XSS / LFI) must block. A single
       class blocking is consistent with an app-native input validator, not a WAF.
       Genuinely different vectors are what only a shared rule engine blocks uniformly.

  Q2 — 5-gate false-positive check on each block, so we don't mistake the app's own
       403 page for an edge WAF block.
"""
import re

# Q1: genuinely different attack vectors. The bar stays ">=2 of these blocked" — a single
# class alone is an app-native input validator, not a WAF.
#
# ⛔ EXPANDED 2026-09-29 (relay 525). The old tuple was ("sqli","xss","lfi") — and on
# commandcommcentral those are EXACTLY the three FortiWeb does not block, while the two it
# DOES block (log4shell-param, ssrf-metadata, both 403/15B in Howie's run) were not counted
# at all. Measured on his real numbers with correct labels, the old set returned
# waf_present=False on a host with a demonstrably blocking WAF. A tally that excludes the
# vectors a device actually refuses cannot see that device.
#
# ⚠ THE COUNTED SET AND THE FIRED SET MUST MOVE TOGETHER. Firing a class nobody counts is
# the bug above; counting a class nobody fires is merely inert. _WAF_PAYLOADS in run_heavy
# is the fired set — keep them aligned, and see relay 526 on encoding, which is the second
# half of why the fired set currently measures nothing.
INDEPENDENT_CLASSES = ("sqli", "xss", "lfi", "log4shell-param", "ssrf-metadata")
_EDGE_STATUS = {403, 406, 429, 503}            # generic edge-deny codes
_SMALL_BODY = 512                              # a generic edge error is small (Q2 gate 3)


def _payload_blocked(baseline: dict, resp: dict) -> bool:
    """Q2 5-gate (per-payload). baseline is assumed already-2xx (gate 1 is checked once
    by the caller). Each of `baseline`/`resp` = {status:int, size:int, tokens:set[str],
    headers:set[str]} where `tokens` are app-context strings observed in the body
    (app name / session ids / user data) and `headers` are app-specific response header
    names (app Set-Cookie names, app headers)."""
    b_status, b_size = baseline["status"], baseline["size"]
    r_status, r_size = resp["status"], resp["size"]

    # gate 2 — the deny must DIFFER from the benign baseline. Byte-identical to benign
    # (same status AND size) => nothing inspected it (this is exactly demo.prodexlabs.com).
    if r_status == b_status and r_size == b_size:
        return False

    # ⭐ GATE 2b — A SELF-IDENTIFYING BLOCK PAGE IS DISPOSITIVE (relay 528).
    # A block is not always a terse status. FortiWeb serves a FULL block page at HTTP 500
    # — measured on commandcommcentral 2026-09-29, body "Web Page Blocked! / Attack ID:
    # 20000008". 500 is not in _EDGE_STATUS and 39,121 B is not a small body, so gate 3
    # rejected it and the asset scored waf_present=False — which publishes a customer-facing
    # HIGH claiming "no enforcing WAF" about a fully protected host. That is the most
    # damaging direction this classifier can fail in.
    #
    # ⛔ Placed AFTER gate 2 deliberately: a response byte-identical to the benign baseline
    # is not a block whatever it contains. Placed BEFORE gates 3-5 because a page that names
    # itself a block, with the vendor's own per-request incident id, IS the edge refusing —
    # there is nothing for a size heuristic or a token intersection to add, and letting them
    # veto it is how this defect happened.
    if resp.get("block_tell"):
        return True

    # gate 3 — the deny is a GENERIC EDGE ERROR: a generic edge-deny status, OR a small
    # body (not the full app page).
    #
    # ⛔ `or (r_status != b_status)` REMOVED 2026-09-29 (relay 523). A block changes the
    # status by definition, so that clause was true in essentially every case the gate is
    # asked about — which made BOTH its neighbours decorative: _EDGE_STATUS and
    # _SMALL_BODY could never reject anything the middle clause had already accepted.
    #
    # ⭐ Howie's live FortiWeb run is the fixture. Real blocks: 403 / 15 B. Ten fakes:
    # 500 / 39,121 B, byte-identical — that is his APP choking, not an edge refusing, and
    # the old gate scored all ten as blocks, fabricating waf_present=True with three
    # classes "blocked". A 39KB 500 is an application stack trace; an edge deny is small
    # and carries a generic refusal code. Either surviving test separates them alone.
    generic_edge = (r_status in _EDGE_STATUS) or (r_size <= _SMALL_BODY)
    if not generic_edge:
        return False

    # gate 4 — the deny must carry NONE of the app-context tokens seen in the benign
    # response (if the app's own tokens leak into the deny, it's the APP's 403, not an edge).
    if resp.get("tokens") and baseline.get("tokens") and (resp["tokens"] & baseline["tokens"]):
        return False

    # gate 5 — the deny must carry NONE of the app-specific headers seen in benign
    # (app session Set-Cookie / app headers leaking => app-rendered deny, not edge).
    if resp.get("headers") and baseline.get("headers") and (resp["headers"] & baseline["headers"]):
        return False

    return True


# ── 311 (2026-10-13): A REDIRECT IS NOT A TEST ───────────────────────────────────────
# (351, 2026-10-26: except a redirect to a sign-in, which tests the front door; below.)
# www.commandcompanies.com, the first live differential on Command after the probe was
# armed: the benign baseline came back HTTP 301 (nginx, "301 Moved Permanently", 162 B,
# Location: https://commandcompanies.com/?q…) and so did all three attack payloads —
# byte-identical bounces. Gate 1 read `< 400`, so the 301 counted as a clean baseline, the
# tally said "0 of 3 blocked", and the collector published a HIGH "No enforcing WAF in
# front of live application" about an address that serves no application at all. The
# portal's copy of this rule had already been tightened to 2xx on 2026-09-28
# (served-status.mjs, ftp.sciimage.com 302/302) and rendered "ATTACK TEST NOT RUN" two
# inches above the finding that said the test ran. Same capture, two rules, one page lying.
#
# The probe is a COMPARISON. A baseline that did not serve a page establishes nothing to
# compare against, so the verdict is UNDEFINED — `waf_present: None` — never False. False
# is a measurement ("we sent attacks and nothing refused them"); None is the absence of
# one. Downstream, None is already the dry-run shape: the classifier's NOT_NULL capability
# ignores it, the digest's lag() window skips it, the portal's chip reads it as not
# measured. A 3xx baseline is told apart from a dead one (0 / 5xx) because they mean
# different things to the finding this probe mints: a REDIRECT says "no application at
# this address, on this path" (the finding's premise was false — see run_heavy's
# retract_waf_absent_on_redirect); a dead origin says only "could not test today".
UNDEFINED_REDIRECT = "baseline_redirect"
UNDEFINED_NOT_SERVED = "baseline_not_served"


def baseline_served(status) -> bool:
    """The ONE definition of 'the benign request was answered with a page': 2xx only.
    Mirrors served() in the portal's served-status.mjs — the two must agree or the page
    contradicts itself (that was #481d there, and 311 here)."""
    try:
        s = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 200 <= s < 300


# ── 351 (2026-10-26): A SIGN-IN IS THE FRONT DOOR, AND IT CAN BE TESTED ─────────────────
# Howie, 16:01, on atlantis-gcp.prodexlabs.com, where every request is redirected to its
# own Google sign-in (/oauth2/start): "Why does authentication redirect negate the WAF
# scan?" 16:05: "I think you should test. You should say what the test actually measured."
#
# 311 made every redirect baseline UNDEFINED. It was written for www.commandcompanies.com,
# which redirects to ANOTHER site: the application lives at the apex, so nothing at www
# could be about it. A sign-in is different. The application lives behind it, on this
# host, and whatever stands in front of the host answers an attack-shaped request before
# the login does: a firewall there would refuse it, and the login redirects it like any
# other visitor. So a baseline that redirects to a sign-in measures the front door, and
# only the front door. Nothing behind the login is reached (Sentry has no account).
#
# An attack request that got the SAME redirect as the ordinary one (to the same sign-in,
# our query string removed) reached the login: not blocked, whatever its size.
# pm.unimacgraphics.com's ASP.NET redirect echoes the requested address in its body, so
# the four sizes differ (216 / 238 / 264 / 246, 2026-10-16): the same login, four sizes.
# Anything else (a 403, a block page, a redirect somewhere else) is read by the usual
# gates against the redirect.
#
# What counts as a sign-in is the portal's rule (protection-panel.mjs, redirectKind): an
# identity provider's host, or a login path. Same patterns here; both sides are pinned on
# the same real targets (test_signin_front_door_351.py, tests/protection-panel-check.mjs).
FRONT_DOOR_SIGNIN = "signin"
_SIGNIN_HOSTS = re.compile(
    r"(^|\.)(login\.microsoftonline\.com|accounts\.google\.com|login\.live\.com|okta\.com"
    r"|auth0\.com|onelogin\.com)$", re.I)
_SIGNIN_PATH = re.compile(r"oauth|log-?in|sign-?in|sso|saml|authorize|/auth(/|$)", re.I)
_ABS_URL = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]+)(.*)$", re.I)


def redirect_is_signin(target) -> bool:
    """Does this redirect target (the Location without its query string) go to a sign-in?
    True for an identity provider's host, or for a login path on any host (a relative
    Location is a path on this host)."""
    t = (target or "").strip() if isinstance(target, str) else ""
    if not t:
        return False
    m = _ABS_URL.match(t)
    host, path = (m.group(1).split(":")[0].lower(), m.group(2) or "/") if m else ("", t)
    return bool((host and _SIGNIN_HOSTS.search(host)) or _SIGNIN_PATH.search(path))


def _reached_same_signin(baseline: dict, resp: dict) -> bool:
    """The attack request got the same redirect as the ordinary one: it reached the login."""
    try:
        s = int(resp.get("status") or 0)
    except (TypeError, ValueError):
        return False
    b = (baseline.get("redirect_to") or "").strip()
    return 300 <= s < 400 and bool(b) and (resp.get("redirect_to") or "").strip() == b


def _classify_signin_front_door(baseline: dict, payloads: list, status, target: str) -> dict:
    """351: the baseline redirected to a sign-in. Measure the front door."""
    counted = [p for p in payloads if p.get("cls") in INDEPENDENT_CLASSES]
    at_login = sorted({p["cls"] for p in counted if _reached_same_signin(baseline, p)})
    blocked = sorted({p["cls"] for p in counted
                      if not _reached_same_signin(baseline, p) and _payload_blocked(baseline, p)})
    base = {"evidence_class": "presence_only", "blocked": blocked,
            "front_door": FRONT_DOOR_SIGNIN, "redirect_to": target, "reached_signin": at_login}
    if len(blocked) >= 2:
        return {**base, "waf_present": True,
                "reason": (f"baseline redirected to a sign-in (status={status} to {target}); "
                           f"{len(blocked)} independent payload classes were refused before it "
                           f"({', '.join(blocked)})")}
    return {**base, "waf_present": False,
            "reason": (f"baseline redirected to a sign-in (status={status} to {target}); the front "
                       f"door was measured: {len(at_login)} payload class(es) got the same redirect "
                       f"to the sign-in, {len(blocked)} blocked ({', '.join(blocked) or 'none'}). "
                       "Nothing behind the sign-in was reached.")}


def classify_waf_differential(baseline: dict, payloads: list) -> dict:
    """Return {waf_present, evidence_class, blocked, reason[, undefined, redirect_to]}.

    - waf_present True  => a payload-inspecting WAF is BLOCKING in front (presence_only,
                           renders "Behind a WAF (suspected)"; NEVER a vendor — Q3).
    - waf_present False => MEASURED and not asserted: the baseline was served and either
                           nothing blocked or <2 independent classes did.
    - waf_present None  => UNDEFINED (311): the baseline was not a served page, so there
                           is nothing to compare. `undefined` says which kind —
                           'baseline_redirect' (3xx; `redirect_to` carries the Location
                           target without its query string) or 'baseline_not_served'
                           (0 / 4xx / 5xx). Not a measurement; never earns a finding.
    - front_door 'signin' (351): the baseline redirected to a sign-in, so the front door
                           was measured (True / False as above, of the door only), with
                           `redirect_to` and `reached_signin` (the classes that got the
                           same redirect as the ordinary request).
    `payloads` = list of {cls: 'sqli'|'xss'|'lfi', status, size, tokens, headers}.
    """
    # gate 1 — a differential is only meaningful if the BENIGN baseline was SERVED (2xx).
    if not baseline_served(baseline.get("status")):
        status = baseline.get("status")
        try:
            is_redirect = 300 <= int(status or 0) < 400
        except (TypeError, ValueError):
            is_redirect = False
        if is_redirect:
            target = baseline.get("redirect_to") or ""
            if redirect_is_signin(target):
                return _classify_signin_front_door(baseline, payloads, status, target)
            return {"waf_present": None, "evidence_class": "presence_only", "blocked": [],
                    "undefined": UNDEFINED_REDIRECT, "redirect_to": target or None,
                    "reason": (f"baseline redirected (status={status}"
                               f"{' to ' + target if target else ''}) — nothing to compare; "
                               "not a measurement. Test the address it redirects to.")}
        return {"waf_present": None, "evidence_class": "presence_only", "blocked": [],
                "undefined": UNDEFINED_NOT_SERVED, "redirect_to": None,
                "reason": f"baseline not served (status={status}) — nothing to compare; not a measurement"}

    blocked = sorted({p["cls"] for p in payloads
                      if p.get("cls") in INDEPENDENT_CLASSES and _payload_blocked(baseline, p)})

    # Q1 — require >=2 INDEPENDENT classes. One class alone = app-native input validator FP.
    if len(blocked) >= 2:
        return {"waf_present": True, "evidence_class": "presence_only",
                "blocked": blocked,
                "reason": f"{len(blocked)} independent payload classes blocked ({', '.join(blocked)}); benign passed"}
    return {"waf_present": False, "evidence_class": "presence_only", "blocked": blocked,
            "reason": (f"only {len(blocked)} class blocked ({', '.join(blocked) or 'none'}) — "
                       "below the >=2-independent-class bar (single-class block = app input-validator, not a WAF)")}
