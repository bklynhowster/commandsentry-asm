#!/usr/bin/env python3
"""(354a) The DIFFERENTIAL enforcement probe — the instrument, not the verdict.

⛔ WHAT THIS TURN IS. Relay 354/355 sequenced enforcement as measurement BEFORE
signal, and this is the measurement half: build the probe, ship it firing
NOTHING by default, and STOP so 4.7 reads the captured bytes before any verdict
is built (354b). No enforcement claim is made here — that is the whole point.

⛔ WHY THE OLD PROBE PROVED NOTHING (4.7's 354 correction). `is_armor_block`
keyed on 400 + "malformed or illegal request" — but that 400 is the Google Front
End rejecting malformed HTTP SYNTAX, which fires on EVERY GCLB-fronted host
whether or not an Armor policy exists. Measured 2026-09-20: the refusal_response
and path_followup artifacts number ZERO on both instances — the malformed probe
has never recorded a useful byte, and it never could: a well-formed scanner does
not send malformed syntax, and the 400 would not prove Armor even if it did.

⛔ THE CORRECT SHAPE IS DIFFERENTIAL. A syntactically VALID request carrying an
attack signature (a CRS tripwire), measured against a benign baseline on the
SAME path from the SAME egress:

    benign passes (2xx/3xx)  +  attack blocked (a distinctive 403)  = enforcing edge WAF
    both identical                                                   = present-but-not-enforcing

⚠ CLAIM CEILING, STATED (from the 354 body). This proves "an enforcing edge WAF
blocked a generic attack the benign request did not." It does NOT separate
Armor-CRS from a custom rule from a backend WAF, so 354b will keep CONFIRMED at
"enforcing edge WAF" and leave "Armor specifically" at suspected unless a
Google-specific block body is in the captured bytes.

⛔ THIS MODULE FIRES NOTHING. It PLANS the pair and decides authorisation; the
caller in run_light does the sending, and only when both the per-asset
`enforcement_probe_authorized` flag AND the ENFORCEMENT_PROBE_LIVE env are set —
the fwbbot/EXPLOIT_LIVE pattern. Default is dry-run: the plan is recorded, the
wire stays quiet. Live firing at one opted-in owned host is Howie's switch, not
cron's, and not this session's (an external attack-signature request from here
would break the standing rule; I do not send it).
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# ── The attack signatures. CANONICAL CRS TRIPWIRES, valid HTTP, no traversal ──
# ⚠ Each is a syntactically VALID request that a standard OWASP CRS / Cloud Armor
# preconfigured ruleset scores as an attack — a libinjection-tripping SQLi
# tautology and a reflected-XSS string. They are carried as QUERY parameters on a
# real path, so the request is well-formed and reaches the edge's rule engine
# (unlike /%zz, which the GFE rejects at the syntax layer before any policy).
#
# ⚠ NOT traversal, NOT an RCE, NOT anything that could act if it reached origin —
# these are DETECTION signatures, chosen because a WAF blocks them and an
# undefended origin simply 404s/200s the odd query string. The point is the WAF's
# reaction, never the origin's.
ATTACK_SIGNATURES = (
    ("sqli", "?id=1%27%20OR%20%271%27%3D%271"),   # ' OR '1'='1  (libinjection tautology, fully encoded)
    ("xss", "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),  # <script>alert(1)</script>
)

# The env that must be set for the caller to fire live. Mirrors the fwbbot /
# EXPLOIT_LIVE gate: absent -> dry-run, plan only, nothing sent.
LIVE_ENV = "ENFORCEMENT_PROBE_LIVE"

# The per-asset authorisation flag. DISTINCT from active_probe_authorized: this
# sends attack signatures, heavier than a bot GET, so it gets its own opt-in.
AUTH_FLAG = "enforcement_probe_authorized"

ENFORCEMENT_PROBE_ARTIFACT = "enforcement_probe"


@dataclass(frozen=True)
class ProbePlan:
    """One benign baseline + one attack request, on the SAME path, one egress.

    ⚠ SAME PATH, SAME EGRESS is not a detail — it is what makes the comparison
    mean anything. If the baseline and the attack take different exits, a 403 on
    the attack could be the IP's reputation, not the WAF's rule (the 354c
    concern). The plan pins them together; the caller must honour it.
    """
    host: str
    path: str
    baseline_url: str
    attack_url: str
    signature: str            # which CRS tripwire ("sqli" / "xss")


def probe_is_authorised(asset: dict | None, env: dict | None = None) -> bool:
    """Fire live ONLY when BOTH the per-asset flag and the live env are set.

    ⛔ TWO INDEPENDENT GATES, AND-ed. The env is the fleet-wide kill switch
    (default off = dry-run everywhere); the flag is the per-asset opt-in Howie
    sets on the ONE host he is probing. Either alone is not enough — the env on
    without the flag must not fire a host nobody opted in, and the flag on
    without the env must not fire on cron.
    """
    e = os.environ if env is None else env
    if str(e.get(LIVE_ENV, "")).strip().lower() not in ("1", "true", "yes"):
        return False
    a = asset or {}
    return a.get(AUTH_FLAG) is True


def build_probe_plan(host: str, path: str, signature: str = "sqli") -> ProbePlan:
    """The pair for one host+path. Pure — builds URLs, sends nothing.

    ⚠ `path` is the benign real path (e.g. "/"); the attack request is that same
    path with the CRS query appended, so both hit the same route and the only
    difference on the wire is the signature.
    """
    sig = dict(ATTACK_SIGNATURES).get(signature)
    if sig is None:
        raise ValueError(f"unknown attack signature: {signature!r}")
    base = f"https://{host}{path}"
    return ProbePlan(
        host=host,
        path=path,
        baseline_url=base,
        attack_url=base + sig,
        signature=signature,
    )


def record_probe_pair(artifacts: list, plan: ProbePlan, egress_ip: str | None,
                      baseline: dict | None, attack: dict | None,
                      *, fired: bool, body_max: int = 4096) -> None:
    """Record BOTH halves as one `enforcement_probe` artifact.

    ⛔ NO VERDICT. This stores what was observed (or, dry-run, what WOULD be
    sent) and stops. Whether the delta means "enforcing" is 354b's job, built
    from these bytes, not asserted here. `fired` records whether the wire was
    actually touched — a dry-run artifact is a plan, not evidence, and must never
    be read as a captured block.

    Each half, when present, is {status, content_type, body_snippet, truncated}.
    """
    def half(resp: dict | None) -> dict | None:
        if resp is None:
            return None
        body = resp.get("body") or ""
        return {
            "status": resp.get("status"),
            "content_type": resp.get("content_type"),
            "body_snippet": body[:body_max],
            "truncated": len(body) > body_max,
        }

    artifacts.append((ENFORCEMENT_PROBE_ARTIFACT, "json", _dumps({
        "schema": 1,
        "fired": bool(fired),          # ⛔ dry-run plans are fired=False
        "signature": plan.signature,
        "host": plan.host,
        "path": plan.path,
        "egress_ip": egress_ip,        # 354c: the ONE exit both halves shared
        "baseline_url": plan.baseline_url,
        "attack_url": plan.attack_url,
        "baseline": half(baseline),
        "attack": half(attack),
    })))


def _dumps(obj) -> str:
    import json
    return json.dumps(obj)
