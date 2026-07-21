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

INDEPENDENT_CLASSES = ("sqli", "xss", "lfi")   # Q1: genuinely different attack vectors
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

    # gate 3 — the deny is a GENERIC EDGE ERROR: a distinct edge-deny status, OR a
    # small/structurally-different body (not the full app page).
    generic_edge = (r_status in _EDGE_STATUS) or (r_status != b_status) or (r_size <= _SMALL_BODY)
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


def classify_waf_differential(baseline: dict, payloads: list) -> dict:
    """Return {waf_present, evidence_class, blocked, reason}.

    - waf_present True  => a payload-inspecting WAF is BLOCKING in front (presence_only,
                           renders "Behind a WAF (suspected)"; NEVER a vendor — Q3).
    - waf_present False => not asserted (either nothing blocks, or <2 independent classes
                           blocked, or the baseline itself wasn't clean).
    `payloads` = list of {cls: 'sqli'|'xss'|'lfi', status, size, tokens, headers}.
    """
    # gate 1 — a differential is only meaningful if the BENIGN baseline passed.
    if not (200 <= baseline.get("status", 0) < 400):
        return {"waf_present": False, "evidence_class": "presence_only",
                "blocked": [], "reason": f"baseline not 2xx/3xx (status={baseline.get('status')}) — differential undefined"}

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
