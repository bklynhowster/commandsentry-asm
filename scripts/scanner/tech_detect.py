"""Tech-detection validity — shared by run_light and run_medium.

4.7 ruling ⑭′ (2026-08-31). A WAF block page is a VALID HTTP response
carrying parseable httpx JSON:

    rc=0, {"tech": ["Nginx"], "title": "403 Forbidden", "status_code": 403}

Fed to ctx.tech_stack it describes the WAF's stack, not the target's. Two
consequences, one loud and one silent:

  * run_light emits a `tech-disclosure` finding announcing the block page's
    server banner as the asset's technology. Wrong, but visible.
  * run_medium's ctx.tech_stack drives build_chunk_plan, so the
    stack-specific nuclei chunks are NEVER PLANNED — and the run still
    records httpx[-td] = {"ok": true}. Nothing in tool_status distinguishes
    "we planned six chunks and four were cut" from "we planned four".

A chunk cut at 92% looked and ran out of time. A chunk never planned never
looked. That is why this is a correctness fix rather than a tuning knob.

Measured on Command, 30 days to 2026-08-31:
  * heavy: 15 runs, 4 carried a blocked tech artifact, and ALL 15 also
    carried a clean one with >= 2 techs — which is what makes the
    artifact fallback in run_medium worth having.
  * light: 187 runs, 22 blocked. Light has one invocation by design and
    builds no chunk plan, so there is nothing to fall back to and nothing
    to shrink; the fix there is purely to stop emitting the bogus finding.

This module is pure: no I/O, no ctx, no logging. Everything here is a
function of its arguments so the branches are cheap to test directly.
"""

from __future__ import annotations

import json

# Status codes that mean "we were denied", not "here is the app".
TECH_BLOCK_STATUSES = frozenset({401, 403, 429, 503})

# Substrings matched case-insensitively against the response title.
TECH_BLOCK_TITLE_PHRASES = (
    "blocked",
    "access denied",
    "forbidden",
    "attention required",
    "security check",
    "request rejected",
    "service unavailable",
    "rate limit",
    "are you a robot",
)

# What a block page echoes back. A LONE web-server banner is a server
# header, not a detected application stack — see the yield floor below.
TECH_SERVER_BANNERS = frozenset({
    "nginx", "apache", "iis", "microsoft-iis", "cloudflare", "cloudfront",
    "akamai", "litespeed", "openresty", "envoy", "varnish", "haproxy",
})


def is_tech_detection_valid(row: dict) -> tuple[bool, str]:
    """(valid, reject_reason) for ONE httpx -json row.

    Rejecting is safe rather than lossy: a blocked or redirected response
    is empirically not the target's content, so the tech it reports is
    empirically not the target's tech. Returning nothing is honest;
    returning the WAF's banner is not.
    """
    raw_status = row.get("status_code", row.get("status-code"))
    try:
        status = int(raw_status)
    except (TypeError, ValueError):
        status = 0
    if status in TECH_BLOCK_STATUSES:
        return False, f"blocked_status_{status}"
    if 300 <= status < 400:
        return False, f"redirect_status_{status}"
    title = str(row.get("title") or "").lower()
    for phrase in TECH_BLOCK_TITLE_PHRASES:
        if phrase in title:
            return False, "blocked_title_" + phrase.replace(" ", "_")
    return True, ""


def row_techs(row: dict) -> set[str]:
    """Lowercased tech names from one row, for matching chunk-plan keys."""
    techs = row.get("tech") or row.get("technologies") or []
    return {t.lower() for t in techs if isinstance(t, str)}


def parse_httpx_rows(stdout: str) -> list[dict]:
    """Every JSON object httpx emitted, not just the first line.

    httpx writes one object per probed URL (redirect targets, alternate
    ports, protocol variants). Taking splitlines()[0] made the outcome
    depend on line ORDER, so a blocked first line discarded a clean second
    one. Junk lines are skipped rather than fatal — httpx interleaves
    non-JSON diagnostics on some paths.
    """
    rows: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:                    # noqa: BLE001 — skip junk lines
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def merge_tech_detection(rows: list[dict]) -> tuple[set[str], int, list[str]]:
    """UNION the tech of every VALID row.

    Returns (techs, n_valid, reject_reasons). Union rather than
    first-wins: different rows are different observations of the same
    target, and no single row's arbitrary position should decide the
    outcome.
    """
    techs: set[str] = set()
    n_valid = 0
    rejects: list[str] = []
    for row in rows:
        valid, reason = is_tech_detection_valid(row)
        if not valid:
            rejects.append(reason)
            continue
        n_valid += 1
        techs |= row_techs(row)
    return techs, n_valid, rejects


def tech_detection_meets_yield_floor(techs: set[str]) -> bool:
    """False when the 'detection' carries no application-layer signal.

    Deliberately conservative (4.7 ⑭′.5): this rejects ONLY the single
    web-server-banner case, which is exactly what a block page echoes. An
    Apache-fronted app with genuinely nothing else fingerprinted looks
    identical from here, so widening the rule would start discarding true
    detections. Refine from observed data, not from intuition.
    """
    if not techs:
        return False
    if len(techs) == 1 and techs <= TECH_SERVER_BANNERS:
        return False
    return True


def tech_rows_from_artifacts(artifacts) -> list[dict]:
    """Tech observations an EARLIER phase already banked this run.

    Under cumulative heavy, light's check_httpx_tech runs before medium's
    detect_tech_stack and writes an 'httpx_tech' artifact. When medium's
    own probe comes back blocked, that row is evidence already in hand —
    re-reading it costs zero requests and zero ban exposure, which is the
    whole point: the alternative is re-probing the thing that just blocked
    us.

    Takes the artifact list rather than ctx so this stays pure.
    """
    rows: list[dict] = []
    for entry in artifacts or []:
        try:
            name, kind, payload = entry[0], entry[1], entry[2]
        except (TypeError, IndexError, KeyError):
            continue
        if kind != "json" or name not in ("httpx_tech", "httpx"):
            continue
        if isinstance(payload, str):
            rows.extend(parse_httpx_rows(payload))
    return rows
