#!/usr/bin/env python3
"""(relay 382) The enforcement SWEEP — planner + blast-radius preview.

⛔ WHAT THIS TURN IS. 4.7 chose breadth: quantify how many WAF-fingerprinted
hosts are decorative (present but not enforcing). Two were hand-probed — Armor
passes to an identical 200, FortiWeb passes to a 500 — and the value now is the
COVERAGE NUMBER across the fleet. Hand-firing ~30 dispatches is the wrong way.

⛔ THIS MODULE FIRES NOTHING, AND CANNOT. It selects the in-scope hosts and
builds the DRY-RUN blast-radius preview — the list Howie reads BEFORE anything
is armed. There is deliberately no HTTP, no arming, no ENFORCEMENT_PROBE_LIVE in
this file: the live sweep (carrying the two gates across N hosts in one operator
action) is the sensitive follow-up, routed to 4.7 for the firing-mechanism
ruling. The instrument-then-stop pattern of 354a, applied to the sweep.

⛔ NEVER THE WHOLE WORLD BY DEFAULT. Scope is bound to the SAME ownership
authority the ROE gate uses — ROE_OWNERSHIP_ALLOWLIST = {owned, test_target}.
A client-facing host is out of scope unless an operator explicitly widens the
ownership scope, and that is Howie's call because the sweep is offensive traffic.

⛔ SCOPE IS DERIVED FROM THE ENFORCEMENT MECHANISM (relay 414 Axis 2), not from a
hardcoded class list. "Is it enforcing?" is meaningful iff the edge has a
mechanism that is not `none` — see scripts/scanner/enforcement_mechanism.py, and
its mirror src/lib/enforcement-mechanism.mjs in the portal. An origin_host or a
cloud_endpoint has nothing to probe for enforcement and is never in scope.

Resolution mirrors the portal: the live device_class column unless it is unknown,
else the newest dry-run verdict (soak mode, --write held).
"""
from __future__ import annotations

import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Bound to the SAME authority the ROE gate enforces at pull time — one list, not
# a second copy that can drift. Widening it is a documented ROE decision there.
from roe_gate import ROE_OWNERSHIP_ALLOWLIST  # noqa: E402
from enforcement_mechanism import enforcement_applies  # noqa: E402

# ⛔ RETIRED AS THE MEMBERSHIP TEST (relay 414 Axis 2). This tuple used to BE the
# population rule, hardcoded here and mirrored in the portal. It now records only
# what the population was BEFORE the mechanism axis, so the blast-radius pin has
# something to diff against. Membership is decided by enforcement_applies().
#
# Why it had to stop being the rule: a class list conflates "what is this box"
# with "can enforcement be tested here", which forced every managed-hosting edge
# to be either over-claimed as a WAF or silently dropped as a CDN.
LEGACY_PROTECTIVE_CLASSES = ("waf", "edge_firewall", "adc_lb")

# Default sweep ownership scope = the ROE allowlist. NEVER client by default.
DEFAULT_OWNERSHIP_SCOPE = frozenset(ROE_OWNERSHIP_ALLOWLIST)


def resolved_device_class(asset: dict) -> str | None:
    """Live column unless unknown/absent, else the newest dry-run verdict.

    Mirrors the portal precedence (device-class-resolve): a live class wins, but
    a soak-mode host whose live column is still 'unknown' resolves to its dry-run
    class so it is not silently excluded from the sweep.
    """
    live = asset.get("device_class")
    if live and live != "unknown":
        return live
    return asset.get("dryrun_device_class")


def in_scope(asset: dict, *, ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE) -> bool:
    """Is this asset a legitimate enforcement-sweep target?

    Protective resolved class AND an in-scope ownership. Both required: a WAF on
    a client host is out of scope by default, and an owned origin_host has
    nothing to probe.
    """
    return (
        enforcement_applies(resolved_device_class(asset), _vendor_product(asset))
        and asset.get("ownership") in ownership_scope
    )


def select_sweep_scope(
    assets: list[dict], *, ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE
) -> list[dict]:
    """Filter a candidate list to the in-scope hosts. Pure — no I/O."""
    return [a for a in assets if in_scope(a, ownership_scope=ownership_scope)]


def _vendor_product(asset: dict) -> dict | None:
    """The vendor_product DICT the mechanism rule reads (relay 414 Axis 2).

    Distinct from _vendor() below, which flattens to one display string. The
    mechanism needs vendor AND product because the rate-based test is a token
    match over both ("Fortinet"/"FortiWeb" can arrive in either field).
    Non-dict shapes (a bare string, null) resolve to None and fail closed to a
    signature/none decision rather than raising.
    """
    vp = asset.get("vendor_product")
    return vp if isinstance(vp, dict) else None


def _vendor(asset: dict) -> str | None:
    """A display vendor for the preview table, best-effort from vendor_product."""
    vp = asset.get("vendor_product")
    if isinstance(vp, dict):
        return vp.get("vendor") or vp.get("product")
    if isinstance(vp, str):
        return vp or None
    return None


def build_blast_radius(
    assets: list[dict], *, ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE
) -> dict:
    """The DRY-RUN preview: exactly which hosts WOULD be probed, and nothing sent.

    ⛔ This is the whole safety story of the preview — it returns a description,
    never a request. Howie reads `count` and `hosts` and decides whether to arm.
    """
    scope = select_sweep_scope(assets, ownership_scope=ownership_scope)
    return {
        "dry_run": True,               # ⛔ a preview is ALWAYS dry-run
        "fired": False,                # nothing was sent to build this
        "ownership_scope": sorted(ownership_scope),
        "count": len(scope),
        "hosts": [
            {
                "asset_id": a.get("asset_id"),
                "host": a.get("name"),
                "device_class": resolved_device_class(a),
                "ownership": a.get("ownership"),
                "vendor": _vendor(a),
                "already_authorized": a.get("enforcement_probe_authorized") is True,
            }
            for a in scope
        ],
    }


# ── the candidate SQL for the CLI preview (impure shell; the planner above is
#    what the tests exercise). ⚠ SHAPE UNCONFIRMED LIVE — see the 382 relay body;
#    the CLI only PRINTS, so a shape miss shows a wrong count, never a request. ──
FETCH_CANDIDATES_SQL = """
select a.asset_id,
       a.name,
       a.device_class,
       a.ownership,
       a.vendor_product,
       a.enforcement_probe_authorized,
       d.device_class as dryrun_device_class
from public.assets a
left join lateral (
  select device_class
    from public.device_class_dryrun x
   where x.asset_id = a.asset_id
   order by evaluated_at desc
   limit 1
) d on true
where a.discovery_status = 'confirmed_live';
"""


def fetch_candidates(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(FETCH_CANDIDATES_SQL)
        return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# (relay 382-live-2) THE ARM+ENQUEUE LIVE PATH — one operator action, N hosts.
# ⛔ SHIPPED BEHIND A HARD GATE. `_DISARM_WIRED` is False until 4.7 rules the
# fire-once/disarm mechanism (relay 391 fork A/B/C) and it is wired. Until then
# execute_sweep REFUSES to arm or enqueue even under --confirm, so a sweep can
# NEVER leave the fleet standing-armed in a shipped state. The plan builder and
# SQL are present and tested; the wire stays blocked.
# ─────────────────────────────────────────────────────────────────────────────

# ⛔ Disarm IS wired (relay 382-live-3, mechanism A-refined): run_light clears the
# per-asset arm atomically after a per-scan-flag (enforcement_probe_live) fired
# capture, so a sweep is fire-once and cannot leave the fleet standing-armed.
# This flip is what makes --confirm actually fire; it lands in the SAME change as
# the disarm wiring, never before.
_DISARM_WIRED = True

# The enqueued row's source. 'workflow_dispatch' = an operator-driven manual
# fire (closest existing scan_source_t value). ⚠ Disarm option A would want a
# DISTINCT marker so only sweep-armed hosts self-disarm — that is an enum
# migration and part of the 391 fork, not decided here.
SWEEP_ENQUEUE_SOURCE = "workflow_dispatch"

ARM_SQL = """
update public.assets
set enforcement_probe_authorized = true
where asset_id = %(asset_id)s;
"""

ENQUEUE_SQL = """
insert into public.scan_queue
  (asset_id, intensity, authenticated, source, notes, enforcement_probe_live)
values
  (%(asset_id)s, 'light', false, %(source)s,
   'relay 382 enforcement sweep', true);
"""


def build_arm_enqueue_plan(
    assets: list[dict], *, ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE
) -> dict:
    """PURE. From the candidate list, the exact arm set + enqueue rows — for the
    IN-SCOPE hosts only. A host that fails the ownership/class scope is never in
    the plan; the plan is computed from the SAME in_scope() the preview uses, so
    what you previewed is exactly what would fire.
    """
    scope = select_sweep_scope(assets, ownership_scope=ownership_scope)
    return {
        "arm": [a["asset_id"] for a in scope],
        "enqueue": [
            {"asset_id": a["asset_id"], "source": SWEEP_ENQUEUE_SOURCE}
            for a in scope
        ],
    }


def execute_sweep(
    conn, assets: list[dict], *, confirmed: bool,
    ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE,
    disarm_wired: bool = _DISARM_WIRED,
) -> dict:
    """Arm + enqueue the in-scope hosts — the one-action N-host fire.

    ⛔ TWO HARD REFUSALS before any write:
      1. not `confirmed` → refuse. --confirm is the ONLY path that may write;
         the default (preview) never reaches here.
      2. not `disarm_wired` → refuse. Firing without a disarm story would leave
         the fleet standing-armed, the exact risk 391 is resolving. Shipped as
         False, so today this ALWAYS refuses even under --confirm.
    Either refusal writes NOTHING and returns {armed: 0, enqueued: 0, ...}.
    """
    plan = build_arm_enqueue_plan(assets, ownership_scope=ownership_scope)
    if not confirmed:
        return {"executed": False, "reason": "not confirmed (preview only)",
                "armed": 0, "enqueued": 0, "would_arm": len(plan["arm"])}
    if not disarm_wired:
        return {"executed": False,
                "reason": "disarm mechanism not wired (relay 391 fork unresolved) "
                          "— refusing to arm the fleet with no fire-once path",
                "armed": 0, "enqueued": 0, "would_arm": len(plan["arm"])}
    armed = enqueued = 0
    with conn.cursor() as cur:
        for asset_id in plan["arm"]:
            cur.execute(ARM_SQL, {"asset_id": asset_id})
            armed += 1
        for row in plan["enqueue"]:
            cur.execute(ENQUEUE_SQL, row)
            enqueued += 1
    return {"executed": True, "armed": armed, "enqueued": enqueued,
            "reason": "armed + enqueued in-scope hosts"}


# ── (relay 381) per-host attack-status signal: 2xx passthrough vs 5xx choke ──

def sweep_attack_signal(verdict_state: str, attack_status: object) -> str:
    """Fold the 381 refinement into the fleet output. A not_enforcing host that
    passed the attack to a 2xx is a CLEAN passthrough; one that passed it to a
    5xx is the origin visibly choking on the injection — higher signal, worth a
    manual look (a lead, NOT proof of exploit). Enforcing/not_verified are
    unchanged. Pure.
    """
    if verdict_state == "not_enforcing":
        s = attack_status if isinstance(attack_status, int) else None
        if s is not None and 500 <= s <= 599:
            return "not_enforcing_origin_error"   # 5xx — origin reacted
        return "not_enforcing_passthrough"        # 2xx/other — clean pass
    return verdict_state


def main(argv: list[str] | None = None) -> int:
    """DRY-RUN preview only. Prints the blast radius; sends nothing. Arming and
    firing the sweep is the routed follow-up (Howie's scope + fire)."""
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="Enforcement-sweep blast-radius preview (DRY-RUN, fires nothing).")
    ap.add_argument("--include-client", action="store_true",
                    help="widen ownership scope beyond the ROE allowlist to ALL "
                         "ownerships (client hosts included). Preview only — this "
                         "does not fire anything; it only widens what the preview "
                         "would list. Off by default.")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--confirm", action="store_true",
                    help="ARM + ENQUEUE the in-scope hosts (the one-action N-host "
                         "fire). Without this flag the run is a dry-run preview "
                         "that writes nothing. ⛔ Even with it, execution is "
                         "BLOCKED until the disarm mechanism (relay 391) is wired "
                         "— the fleet must never be left standing-armed.")
    args = ap.parse_args(argv)

    if not args.dsn:
        print("error: SUPABASE_DSN not set (pass --dsn)", file=sys.stderr)
        return 2

    ownership_scope = None if args.include_client else DEFAULT_OWNERSHIP_SCOPE

    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(args.dsn, row_factory=dict_row) as conn:
        candidates = fetch_candidates(conn)

        if args.confirm:
            # ⛔ The live arm+enqueue path. execute_sweep refuses (writes nothing)
            # while _DISARM_WIRED is False — so today this echoes the plan and
            # STOPS. --include-client is preview-only; --confirm never widens
            # past the ROE allowlist without the operator also passing it.
            scope_for_confirm = (None if args.include_client
                                 else DEFAULT_OWNERSHIP_SCOPE)
            eff_scope = (frozenset({a.get("ownership") for a in candidates})
                         if scope_for_confirm is None else scope_for_confirm)
            plan = build_arm_enqueue_plan(candidates, ownership_scope=eff_scope)
            print(f"⛔ --confirm: {len(plan['arm'])} host(s) in scope WOULD be "
                  f"armed + enqueued.", file=sys.stderr)
            result = execute_sweep(conn, candidates, confirmed=True,
                                   ownership_scope=eff_scope)
            if result["executed"]:
                conn.commit()
            print(json.dumps(result, indent=2, default=str))
            if not result["executed"]:
                print(f"\n⛔ NOTHING WRITTEN — {result['reason']}.", file=sys.stderr)
                return 3
            print(f"\n✅ armed {result['armed']}, enqueued {result['enqueued']}.",
                  file=sys.stderr)
            return 0

    if ownership_scope is None:
        # --include-client: every ownership is in scope for the PREVIEW.
        scope = [a for a in candidates
                 if enforcement_applies(resolved_device_class(a), _vendor_product(a))]
        radius = {
            "dry_run": True, "fired": False, "ownership_scope": ["ALL (client included)"],
            "count": len(scope),
            "hosts": [{"asset_id": a.get("asset_id"), "host": a.get("name"),
                       "device_class": resolved_device_class(a),
                       "ownership": a.get("ownership"), "vendor": _vendor(a),
                       "already_authorized": a.get("enforcement_probe_authorized") is True}
                      for a in scope],
        }
    else:
        radius = build_blast_radius(candidates, ownership_scope=ownership_scope)

    print(json.dumps(radius, indent=2, default=str))
    print(f"\n⛔ DRY-RUN preview only — {radius['count']} host(s) WOULD be probed; "
          f"nothing was sent. Arming + firing is a separate operator action.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
