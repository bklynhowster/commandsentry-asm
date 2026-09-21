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

⛔ SCOPE IS PROTECTIVE CLASSES ONLY. "Is it enforcing?" is only meaningful for a
host with something in front — waf / edge_firewall / adc_lb. Same set the portal
uses (src/lib/enforcement-status.mjs PROTECTIVE_CLASSES). An origin_host or a
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

# The "something is in front" classes — mirror of the portal's PROTECTIVE_CLASSES.
PROTECTIVE_CLASSES = ("waf", "edge_firewall", "adc_lb")

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
        resolved_device_class(asset) in PROTECTIVE_CLASSES
        and asset.get("ownership") in ownership_scope
    )


def select_sweep_scope(
    assets: list[dict], *, ownership_scope: frozenset = DEFAULT_OWNERSHIP_SCOPE
) -> list[dict]:
    """Filter a candidate list to the in-scope hosts. Pure — no I/O."""
    return [a for a in assets if in_scope(a, ownership_scope=ownership_scope)]


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
    args = ap.parse_args(argv)

    if not args.dsn:
        print("error: SUPABASE_DSN not set (pass --dsn)", file=sys.stderr)
        return 2

    ownership_scope = None if args.include_client else DEFAULT_OWNERSHIP_SCOPE

    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(args.dsn, row_factory=dict_row) as conn:
        candidates = fetch_candidates(conn)

    if ownership_scope is None:
        # --include-client: every ownership is in scope for the PREVIEW.
        scope = [a for a in candidates
                 if resolved_device_class(a) in PROTECTIVE_CLASSES]
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
