#!/usr/bin/env python3
"""asset_liveness_probe.py — per-sweep liveness probe worker (Obsidian 161 step 2, 4.7 Q2/Q4/Q7).

Probes EVERY confirmed_live asset once per sweep and writes ONE public.asset_liveness_verdict row
per asset — the shared verdict later read by the dark-digest suppression AND the went_dark demotion
writer (via asset_liveness.get_fresh_verdict). PURE observation: writes only to
asset_liveness_verdict, NEVER mutates asset state. Runs as a step in asm-discover.yml BEFORE
demotion_writer, every 6h (4.7 Q4 cadence). Verdict-writing is LIVE from ship (that's how data
accumulates); the DRY-RUN in this program (--dry-run) only skips the write for a manual first look —
the consumer-side dry-run (digest logs-not-acts) is a separate, later push.

Ports (4.7 Q2): asset_surface known-open ∪ asset-type fallback ∪ safe defaults, via
asset_liveness.select_probe_ports. Verdict booleans (4.7 Q3): asset_liveness.verdict_booleans
(any_port_responded = open OR refused; any_port_open = open only). Probe primitives reused from
demotion_writer (resolve_host / probe_port / known_ports) so probe behaviour is identical fleet-wide.

Sweep-health (4.7 Q7 fail-safe): if a non-trivial fleet comes back almost entirely non-responding,
that's OUR egress breaking, not the fleet dying — abort the sweep and write NOTHING rather than
stamp a fleet of false-dead verdicts. A resolver hiccup on a single asset skips that asset (no row)
rather than recording a wrong verdict.

Env: SUPABASE_DSN or --dsn. psycopg3.
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print("error: psycopg (psycopg3) required. pip install --user --break-system-packages 'psycopg[binary]'",
          file=sys.stderr)
    raise

from asset_liveness import select_probe_ports, verdict_booleans
from demotion_writer import resolve_host, probe_port, known_ports

UTC = timezone.utc

MAX_WORKERS = 24                 # bounded concurrency (4.7 Q7 pacing — light TCP connects, not scans)
SWEEP_RESPONDED_FLOOR = 0.10     # <10% of a non-trivial fleet responding => egress broken => abort
MIN_FLEET_FOR_FLOOR = 10         # below this, no floor (a tiny fleet legitimately can be mostly quiet)

Q_CONFIRMED_LIVE = "SELECT asset_id FROM public.assets WHERE discovery_status = 'confirmed_live'"
Q_UPSERT_VERDICT = """
INSERT INTO public.asset_liveness_verdict
  (asset_id, sweep_id, probed_at, any_port_responded, any_port_open, per_port_results, probe_source)
VALUES (%(asset_id)s, %(sweep_id)s, now(), %(responded)s, %(open)s, %(ppr)s, %(src)s)
ON CONFLICT (asset_id, sweep_id) DO UPDATE SET
  probed_at          = EXCLUDED.probed_at,
  any_port_responded = EXCLUDED.any_port_responded,
  any_port_open      = EXCLUDED.any_port_open,
  per_port_results   = EXCLUDED.per_port_results,
  probe_source       = EXCLUDED.probe_source
"""


def log(m: str) -> None:
    print(f"[liveness_probe] {m}", flush=True)


# ── PURE cores (unit-tested; probe primitives patched in tests) ─────────────────────────────────
def probe_asset(asset_id: str, ports: list[int]) -> dict | None:
    """Probe one asset (PURE network — no DB, thread-safe). Returns the verdict dict, or None to
    SKIP this asset (resolver hiccup: don't record a wrong verdict). asset_id doubles as the host
    (resolvable), matching demotion_writer.single_probe."""
    ip, status = resolve_host(asset_id)
    if status == "nxdomain":
        # DNS truly gone => nothing answered => not responded (a genuinely-dark asset stays dark).
        return {"any_port_responded": False, "any_port_open": False,
                "per_port_results": {"_dns": "nxdomain"}}
    if status != "ok" or not ip:
        return None                                    # EAI_AGAIN etc. — resolver hiccup, skip
    per: dict = {}
    for p in ports:
        per[str(p)] = {"result": probe_port(ip, p)}
    results = [per[str(p)]["result"] for p in ports]
    responded, is_open = verdict_booleans(results)
    return {"any_port_responded": responded, "any_port_open": is_open, "per_port_results": per}


def sweep_ok(verdicts: list, fleet_size: int) -> tuple[bool, str]:
    """Egress fail-safe (4.7 Q7). A non-trivial fleet coming back almost entirely non-responding
    is our egress, not the fleet — abort. Small fleets get no floor (they can legitimately be
    mostly quiet). None verdicts (skipped) don't count as responded."""
    if fleet_size < MIN_FLEET_FOR_FLOOR:
        return True, f"small_fleet({fleet_size})_no_floor"
    responded = sum(1 for v in verdicts if v and v.get("any_port_responded"))
    frac = responded / fleet_size if fleet_size else 0.0
    if frac < SWEEP_RESPONDED_FLOOR:
        return False, (f"only {responded}/{fleet_size} responded ({frac:.0%}) < floor "
                       f"{SWEEP_RESPONDED_FLOOR:.0%} — likely egress outage, not the fleet")
    return True, f"{responded}/{fleet_size} responded ({frac:.0%})"


# ── DB glue ─────────────────────────────────────────────────────────────────────────────────────
def confirmed_live_targets(conn) -> list[tuple[str, list[int]]]:
    """(asset_id, probe_ports) for every confirmed_live asset. Ports = known-open (asset_surface)
    ∪ asset-type fallback ∪ safe defaults."""
    with conn.cursor() as cur:
        cur.execute(Q_CONFIRMED_LIVE)
        asset_ids = [r[0] for r in cur.fetchall()]
    targets = []
    for a in asset_ids:
        ko = known_ports(conn, a)                      # reuse demotion_writer (surface services -> ports)
        targets.append((a, select_probe_ports(a, ko)))
    return targets


def write_verdict(conn, asset_id: str, sweep_id: str, v: dict, source: str) -> None:
    with conn.cursor() as cur:
        cur.execute(Q_UPSERT_VERDICT, {
            "asset_id": asset_id, "sweep_id": sweep_id,
            "responded": bool(v["any_port_responded"]), "open": bool(v["any_port_open"]),
            "ppr": Json(v["per_port_results"]), "src": source,
        })


def run(conn, dry_run: bool, sweep_id: str, source: str) -> int:
    targets = confirmed_live_targets(conn)
    fleet = len(targets)
    log(f"sweep {sweep_id[:8]} — {fleet} confirmed_live asset(s); dry_run={dry_run}")
    if not targets:
        log("no confirmed_live assets — nothing to probe")
        return 0

    results: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(probe_asset, a, ports): a for a, ports in targets}
        for f in as_completed(futs):
            a = futs[f]
            try:
                results[a] = f.result()
            except Exception as e:                     # a single probe blowing up must not kill the sweep
                log(f"  probe error {a}: {e!r} — skipping")
                results[a] = None

    ok, reason = sweep_ok(list(results.values()), fleet)
    log(f"sweep-health: {reason}")
    if not ok:
        log("ABORT (fail-safe): writing NO verdicts this sweep")
        return 0

    responded = sum(1 for v in results.values() if v and v.get("any_port_responded"))
    open_svc = sum(1 for v in results.values() if v and v.get("any_port_open"))
    skipped = sum(1 for v in results.values() if v is None)
    log(f"verdicts: responded={responded} open={open_svc} skipped(resolver)={skipped}")

    written = 0
    for a, v in results.items():
        if v is None:
            continue
        if dry_run:
            log(f"  DRY-RUN {a}: responded={v['any_port_responded']} open={v['any_port_open']} "
                f"ports={list(v['per_port_results'])}")
        else:
            write_verdict(conn, a, sweep_id, v, source)
        written += 1
    if not dry_run:
        conn.commit()
    log(f"{'would-write' if dry_run else 'wrote'} {written} verdict(s)")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-sweep liveness probe worker (Obsidian 161).")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--dry-run", action="store_true", help="probe + log, write NO verdicts")
    ap.add_argument("--run-tag", default="", help="correlation tag (e.g. GITHUB_RUN_ID); informational")
    ap.add_argument("--source", default="liveness_sweep")
    args = ap.parse_args()
    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 2
    sweep_id = str(uuid.uuid4())
    if args.run_tag:
        log(f"run-tag={args.run_tag}")
    with psycopg.connect(args.dsn, autocommit=False, connect_timeout=15) as conn:
        run(conn, dry_run=args.dry_run, sweep_id=sweep_id, source=args.source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
