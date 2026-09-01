#!/usr/bin/env python3
"""wall_clock_rollback_trigger.py — the ⑯′ rollback trigger for ⑮ (400s).

4.7 ruling ⑯′ as originally written asked for "ban rate baseline + 10% for 3
consecutive days." That is NOT COMPUTABLE on this fleet: the pre-⑮ baseline is
**2 failures in 18 medium/heavy runs across 30 days** — roughly 0.6 runs a day.
Most days have zero runs, so a daily rate is undefined and a 3-consecutive-day
rule would either never fire or fire on a single unlucky run.

Ruling ⑯′-recalibrated (2026-09-01) replaces it with a COUNT trigger plus a TIME
window, so it works at both high and low volume. Either condition fires:

    1. 3+ failures in any consecutive 10-run window of medium/heavy runs
    2. 5+ failures in any 20-day window

Baseline for reference: 2 failures / 18 runs = 11.1%. Trigger (1) is 30%.

WHAT ROLLBACK MEANS — one constant, both instances:
    scripts/scanner/run_medium.py :: NUCLEI_CHUNK_WALL_S = 400  ->  180
No migration, no schema, no data change. Revert, run the suite, push both.
`test_nuclei_chunk_wall_is_400s_not_180` will fail on the reverted value — that
is expected and is the pin doing its job; update it in the same commit.

WHY A SCRIPT AND NOT A DASHBOARD: 4.7's fourth-biggest risk was shipping a
trigger whose rollback path had never been exercised. This is runnable, so the
path can be tested with --simulate before it is ever needed for real.

Usage:
    python3 wall_clock_rollback_trigger.py                 # evaluate live
    python3 wall_clock_rollback_trigger.py --simulate 3    # dry-run N failures
Exit 0 = no rollback indicated. Exit 2 = TRIGGER FIRED.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

# ── the trigger, as ruled ────────────────────────────────────────────────────
RUN_WINDOW = 10          # consecutive medium/heavy runs
RUN_FAILURES = 3         # failures within RUN_WINDOW that fire the trigger
DAY_WINDOW = 20          # days
DAY_FAILURES = 5         # failures within DAY_WINDOW that fire the trigger

# Pre-⑮ baseline, captured 2026-09-01 BEFORE the 400s bump shipped.
BASELINE_RUNS = 18
BASELINE_FAILURES = 2

SHIP_DATE = datetime(2026, 9, 1, tzinfo=timezone.utc)   # ⑮ shipped

QUERY = """
select
  scan_run_id,
  status,
  started_at
from public.scan_run
where intensity in ('medium','heavy')
  and started_at >= %(since)s
order by started_at desc
limit 200;
"""


def evaluate(rows: list[dict]) -> tuple[bool, list[str]]:
    """(fired, reasons). rows newest-first, each {status, started_at}.

    Pure so the trigger logic is testable without a database — the rollback
    path has to be exercisable before it is needed.
    """
    reasons: list[str] = []
    failed = [r for r in rows if r.get("status") != "complete"]

    # 1. count trigger over the most recent RUN_WINDOW runs
    window = rows[:RUN_WINDOW]
    n_fail = sum(1 for r in window if r.get("status") != "complete")
    if len(window) >= RUN_WINDOW and n_fail >= RUN_FAILURES:
        reasons.append(
            f"{n_fail} failures in the last {RUN_WINDOW} medium/heavy runs "
            f"(threshold {RUN_FAILURES}; baseline {BASELINE_FAILURES}/"
            f"{BASELINE_RUNS} = "
            f"{100*BASELINE_FAILURES/BASELINE_RUNS:.1f}%)")

    # 2. time trigger — for stretches too sparse for the count trigger to fill
    cutoff = datetime.now(timezone.utc) - timedelta(days=DAY_WINDOW)
    recent = [r for r in failed
              if r.get("started_at") and r["started_at"] >= cutoff]
    if len(recent) >= DAY_FAILURES:
        reasons.append(
            f"{len(recent)} failures in the last {DAY_WINDOW} days "
            f"(threshold {DAY_FAILURES})")

    return bool(reasons), reasons


def _simulate(n_failures: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows = []
    for i in range(RUN_WINDOW):
        rows.append({"scan_run_id": f"sim-{i}",
                     "status": "failed" if i < n_failures else "complete",
                     "started_at": now - timedelta(days=i)})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--simulate", type=int, metavar="N",
                    help="dry-run with N failures in the run window; no DB")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    args = ap.parse_args()

    if args.simulate is not None:
        rows = _simulate(args.simulate)
        print(f"SIMULATION: {args.simulate} failures in a {RUN_WINDOW}-run window")
    else:
        if not args.dsn:
            print("no --dsn / SUPABASE_DSN", file=sys.stderr)
            return 1
        import psycopg                                    # noqa: PLC0415
        with psycopg.connect(args.dsn) as conn, conn.cursor() as cur:
            cur.execute(QUERY, {"since": SHIP_DATE})
            cols = [c.name for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        print(f"evaluated {len(rows)} medium/heavy run(s) since ⑮ shipped")

    fired, reasons = evaluate(rows)
    if fired:
        print("\n🔴 ROLLBACK TRIGGER FIRED")
        for r in reasons:
            print(f"  - {r}")
        print("\nRollback: set NUCLEI_CHUNK_WALL_S back to 180 in")
        print("  scripts/scanner/run_medium.py   (BOTH instances)")
        print("and update test_nuclei_chunk_wall_is_400s_not_180 in the same")
        print("commit — it pins 400 deliberately. No migration involved.")
        return 2

    print("no rollback indicated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
