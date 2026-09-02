#!/usr/bin/env python3
"""sweep_stale_running_scans.py — the liveness sweeper that never existed.

## Why this exists

`poll_queue.py` commits the claim + scan_run insert atomically and then says:

    # If the GH Action subsequently dies, we have a queue row in 'running'
    # state with started_at set — the liveness sweeper (separate cron, M11)
    # detects scans stuck in 'running' for > 4h and marks them failed.

**There was no such sweeper.** Not in either repo, not in any workflow. The
comment described a safety net that was never built, so a runner killed
mid-scan left its rows `running` forever.

That is not merely untidy. BOTH enqueue paths skip an asset that already has a
`queued` or `running` row:

  * `enqueue-fleet.yml`  — `not exists (select 1 from scan_queue q where ...)`
  * `scanner.yml` ad-hoc — "already has an active queue row ... Skipping INSERT"

So one wedged row makes its asset **permanently unscannable, silently**.
Found live on PRODEXsentry 2026-09-02: `cooked.prodexlabs.com` stuck `running`
since 2026-07-10 — **53.6 days** excluded from every fleet sweep, with nothing
anywhere surfacing it. Command was clean (0 rows).

The per-run "Cleanup orphaned running rows" step in scanner.yml does NOT cover
this: it only touches `scan_run_id = <this run>`, so it is a close-out sentinel
for the run that is ending, never a garbage collector for rows abandoned by a
run that died before reaching it.

## Guardrails (Howie's standing rule for destructive auto-actions)

  1. SOURCE-TAG   — every row this writes says so in error_message, so a human
                    reading the DB can tell a swept row from a genuine failure.
  2. THRESHOLD-ABORT — sweeping more than --max-sweep rows is not a few orphans,
                    it is a systemic failure (DB outage, mass runner death). In
                    that case write NOTHING and shout. A sweeper that mass-fails
                    live scans during an incident makes the incident worse.
  3. REAL DRY-RUN — default. `--live` is required to write. Dry-run prints the
                    exact rows it would touch.

## Threshold

--stale-hours defaults to 4. The longest legitimate run observed is ~39 min
(cumulative heavy with testssl), and the cumulative ceiling is 1800s, so 4h is
~6x headroom. A row past it has no live workflow behind it.

Usage:
    python3 sweep_stale_running_scans.py                    # dry-run
    python3 sweep_stale_running_scans.py --live             # actually sweep
    python3 sweep_stale_running_scans.py --stale-hours 8 --max-sweep 5
Exit: 0 nothing to do / swept cleanly | 2 THRESHOLD ABORT | 1 usage or DB error.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_STALE_HOURS = 4
DEFAULT_MAX_SWEEP = 10

SWEEP_TAG = "swept by sweep_stale_running_scans.py"

FIND_SQL = """
select q.queue_id, q.asset_id, q.intensity, q.scan_run_id, q.started_at
  from public.scan_queue q
 where q.status = 'running'
   and q.started_at < %(cutoff)s
 order by q.started_at;
"""

# Both tables, same predicate. scan_run is updated via the queue row's backlink
# so we never touch a scan_run that no queue row claims.
SWEEP_QUEUE_SQL = """
update public.scan_queue
   set status = 'failed',
       completed_at = now(),
       duration_seconds = extract(epoch from (now() - started_at))::int,
       error_message = coalesce(error_message, %(reason)s)
 where queue_id = %(queue_id)s
   and status = 'running';
"""

SWEEP_RUN_SQL = """
update public.scan_run
   set status = 'failed',
       completed_at = now(),
       duration_seconds = extract(epoch from (now() - started_at))::int,
       error_message = coalesce(error_message, %(reason)s)
 where scan_run_id = %(scan_run_id)s
   and status = 'running';
"""


def find_stale(rows, stale_hours: int, now: datetime | None = None) -> list:
    """Rows whose started_at is older than the threshold.

    Pure so the decision is testable without a database — the whole point of
    this file is that an untested safety net is the same as no safety net.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=stale_hours)
    out = []
    for r in rows:
        started = r.get("started_at")
        if started is None:
            # No started_at means the claim never completed. Not ours to judge.
            continue
        if started < cutoff:
            out.append(r)
    return out


def should_abort(n_stale: int, max_sweep: int) -> tuple[bool, str]:
    """THRESHOLD-ABORT. Many stale rows at once is not an orphan problem.

    A handful of rows is what a killed runner leaves behind. Dozens means
    something systemic — and a sweeper that mass-fails rows during an incident
    turns a recoverable outage into lost scan history.
    """
    if n_stale > max_sweep:
        return True, (
            f"{n_stale} stale rows exceeds --max-sweep {max_sweep}. This is not "
            f"a few orphans — it looks systemic (DB outage, mass runner death, "
            f"or a clock problem). Refusing to write. Investigate, then re-run "
            f"with a raised --max-sweep if the rows really are dead.")
    return False, ""


def _reason(stale_hours: int) -> str:
    return (f"{SWEEP_TAG}: stuck in 'running' > {stale_hours}h with no live "
            f"workflow. The GH run almost certainly died mid-scan; poll_queue "
            f"committed the claim before it. Swept so the asset is scannable "
            f"again — both enqueue paths skip assets with an active row.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="actually write. Default is dry-run.")
    ap.add_argument("--stale-hours", type=int, default=DEFAULT_STALE_HOURS)
    ap.add_argument("--max-sweep", type=int, default=DEFAULT_MAX_SWEEP)
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--expect-instance", metavar="SUBSTR",
                    help="abort unless the connected DB's host contains SUBSTR. "
                         "Use it: a shell SUPABASE_DSN pointing at the OTHER "
                         "instance produces a confident 'nothing to do'.")
    args = ap.parse_args()

    if not args.dsn:
        print("no --dsn / SUPABASE_DSN", file=sys.stderr)
        return 1

    import psycopg                                          # noqa: PLC0415
    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.stale_hours)

    # 🔴 SAY WHICH DATABASE. Added 2026-09-02 after this tool reported
    # "no scans stuck in 'running' beyond 4h" against COMMANDsentry while the
    # operator was in the prodexsentry-asm directory intending to sweep Prodex.
    # Command genuinely had zero stale rows, so the wrong-target run looked
    # exactly like success. A destructive tool that does not name its target is
    # one stale shell variable away from a confident no-op — or a confident
    # write against the wrong instance. cwd does NOT determine the DSN.
    host = ""
    try:
        for part in args.dsn.split("@", 1)[-1].split("/")[0].split(","):
            host = part.split(":")[0]
            break
    except Exception:                                       # noqa: BLE001
        host = "<unparseable>"
    print(f"target host: {host or '<unknown>'}")
    if args.expect_instance and args.expect_instance not in host:
        print(f"::warning::ABORT — host {host!r} does not contain "
              f"{args.expect_instance!r}. Refusing to act on a database you "
              f"did not name. Check SUPABASE_DSN.", file=sys.stderr)
        return 2

    with psycopg.connect(args.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(FIND_SQL, {"cutoff": cutoff})
            cols = [c.name for c in cur.description]
            stale = [dict(zip(cols, r)) for r in cur.fetchall()]

        if not stale:
            print(f"no scans stuck in 'running' beyond {args.stale_hours}h "
                  f"on {host or 'this database'}")
            print("  (if you expected rows here, check SUPABASE_DSN points at "
                  "the instance you meant — cwd does not determine it)")
            return 0

        print(f"found {len(stale)} stale running scan(s) "
              f"(> {args.stale_hours}h):")
        for r in stale:
            age_d = (datetime.now(timezone.utc) - r["started_at"]).days
            print(f"  - {r['asset_id']:<40} {r['intensity']:<7} "
                  f"started {r['started_at']:%Y-%m-%d %H:%M}  ({age_d}d)")
            print(f"    ⚠ this asset is EXCLUDED from every enqueue path while "
                  f"this row is 'running'")

        abort, why = should_abort(len(stale), args.max_sweep)
        if abort:
            print(f"\n::warning::THRESHOLD ABORT — {why}")
            return 2

        if not args.live:
            print("\nDRY RUN — nothing written. Re-run with --live to sweep.")
            return 0

        reason = _reason(args.stale_hours)
        n_q = n_r = 0
        with conn.cursor() as cur:
            for r in stale:
                cur.execute(SWEEP_QUEUE_SQL,
                            {"queue_id": r["queue_id"], "reason": reason})
                n_q += cur.rowcount
                if r.get("scan_run_id"):
                    cur.execute(SWEEP_RUN_SQL,
                                {"scan_run_id": r["scan_run_id"],
                                 "reason": reason})
                    n_r += cur.rowcount
        conn.commit()
        print(f"\nswept {n_q} queue row(s) and {n_r} scan_run row(s) to 'failed'")
        print("those assets are scannable again")
    return 0


if __name__ == "__main__":
    sys.exit(main())
