#!/usr/bin/env python3
"""retire_detector_findings.py — transition findings whose DETECTOR left the plan.

4.7 ruling (57). MANUAL ONLY. Dry-run by default. Never scheduled.

## What this is for

A finding whose only detector has been removed from the scan plan can never be
re-observed. It is neither open (we are not looking) nor remediated (nobody
established a fix). `detector_retired` names that condition; this tool is the
only thing that sets it.

Measured scope on Command 2026-09-02: ONE class — source `nuclei`, severity
INFO, 71 open findings across 4 assets, newest observation 2026-03-30. The
scanner's chunk plan (run_medium.py L2407-2426) has no info-severity chunk on
any tier, so no future scan can re-detect them.

## 🔴 TRANSITIONS ARE DELIBERATE, NOT AUTOMATIC

There is no trigger, no cron, no default. An automatic absence-based transition
would be the same defect this workstream keeps deleting, wearing a new status
name. A human decides a detector is retired, and runs this.

CRITERIA — a class qualifies ONLY when BOTH hold:
  1. a specific detector has been removed from the scan plan, AND
  2. the finding's producing check has NO remaining detector in the current
     plan, so it can never be re-observed.

This is NOT a bucket for findings we would rather not triage. Anything failing
(2) — including a finding that is merely stale, or on an asset that simply has
not been scanned lately — stays open. The nikto LOW case is the worked example:
it looked identical at the class level (158 days stale) but `nikto_runs_since=0`
showed the assets had not been scanned, so it is a COVERAGE GAP, not a
retirement, and this tool must not touch it.

## Guardrails (Howie's standing rule for destructive auto-actions)

  1. SOURCE-TAG      — every row records why, which detector, and when.
  2. THRESHOLD-ABORT — more than --max-retire rows is not a known retirement,
                       it is a mistaken predicate. Write NOTHING and shout.
  3. REAL DRY-RUN    — default. --live is required to write.
  4. NAME THE TARGET — prints the DB host FIRST and supports
                       --expect-instance, because a confident no-op against the
                       wrong instance is worse than an error (learned the hard
                       way 2026-09-02, sweep_stale_running_scans.py).
  5. EXPLICIT REASON — --reason is REQUIRED for --live. The audit row is the
                       whole point; an unexplained transition is not auditable.

Usage:
    python3 retire_detector_findings.py --source nuclei --severity INFO \\
        --reason "nuclei info-severity templates absent from chunk plan; see Obsidian 212"
    ... add --live to write, and --expect-instance <ref-prefix> to pin the
    target instance (the Supabase project ref prefix for whichever instance you
    mean — deliberately not named here, since this file ships byte-identical to
    both and a hard-coded example is how you end up pinning the wrong one).

Exit: 0 ok | 2 THRESHOLD ABORT / wrong instance | 1 usage or DB error.
"""
from __future__ import annotations

import argparse
import os
import sys

DEFAULT_MAX_RETIRE = 200

FIND_SQL = """
select f.finding_id, f.asset_id, f.severity::text as severity,
       f.source::text as source, f.title, f.last_observed_at
  from public.findings f
 where f.current_status in ('detected','open','regressed')
   and f.source::text   = %(source)s
   and f.severity::text = %(severity)s
 order by f.last_observed_at, f.finding_id;
"""

# 🔴 CRITERION (2) ENFORCED IN SQL, not assumed by the operator.
# If ANY finding in this class was observed by a scan that completed recently,
# something still detects it and it is NOT retired. Refuse the whole batch.
STILL_OBSERVED_SQL = """
select count(*) as n
  from public.findings f
 where f.source::text   = %(source)s
   and f.severity::text = %(severity)s
   and f.last_observed_at > now() - (interval '1 day' * %(quiet_days)s);
"""

RETIRE_SQL = """
update public.findings
   set current_status      = 'detector_retired',
       detector_retired_at = now(),
       updated_at          = now()
 where finding_id = %(finding_id)s
   and current_status in ('detected','open','regressed')
returning finding_id;
"""

AUDIT_SQL = """
insert into public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email,
   before_state, after_state, details)
values
  (null, 'detector_retired_finding', null, null,
   %(before)s, %(after)s, %(details)s);
"""


def qualifies(n_recent_observations: int) -> tuple[bool, str]:
    """Criterion (2): nothing in this class may have been observed recently.

    Pure so the decision is testable without a database — an untested guard on
    a destructive action is the same as no guard.
    """
    if n_recent_observations > 0:
        return False, (
            f"{n_recent_observations} finding(s) in this class were observed "
            f"within the quiet window. Something still detects them, so this is "
            f"NOT a retired detector — it may be a coverage gap or simple "
            f"staleness. Refusing.")
    return True, ""


def should_abort(n: int, max_retire: int) -> tuple[bool, str]:
    if n > max_retire:
        return True, (
            f"{n} findings exceeds --max-retire {max_retire}. A real detector "
            f"retirement is a known, bounded class. This looks like a mistaken "
            f"predicate. Refusing to write.")
    return False, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help="finding source, e.g. nuclei")
    ap.add_argument("--severity", required=True, help="severity, e.g. INFO")
    ap.add_argument("--reason", default="",
                    help="REQUIRED with --live. Goes into the audit row.")
    ap.add_argument("--live", action="store_true", help="actually write. Default is dry-run.")
    ap.add_argument("--quiet-days", type=int, default=90,
                    help="a class observed inside this window is NOT retired")
    ap.add_argument("--max-retire", type=int, default=DEFAULT_MAX_RETIRE)
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--expect-instance", metavar="SUBSTR",
                    help="abort unless the DB host contains SUBSTR")
    args = ap.parse_args()

    if not args.dsn:
        print("no --dsn / SUPABASE_DSN", file=sys.stderr)
        return 1
    if args.live and not args.reason.strip():
        print("--reason is REQUIRED with --live. The audit row is the point.",
              file=sys.stderr)
        return 1

    host = ""
    try:
        host = args.dsn.split("@", 1)[-1].split("/")[0].split(",")[0].split(":")[0]
    except Exception:                                        # noqa: BLE001
        host = "<unparseable>"
    print(f"target host: {host or '<unknown>'}")
    if args.expect_instance and args.expect_instance not in host:
        print(f"::error::ABORT — host {host!r} does not contain "
              f"{args.expect_instance!r}.", file=sys.stderr)
        return 2

    import psycopg                                           # noqa: PLC0415
    from psycopg.rows import dict_row                        # noqa: PLC0415
    from psycopg.types.json import Json                      # noqa: PLC0415

    with psycopg.connect(args.dsn, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(STILL_OBSERVED_SQL, {"source": args.source,
                                             "severity": args.severity,
                                             "quiet_days": args.quiet_days})
            n_recent = cur.fetchone()["n"]
            ok, why = qualifies(n_recent)
            print(f"criterion (2) — observations within {args.quiet_days}d: {n_recent}")
            if not ok:
                print(f"::error::{why}", file=sys.stderr)
                return 2

            cur.execute(FIND_SQL, {"source": args.source, "severity": args.severity})
            rows = cur.fetchall()

        print(f"class {args.source}/{args.severity}: {len(rows)} open finding(s)")
        abort, why = should_abort(len(rows), args.max_retire)
        if abort:
            print(f"::error::{why}", file=sys.stderr)
            return 2
        if not rows:
            print("nothing to do")
            return 0

        for r in rows[:10]:
            print(f"  {r['asset_id']:<32} {str(r['last_observed_at'])[:10]}  "
                  f"{(r['title'] or '')[:58]}")
        if len(rows) > 10:
            print(f"  ... and {len(rows) - 10} more")

        if not args.live:
            print("\nDRY RUN — nothing written. Re-run with --live --reason '...' to apply.")
            return 0

        n = 0
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(RETIRE_SQL, {"finding_id": r["finding_id"]})
                if cur.fetchone() is None:
                    continue                    # raced; skip silently
                cur.execute(AUDIT_SQL, {
                    "before": Json({"current_status": "open_family",
                                    "source": r["source"],
                                    "severity": r["severity"],
                                    "last_observed_at": str(r["last_observed_at"])}),
                    "after":  Json({"current_status": "detector_retired"}),
                    "details": Json({
                        "finding_id": r["finding_id"],
                        "asset_id": r["asset_id"],
                        "title": r["title"],
                        "retired_class": f"{args.source}/{args.severity}",
                        "reason": args.reason,
                        "tool": "retire_detector_findings.py",
                        "rule": "4.7_ruling_57_detector_retired_manual_transition",
                    }),
                })
                n += 1
        conn.commit()
        print(f"\nretired {n} finding(s) — audit rows written to admin_audit_log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
