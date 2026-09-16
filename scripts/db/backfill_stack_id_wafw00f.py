#!/usr/bin/env python3
"""Backfill the `stack_id_wafw00f` artifacts that heavy runs threw away.

Relay 216/217. DRY-RUN BY DEFAULT — `--write` is Howie's, after 4.7 reads the
dry-run output.

⛔ WHY THERE IS ANYTHING TO BACKFILL. `phase_registry` registers the FUNCTION
`_medium.detect_waf`, which parses wafw00f and writes the RAW artifact. The
structured verdict was written by a SEPARATE call sitting next to `detect_waf(ctx)`
in run_medium.run()'s linear body. When the heavy cutover (b51ef0c1 / 16d778e9,
2026-08-29) began dispatching phases through `run_phases`, heavy inherited the
parse and not the persist:

    heavy runs with raw `wafw00f` and no `stack_id_wafw00f`    18 of 18
    medium runs with both                                      22 of 22

The verdicts were never lost — they are still sitting in the raw `wafw00f` text
artifacts. This reparses them and writes the structured verdict the classifier
reads, so a host like commandcommcentral.com (wafw00f named FortiWeb on 09-03)
goes back to `waf/confirmed` on REAL 13-day-old evidence rather than us preserving
a stale label and calling it honest.

⛔ THE PARSE IS IMPORTED, NEVER RE-IMPLEMENTED. A second copy of the regexes here
would be a third place for this class of bug to live — the drift that caused Q7,
and the reason 4.7's ruling was FOLD rather than register-a-pair. This runs
`run_medium._classify_wafw00f_output` against a duck-typed ctx, which is exactly
what a real scan runs, and then `run_medium.persist_stack_id_wafw00f` to build the
artifact body. If either changes shape, this script changes with it or fails loudly.

⚠ WHAT IT WILL NOT DO
  * It never overwrites: a run that already has a `stack_id_wafw00f` is skipped.
  * It never invents: a run whose raw artifact is missing or unparseable is
    REPORTED and skipped, not defaulted to "no WAF found". An absent verdict and a
    negative verdict are different facts, and conflating them is the whole defect
    this repo has been chasing.
  * It does not touch `assets`. The classifier re-derives on its next pass.

Usage
    python3 scripts/db/backfill_stack_id_wafw00f.py              # dry-run, prints a plan
    python3 scripts/db/backfill_stack_id_wafw00f.py --write      # Howie only, after review
    python3 scripts/db/backfill_stack_id_wafw00f.py --limit 5    # bound the read
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import types
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "scanner"))

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:                                    # pragma: no cover
    psycopg = None

import run_medium as _medium  # noqa: E402  — the parse lives THERE, not here


FIND_SQL = """
select r.scan_run_id, r.asset_id, r.intensity, r.completed_at,
       coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw
  from scan_run r
  join scan_run_artifacts a on a.scan_run_id = r.scan_run_id
 where a.tool_name = 'wafw00f'
   and not exists (select 1 from scan_run_artifacts b
                    where b.scan_run_id = r.scan_run_id
                      and b.tool_name = 'stack_id_wafw00f')
 order by r.completed_at desc
"""

INSERT_SQL = """
insert into public.scan_run_artifacts (scan_run_id, tool_name, content_type, content_jsonb)
values (%s, 'stack_id_wafw00f', 'json', %s::jsonb)
"""


def verdict_from_raw(raw: str) -> dict | None:
    """Reparse a stored raw wafw00f artifact with the SCANNER'S OWN parser.

    Returns the verdict dict `persist_stack_id_wafw00f` would have written, or
    None if the raw text is absent/unusable — never a fabricated negative."""
    if not raw or not raw.strip():
        return None
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    # rc=0: the artifact exists, so wafw00f produced output. _classify_wafw00f_output
    # treats rc != 0 as "assume no WAF", which is exactly the fabricated negative
    # this function refuses to produce.
    _medium._classify_wafw00f_output(ctx, raw, 0)
    _medium.persist_stack_id_wafw00f(ctx)
    if not ctx.artifacts:
        return None
    return json.loads(ctx.artifacts[-1][2])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="actually insert (Howie only, after 4.7 reads the dry-run)")
    ap.add_argument("--limit", type=int, default=0, help="bound the number of runs considered")
    args = ap.parse_args()

    if psycopg is None:
        sys.exit("psycopg required (run in the scanner env).")
    dsn = (os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
           or os.environ.get("DSN"))
    if not dsn:
        sys.exit("set SUPABASE_DSN (or COMMAND_SUPABASE_DSN / DSN)")

    mode = "WRITE" if args.write else "DRY-RUN"
    print(f"backfill_stack_id_wafw00f — {mode}")
    print("  parser: run_medium._classify_wafw00f_output (imported, not reimplemented)\n")

    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=15)
    conn.autocommit = False
    tally = Counter()
    unparseable = []

    with conn.cursor() as cur:
        cur.execute(FIND_SQL)
        rows = cur.fetchall() or []
        if args.limit:
            rows = rows[: args.limit]
        print(f"  runs with a raw wafw00f and NO stack_id_wafw00f: {len(rows)}\n")
        print(f"    {'intensity':9s} {'completed':12s} {'detected':9s} {'kind':12s} asset")
        for r in rows:
            v = verdict_from_raw(r.get("raw") or "")
            if v is None:
                tally["unparseable"] += 1
                unparseable.append(f"{r['asset_id']} {str(r['completed_at'])[:16]}")
                print(f"    {str(r['intensity']):9s} {str(r['completed_at'])[:12]:12s} "
                      f"{'—':9s} {'UNPARSEABLE':12s} {r['asset_id'][:36]}")
                continue
            tally["would_write" if not args.write else "written"] += 1
            tally[f"kind:{v['wafw00f_kind']}"] += 1
            print(f"    {str(r['intensity']):9s} {str(r['completed_at'])[:12]:12s} "
                  f"{str(v['wafw00f_detected']):9s} {str(v['wafw00f_kind']):12s} "
                  f"{r['asset_id'][:36]}")
            if args.write:
                cur.execute(INSERT_SQL, (r["scan_run_id"], json.dumps(v)))
        if args.write:
            conn.commit()
        else:
            conn.rollback()
    conn.close()

    print(f"\n  summary: {dict(tally)}")
    if unparseable:
        print("  ⚠ UNPARSEABLE — reported, NOT defaulted to 'no WAF found':")
        for u in unparseable:
            print(f"      {u}")
    if not args.write:
        print("\n  DRY-RUN — nothing written. Re-run with --write after 4.7 reads this.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
