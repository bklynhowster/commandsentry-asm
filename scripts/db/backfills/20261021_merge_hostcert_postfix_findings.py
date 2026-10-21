#!/usr/bin/env python3
"""
20261021_merge_hostcert_postfix_findings.py

One-time backfill for testssl findings minted with testssl 3.3dev's
per-certificate postfix ids ("<hostCert#1>", "<#N>", bracket-less
"hostCert#1").

Context (328, 2026-10-21):
  testssl 3.3dev enumerates per-certificate records when an endpoint presents
  more than one host cert (email.commandcompanies.com: Microsoft rotated the
  outlook.com leaf between the 10-12 and 10-19 heavies). The parser passed the
  postfixed ids through verbatim, so each postfixed record minted a NEW
  finding identity next to the plain one: one real name-mismatch sat as three
  findings (one MODERATE + two HIGH) and one wildcard fact as three rows. The
  parser is fixed (_normalize_id strips the postfix); this backfill merges the
  already-minted rows back onto their base findings, so the next re-observation
  lands on the base row instead of duplicating again.

  MERGE SET — postfixed rows whose BASE row exists. Today (2026-10-21,
  Command): the 4 active <hostCert#N> rows on email.commandcompanies.com
  (base row exists 4/4) + their 8 finding_history rows (all 8 collide with the
  base row's history for the same scan). Prodex: 0 postfixed rows (no-op).

  OUT OF SCOPE, REPORTED ONLY — postfixed rows whose base does NOT exist:
  the 44 legacy <#N> rows at INFO / current_status='remediated' (first
  detected 2026-03-24 → 03-29, 7 other assets) + their 88 finding_history
  rows. No merge target exists, INFO records are dropped at parse level
  (SKIP_SEVERITIES, cs_parsers/testssl.py), so they can never re-observe.
  Nothing is deleted: deleting them would destroy 88 rows of dated history
  for no gain.

Steps (FK/UNIQUE-safe, IN THIS ORDER):
  1. Derive the base id by STRING SURGERY on the existing finding_id — strip
     the postfix token(s) from the template part, keep <asset>:<source> and
     the trailing :<hash7> verbatim. NOT recomputed from port: findings.port
     is NULL on the active postfixed rows, so a port-based rebuild would mint
     a base id that does not exist and the deletes below would DESTROY rows
     instead of merging them.
  2. DELETE postfixed finding_history rows whose (base_id, scan_id) already
     exists on the base — finding_history is UNIQUE (finding_id, scan_id), so
     the move would abort otherwise.
  3. UPDATE the remaining postfixed history rows to the base id.
  4. DELETE the postfixed findings rows — AFTER the history move: the FK is
     ON DELETE CASCADE, so deleting first would take the history with it.
  5. Recompute posture (refresh_all_asset_posture).

  CASCADE ACCOUNTING (code-review must-fix 1, 2026-10-21): findings has FIVE
  ON DELETE CASCADE children — evidence_artifacts, exploit_attempts,
  finding_feedback, finding_history, remediation_requests. finding_history
  is merged (steps 2-3); the other four are COUNTED in the report and
  --apply REFUSES (exit 3) when any of them holds rows on a merge-set
  finding: a portal feedback row or an attached evidence row must never be
  cascade-deleted silently, uncounted. Measured 2026-10-21 (read-only SQL):
  all four are 0 on the 4-row merge set.

--dry-run is the default and performs NO writes. --apply is Howie's act (a
backfill run changes DB data). SAFETY_THRESHOLD caps the merge set — abort if
more findings rows than that would be touched. Idempotent: re-running after
--apply reports 0 merge rows (only the untouched out-of-scope report remains).

Apply with:
  export SUPABASE_DSN='...'
  python3 scripts/db/backfills/20261021_merge_hostcert_postfix_findings.py --dry-run
  python3 scripts/db/backfills/20261021_merge_hostcert_postfix_findings.py --apply
"""
from __future__ import annotations

import argparse
import os
import re
import sys

try:
    import psycopg
except ImportError:
    print("error: pip install --user --break-system-packages 'psycopg[binary]'", file=sys.stderr)
    sys.exit(1)


SAFETY_THRESHOLD = 100  # abort if more MERGE-SET findings rows than this

# Mirror of cs_parsers/testssl.py:_HOSTCERT_POSTFIX_RE (328). A postfixed
# finding_id's template part ends with the per-cert token(s) immediately
# before the final ':<hash7>'.
_HOSTCERT_POSTFIX_RE = re.compile(r"(?:\s+<?(?:hostCert)?#\d+>?)+$")
_HASH7_SUFFIX_RE = re.compile(r":[0-9a-f]{7}$")

# Selection regex (same token shape, anchored at the finding_id tail):
_POSTFIXED_FINDING_SQL = r"(?:\s+<?(?:hostCert)?#\d+>?)+:[0-9a-f]{7}$"


def derive_base_id(finding_id: str) -> str | None:
    """String surgery on the existing finding_id: strip the per-cert postfix
    token(s) from the end of the template part, keep <asset>:<source> and the
    trailing :<hash7> verbatim. None when the id is not postfixed."""
    m = _HASH7_SUFFIX_RE.search(finding_id)
    if not m:
        return None
    template = finding_id[: m.start()]
    stripped = _HOSTCERT_POSTFIX_RE.sub("", template)
    if stripped == template or not stripped:
        return None  # no postfix to strip — not a postfixed row
    return stripped + finding_id[m.start():]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what would change. No writes.")
    ap.add_argument("--apply", action="store_true",
                    help="Actually merge. Howie's act — changes DB data.")
    args = ap.parse_args()

    if not (args.dry_run or args.apply):
        print("error: pass --dry-run or --apply", file=sys.stderr)
        return 2
    if args.dry_run and args.apply:
        print("error: --dry-run and --apply are mutually exclusive", file=sys.stderr)
        return 2

    dsn = os.environ.get("SUPABASE_DSN")
    if not dsn:
        print("error: SUPABASE_DSN not set", file=sys.stderr)
        return 2

    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            # Selection: testssl rows whose finding_id ends with a per-cert
            # postfix token + :hash7. Both bracket forms match ('hostCert'
            # not required), so the 44 legacy <#N> rows are selected too —
            # then split by base-existence below.
            cur.execute(
                """
                select finding_id, asset_id
                from public.findings
                where source = 'testssl'
                  and finding_id ~ %s
                """,
                (_POSTFIXED_FINDING_SQL,),
            )
            postfixed = [(r[0], r[1]) for r in cur.fetchall()]

            merges: list[tuple[str, str]] = []  # (postfixed_id, base_id)
            out_of_scope: list[str] = []        # postfixed_id — base missing
            for fid, _asset_id in postfixed:
                base = derive_base_id(fid)
                if base is None:
                    print(f"   !! selected but surgery failed: {fid}")
                    continue
                # DRY-RUN ASSERTS BASE-EXISTS BEFORE ANY WRITE (round-1
                # review must-fix 3): no merge target → reported, untouched.
                cur.execute(
                    "select 1 from public.findings where finding_id = %s",
                    (base,),
                )
                if cur.fetchone() is not None:
                    merges.append((fid, base))
                else:
                    out_of_scope.append(fid)

            print(f"postfixed testssl findings rows: {len(postfixed)}")
            print(f"  merge set (base row exists): {len(merges)}")
            print(f"  out of scope (no base row; reported only, "
                  f"nothing deleted): {len(out_of_scope)}")
            for fid in out_of_scope[:5]:
                print(f"    e.g. {fid}")
            if len(out_of_scope) > 5:
                print(f"    ... and {len(out_of_scope) - 5} more")

            # History arithmetic on the merge set (dry-run shows the same
            # numbers --apply would act on).
            hist_total = 0
            hist_colliding = 0
            for fid, base in merges:
                cur.execute(
                    "select count(*) from public.finding_history where finding_id = %s",
                    (fid,),
                )
                n_hist = cur.fetchone()[0]
                hist_total += n_hist
                # Collision: the base already has a history row for the
                # same scan (finding_history UNIQUE (finding_id, scan_id)).
                cur.execute(
                    """
                    select count(*) from public.finding_history fh
                    join public.finding_history bh
                      on bh.finding_id = %s and bh.scan_id = fh.scan_id
                    where fh.finding_id = %s
                    """,
                    (base, fid),
                )
                hist_colliding += cur.fetchone()[0]

            print(f"merge-set history rows: {hist_total} "
                  f"(collide with base, would be deleted: {hist_colliding}; "
                  f"would be moved to the base id: "
                  f"{hist_total - hist_colliding})")

            if not merges:
                print("nothing to merge — out-of-scope rows are reported "
                      "above only.")
                conn.rollback()
                return 0

            if len(merges) > SAFETY_THRESHOLD:
                print(f"!! merge set {len(merges)} > SAFETY_THRESHOLD "
                      f"{SAFETY_THRESHOLD} — refusing. Investigate before retry.")
                conn.rollback()
                return 3

            # CASCADE ACCOUNTING (code-review must-fix 1, 2026-10-21):
            # findings has FIVE ON DELETE CASCADE children. finding_history
            # is merged (collisions deleted / rest moved, counted above);
            # these four are COUNTED here and --apply REFUSES if any is
            # non-zero — a portal feedback row or an attached evidence row
            # on a merge-set finding must never vanish silently, uncounted.
            cascade_counts = {}
            for table in ("evidence_artifacts", "exploit_attempts",
                          "finding_feedback", "remediation_requests"):
                cur.execute(
                    f"select count(*) from public.{table} "
                    "where finding_id = any(%s)",
                    ([fid for fid, _ in merges],),
                )
                cascade_counts[table] = cur.fetchone()[0]
            print("merge-set rows in the other cascade children of findings:")
            for table, n in cascade_counts.items():
                print(f"  {table}: {n}")
            if any(cascade_counts.values()):
                if args.dry_run:
                    print("!! non-zero rows outside finding_history on "
                          "merge-set findings — --apply will REFUSE until "
                          "they are resolved (they would be cascade-"
                          "deleted, uncounted).")
                else:
                    print("!! non-zero rows outside finding_history on "
                          "merge-set findings — REFUSING to apply: resolve "
                          "or move them first (they would be cascade-"
                          "deleted, uncounted).")
                    conn.rollback()
                    return 3

            print()
            if args.dry_run:
                print(">> DRY RUN sample (first 5):")
                for fid, base in merges[:5]:
                    print(f"   {fid}")
                    print(f"-> {base}")
                print("\n   Re-run with --apply to merge. No writes were made.")
                conn.rollback()
                return 0

            print(">> Applying merge...")
            deleted_hist = 0
            moved_hist = 0
            deleted_rows = 0
            for fid, base in merges:
                # (a) delete colliding history rows (the base already has
                # this scan) — BEFORE the move, or UNIQUE (finding_id,
                # scan_id) aborts it.
                cur.execute(
                    """
                    delete from public.finding_history fh
                    using public.finding_history bh
                    where fh.finding_id = %s
                      and bh.finding_id = %s
                      and bh.scan_id = fh.scan_id
                    """,
                    (fid, base),
                )
                deleted_hist += cur.rowcount
                # (b) move the remaining postfixed history rows to the base id
                cur.execute(
                    "update public.finding_history set finding_id = %s "
                    "where finding_id = %s",
                    (base, fid),
                )
                moved_hist += cur.rowcount
                # (c) delete the postfixed findings row — AFTER the history
                # move (the FK is ON DELETE CASCADE).
                cur.execute(
                    "delete from public.findings where finding_id = %s",
                    (fid,),
                )
                deleted_rows += cur.rowcount
            print(f"   history rows deleted (collisions): {deleted_hist}")
            print(f"   history rows moved to base id:   {moved_hist}")
            print(f"   postfixed findings rows deleted:  {deleted_rows}")

            # (d) recompute posture
            cur.execute("select refresh_all_asset_posture()")
            n = cur.fetchone()[0]
            print(f"   posture recomputed on {n} asset(s)")

            conn.commit()
            print(">> Merge complete. Idempotent — re-running reports 0 merges.")
            return 0


if __name__ == "__main__":
    sys.exit(main())