#!/usr/bin/env python3
"""backfill_auth_gated.py — one-time #24 Phase 2 catch-up.

Walks every row in public.asset_surface and re-runs compute_auth_gated
over the existing surface_data, then UPDATEs auth_gated where the
computed value differs from the stored value. Idempotent (IS DISTINCT
FROM guard) — re-running on already-correct state results in zero flips.

WHY THIS EXISTS
---------------
import_asm_to_surface.py computes auth_gated on every UPSERT, but
existing asset_surface rows that pre-date the compute (rows last
written before this morning's #24 Phase 2 push, commit eb77b44+next)
carry the default value (false from migration 20260615b). Those rows
only re-flip when asm-discover happens to re-find their subdomain and
trigger another UPSERT.

For Entra-fronted assets specifically, subfinder can't surface them on
the apex CT log (the cert SAN is *.microsoftonline.com, not the apex
domain), so asm-discover skips them indefinitely on the normal cron.
Their auth_gated would stay default-false forever without this backfill.

Pre-build dry-run (Howie, 2026-06-15) over all 59 asset_surface rows:
  Flips to TRUE: exactly 2 (myordersauth, myordersauth-test)
  ZERO false positives fleet-wide.
  AND-gate proof: ftp.sciimage.com — login-ish title + non-IdP cert →
  correctly FALSE. Title-only would have mis-skipped it.

USAGE
-----
    # DRY-RUN (default) — reports flips, makes ZERO writes
    python3 scripts/db/backfill_auth_gated.py --dsn "$SUPABASE_DSN"

    # APPLY — only after dry-run confirms expected flip list
    python3 scripts/db/backfill_auth_gated.py --dsn "$SUPABASE_DSN" --apply

DESIGN DISCIPLINE
-----------------
1. Default dry-run. --apply required to write. Mirrors the
   20260613b sweep discipline.
2. Single source of truth for the compute: import_asm_to_surface.
   compute_auth_gated(). Never copy-paste the AND-gate logic.
3. IS DISTINCT FROM guard means re-runnable: zero churn on
   already-correct rows.
4. DOES NOT touch updated_at. This is a compute catch-up, NOT a new
   observation. asset_surface has no updated_at trigger today
   (verified against schema.sql 2026-06-15), but the bare-SET
   discipline is explicit so a future trigger addition doesn't
   silently bump observation timestamps via this backfill.
5. Flip count comes from UPDATE rowcount, not Python-side counting
   of true-computes. Two different counts (number of trues vs number
   of changes) and the meaningful one is "what did we actually
   modify."
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Make scripts/db importable like import_asm_to_surface does
sys.path.insert(0, str(Path(__file__).parent))

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    print(
        "error: psycopg (psycopg3) required.\n"
        "  pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(2)

from import_asm_to_surface import compute_auth_gated  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-time backfill: recompute auth_gated over all "
                    "asset_surface rows from their existing surface_data."
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN env var)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write changes. Without this flag, runs in "
             "DRY-RUN mode — reports what would change but makes no DB writes.",
    )
    args = parser.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN env var required", file=sys.stderr)
        return 2

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f">> backfill_auth_gated.py — mode={mode}")

    with psycopg.connect(args.dsn, row_factory=dict_row, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT asset_id, auth_gated, surface_data "
                "  FROM public.asset_surface "
                " ORDER BY asset_id"
            )
            rows = cur.fetchall()

        print(f">> scanned {len(rows)} asset_surface row(s)")

        # First pass: compute new value for every row, collect diffs
        flips: list[tuple[str, bool, bool]] = []
        for row in rows:
            asset_id = row["asset_id"]
            current = bool(row["auth_gated"])
            computed = compute_auth_gated(row["surface_data"] or {})
            if current != computed:
                flips.append((asset_id, current, computed))

        # Always print the diff list (DRY-RUN and APPLY both show it)
        if not flips:
            print(">> zero diffs — DB already matches compute_auth_gated() output")
        else:
            print(f">> would flip {len(flips)} row(s):")
            for asset_id, current, computed in flips:
                arrow = f"{current!s:>5} -> {computed!s:<5}"
                print(f"   {arrow}  {asset_id}")

        # Stop here if dry-run
        if not args.apply:
            print(f">> DRY-RUN complete — no writes. Re-run with --apply to commit.")
            conn.rollback()  # belt + suspenders even though we never wrote
            return 0

        # APPLY path — per-row UPDATE with IS DISTINCT FROM guard.
        # Flip count comes from cursor.rowcount (advisor refinement) —
        # the canonical "what did we actually modify" number.
        actual_flips = 0
        with conn.cursor() as cur:
            for asset_id, _current, computed in flips:
                cur.execute(
                    # Intentionally NOT touching updated_at. asset_surface
                    # has no updated_at trigger today, but the discipline
                    # is: backfills MUST NOT bump observation timestamps.
                    # See module docstring for the full rationale.
                    "UPDATE public.asset_surface "
                    "   SET auth_gated = %s "
                    " WHERE asset_id = %s "
                    "   AND auth_gated IS DISTINCT FROM %s",
                    (computed, asset_id, computed),
                )
                actual_flips += cur.rowcount  # canonical flip count
        conn.commit()
        print(f">> APPLY complete — actually modified {actual_flips} row(s)")

        if actual_flips != len(flips):
            # Concurrent writes shouldn't happen for a one-time backfill,
            # but if cursor.rowcount and pre-pass count diverge that's
            # worth a loud surface for review.
            print(
                f"   ⚠ pre-pass identified {len(flips)} diffs but UPDATE "
                f"touched {actual_flips} rows. Likely concurrent write "
                f"during backfill — re-run dry-run to confirm final state."
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
