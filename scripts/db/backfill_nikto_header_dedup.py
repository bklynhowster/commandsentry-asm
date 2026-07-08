#!/usr/bin/env python3
"""
backfill_nikto_header_dedup.py — 4.7 H6. Retroactively assign the shared
normalized_key to EXISTING nikto response-header findings so they collapse in the
dedup view immediately, instead of waiting for the next scan to re-emit them.

SINGLE SOURCE OF TRUTH (4.7 H6): imports `_classify_header_line` from
cs_parsers/nikto.py — the exact classifier used at ingest. The bucket boundary is
NOT re-implemented here, so it cannot drift from the parser.

Scope: only touches nikto findings whose message classifies into the fingerprint
or version bucket AND whose stored normalized_key differs from the derived one.
Bucket 3 (missing/misconfigured security headers, cookies, CORS, BREACH, exposed
paths) classifies to None → never touched. Severity/title are left alone — the
next scan re-emits them; this backfill only sets normalized_key for the collapse.

Safety (4.7 H6):
  * DRY-RUN by default — lists every row that would change (old → new key), NO writes.
  * --apply required to write, AND an interactive 'yes' confirmation.
  * Batched commits (1000/txn) — bounded blast radius.
  * Every mutation logged to admin_audit_log (action='nikto_header_dedup_backfill').

Usage:
    export SUPABASE_DSN=...                                   # target instance's DB
    python3 scripts/db/backfill_nikto_header_dedup.py                     # dry-run, all assets
    python3 scripts/db/backfill_nikto_header_dedup.py --asset cooked.prodexlabs.com
    python3 scripts/db/backfill_nikto_header_dedup.py --asset cooked.prodexlabs.com --apply
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Import the parser's classifier — 4.7 H6 single source of truth.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from cs_parsers.nikto import _classify_header_line  # noqa: E402

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    sys.exit("psycopg required (run in the scanner env: pip install 'psycopg[binary]')")

DSN = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
if not DSN:
    sys.exit("set SUPABASE_DSN (or COMMAND_SUPABASE_DSN) to the TARGET instance's DB")

BATCH = 1000
_TITLE_PREFIX = re.compile(r"^nikto\[\d+\]:\s*")


def _classifiable(title: str, description: str):
    """Return (severity, category, normalized_key, new_title) for a header
    disclosure, else None. Tries the raw description first, then the title with
    its 'nikto[NNNNNN]: ' prefix stripped (pre-fix findings store it there)."""
    for text in (description or "", _TITLE_PREFIX.sub("", title or "")):
        hb = _classify_header_line(text)
        if hb:
            return hb
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--asset", help="restrict to one asset_id (e.g. cooked.prodexlabs.com)")
    args = ap.parse_args()

    conn = psycopg.connect(DSN, connect_timeout=15)
    cur = conn.cursor()

    where = "source::text = 'nikto'"
    params: list = []
    if args.asset:
        where += " AND asset_id = %s"
        params.append(args.asset)
    cur.execute(
        f"select finding_id, asset_id, title, description, normalized_key "
        f"from findings where {where}", params)
    rows = cur.fetchall()

    changes = []  # (finding_id, asset_id, old_key, new_key)
    for fid, asset_id, title, desc, old_key in rows:
        hb = _classifiable(title, desc)
        if not hb:
            continue
        new_key = hb[2]
        if old_key == new_key:
            continue
        changes.append((fid, asset_id, old_key, new_key))

    print(f"nikto findings scanned: {len(rows)}"
          + (f" (asset={args.asset})" if args.asset else "")
          + f"  |  need normalized_key backfill: {len(changes)}")
    # Group preview by (asset, new_key) so the collapse is obvious.
    from collections import Counter
    by = Counter((c[1], c[3]) for c in changes)
    for (asset_id, new_key), n in sorted(by.items(), key=lambda x: -x[1])[:30]:
        print(f"  {asset_id:40s} {new_key:24s}  {n} finding(s) → 1")

    if not changes:
        print("nothing to do.")
        return 0
    if not args.apply:
        print("\nDRY-RUN — no writes performed. Re-run with --apply to write.")
        return 0

    resp = input(f"\nApply normalized_key to {len(changes)} findings on this DB? type 'yes': ").strip()
    if resp != "yes":
        print("aborted — no writes.")
        return 0

    done = 0
    for i in range(0, len(changes), BATCH):
        for fid, asset_id, old_key, new_key in changes[i:i + BATCH]:
            cur.execute("update findings set normalized_key = %s where finding_id = %s",
                        (new_key, fid))
            cur.execute(
                "insert into admin_audit_log (action, before_state, after_state, details) "
                "values (%s, %s, %s, %s)",
                ("nikto_header_dedup_backfill",
                 Json({"normalized_key": old_key}),
                 Json({"normalized_key": new_key}),
                 Json({"finding_id": fid, "asset_id": asset_id, "ref": "4.7-H6"})))
        conn.commit()
        done += len(changes[i:i + BATCH])
        print(f"  committed {done}/{len(changes)}")
    print(f"done — {done} findings reclassified (dedup view will now collapse them).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
