#!/usr/bin/env python3
"""
backfill_nikto_header_dedup.py — 4.7 H6 + I4. Retroactively assign the shared
normalized_key to EXISTING nikto response-header findings so they collapse in the
dedup view immediately, instead of waiting for the next scan to re-emit them.

I4 PATH CORRECTION (2026-07-08): the live inflating rows are written by
`run_medium.py :: parse_nikto_findings` with source ∈ {commandsentry_light,
commandsentry_medium, commandsentry_heavy} and normalized_key=NULL — NOT the
source='nikto' normalize path. So this backfill targets `source LIKE
'commandsentry_%'` and reads the header out of the stored TITLE
('nikto: [id] /path: desc'), which is the only field that parses: the DESCRIPTION
is wrapped ('Nikto reported on host: [id] ... Review the raw ...') and the
extractor's regexes are anchored, so the wrapper defeats them.

SINGLE SOURCE OF TRUTH (4.7 H5/I1): imports `extract_header_disclosure` +
`classify_nikto_header` from cs_parsers/nikto.py — the exact SSOT pair used at
ingest by run_medium.py. The bucket boundary and the title-format parsing are NOT
re-implemented here, so they cannot drift from the parser or the anchor tests
(test_extraction_agreement_across_parser_formats pins title==bare agreement).

Scope: only nikto findings that (a) live on a commandsentry_* source, (b) have a
NULL normalized_key today, and (c) classify into the fingerprint or version
bucket. Bucket 3 (missing/misconfigured security headers, cookies, CORS, BREACH,
exposed paths) classifies to None → never touched. Severity/title are left alone —
the next scan re-emits them; this backfill only sets normalized_key for collapse.

Safety (4.7 H6):
  * DRY-RUN by default — prints per-row classifications (header→bucket→key) AND a
    grouped N→1 preview. NO writes.
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
import sys
from collections import Counter
from pathlib import Path

# Import the parser's SSOT classifier — 4.7 H5/I1 single source of truth.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from cs_parsers.nikto import (  # noqa: E402
    classify_nikto_header,
    extract_header_disclosure,
)

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    sys.exit("psycopg required (run in the scanner env: pip install 'psycopg[binary]')")

DSN = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
if not DSN:
    sys.exit("set SUPABASE_DSN (or COMMAND_SUPABASE_DSN) to the TARGET instance's DB")

BATCH = 1000


def _derive(title: str, description: str):
    """Return (new_key, bucket, header_name, header_value) for a fingerprint/version
    header disclosure, else None. Reads TITLE first (the only field that parses — see
    module docstring), description as a defensive fallback. Uses the SSOT extractor +
    classifier so it can never drift from ingest."""
    for text in (title or "", description or ""):
        hd = extract_header_disclosure(text)
        if not hd:
            continue
        bucket, nkey = classify_nikto_header(hd[0], hd[1])
        if bucket in ("fingerprint", "version"):
            return nkey, bucket, hd[0], hd[1]
    return None


def _close_orphaned_synthetics(conn, cur, args) -> int:
    """4.7 I6 — close leftover roll-up synthetics after I5 retired the roll-up
    (COMMANDsentry never emitted these; this is a no-op there — it exists so the
    shared script stays identical across instances). Discriminator
    `finding_id LIKE '%:medium:nikto-tech-fingerprint-headers'` is unique to the
    retired emitter, so nothing else can match. Mirrors delta_close: only rows
    still in the OPEN set flip to 'remediated' with remediated_at set; one
    admin_audit_log row each. DRY-RUN unless --apply (+ 'yes')."""
    where = ("finding_id LIKE %s AND "
             "current_status IN ('detected','confirmed','open','regressed')")
    params: list = ["%:medium:nikto-tech-fingerprint-headers"]
    if args.asset:
        where += " AND asset_id = %s"
        params.append(args.asset)
    cur.execute(
        f"select finding_id, asset_id, current_status from findings where {where}",
        params)
    rows = cur.fetchall()

    print(f"open roll-up synthetics to retire: {len(rows)}"
          + (f" (asset={args.asset})" if args.asset else ""))
    for fid, asset_id, st in rows[:40]:
        print(f"  {asset_id:40.40s} {str(st):10s} {fid}")
    if not rows:
        print("nothing to do.")
        return 0
    if not args.apply:
        print("\nDRY-RUN — no writes performed. Re-run with --apply to close.")
        return 0

    resp = input(f"\nClose {len(rows)} synthetic(s) -> remediated on this DB? type 'yes': ").strip()
    if resp != "yes":
        print("aborted — no writes.")
        return 0

    done = 0
    for i in range(0, len(rows), BATCH):
        for fid, asset_id, st in rows[i:i + BATCH]:
            cur.execute("update findings set current_status = 'remediated', "
                        "remediated_at = now() where finding_id = %s", (fid,))
            cur.execute(
                "insert into admin_audit_log (action, before_state, after_state, details) "
                "values (%s, %s, %s, %s)",
                ("nikto_rollup_synthetic_retired",
                 Json({"current_status": str(st)}),
                 Json({"current_status": "remediated"}),
                 Json({"finding_id": fid, "asset_id": asset_id, "ref": "4.7-I5/I6",
                       "reason": "roll-up-retired-in-favor-of-per-header-collapse"})))
        conn.commit()
        done += len(rows[i:i + BATCH])
        print(f"  committed {done}/{len(rows)}")
    print(f"done — {done} synthetic(s) closed (superseded by per-header collapse).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--asset", help="restrict to one asset_id (e.g. cooked.prodexlabs.com)")
    ap.add_argument("--close-orphaned-synthetics", action="store_true",
                    help="4.7 I6: separate one-shot — close leftover roll-up synthetic "
                         "findings (nikto-tech-fingerprint-headers) retired by I5, "
                         "current_status -> remediated. Does NOT run the key backfill.")
    args = ap.parse_args()

    conn = psycopg.connect(DSN, connect_timeout=15)
    cur = conn.cursor()

    if args.close_orphaned_synthetics:
        return _close_orphaned_synthetics(conn, cur, args)

    # I4: live rows are commandsentry_* with a NULL key. Pattern is bound as a
    # PARAMETER (not inlined) so the LIKE metachars live in the value, not the SQL
    # text — no %%-escaping games. normalized_key IS NULL excludes already-collapsed
    # rows (idempotent re-runs) and anything the light path already keyed.
    where = "source::text LIKE %s AND normalized_key IS NULL"
    params: list = ["commandsentry_%"]
    if args.asset:
        where += " AND asset_id = %s"
        params.append(args.asset)
    cur.execute(
        f"select finding_id, asset_id, title, description, normalized_key "
        f"from findings where {where}", params)
    rows = cur.fetchall()

    # (finding_id, asset_id, old_key, new_key, bucket, header_name, header_value)
    changes = []
    for fid, asset_id, title, desc, old_key in rows:
        d = _derive(title, desc)
        if not d:
            continue
        new_key, bucket, hn, hv = d
        if old_key == new_key:
            continue
        changes.append((fid, asset_id, old_key, new_key, bucket, hn, hv))

    print(f"candidate rows scanned: {len(rows)}"
          + (f" (asset={args.asset})" if args.asset else "")
          + f"  |  need normalized_key backfill: {len(changes)}")

    if changes:
        # I4 — per-row sample so the classification is auditable BEFORE any write.
        print("\nsample per-row classifications (first 25):")
        for fid, asset_id, _o, new_key, bucket, hn, hv in changes[:25]:
            val = (hv or "")[:20]
            print(f"  {asset_id:30.30s} {hn.lower():20.20s}={val:20.20s} "
                  f"→ {bucket:11s} → {new_key}")
        # Grouped N→1 preview so the collapse is obvious.
        print("\ncollapse preview (asset, key → count):")
        by = Counter((c[1], c[3]) for c in changes)
        for (asset_id, new_key), n in sorted(by.items(), key=lambda x: -x[1])[:30]:
            print(f"  {asset_id:30.30s} {new_key:26s}  {n} finding(s) → 1")

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
        for fid, asset_id, old_key, new_key, _b, _hn, _hv in changes[i:i + BATCH]:
            cur.execute("update findings set normalized_key = %s where finding_id = %s",
                        (new_key, fid))
            cur.execute(
                "insert into admin_audit_log (action, before_state, after_state, details) "
                "values (%s, %s, %s, %s)",
                ("nikto_header_dedup_backfill",
                 Json({"normalized_key": old_key}),
                 Json({"normalized_key": new_key}),
                 Json({"finding_id": fid, "asset_id": asset_id, "ref": "4.7-H6/I4"})))
        conn.commit()
        done += len(changes[i:i + BATCH])
        print(f"  committed {done}/{len(changes)}")
    print(f"done — {done} findings reclassified (dedup view will now collapse them).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
