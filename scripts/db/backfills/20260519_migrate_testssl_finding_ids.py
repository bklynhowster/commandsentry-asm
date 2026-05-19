#!/usr/bin/env python3
"""
20260519_migrate_testssl_finding_ids.py

One-time migration for testssl + sslyze findings.

Context:
  The testssl/sslyze parsers were just patched (commit 5fe8b38) so the
  finding_id hash is computed from stable canonical inputs (event_asset_id
  + port) instead of the scan-varying `host` string. Future scans will
  produce stable finding_ids.

  But all EXISTING testssl/sslyze findings in the DB still carry hashes
  computed from the old (unstable) inputs. If we re-scan without
  migrating, the new ingest creates *different* finding_ids than the
  existing rows → dupes come right back.

  This migration rewrites every existing testssl/sslyze finding_id to
  match what the new parser would produce. After this runs, a re-scan
  produces matching IDs → history merges cleanly → no new dupes.

Strategy (FK-safe):
  1. Compute new_finding_id for each row.
  2. For rows where new_id != old_id:
     a. INSERT the row with new_id (cloning the rest of the columns).
     b. UPDATE finding_history.finding_id from old_id → new_id.
     c. DELETE the old findings row.
  3. Recompute posture.

Idempotent. Re-running it is a no-op.

Apply with:
  export SUPABASE_DSN='...'
  python3 scripts/db/backfills/20260519_migrate_testssl_finding_ids.py --dry-run
  python3 scripts/db/backfills/20260519_migrate_testssl_finding_ids.py --apply
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

try:
    import psycopg
except ImportError:
    print("error: pip install --user --break-system-packages 'psycopg[binary]'", file=sys.stderr)
    sys.exit(1)


SAFETY_THRESHOLD = 5000  # abort if more rows than this would be touched


def stable_finding_id(asset_id: str, source: str, template_id: str, matched_at: str) -> str:
    """Mirror of scripts/normalize/cs_parsers/common.py:stable_finding_id."""
    h = hashlib.sha256((matched_at or "").encode("utf-8")).hexdigest()[:7]
    return f"{asset_id}:{source}:{template_id}:{h}"


def parse_template_id(finding_id: str, asset_id: str, source: str) -> str | None:
    """
    finding_id format: <asset>:<source>:<template>:<hash7>

    asset_id can contain colons (e.g. 'ip-range:cablenet-nodns'), so we
    can't naive-split. Strip the known prefix + suffix and what's left
    is the template.
    """
    prefix = f"{asset_id}:{source}:"
    if not finding_id.startswith(prefix):
        return None
    body = finding_id[len(prefix):]
    # body is now '<template>:<hash7>'
    if len(body) < 9 or body[-8] != ":":
        return None
    return body[:-8]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what would change. No writes.")
    ap.add_argument("--apply", action="store_true",
                    help="Actually perform the migration.")
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
            cur.execute("""
                SELECT finding_id, asset_id, source::text, port
                  FROM findings
                 WHERE source IN ('testssl', 'sslyze')
                 ORDER BY finding_id
            """)
            rows = cur.fetchall()
            print(f">> Loaded {len(rows)} testssl+sslyze findings")

            migrations: list[tuple[str, str]] = []   # (old_id, new_id)
            unparseable: list[str] = []
            unchanged = 0
            for finding_id, asset_id, source, port in rows:
                template_id = parse_template_id(finding_id, asset_id, source)
                if template_id is None:
                    unparseable.append(finding_id)
                    continue
                new_matched_at = f"port-{port}"
                new_id = stable_finding_id(asset_id, source, template_id, new_matched_at)
                if new_id == finding_id:
                    unchanged += 1
                    continue
                migrations.append((finding_id, new_id))

            print(f">> Unchanged (already in new format): {unchanged}")
            print(f">> Unparseable (skipped): {len(unparseable)}")
            print(f">> To migrate: {len(migrations)}")
            if unparseable:
                print("   First few unparseable IDs:", unparseable[:3])

            # Safety threshold
            if len(migrations) > SAFETY_THRESHOLD:
                print(f"!! SAFETY ABORT — {len(migrations)} > {SAFETY_THRESHOLD}")
                return 3

            if not migrations:
                print(">> Nothing to migrate. Exiting.")
                return 0

            # Check that no proposed new_id already exists as a different
            # row — that would mean a collision (shouldn't happen, but
            # check before destructive ops).
            new_ids = [n for (_, n) in migrations]
            cur.execute(
                "SELECT finding_id FROM findings WHERE finding_id = ANY(%s)",
                (new_ids,),
            )
            existing = {r[0] for r in cur.fetchall()}
            collisions = [n for n in new_ids if n in existing]
            if collisions:
                print(f"!! {len(collisions)} collision(s) detected. First few:")
                for c in collisions[:5]:
                    print(f"   {c}")
                print("   Refusing to proceed — investigate before retry.")
                return 4

            if args.dry_run:
                print("\n>> DRY RUN sample (first 5):")
                for old_id, new_id in migrations[:5]:
                    print(f"   {old_id}")
                    print(f"-> {new_id}")
                print("\n   Re-run with --apply to perform the migration.")
                conn.rollback()
                return 0

            # Apply
            print(">> Applying migration...")
            # 1. INSERT new rows (cloning everything except finding_id)
            cur.execute(
                """
                INSERT INTO findings (
                  finding_id, asset_id, title, severity, category, description,
                  cwe, cve, "references", current_status, first_detected_at,
                  first_detected_scan, last_observed_at, remediated_at,
                  owner, deadline, source, subdomain, host_ip, port, protocol,
                  tags, created_at, updated_at
                )
                SELECT
                  m.new_id, f.asset_id, f.title, f.severity, f.category, f.description,
                  f.cwe, f.cve, f."references", f.current_status, f.first_detected_at,
                  f.first_detected_scan, f.last_observed_at, f.remediated_at,
                  f.owner, f.deadline, f.source, f.subdomain, f.host_ip, f.port,
                  f.protocol, f.tags, f.created_at, f.updated_at
                FROM findings f
                JOIN unnest(%s::text[], %s::text[]) AS m(old_id, new_id)
                  ON f.finding_id = m.old_id
                ON CONFLICT (finding_id) DO NOTHING
                """,
                ([m[0] for m in migrations], [m[1] for m in migrations]),
            )
            print(f"   inserted: {cur.rowcount}")

            # 2. Move finding_history rows
            cur.execute(
                """
                UPDATE finding_history fh
                   SET finding_id = m.new_id
                  FROM unnest(%s::text[], %s::text[]) AS m(old_id, new_id)
                 WHERE fh.finding_id = m.old_id
                """,
                ([m[0] for m in migrations], [m[1] for m in migrations]),
            )
            print(f"   history rows moved: {cur.rowcount}")

            # 3. Delete old findings rows
            cur.execute(
                "DELETE FROM findings WHERE finding_id = ANY(%s)",
                ([m[0] for m in migrations],),
            )
            print(f"   old rows deleted: {cur.rowcount}")

            # Recompute posture
            cur.execute("SELECT refresh_all_asset_posture()")
            n = cur.fetchone()[0]
            print(f"   posture recomputed on {n} asset(s)")

            conn.commit()
            print(">> Migration complete.")
            return 0


if __name__ == "__main__":
    sys.exit(main())
