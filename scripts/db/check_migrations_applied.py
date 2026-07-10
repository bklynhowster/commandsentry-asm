#!/usr/bin/env python3
"""
check_migrations_applied.py — read-only migration-ledger GATE (4.7 Q5, 2026-07-10).
See SCANNER_MIGRATION_LEDGER_SPEC.md.

Runs at the TOP of scanner.yml, BEFORE the scan claims work. Refuses the run (exit 1)
if any scripts/db/migrations/*.sql is:
  * NOT in schema_migrations on THIS DB (unapplied), or
  * in the ledger but its content_sha256 no longer matches the file (edited post-apply).
Fails in seconds instead of 18 minutes at the final write-back. Read-only — never writes.
Retired migrations (scripts/db/migrations/retired/) are ignored (non-recursive glob).

Phase 2 NOTE: this refuses ALL unapplied migrations. The `safe_auto_apply` exemption
(4.7 Q1/Q5) activates only once migrate.yml (Phase 3) exists to apply them; until then
nothing auto-applies, so an exempt-but-unapplied migration would silently scan against a
missing object — so we refuse regardless of the header.

Usage:
    check_migrations_applied.py --dsn "$SUPABASE_DSN" [--migrations-dir scripts/db/migrations]
    # DSN may also come from env SUPABASE_DSN / DSN.
Exit: 0 clean (all applied + sha-matched) | 1 unapplied/mismatch (REFUSE) | 2 usage/DB error.
"""
import argparse, glob, hashlib, os, sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN") or os.environ.get("DSN"))
    ap.add_argument("--migrations-dir", default="scripts/db/migrations")
    args = ap.parse_args()
    if not args.dsn:
        print("::error::no DSN (pass --dsn or set SUPABASE_DSN)", file=sys.stderr); return 2

    try:
        import psycopg  # psycopg3 (lazy — --help works without it)
    except ImportError:
        print("::error::psycopg (psycopg3) required: pip install --break-system-packages 'psycopg[binary]'", file=sys.stderr)
        return 2

    files = sorted(glob.glob(os.path.join(args.migrations_dir, "*.sql")))
    if not files:
        print(f"::error::no migrations in {args.migrations_dir}", file=sys.stderr); return 2

    try:
        cur = psycopg.connect(args.dsn, connect_timeout=20).cursor()
        cur.execute("select to_regclass('public.schema_migrations')")
        if cur.fetchone()[0] is None:
            print("::error::schema_migrations missing — apply 20260710a_schema_migrations_ledger.sql + run seed_ledger.py", file=sys.stderr)
            return 2
        cur.execute("select filename, content_sha256 from public.schema_migrations")
        ledger = {r[0]: r[1] for r in cur.fetchall()}
    except Exception as e:  # noqa
        print(f"::error::ledger read failed: {e}", file=sys.stderr); return 2

    unapplied, mismatch = [], []
    for path in files:
        fn = os.path.basename(path)
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if fn not in ledger:
            unapplied.append(fn)
        elif ledger[fn] and ledger[fn] != sha:
            mismatch.append(fn)

    if unapplied or mismatch:
        print("::error::migration-ledger gate FAILED — scan REFUSED (resolve before scanning):")
        for fn in unapplied:
            print(f"  UNAPPLIED     {fn}  (not applied on this DB — apply it + record via seed_ledger.py / migrate.yml)")
        for fn in mismatch:
            print(f"  SHA-MISMATCH  {fn}  (file edited after apply — ledger content_sha256 != current file; investigate)")
        return 1

    print(f"migration-ledger gate OK — {len(files)} migration(s) applied + sha-matched on this DB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
