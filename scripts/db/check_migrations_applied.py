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

CONNECT RETRY (2026-07-25). The gate sits on the 10-minute scan cron, so it is the most
frequently executed DB call in the system. It was single-shot: one connect, no retry,
fail-closed. Scanner run #1348 died on `connection timeout expired` — a transient pooler
blip, not ledger drift — killing the whole tick and paging on a healthy DB (73/73 ledger
rows matched minutes later). Fail-closed is right for a ledger DISAGREEMENT; a transport
failure is "I don't know yet," which is a different thing. So: transport errors now retry
(3 attempts, 2s then 8s backoff), while any real answer from the DB — including
"schema_migrations missing" — short-circuits immediately and is never retried. Exhausting
all attempts still exits non-zero (we never scan against an unverified schema), but says
UNREADABLE rather than implying drift. Tunable via LEDGER_GATE_ATTEMPTS /
LEDGER_GATE_CONNECT_TIMEOUT for tests.

Usage:
    check_migrations_applied.py --dsn "$SUPABASE_DSN" [--migrations-dir scripts/db/migrations]
    # DSN may also come from env SUPABASE_DSN / DSN.
Exit: 0 clean (all applied + sha-matched) | 1 unapplied/mismatch (REFUSE) | 2 usage/DB error.
"""
import argparse, glob, hashlib, os, sys, time

ATTEMPTS = int(os.environ.get("LEDGER_GATE_ATTEMPTS", "3"))
CONNECT_TIMEOUT = int(os.environ.get("LEDGER_GATE_CONNECT_TIMEOUT", "20"))


class LedgerVerdict(Exception):
    """A real answer from the DB about ledger STATE — authoritative, never retried.

    Distinct from a transport failure. If the connection worked and the DB told us
    something (e.g. the ledger table does not exist), retrying just repeats the same
    answer three times and delays the failure by a minute.
    """

    def __init__(self, msg, code):
        super().__init__(msg)
        self.msg = msg
        self.code = code


def read_ledger(psycopg, dsn):
    """One attempt at reading the ledger.

    Returns {filename: content_sha256}. Raises LedgerVerdict for an authoritative
    answer; any other exception is treated as transport and is retryable.
    """
    conn = psycopg.connect(dsn, connect_timeout=CONNECT_TIMEOUT)
    try:
        cur = conn.cursor()
        cur.execute("select to_regclass('public.schema_migrations')")
        if cur.fetchone()[0] is None:
            raise LedgerVerdict(
                "schema_migrations missing — apply 20260710a_schema_migrations_ledger.sql + run seed_ledger.py",
                2,
            )
        cur.execute("select filename, content_sha256 from public.schema_migrations")
        return {r[0]: r[1] for r in cur.fetchall()}
    finally:
        try:
            conn.close()
        except Exception:  # noqa — close is best-effort; never mask the real error
            pass


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

    ledger, last_err = None, None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            ledger = read_ledger(psycopg, args.dsn)
            break
        except LedgerVerdict as v:
            print(f"::error::{v.msg}", file=sys.stderr); return v.code
        except Exception as e:  # noqa — transport: connect timeout, reset, DNS, pooler
            last_err = e
            if attempt < ATTEMPTS:
                backoff = 2 * (attempt ** 2)  # 2s, 8s
                print(
                    f"::warning::ledger read attempt {attempt}/{ATTEMPTS} failed ({e}) — retrying in {backoff}s",
                    file=sys.stderr,
                )
                time.sleep(backoff)

    if ledger is None:
        # Still fail-closed — we never scan against a schema we could not verify — but
        # name it correctly so the alert isn't mistaken for migration drift.
        print(
            f"::error::ledger UNREADABLE after {ATTEMPTS} attempt(s) — DB unreachable, "
            f"NOT ledger drift. Last error: {last_err}",
            file=sys.stderr,
        )
        return 2

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
