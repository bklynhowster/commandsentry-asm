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

CONNECT RETRY (2026-07-25, refactored onto the shared framework same day per 4.7 G1).
The gate sits on the 10-minute scan cron, so it is the most frequently executed DB call in
the system. It was single-shot: one connect, no retry, fail-closed. Scanner run #1348 died
on `connection timeout expired` — a transient pooler blip, not ledger drift — killing the
whole tick and paging on a healthy DB (73/73 ledger rows matched minutes later).
Fail-closed is right for a ledger DISAGREEMENT; a transport failure is "I don't know yet."

The retry logic now lives in scripts/common/gate_retry.py and is SHARED with roe_gate and
every other gate (G1: one library, so gates cannot drift apart). This module supplies only
the domain part — what counts as a verdict here. Budget = FAST_CRON (3 attempts, 4s connect,
1s/3s backoff, ~16s worst case; see the deviation note in gate_retry re G3's literal 10s).

FAIL DIRECTION (G4): the ledger gate is a PROGRESS gate — it protects schema correctness,
not real-world consequences. G4 permits progress gates to fail OPEN on unreadable, but only
behind an explicit operator-set env var, never a code default. Default here stays CLOSED.
Set LEDGER_GATE_TRANSPORT_MODE=fail_open to accept the trade (proceed on unreadable, loudly).

Usage:
    check_migrations_applied.py --dsn "$SUPABASE_DSN" [--migrations-dir scripts/db/migrations]
    # DSN may also come from env SUPABASE_DSN / DSN.
Exit: 0 clean (all applied + sha-matched) | 1 unapplied/mismatch (REFUSE) | 2 usage/DB error.
"""
import argparse, glob, hashlib, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from gate_retry import (  # noqa: E402
    FAST_CRON,
    TransportFailure,
    Verdict,
    run_with_transport_retry,
)

# Operator-set fail direction (G4). Progress gates MAY fail open; this must be a
# deliberate operational choice, never a code default. Safety gates get no such switch.
FAIL_OPEN = os.environ.get("LEDGER_GATE_TRANSPORT_MODE", "").lower() == "fail_open"


def read_ledger(psycopg, dsn):
    """One attempt at reading the ledger.

    Returns a Verdict. `passed=True` carries {filename: content_sha256}.
    `passed=False` is an authoritative negative answer (the ledger table does
    not exist) — a real answer, so the framework will NOT retry it. Anything
    that means we never got an answer raises TransportFailure.
    """
    try:
        conn = psycopg.connect(dsn, connect_timeout=FAST_CRON.connect_timeout_s)
    except Exception as e:  # noqa — connect never reached the server
        raise TransportFailure(repr(e)) from e
    try:
        cur = conn.cursor()
        cur.execute("select to_regclass('public.schema_migrations')")
        if cur.fetchone()[0] is None:
            return Verdict(False, "schema_migrations_missing")
        cur.execute("select filename, content_sha256 from public.schema_migrations")
        return Verdict(True, "ledger_read", payload={r[0]: r[1] for r in cur.fetchall()})
    except Exception as e:  # noqa — mid-query loss of the server
        raise TransportFailure(repr(e)) from e
    finally:
        try:
            conn.close()
        except Exception:
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

    v = run_with_transport_retry(
        lambda: read_ledger(psycopg, args.dsn),
        FAST_CRON,
        on_retry=lambda n, e, back: print(
            f"::warning::ledger read attempt {n}/{FAST_CRON.attempts} failed "
            f"({e}) — retrying in {back}s",
            file=sys.stderr,
        ),
    )

    if v.unreadable:
        # Never scan against a schema we could not verify — but name it
        # correctly so the alert is not mistaken for migration drift.
        msg = (
            f"ledger UNREADABLE after {v.attempts} attempt(s) over "
            f"~{FAST_CRON.worst_case_s:.0f}s — DB unreachable, NOT ledger drift. "
            f"Last error: {v.payload!r}"
        )
        if FAIL_OPEN:
            print(f"::warning::{msg} — LEDGER_GATE_TRANSPORT_MODE=fail_open, PROCEEDING UNVERIFIED", file=sys.stderr)
            return 0
        print(f"::error::{msg}", file=sys.stderr)
        return 2

    if not v.passed:  # authoritative negative — never retried
        print("::error::schema_migrations missing — apply 20260710a_schema_migrations_ledger.sql "
              "+ run seed_ledger.py", file=sys.stderr)
        return 2

    ledger = v.payload

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
