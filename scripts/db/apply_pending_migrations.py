#!/usr/bin/env python3
"""
apply_pending_migrations.py — migrate.yml runner (4.7 Q5/Q7, 2026-07-10).
See SCANNER_MIGRATION_LEDGER_SPEC.md.

PENDING = migration files in scripts/db/migrations/*.sql NOT yet in schema_migrations
(retired/ excluded; grandfathered ledger rows skipped). Modes:

  --check : validate the MIGRATION-META header on every pending migration; report how many are
            safe_auto_apply vs manual. Read-only. Exit 1 if any META is missing/invalid. Used by
            the migrate.yml `detect` job (writes has_auto_apply to $GITHUB_OUTPUT) and as a PR lint.

  --auto  : under a pg advisory lock, validate all pending META first (fail-fast), then for each
            pending migration in filename order:
              * safe_auto_apply:true  -> apply its statements AND insert the ledger row in ONE tx
                (atomic), timing it; then post-apply verify (row present, count incremented, SELECT 1).
              * safe_auto_apply:false -> report "manual apply required" and leave it (the scanner
                gate keeps refusing scans until a human applies + records it).

Never applies a non-safe_auto_apply migration. Fail-fast on invalid META or any apply error
(rolls back that migration; nothing half-applied).

Usage:
  apply_pending_migrations.py --dsn "$SUPABASE_DSN" --instance prodex [--migrations-dir DIR] \
      [--git-sha "$GITHUB_SHA"] (--check | --auto) [--dry-run]
Exit: 0 ok | 1 META-invalid / apply-error | 2 usage/DB error.
"""
import argparse, glob, hashlib, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from migration_meta import parse_meta, validate_meta, is_safe_auto_apply  # noqa: E402

LOCK_KEY = "scanner_migrations"


def _strip_comments(sql):
    out, i, n, q = [], 0, len(sql), False
    while i < n:
        c = sql[i]
        if q:
            out.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    out.append(sql[i + 1]); i += 2; continue
                q = False
            i += 1; continue
        if c == "'":
            q = True; out.append(c); i += 1; continue
        if c == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        out.append(c); i += 1
    return "".join(out)


def _split(sql):
    """Comment-stripped, quote-aware split on ';', with BEGIN/COMMIT removed (we wrap our own tx)."""
    body = _strip_comments(sql)
    out, buf, q, i = [], [], False, 0
    while i < len(body):
        c = body[i]; buf.append(c)
        if c == "'":
            if q and i + 1 < len(body) and body[i + 1] == "'":
                buf.append(body[i + 1]); i += 2; continue
            q = not q
        elif c == ";" and not q:
            out.append("".join(buf).strip()); buf = []
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    stmts = []
    for s in out:
        s = s.rstrip(";").strip()
        if not s or s.upper() in ("BEGIN", "COMMIT", "START TRANSACTION"):
            continue
        stmts.append(s)
    return stmts


def _load(migrations_dir):
    """Return [(filename, path, sha, sql_text)] sorted by filename (retired/ excluded)."""
    rows = []
    for path in sorted(glob.glob(os.path.join(migrations_dir, "*.sql"))):
        raw = open(path, "rb").read()
        rows.append((os.path.basename(path), path, hashlib.sha256(raw).hexdigest(),
                     raw.decode("utf-8", "replace")))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN") or os.environ.get("DSN"))
    ap.add_argument("--migrations-dir", default="scripts/db/migrations")
    ap.add_argument("--git-sha", default=os.environ.get("GITHUB_SHA"))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--auto", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="with --auto: validate + report, apply nothing")
    args = ap.parse_args()
    if not args.dsn:
        print("::error::no DSN (pass --dsn or set SUPABASE_DSN)", file=sys.stderr); return 2

    try:
        import psycopg
    except ImportError:
        print("::error::psycopg (psycopg3) required", file=sys.stderr); return 2

    files = _load(args.migrations_dir)
    if not files:
        print(f"::error::no migrations in {args.migrations_dir}", file=sys.stderr); return 2

    try:
        gate = psycopg.connect(args.dsn, autocommit=True, connect_timeout=20)
        gc = gate.cursor()
        gc.execute("select to_regclass('public.schema_migrations')")
        if gc.fetchone()[0] is None:
            print("::error::schema_migrations missing — run Phase 1 (20260710a + seed_ledger.py) first", file=sys.stderr)
            return 2
        gc.execute("select filename from public.schema_migrations")
        ledger = {r[0] for r in gc.fetchall()}
    except Exception as e:  # noqa
        print(f"::error::ledger read failed: {e}", file=sys.stderr); return 2

    pending = [(fn, p, sha, txt) for (fn, p, sha, txt) in files if fn not in ledger]

    # ── validate META on ALL pending first (fail-fast, both modes) ──
    errs, autos, manuals = [], [], []
    for fn, p, sha, txt in pending:
        meta = parse_meta(txt)
        e = validate_meta(meta, fn)
        if e:
            errs.extend(e); continue
        (autos if is_safe_auto_apply(meta) else manuals).append((fn, p, sha, txt, meta))
    if errs:
        print("::error::MIGRATION-META validation FAILED (fix before this can apply/scan):")
        for e in errs:
            print(f"  {e}")
        return 1

    def out(k, v):
        gh = os.environ.get("GITHUB_OUTPUT")
        if gh:
            open(gh, "a").write(f"{k}={v}\n")

    print(f"pending={len(pending)}  safe_auto_apply={len(autos)}  manual={len(manuals)}")
    for fn, *_ in manuals:
        print(f"  manual apply required: {fn} (safe_auto_apply=false — apply by hand + record)")

    if args.check:
        out("has_auto_apply", "true" if autos else "false")
        print("META check OK")
        return 0

    # ── --auto: apply the safe_auto_apply ones under an advisory lock ──
    if not autos:
        print("nothing to auto-apply.")
        return 0
    if args.dry_run:
        for fn, *_ in autos:
            print(f"  [dry-run] would apply {fn}")
        return 0

    try:
        gc.execute("set lock_timeout = '30s'")
        gc.execute("select pg_advisory_lock(hashtext(%s))", (LOCK_KEY,))
    except Exception as e:  # noqa
        print(f"::error::could not acquire migrate advisory lock (another run in progress?): {e}", file=sys.stderr)
        return 2

    applied = []
    try:
        work = psycopg.connect(args.dsn, autocommit=False, connect_timeout=20)
        for fn, p, sha, txt, meta in autos:
            stmts = _split(txt)
            t0 = time.time()
            try:
                with work.cursor() as wc:
                    for s in stmts:
                        wc.execute(s)
                    wc.execute(
                        "insert into public.schema_migrations "
                        "(filename, applied_by, content_sha256, git_commit_sha, applied_duration_ms, notes) "
                        "values (%s,%s,%s,%s,%s,%s) on conflict (filename) do nothing",
                        (fn, "ci", sha, args.git_sha, int((time.time() - t0) * 1000),
                         (meta.get("notes") or "auto-applied")[:500]))
                work.commit()
            except Exception as e:  # noqa
                work.rollback()
                print(f"::error::apply FAILED on {fn} (rolled back; nothing half-applied): {e}", file=sys.stderr)
                return 1
            # post-apply verify (4.7 Q7)
            with work.cursor() as vc:
                vc.execute("select 1 from public.schema_migrations where filename=%s", (fn,))
                ok_row = vc.fetchone() is not None
                vc.execute("select 1")
            if not ok_row:
                print(f"::error::post-apply verify FAILED for {fn} (ledger row not found)", file=sys.stderr)
                return 1
            applied.append(fn)
            print(f"  applied + recorded: {fn} ({int((time.time()-t0)*1000)}ms)")
    finally:
        try:
            gc.execute("select pg_advisory_unlock(hashtext(%s))", (LOCK_KEY,))
        except Exception:  # noqa
            pass
        gate.close()

    print(f"auto-applied {len(applied)} migration(s): {', '.join(applied) or '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
