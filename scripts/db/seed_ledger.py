#!/usr/bin/env python3
"""
seed_ledger.py — verify-then-seed the schema_migrations ledger (4.7 ruling Q3, 2026-07-10).
See SCANNER_MIGRATION_LEDGER_SPEC.md.

For each scripts/db/migrations/*.sql NOT already in the ledger, parse its DECLARED objects
(CREATE TABLE / ADD COLUMN / CREATE INDEX / ALTER TYPE ADD VALUE), verify each exists in the
LIVE DB, and:
  * all present    -> seed the ledger row as applied (content_sha256, applied_by=backfill).
  * any missing    -> LOUD drift: report, DO NOT seed (a human applies the migration or investigates).
  * none parseable -> "needs manual verification" bucket (functions/grants/RLS/data). NOT auto-seeded;
                      re-run with --seed-manual once a human confirms they were applied.

Never RUNS a migration — only records ones whose effects are already present. Idempotent
(ON CONFLICT DO NOTHING); already-seeded files are skipped. The ledger table must exist first
(migration 20260710a_schema_migrations_ledger.sql).

Usage:
    seed_ledger.py --instance prodex --dsn "$SUPABASE_DSN" \
        [--migrations-dir scripts/db/migrations] [--git-sha "$(git rev-parse HEAD)"] \
        [--seed-manual] [--dry-run]
    # DSN may also come from env SUPABASE_DSN / DSN.
Exit: 0 clean (all seeded / already present, no unacked manual) | 1 drift or unacked manual | 2 usage/DB error.
"""
import argparse, glob, hashlib, os, re, sys


def split_sql(s):
    """Quote-aware split on ';' (handles ';' inside string literals + '' escapes)."""
    out, buf, q, i = [], [], False, 0
    while i < len(s):
        c = s[i]; buf.append(c)
        if c == "'":
            if q and i + 1 < len(s) and s[i + 1] == "'":
                buf.append(s[i + 1]); i += 2; continue
            q = not q
        elif c == ";" and not q:
            out.append("".join(buf)); buf = []
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf))
    return [x for x in out if x.strip()]


def strip_sql_comments(sql):
    """Remove -- comments to end-of-line, respecting single-quoted string literals
    (so an inline comment containing ';' can't corrupt the statement split)."""
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


def declared_objects(sql_text):
    """Return list of declared-object tuples the parser recognizes. Empty => unparseable
    (goes to the manual bucket). Covers the corpus's common DDL shapes."""
    body = strip_sql_comments(sql_text)
    decl = []
    for st in split_sql(body):
        low = st.lower()
        m = re.search(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?(\w+)"?', low)
        if m:
            decl.append(("table", m.group(1)))
        mt = re.search(r'alter\s+table\s+(?:only\s+)?(?:public\.)?"?(\w+)"?', low)
        if mt and "add column" in low:
            for cm in re.finditer(r'add\s+column\s+(?:if\s+not\s+exists\s+)?"?(\w+)"?', low):
                decl.append(("column", mt.group(1), cm.group(1)))
        for im in re.finditer(
                r'create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?"?(\w+)"?\s+on', low):
            decl.append(("index", im.group(1)))
        me = re.search(r'alter\s+type\s+(?:public\.)?"?(\w+)"?', low)
        if me and "add value" in low:
            for vm in re.finditer(r"add\s+value\s+(?:if\s+not\s+exists\s+)?'([^']+)'", st):
                decl.append(("enum", me.group(1), vm.group(1)))
    # de-dup, preserve order
    seen, uniq = set(), []
    for d in decl:
        if d not in seen:
            seen.add(d); uniq.append(d)
    return uniq


def exists(cur, d):
    if d[0] == "table":
        cur.execute("select 1 from information_schema.tables where table_schema='public' and table_name=%s", (d[1],))
    elif d[0] == "column":
        cur.execute("select 1 from information_schema.columns where table_schema='public' and table_name=%s and column_name=%s", (d[1], d[2]))
    elif d[0] == "index":
        cur.execute("select 1 from pg_indexes where schemaname='public' and indexname=%s", (d[1],))
    elif d[0] == "enum":
        cur.execute("select 1 from pg_enum e join pg_type t on t.oid=e.enumtypid where t.typname=%s and e.enumlabel=%s", (d[1], d[2]))
    else:
        return None
    return cur.fetchone() is not None


def fmt(d):
    return f"{d[1]}.{d[2]}" if d[0] in ("column", "enum") else d[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True, help="command | prodex")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN") or os.environ.get("DSN"))
    ap.add_argument("--migrations-dir", default="scripts/db/migrations")
    ap.add_argument("--git-sha", default=None)
    ap.add_argument("--seed-manual", action="store_true",
                    help="seed the 'needs manual verification' files as applied (human-acked)")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
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
        conn = psycopg.connect(args.dsn, autocommit=False, connect_timeout=20)
    except Exception as e:  # noqa
        print(f"::error::connect failed: {e}", file=sys.stderr); return 2
    cur = conn.cursor()
    try:
        cur.execute("select to_regclass('public.schema_migrations')")
        if cur.fetchone()[0] is None:
            print("::error::schema_migrations table missing — apply 20260710a_schema_migrations_ledger.sql first", file=sys.stderr)
            return 2
        cur.execute("select filename from public.schema_migrations")
        already = {r[0] for r in cur.fetchall()}
    except Exception as e:  # noqa
        print(f"::error::ledger read failed: {e}", file=sys.stderr); return 2

    seeded, skipped, drift, manual = [], [], [], []
    for path in files:
        fn = os.path.basename(path)
        if fn in already:
            skipped.append(fn); continue
        raw = open(path, "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        decls = declared_objects(raw.decode("utf-8", "replace"))
        if not decls:
            manual.append(fn)
            if not args.seed_manual:
                continue
            note, by = "manual-acked (unparseable declares)", "backfill:manual"
        else:
            missing = [d for d in decls if not exists(cur, d)]
            if missing:
                drift.append((fn, [fmt(d) for d in missing])); continue
            note, by = f"verify-then-seed: {len(decls)} object(s) confirmed", "backfill"
        if not args.dry_run:
            cur.execute(
                "insert into public.schema_migrations (filename, applied_by, content_sha256, git_commit_sha, notes) "
                "values (%s,%s,%s,%s,%s) on conflict (filename) do nothing",
                (fn, by, sha, args.git_sha, note))
        seeded.append(fn)

    if args.dry_run:
        conn.rollback()
    else:
        conn.commit()

    print(f"\n=== seed_ledger [{args.instance}] {'(dry-run) ' if args.dry_run else ''}===")
    print(f"  already in ledger : {len(skipped)}")
    print(f"  seeded            : {len(seeded)}" + (f"  (incl. {sum(1 for _ in manual)} manual-acked)" if args.seed_manual else ""))
    if drift:
        print(f"  ⚠ DRIFT (declared but MISSING — NOT seeded; apply the migration or investigate): {len(drift)}")
        for fn, objs in drift:
            print(f"      {fn}: missing {', '.join(objs)}")
    if manual and not args.seed_manual:
        print(f"  ○ needs manual verification (no parseable DDL — functions/grants/RLS/data): {len(manual)}")
        for fn in manual:
            print(f"      {fn}")
        print("      → confirm these were applied, then re-run with --seed-manual to record them.")
    ok = not drift and not (manual and not args.seed_manual)
    print("RESULT:", "✓ ledger baseline complete" if ok else "⚠ action needed (drift and/or unacked manual above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
