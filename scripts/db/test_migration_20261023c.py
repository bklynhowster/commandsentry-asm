"""(KB 12 job 3s, 2026-10-23) The record of what the digests told: public.digest_told.

Howie, 2026-10-22 20:02, "Agreed": a problem gets a full card when it is NEW, WORSE or CAME
BACK; after that one quiet line in the weekly, and a full reminder on a timer. Nothing recorded
what had been told. Pinned: one new table with exactly the columns run_alerter.py reads and
writes, RLS on with no policy, anon/authenticated revoked, nothing else touched, re-applying
changes nothing, the meta auto-applies. Proven on PostgreSQL 16 in the build note.
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261023c_digest_told.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "alerter"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_one_table_its_comment_rls_on_and_revoked():
    st = _stmts()
    assert len(st) == 4
    assert st[0].startswith("CREATE TABLE IF NOT EXISTS public.digest_told (")
    assert st[1].startswith("COMMENT ON TABLE public.digest_told IS")
    assert st[2] == "ALTER TABLE public.digest_told ENABLE ROW LEVEL SECURITY"
    assert st[3] == "REVOKE ALL ON public.digest_told FROM anon, authenticated"


def test_the_columns_are_the_ones_the_alerter_reads_and_writes():
    body = _stmts()[0].split("(", 1)[1].strip()
    cols = re.findall(r"(?:^|, )([a-z_]+) (?:text|timestamptz|integer)", body)
    assert cols == ["finding_id", "first_told_at", "last_full_at", "last_full_severity",
                    "last_full_in", "reminders", "closed_seen_at", "updated_at"]
    assert "finding_id text PRIMARY KEY" in body
    assert "last_full_in text NOT NULL CHECK (last_full_in IN ('daily', 'weekly'))" in body
    assert "closed_seen_at timestamptz NULL" in body
    import run_alerter as ra
    read = " ".join(ra.SQL_TOLD_READ.split())
    assert read.startswith("SELECT " + ", ".join(cols[:7]) + " FROM public.digest_told")
    rec = " ".join(ra.SQL_TOLD_RECORD.split())
    assert "(finding_id, first_told_at, last_full_at, last_full_severity, last_full_in, reminders, updated_at)" in rec


def test_nothing_else_no_policy_no_data_no_dollar_quoting():
    low = " ".join(_stmts()).lower()
    for bad in ("delete from", "drop ", "truncate", "insert into", "update ", "create policy",
                "grant ", "alter type", "create function", "create or replace", "findings"):
        assert bad not in low, bad
    assert "$$" not in SQL.split("END-META", 1)[1]


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
