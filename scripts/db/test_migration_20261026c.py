"""(KB 12 job 3l, 2026-10-26) Migration 20261026c: the digest comes to Howie first.

Howie, 14:00: "I want the mail to come only to me, and then I have the ability to approve it
for further distribution." 14:17: "This should be a simple process."

Pinned here: the stored-email table (RLS on, no policies, anon and authenticated revoked, its
sequence too); the two portal functions are SECURITY DEFINER with an empty search_path, granted
to anon and authenticated only after PUBLIC is revoked; the Send button approves only a waiting,
unexpired email and says why not otherwise; no data changes; no dollar quotes (the runner can't
split them); the meta auto-applies. Proven on PostgreSQL 16 in the build note (pgproof-dg.txt):
two applies, anon can't read the table, the whole build -> approve -> send flow.
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261026c_digest_approval.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_the_statements_in_order():
    want = [
        "CREATE TABLE IF NOT EXISTS public.digest_pending (",
        "CREATE INDEX IF NOT EXISTS digest_pending_status_built_idx ON public.digest_pending (status, built_at)",
        "ALTER TABLE public.digest_pending ENABLE ROW LEVEL SECURITY",
        "REVOKE ALL ON public.digest_pending FROM anon, authenticated",
        "REVOKE ALL ON SEQUENCE public.digest_pending_id_seq FROM anon, authenticated",
        "CREATE OR REPLACE FUNCTION public.digest_approval_preview(p_token text)",
        "CREATE OR REPLACE FUNCTION public.digest_approve(p_token text)",
        "REVOKE ALL ON FUNCTION public.digest_approval_preview(text) FROM PUBLIC",
        "REVOKE ALL ON FUNCTION public.digest_approve(text) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.digest_approval_preview(text) TO anon, authenticated",
        "GRANT EXECUTE ON FUNCTION public.digest_approve(text) TO anon, authenticated",
    ]
    st = _stmts()
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:120], w)
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_the_functions_run_as_owner_with_no_search_path():
    for s in _stmts()[5:7]:
        assert "SECURITY DEFINER SET search_path TO ''" in s, s[:200]
        assert "FROM public.digest_pending d" in s


def test_the_table_statuses_and_the_one_way_in():
    t = _stmts()[0]
    assert "token_hash text NOT NULL UNIQUE" in t
    assert ("CHECK (status IN ('awaiting', 'approved', 'sending', 'sent', 'superseded', 'failed'))") in t
    assert "token text" not in t.replace("token_hash text", ""), "the token itself is never stored"


def test_send_approves_only_a_waiting_unexpired_email():
    s = _stmts()[6]
    assert ("SET status = ''approved'', approved_at = now() FROM t WHERE d.token_hash = t.h "
            "AND d.status = ''awaiting'' AND d.expires_at > now()") in s
    for word in ("''already approved''", "''expired''", "''unknown''"):
        assert word in s


def test_no_data_changes():
    for s in _stmts():
        assert not s.startswith(("INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP")), s[:80]


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
