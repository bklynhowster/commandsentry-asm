"""(KB 12 job 4, 2026-10-25) Migration A: public.site_members, the evidence for "one site, not two".

Howie, 2026-10-25 08:46 (D1, "Yes"): a www name and its plain name are one site only on evidence
seen on both. Pinned here: one new table with exactly the columns site_members.py writes; the
www-of-site constraint; RLS on with one SELECT policy for authenticated users with a role (the
scan_run pattern, checker's M2); everything revoked from anon and authenticated, then SELECT
granted to authenticated; nothing else touched (no view, no reader re-pointed: that is migration
B, after the read-back, checker's M1); re-applying changes nothing; the meta auto-applies.
Proven on PostgreSQL 16 in the build note (applied twice; anon denied; authenticated with a role
reads, without one sees nothing; nobody but the owner writes).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261025a_site_members.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402
import site_members  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_the_statements_in_order():
    st = _stmts()
    assert len(st) == 7
    assert st[0].startswith("CREATE TABLE IF NOT EXISTS public.site_members (")
    assert st[1].startswith("COMMENT ON TABLE public.site_members IS")
    assert st[2] == "ALTER TABLE public.site_members ENABLE ROW LEVEL SECURITY"
    assert st[3] == "DROP POLICY IF EXISTS site_members_select ON public.site_members"
    assert st[4] == ("CREATE POLICY site_members_select ON public.site_members FOR SELECT TO authenticated "
                     "USING (public.has_role('admin') OR public.has_role('asset_owner') OR public.has_role('viewer'))")
    assert st[5] == "REVOKE ALL ON public.site_members FROM anon, authenticated"
    assert st[6] == "GRANT SELECT ON public.site_members TO authenticated"


def test_the_columns_are_the_ones_the_writer_writes():
    body = _stmts()[0].split("(", 1)[1]
    cols = re.findall(r"(?:^ ?|, )([a-z_]+) (?:text|integer|jsonb|timestamptz)\b", body)
    assert cols == ["member_asset_id", "site_asset_id", "verdict", "last_result", "contrary_runs",
                    "evidence", "checked_at", "since"]
    up = " ".join(site_members.Q_UPSERT.split())
    assert ("(member_asset_id, site_asset_id, verdict, last_result, contrary_runs, evidence, checked_at, since)"
            in up)
    rd = " ".join(site_members.Q_READ.split())
    assert rd.startswith("SELECT member_asset_id, verdict, contrary_runs, evidence, since FROM public.site_members")


def test_the_constraints():
    body = _stmts()[0]
    assert "member_asset_id text PRIMARY KEY" in body
    assert "verdict text NULL CHECK (verdict IN ('same_site', 'separate'))" in body
    assert "last_result text NOT NULL CHECK (last_result IN ('same_site', 'separate', 'unknown'))" in body
    assert "CONSTRAINT site_members_www_of_site CHECK (member_asset_id = 'www.' || site_asset_id)" in body


def test_nothing_else_no_view_no_reader_no_data_no_dollar_quoting():
    low = " ".join(_stmts()).lower()
    for bad in ("create view", "create or replace", "v_fleet_open_reps", "v_site_of", "delete from",
                "truncate table", "insert into", "update public", "alter type", "create function",
                "drop table", "findings"):
        assert bad not in low, bad
    assert "$$" not in SQL.split("END-META", 1)[1]


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
