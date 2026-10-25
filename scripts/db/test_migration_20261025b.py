"""(KB 12 job 4, 2026-10-25) Migration B: the readers ask site_members, not the names.

Howie, 2026-10-25 08:46 (D1, "Yes"): a www name and its plain name are one site only on evidence
seen on both. Pinned here: a new view v_site_of (each asset -> its site; only a 'same_site' row
moves a www name to its plain name); v_fleet_open_reps replaced in place with its pairs read from
v_site_of and EVERYTHING ELSE byte-identical to 20261013a (scope rule, dedup key, columns, order,
grants); both run as the caller; no table, no data, no function, no DROP; re-applying changes
nothing; the meta auto-applies. Proven on PostgreSQL 16 in the build note: with site_members
saying the same five pairs, v_fleet_open_reps returns exactly what 20261013a's name rule
returned; a NULL or 'separate' verdict un-merges that pair only; anon is denied.
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261025b_site_of.sql"
SQL = MIG.read_text()
OLD = (DB / "migrations" / "20261013a_reclassified_is_closed_and_fleet_open_reps.sql").read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _view(sql: str, name: str) -> str:
    """The body of `CREATE OR REPLACE VIEW public.<name>` up to its first GRANT."""
    start = sql.index(f"CREATE OR REPLACE VIEW public.{name}")
    return sql[start:sql.index("GRANT SELECT", start)]


def test_the_statements_in_order():
    st = _stmts()
    want = [
        "CREATE OR REPLACE VIEW public.v_site_of WITH (security_invoker = true) AS",
        "GRANT SELECT ON public.v_site_of TO authenticated",
        "REVOKE ALL ON public.v_site_of FROM anon",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_site_of FROM authenticated",
        "CREATE OR REPLACE VIEW public.v_fleet_open_reps WITH (security_invoker = true) AS",
        "GRANT SELECT ON public.v_fleet_open_reps TO authenticated",
        "REVOKE ALL ON public.v_fleet_open_reps FROM anon",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_fleet_open_reps FROM authenticated",
    ]
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:90], w)
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_v_site_of_moves_only_a_same_site_member():
    v = " ".join(_view(SQL, "v_site_of").split())
    assert v.startswith("CREATE OR REPLACE VIEW public.v_site_of WITH (security_invoker = true) AS")
    assert "SELECT a.asset_id, coalesce(sm.site_asset_id, a.asset_id) AS site_asset_id" in v
    assert "FROM public.assets a LEFT JOIN public.site_members sm" in v
    assert "ON sm.member_asset_id = a.asset_id AND sm.verdict = 'same_site'" in v


def test_fleet_reps_pairs_come_from_v_site_of_with_both_names_in_scope():
    v = " ".join(_view(SQL, "v_fleet_open_reps").split())
    assert "FROM public.v_site_of so WHERE so.asset_id <> so.site_asset_id" in v
    assert "AND so.asset_id IN (SELECT asset_id FROM scope)" in v
    assert "AND so.site_asset_id IN (SELECT asset_id FROM scope)" in v
    # the name rule is gone from the new definition
    assert "string_to_array" not in v and "'www.' ||" not in v


def test_everything_but_the_pairs_is_20261013a_byte_for_byte():
    new, old = _view(SQL, "v_fleet_open_reps"), _view(OLD, "v_fleet_open_reps")
    # scope CTE
    s_new = new[new.index("WITH scope AS ("):new.index("), site_pairs AS (")]
    s_old = old[old.index("WITH scope AS ("):old.index("), pairs AS (")]
    assert s_new == s_old
    # cluster_findings onwards (dedup key, sev rank, reps, union, column order)
    t_new = new[new.index("), cluster_findings AS ("):]
    t_old = old[old.index("), cluster_findings AS ("):]
    assert t_new == t_old
    # the same three grant lines as 20261013a
    for line in ("GRANT SELECT ON public.v_fleet_open_reps TO authenticated;",
                 "REVOKE ALL ON public.v_fleet_open_reps FROM anon;",
                 "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_fleet_open_reps FROM authenticated;"):
        assert line in SQL and line in OLD, line


def test_members_are_the_site_and_its_member():
    v = " ".join(_view(SQL, "v_fleet_open_reps").split())
    assert ("members AS ( SELECT DISTINCT p.apex, p.apex AS member FROM site_pairs p UNION ALL "
            "SELECT p.apex, p.member FROM site_pairs p )") in v


def test_nothing_else_no_table_no_data_no_function_no_drop():
    low = " ".join(_stmts()).lower()
    for bad in ("create table", "alter table", "drop ", "delete from", "truncate table", "insert into",
                "update public", "create function", "alter type", "create policy", "recompute_"):
        assert bad not in low, bad
    assert low.count("create or replace view") == 2


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
