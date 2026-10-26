"""(KB 12 job 3t, 2026-10-26) Hotfix 20261026b: the portal's dashboard read of v_asset_reachability
timed out (8 s statement_timeout for portal users), so the dashboards showed no "Not responding".

Pinned here: the verdict policy asks is_viewer_or_higher() once per query, (select ...), never once
per row; the view is 20261026a's view byte for byte except its three CTEs are AS MATERIALIZED (so
every test of 20261026a's view text still describes the live view); security_invoker restated;
the same grant and revokes; no data changes; no dollar quotes (the runner can't split them); the
meta auto-applies. Proven on PostgreSQL 16 at production's shape in the build note (52.9 s to
29 ms as a viewer; every column of every row unchanged for the owner and for a viewer).
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261026b_reachability_fast_reads.sql"
SQL = MIG.read_text()
SQL_A = (DB / "migrations" / "20261026a_reachability.sql").read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts(sql=SQL):
    return [" ".join(s.split()) for s in runner._split(sql) if s.strip()]


def _view(sql):
    return next(s for s in _stmts(sql) if s.startswith("CREATE OR REPLACE VIEW public.v_asset_reachability"))


def test_the_statements_in_order():
    want = [
        "DROP POLICY IF EXISTS asset_liveness_verdict_role_select ON public.asset_liveness_verdict",
        "CREATE POLICY asset_liveness_verdict_role_select ON public.asset_liveness_verdict FOR SELECT TO authenticated USING ((select public.is_viewer_or_higher()))",
        "CREATE OR REPLACE VIEW public.v_asset_reachability WITH (security_invoker = true) AS",
        "GRANT SELECT ON public.v_asset_reachability TO authenticated",
        "REVOKE ALL ON public.v_asset_reachability FROM anon",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_asset_reachability FROM authenticated",
    ]
    st = _stmts()
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:140], w)
    assert st[1] == want[1], "the policy is exactly the once-per-query form"
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_the_policy_is_asked_once_per_query_not_per_row():
    body = SQL.split("END-META", 1)[1]
    assert "USING ((select public.is_viewer_or_higher()))" in body
    assert "USING (public.is_viewer_or_higher())" not in body, "the per-row form is what timed out"


def test_the_view_is_20261026a_with_its_three_ctes_materialized():
    a, b = _view(SQL_A), _view(SQL)
    assert b.count(" AS MATERIALIZED (") == 3
    assert "WITH answered AS MATERIALIZED (" in b
    assert "), newest AS MATERIALIZED (" in b
    assert "), fleet AS MATERIALIZED (" in b
    assert b.replace(" AS MATERIALIZED (", " AS (") == a, "every other byte of the view is 20261026a's"


def test_the_grants_are_20261026a_s():
    grants = lambda sql: [s for s in _stmts(sql) if s.startswith(("GRANT ", "REVOKE "))]  # noqa: E731
    assert grants(SQL) == grants(SQL_A)


def test_no_data_changes():
    for s in _stmts():
        assert not s.startswith(("INSERT", "UPDATE", "DELETE", "ALTER TABLE", "DROP FUNCTION", "TRUNCATE")), s[:80]


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
