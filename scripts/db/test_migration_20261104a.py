"""(KB 12 job 4, plan v1.3 step 1, 2026-11-04) Migration 20261104a: each site is the name the browser lands on.

Howie, 2026-11-04 (D6): "Where the browser lands (Recommended)". Pinned here: exactly ten statements
in this order; site_members gains face_asset_id, nullable, which can only be one of the row's two
names; v_site_of maps both names of a 'same_site' pair to the face and, with no face, gives
exactly 20261025b's answer (the www name to its plain name, every other asset to itself); it still
runs as the caller with 20261025b's grants; a same_site www row with a NULL apex_domain gets its
plain name and nothing else is changed (no finding, no other column, no row deleted); the audit is
written once per asset for this migration and BEFORE the change, so it records the NULL; no dollar
quotes (the runner can't split them); the meta auto-applies. Proven on PostgreSQL 16 in the build
note (both repos' migration histories, then this file twice).
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261104a_site_face.sql"
SQL = MIG.read_text()
OLD = (DB / "migrations" / "20261025b_site_of.sql").read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

CHECK = ("CHECK (face_asset_id IS NULL OR face_asset_id = member_asset_id "
         "OR face_asset_id = site_asset_id)")


def _stmts(sql: str = SQL):
    return [" ".join(s.split()) for s in runner._split(sql) if s.strip()]


def test_the_statements_in_order():
    st = _stmts()
    want = [
        "ALTER TABLE public.site_members ADD COLUMN IF NOT EXISTS face_asset_id text",
        "ALTER TABLE public.site_members DROP CONSTRAINT IF EXISTS site_members_face_is_one_of_the_pair",
        "ALTER TABLE public.site_members ADD CONSTRAINT site_members_face_is_one_of_the_pair " + CHECK,
        "COMMENT ON COLUMN public.site_members.face_asset_id IS ",
        "CREATE OR REPLACE VIEW public.v_site_of WITH (security_invoker = true) AS",
        "GRANT SELECT ON public.v_site_of TO authenticated",
        "REVOKE ALL ON public.v_site_of FROM anon",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_site_of FROM authenticated",
        "INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details) "
        "SELECT NULL, 'site_member_apex_domain_set',",
        "UPDATE public.assets a SET apex_domain = sm.site_asset_id FROM public.site_members sm",
    ]
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:100], w)
    body = SQL.split("END-META", 1)[1]
    assert "$$" not in body, "the runner is not dollar-quote aware"
    for s in st:
        u = s.upper()
        assert not u.startswith(("DELETE", "TRUNCATE", "DROP")), s[:60]
        assert "DROP COLUMN" not in u and "DROP TABLE" not in u and "DROP VIEW" not in u, s[:60]
        assert "PUBLIC.FINDINGS" not in u, s[:60]


def test_the_column_is_nullable_and_only_one_of_the_two_names():
    add = _stmts()[0]
    assert "NOT NULL" not in add and "DEFAULT" not in add
    assert _stmts()[2].endswith(CHECK)


def test_v_site_of_maps_a_pair_to_its_face_else_to_the_plain_name():
    v = _stmts()[4]
    assert ("SELECT a.asset_id, coalesce(sw.face_asset_id, sw.site_asset_id, sp.face_asset_id, "
            "a.asset_id) AS site_asset_id") in v
    assert ("FROM public.assets a LEFT JOIN public.site_members sw ON sw.member_asset_id = a.asset_id "
            "AND sw.verdict = 'same_site' LEFT JOIN public.site_members sp ON sp.site_asset_id = "
            "a.asset_id AND sp.verdict = 'same_site'") in v
    assert v.endswith("AND sp.verdict = 'same_site'")


def test_the_view_keeps_20261025b_columns_and_grants():
    old = _stmts(OLD)
    assert old[0].startswith("CREATE OR REPLACE VIEW public.v_site_of WITH (security_invoker = true) AS "
                             "SELECT a.asset_id, coalesce(sm.site_asset_id, a.asset_id) AS site_asset_id")
    assert _stmts()[5:8] == old[1:4]


def test_apex_domain_set_only_where_null_on_a_same_site_www_row():
    up = _stmts()[9]
    assert up == ("UPDATE public.assets a SET apex_domain = sm.site_asset_id FROM public.site_members sm "
                  "WHERE sm.member_asset_id = a.asset_id AND sm.verdict = 'same_site' "
                  "AND a.apex_domain IS NULL")


def test_audited_once_per_asset_before_the_change():
    ins = _stmts()[8]
    assert "jsonb_build_object('apex_domain', NULL)" in ins
    assert "jsonb_build_object('apex_domain', sm.site_asset_id)" in ins
    assert "WHERE a.apex_domain IS NULL" in ins
    assert "l.details ->> 'migration' = '20261104a'" in ins
    assert "'migration', '20261104a'" in ins
    assert SQL.index("INSERT INTO public.admin_audit_log") < SQL.index("UPDATE public.assets")


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
