"""Pins for migration 20261013a (note 307): the file the runner will execute, checked with the
runner's own splitter and META parser, plus the SQL that must keep matching the portal's
TypeScript (src/lib/scope.ts, src/lib/posture.ts). Execution on real PostgreSQL is in the
push-307c evidence; these keep the next edit from shredding what was verified."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta as meta  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "migrations", "20261013a_reclassified_is_closed_and_fleet_open_reps.sql")
SQL = open(PATH, encoding="utf-8").read()
CLOSED = ["remediated", "validated_remediated", "false_positive", "wont_fix", "accepted_risk",
          "closed_reclassified", "detector_retired"]
OPEN = ["detected", "confirmed", "open", "regressed"]


def _stmts():
    return runner._split(SQL)


def test_meta_is_valid_and_auto_applies():
    m = meta.parse_meta(SQL)
    assert m is not None and meta.validate_meta(m, os.path.basename(PATH)) == []
    assert meta.is_safe_auto_apply(m)
    assert m["idempotent"].lower() == "true" and m["transactional"].lower() == "true"


def test_the_runner_splits_it_into_the_expected_statements():
    heads = [" ".join(s.split()[:2]).upper() for s in _stmts()]
    assert heads == ["CREATE OR", "CREATE OR", "CREATE OR", "GRANT SELECT", "REVOKE ALL", "REVOKE INSERT,",
                     "SELECT PUBLIC.RECOMPUTE_ASSET_CURRENT_RISK_FOR(G.ASSET_ID)"], heads
    assert "$$" not in SQL and "$function$" not in SQL, "the runner is not dollar-quote aware"


def test_views_are_replaced_in_place_as_caller_with_the_full_closed_list():
    for v in ("v_open_findings_dedup", "v_asset_posture_counts", "v_fleet_open_reps"):
        assert f"CREATE OR REPLACE VIEW public.{v}\nWITH (security_invoker = true) AS" in SQL, v
    dedup = SQL[SQL.index("VIEW public.v_open_findings_dedup"):SQL.index("VIEW public.v_asset_posture_counts")]
    for st in CLOSED:
        assert f"'{st}'::finding_status_t" in dedup, st
    assert "DROP VIEW" not in SQL, "a drop would break the portal between statements and lose grants"


def test_dedup_view_columns_are_the_production_eleven_in_order():
    dedup = SQL[SQL.index("VIEW public.v_open_findings_dedup"):SQL.index("VIEW public.v_asset_posture_counts")]
    cols = re.search(r"SELECT grouped\.asset_id, grouped\.dedup_id, grouped\.severity, grouped\.current_status,\s*"
                     r"grouped\.title, grouped\.sources, grouped\.source_count, grouped\.first_detected_at,\s*"
                     r"grouped\.last_observed_at, grouped\.cve, grouped\.member_finding_ids", dedup)
    assert cols, "column list / order changed — the portal and recompute_asset_current_risk_for read it"


def test_fleet_reps_mirror_the_portal_scope_rule():
    reps = SQL[SQL.index("VIEW public.v_fleet_open_reps"):]
    assert "coalesce(a.ownership, 'unknown') = 'owned'" in reps
    assert "coalesce(a.discovery_status, 'unverified') <> ALL (ARRAY['ct_ghost', 'went_dark', 'retired'])" in reps
    for marker in ("a.asset_id LIKE 'range:%'", "a.asset_id LIKE 'ip-range:%'", "a.asset_id LIKE 'ip:%'",
                   "a.asset_id ~ '^[0-9.]+$'"):
        assert marker in reps, marker


def test_fleet_reps_mirror_the_portal_pair_and_dedup_rules():
    reps = SQL[SQL.index("VIEW public.v_fleet_open_reps"):]
    assert "array_length(string_to_array(s.asset_id, '.'), 1) = 2" in reps, "isBareApex: exactly two labels"
    assert "w.asset_id = 'www.' || s.asset_id" in reps
    assert "'nk:' || f.normalized_key" in reps
    assert "'high-no-fallback:' || f.finding_id" in reps
    assert ("regexp_replace(lower(coalesce(f.title, '')), '[^a-z0-9]+', '-', 'g'), 120)" in reps
            and "trim(BOTH '-' FROM left(" in reps), "slugify: lower, [^a-z0-9]+ -> '-', first 120, strip '-'"
    for st in OPEN:
        assert f"'{st}'::finding_status_t" in reps, st


def test_recompute_targets_exactly_the_groups_the_view_change_closes():
    sel = SQL[SQL.index("SELECT public.recompute_asset_current_risk_for"):]
    assert "HAVING bool_or(f.current_status = ANY (ARRAY['closed_reclassified'::finding_status_t," in sel
    assert "AND NOT bool_or(f.current_status <> ALL (ARRAY[" in sel
    for st in CLOSED:
        assert f"'{st}'::finding_status_t" in sel, st


def test_no_write_to_findings_and_no_anon_read():
    body = re.sub(r"--.*$", "", SQL, flags=re.M)
    assert not re.search(r"^\s*(UPDATE|DELETE FROM|INSERT INTO|ALTER TABLE)\b", body, re.I | re.M), \
        "no statement writes a table (the only UPDATE/DELETE words are inside REVOKE)"
    assert "REVOKE ALL ON public.v_fleet_open_reps FROM anon" in SQL
    assert "TO anon" not in body
