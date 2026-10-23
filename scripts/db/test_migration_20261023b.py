"""(KB 12 job 3r-b, 2026-10-23) A group is rated by its open members; old "No WAF" HIGHs -> MODERATE.

After migration 20261023a closed the never-applied Slider Revolution advisories, five Command
sites stayed HIGH with no open HIGH finding: v_open_findings_dedup took a group's severity from
ALL members, closed ones included. Howie, 11:41: "We are still showing a high with regard to the
lack of a WAF. I thought we agreed on cutting that back down to a medium." (job 3b's ruling was
applied at write time only.)

Pinned: a bounded guard, the view (same columns as 20261013a; severity, title and CVE list read
open members first, and only open members' CVEs while any is open), the audited WAF step (its
WHERE equals the guard's), one recompute of every asset, nothing deleted, the meta auto-applies.
Proven on PostgreSQL 16 against production's definitions in the build note (not here: no DB).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261023b_open_members_rate_a_group.sql"
OLD = DB / "migrations" / "20261013a_reclassified_is_closed_and_fleet_open_reps.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

CLOSED = ("'remediated'::finding_status_t", "'validated_remediated'::finding_status_t",
          "'false_positive'::finding_status_t", "'wont_fix'::finding_status_t",
          "'accepted_risk'::finding_status_t", "'closed_reclassified'::finding_status_t",
          "'detector_retired'::finding_status_t")


def _stmts(sql=SQL):
    return [" ".join(s.split()) for s in runner._split(sql) if s.strip()]


def _cols(view_sql):
    """The final SELECT lists of the view (grouped and ungrouped), as written."""
    return re.findall(r"SELECT (grouped\.asset_id.*?) FROM grouped|SELECT (ungrouped\.asset_id.*?) FROM ungrouped",
                      view_sql)


def test_guard_view_audited_step_recompute():
    st = _stmts()
    assert len(st) == 4
    assert st[0].startswith("SELECT 1 / (CASE WHEN count(*) <= 20 THEN 1 ELSE 0 END)")
    assert st[1].startswith("CREATE OR REPLACE VIEW public.v_open_findings_dedup WITH (security_invoker = true) AS")
    assert st[2].startswith("WITH changed AS ( UPDATE public.findings f SET severity = 'MODERATE'::severity_t")
    assert "INSERT INTO public.admin_audit_log" in st[2] and st[2].endswith("FROM changed c")
    assert "'job_3r_waf_absence_moderate'" in st[2] and "'rule', 'job_3b'" in st[2]
    assert st[3] == "SELECT public.refresh_all_asset_posture()"


def test_the_waf_step_touches_exactly_what_the_guard_counts():
    g = _stmts()[0].split(" WHERE ", 1)[1]
    u = _stmts()[2].split(" WHERE ", 1)[1].split(" RETURNING ")[0]
    assert g == u
    for p in ("LIKE '%:commandsentry_heavy:waf-absent-differential:%'", "f.severity::text = 'HIGH'",
              "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')"):
        assert p in u, p


def test_the_view_keeps_its_columns_and_reads_open_members_first():
    new = _stmts()[1]
    old = [s for s in _stmts(OLD.read_text()) if s.startswith("CREATE OR REPLACE VIEW public.v_open_findings_dedup")][0]
    assert _cols(new) == _cols(old), "same columns, same order: dependents read it unchanged"
    assert new.split("), ungrouped AS (")[1] == old.split("), ungrouped AS (")[1], "ungrouped rows unchanged"
    closed = "(findings.current_status = ANY (ARRAY[ " + ", ".join(CLOSED) + "]))"
    sev = new.split("AS severity,")[0]
    assert sev.count(closed) == 1 and sev.index(closed) < sev.index("CASE findings.severity"), \
        "open members sort before closed ones, then by severity"
    title = new.split("AS current_status,")[1].split("AS title,")[0]
    assert closed in title and title.index(closed) < title.index("length(findings.title)")
    cve = new.split("max(findings.last_observed_at) AS last_observed_at,")[1].split("AS cve,")[0]
    assert "array_cat_agg(findings.cve) FILTER (WHERE findings.current_status <> ALL" in cve
    assert cve.count("array_cat_agg(findings.cve)") == 2, "open members' CVEs while any is open, else all"
    status = new.split("AS severity,")[1].split("AS current_status,")[0]
    assert status == old.split("AS severity,")[1].split("AS current_status,")[0], "open/closed rule unchanged"


def test_nothing_deleted_no_other_schema_no_dollar_quoting():
    low = " ".join(_stmts()).lower()
    for bad in ("delete from", "drop ", "truncate", "alter table", "alter type", "create table",
                "create function", "create or replace function"):
        assert bad not in low, bad
    assert "$$" not in SQL.split("END-META", 1)[1]


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
