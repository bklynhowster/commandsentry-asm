"""(note 308, item 2, 2026-10-13) One-time reviewed batch: close testssl findings a later clean
deep scan looked for properly and did not find.

The deep tier's remediation engine (asm_autoclose_stale_findings) is blocked live (20260902a,
ruling 20) and its evidence — "the tool ran ok and did not re-report" — was shown to be fooled
by a tool that succeeds without reading the host. 20261013c closes a narrower set under a
stricter rule and lifts nothing. These pins keep every clause of that rule in place; execution
is in the push evidence (realdb_308c.sh: both shapes, the guard, and the production regress
function flipping a re-emitted closed row back to 'regressed').
"""
import pathlib
import re

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261013c_autoclose_testssl_not_reobserved_once.sql"
SQL = MIG.read_text()
PROTO_EXCLUSION = "!~ ':testssl:(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3|DNS_CAArecord):'"


def _stmts():
    import sys
    sys.path.insert(0, str(DB))
    import apply_pending_migrations as a  # noqa: PLC0415
    return a._split(SQL)


def test_meta_header_valid_and_auto_applicable():
    import sys
    sys.path.insert(0, str(DB))
    import migration_meta as m  # noqa: PLC0415
    meta = m.parse_meta(SQL)
    assert m.validate_meta(meta, MIG.name) == []
    assert meta["safe_auto_apply"] == "true" and meta["transactional"] == "true" and meta["idempotent"] == "true"


def test_two_statements_guard_then_batch_begin_commit_stripped():
    s = _stmts()
    assert len(s) == 2, [x[:60] for x in s]
    assert s[0].startswith("SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END)")
    assert s[1].startswith("WITH batch AS (")
    assert "\nBEGIN;\n" in SQL and SQL.rstrip().endswith("COMMIT;")
    assert "$$" not in SQL


def test_it_lifts_nothing():
    for st in _stmts():
        assert "asm_autoclose_stale_findings" not in st
        assert "CREATE" not in st and "ALTER" not in st and "DROP" not in st


def test_the_rule_every_clause_in_both_statements():
    for st in _stmts():
        assert "f.source::text = 'testssl'" in st
        assert "f.severity::text IN ('LOW', 'MODERATE')" in st, "never HIGH or above; INFO out of scope"
        assert "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in st
        assert "f.last_observed_at < now() - interval '30 days'" in st
        assert "f.finding_id LIKE f.asset_id || ':testssl:%'" in st
        # (a) a later COMPLETE scan that ran testssl.sh with ok = true
        assert "sr.status::text = 'complete'" in st
        assert "sr.completed_at > f.last_observed_at" in st
        assert "'testssl.sh' = ANY (sr.tools_run)" in st
        assert "sr.tool_status -> 'testssl.sh' ->> 'ok' = 'true'" in st
        # (b) a PRE-EXISTING sibling observed BY that scan (finding_history), same host, same port
        assert "g.first_detected_at < sr.completed_at - interval '1 day'" in st
        assert "ON fh.finding_id = g.finding_id AND fh.scan_id = sr.scan_run_id::text" in st
        assert "g.asset_id = f.asset_id" in st and "sr.asset_id = f.asset_id" in st
        assert "substring(g.finding_id from ':[^:]*$') = substring(f.finding_id from ':[^:]*$')" in st
        assert "g.finding_id <> f.finding_id" in st and "g.source::text = 'testssl'" in st
        assert "g.last_observed_at >= sr.completed_at" not in st, "witness must be bound to the scan, not 'seen at or after'"
        # (c) this finding NOT observed by that scan
        assert "WHERE fx.finding_id = f.finding_id AND fx.scan_id = sr.scan_run_id::text" in st
        # (d) the witness needs a completed handshake
        assert PROTO_EXCLUSION in st
        # (e) the check is alive somewhere in the fleet — exact compare, no LIKE wildcard on the id
        assert "h.last_observed_at > now() - interval '30 days'" in st
        assert "= regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '')" in st
        assert "|| regexp_replace(substr(f.finding_id" not in st
        assert "AND EXISTS (" in st and "OR EXISTS" not in st


def test_structure_pins_the_string_pins_cannot_see():
    b = _stmts()[1]
    assert "LEFT JOIN" not in SQL, "the witness is required, never optional"
    assert b.count("JOIN LATERAL (") == 2
    assert "WHERE f.finding_id = c.finding_id" in b, "the UPDATE is bound to the candidates"
    assert "length(f.asset_id) + 10" in b and "+ 9" not in SQL


def test_evidence_is_the_earliest_covering_scan_and_its_witness():
    b = _stmts()[1]
    assert "ORDER BY sr.completed_at ASC\n       LIMIT 1" in b
    assert "ORDER BY g.first_detected_at, g.finding_id\n           LIMIT 1" in b
    assert "'scan_run_id',         c.scan_run_id" in b
    assert "'witness_finding_id',  c.witness_finding_id" in b


def test_closes_as_remediated_with_remediated_at_and_nothing_else():
    b = _stmts()[1]
    assert "SET current_status = 'remediated'" in b
    assert "remediated_at  = b.at" in b
    assert "detector_retired" not in b
    assert "validated_remediated" not in b


def test_audit_row_matches_the_engines_shape_plus_batch_and_rule():
    b = _stmts()[1]
    assert "INSERT INTO public.admin_audit_log" in b
    assert "'autoclose_stale_finding'" in b, "same action the blocked engine writes"
    assert "'rule',                'note_308_item2_testssl_strict_sibling_v3'" in b
    assert "'batch_rule',          'note_308_item2_testssl_not_reobserved_once'" in b
    assert "'batch_id',            b.id" in b and "'monitoring'," in b
    assert "JOIN closed x ON x.finding_id = c.finding_id" in b, "audit only what was actually updated"


def test_batch_id_and_timestamp_come_from_one_cte_evaluated_once():
    b = _stmts()[1]
    assert "WITH batch AS (\n  SELECT gen_random_uuid() AS id, now() AS at\n)" in b
    assert b.count("gen_random_uuid()") == 1


def test_no_other_table_is_written():
    for st in _stmts():
        for verb, target in re.findall(r"\b(UPDATE|INSERT INTO|DELETE FROM|TRUNCATE)\b\s+([\w.]+)", st):
            assert target in ("public.findings", "public.admin_audit_log"), (verb, target)
