"""(note 308, item 1, 2026-10-13) Retire the open testssl rows whose check the parser dropped.

On 2026-07-25 the testssl parser stopped emitting a set of ids (METADATA_IDS: TLS inventory,
not findings). The rows that already existed were never retired and sat in the open count for
eleven weeks. Migration 20261013b moves them to detector_retired (20260902b), with the
guardrails of scripts/db/retire_detector_findings.py carried into SQL. These pins keep the
migration's id list equal to the parser's, and its shape honest. Execution against real
PostgreSQL is in the push evidence (realdb_308.sh, both instance shapes, both guards).
"""
import ast
import pathlib
import re

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261013b_retire_testssl_metadata_findings.sql"
PARSER = DB.parent / "normalize" / "cs_parsers" / "testssl.py"
SQL = MIG.read_text()


def _stmts():
    """Comment-stripped statements, the way apply_pending_migrations.py sees them."""
    import sys
    sys.path.insert(0, str(DB))
    import apply_pending_migrations as a  # noqa: PLC0415
    return a._split(SQL)


def _retired_ids_in_migration():
    block = re.search(r"-- BEGIN RETIRED CHECK IDS.*?\n(.*?)-- END RETIRED CHECK IDS", SQL, re.S).group(1)
    return set(re.findall(r"'([^']+)'", block))


def _parser_metadata_ids():
    tree = ast.parse(PARSER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "METADATA_IDS" for t in node.targets):
            return {ast.literal_eval(e) for e in node.value.elts}
    raise AssertionError("METADATA_IDS not found in testssl.py")


def test_hand_run_safety_begin_commit_present_and_stripped_by_the_runner():
    assert "\nBEGIN;\n" in SQL and SQL.rstrip().endswith("COMMIT;")
    assert len(_stmts()) == 3, "the runner strips BEGIN/COMMIT and wraps its own transaction"


def test_meta_header_is_valid_and_auto_applicable():
    import sys
    sys.path.insert(0, str(DB))
    import migration_meta as m  # noqa: PLC0415
    meta = m.parse_meta(SQL)
    assert m.validate_meta(meta, MIG.name) == []
    assert meta["safe_auto_apply"] == "true" and meta["transactional"] == "true" and meta["idempotent"] == "true"


def test_three_statements_two_guards_one_transition():
    s = _stmts()
    assert len(s) == 3, [x[:60] for x in s]
    assert s[0].startswith("SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END)")
    assert s[1].startswith("SELECT 1 / (CASE WHEN count(*) <= 200 THEN 1 ELSE 0 END)")
    assert s[2].startswith("WITH retired AS (\n  UPDATE public.findings f")
    assert "$$" not in SQL, "the splitter is not dollar-quote aware"


IDS_DROPPED_2026_07_25 = frozenset({
    "cert_notAfter", "cert_notBefore", "cert_keySize", "cert_signatureAlgorithm", "cert_commonName",
    "cert_subjectAltName", "cert_serialNumber", "cert_fingerprintSHA1", "cert_fingerprintSHA256",
    "cert_caIssuers", "cert_crlDistributionPoints", "cert_ocspURL", "cert_mustStapleExtension",
    "cert_eTS_wildcard", "intermediate_cert_notAfter", "intermediate_cert_notBefore",
    "intermediate_cert_keySize", "intermediate_cert_signatureAlgorithm",
    "FS_TLS12_sig_algs", "FS_ECDHE_curves", "FS_TLS13_sig_algs", "FS_KEMs", "TLS_session_ticket",
    "TLS_timestamp", "TLS_extensions", "SSL_sessionID_support", "sessionresumption_ticket",
    "sessionresumption_ID", "clientsimulation",
})


def test_id_list_is_exactly_the_29_ids_the_parser_dropped_on_2026_07_25():
    """A literal pin: this migration is history. If the parser later re-enables a check, this
    test must NOT start failing — the forward rule lives in
    test_retired_parser_ids_have_migrations.py."""
    mig = _retired_ids_in_migration()
    assert mig == IDS_DROPPED_2026_07_25, {"only in migration": mig - IDS_DROPPED_2026_07_25,
                                           "missing": IDS_DROPPED_2026_07_25 - mig}
    assert len(mig) == 29
    # the same list, verbatim, in all three statements (guards and transition must agree)
    for st in _stmts():
        for cid in mig:
            assert f"'{cid}'" in st, (cid, st[:50])


def test_the_three_statements_carry_the_same_id_set():
    """An id added to the UPDATE alone would retire rows the guards never checked."""
    sets = []
    for st in _stmts():
        body = re.findall(r" IN \(([^)]*)\)", st)[-1]   # the id list is the last IN (...) in each statement
        sets.append(set(re.findall(r"'([^']+)'", body)))
    assert sets[0] == sets[1] == sets[2] == IDS_DROPPED_2026_07_25, sets


def test_deliberately_excluded_ids_are_not_retired():
    """DNS_CAArecord went quiet for an unknown reason (not a parser decision); cert_trust_wildcard
    is still observed. Neither meets criterion (1). LUCKY13 etc. are live checks."""
    ids = _retired_ids_in_migration()
    for live in ("DNS_CAArecord", "cert_trust_wildcard", "LUCKY13", "OCSP_stapling", "cert_chain_of_trust",
                 "cert_trust", "cert_expirationStatus", "BREACH", "HSTS"):
        assert live not in ids, live


def test_guard_1_is_anchored_on_the_parser_change_date_not_a_sliding_window():
    g = _stmts()[0]
    assert "f.last_observed_at > TIMESTAMPTZ '2026-07-26 00:00:00+00'" in g
    assert "interval" not in g.lower()


def test_transition_touches_only_open_testssl_rows_matched_by_exact_check_id():
    t = _stmts()[2]
    assert "f.source::text = 'testssl'" in t
    assert "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in t
    assert "f.finding_id LIKE f.asset_id || ':testssl:%'" in t, "asset ids can contain colons; no naive split"
    assert "regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') IN (" in t
    assert " LIKE '%" not in t.replace("f.asset_id || ':testssl:%'", ""), "no substring matching of ids"


def test_transition_sets_the_retired_pair_and_never_a_remediation():
    t = _stmts()[2]
    assert "SET current_status      = 'detector_retired'" in t
    assert "detector_retired_at = now()" in t
    assert "remediated_at" not in t, "not a remediation (note 126 invariant)"
    assert "'remediated'" not in t


def test_every_retired_row_gets_an_audit_row_with_reason_rule_and_batch():
    t = _stmts()[2]
    assert "INSERT INTO public.admin_audit_log" in t
    assert "'detector_retired_finding'" in t, "same action the manual tool writes"
    assert "'rule',         '4.7_ruling_57_detector_retired_manual_transition'" in t
    assert "'batch_rule',   'note_308_item1_testssl_metadata_ids'" in t
    assert "'check_id',     r.check_id" in t and "'reason'," in t
    assert "FROM retired r" in t


def test_no_other_table_is_written():
    for st in _stmts():
        heads = re.findall(r"\b(UPDATE|INSERT INTO|DELETE FROM|TRUNCATE|ALTER|DROP|CREATE)\b\s+([\w.]+)", st)
        for verb, target in heads:
            assert target in ("public.findings", "public.admin_audit_log"), (verb, target)
            assert verb in ("UPDATE", "INSERT INTO"), (verb, target)
