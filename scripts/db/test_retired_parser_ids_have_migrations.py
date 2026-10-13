"""(note 308, 2026-10-13) When the testssl parser stops emitting a check id, the open rows that
id already produced must be retired in the SAME change, not discovered eleven weeks later
sitting in the daily email's "not seen by any scan in 30+ days" line.

Rule: every id in testssl.py METADATA_IDS must appear in the RETIRED CHECK IDS block of at
least one migration under scripts/db/migrations/. Adding an id to METADATA_IDS without a
retirement migration fails this test; the message says what to write.
"""
import ast
import pathlib
import re

DB = pathlib.Path(__file__).resolve().parent
PARSER = DB.parent / "normalize" / "cs_parsers" / "testssl.py"


def _parser_metadata_ids():
    tree = ast.parse(PARSER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "METADATA_IDS" for t in node.targets):
            return {ast.literal_eval(e) for e in node.value.elts}
    raise AssertionError("METADATA_IDS not found in testssl.py")


def _retired_ids_in_migrations():
    out = {}
    for p in sorted((DB / "migrations").glob("*.sql")):
        for block in re.findall(r"-- BEGIN RETIRED CHECK IDS.*?\n(.*?)-- END RETIRED CHECK IDS", p.read_text(), re.S):
            for cid in re.findall(r"'([^']+)'", block):
                out.setdefault(cid, p.name)
    return out


def test_every_metadata_id_has_a_retirement_migration():
    parser = _parser_metadata_ids()
    retired = _retired_ids_in_migrations()
    missing = sorted(parser - set(retired))
    assert not missing, (
        f"testssl.py METADATA_IDS has {len(missing)} id(s) with no retirement migration: {missing}. "
        "Dropping an id from the parser leaves its existing open rows unobservable forever. Add a "
        "migration modelled on 20261013b_retire_testssl_metadata_findings.sql that retires the open "
        "rows for these ids (detector_retired + audit rows, guards included) in this same change.")


def test_the_block_markers_are_parsed_not_assumed():
    assert "FS_KEMs" in _retired_ids_in_migrations(), "20261013b's RETIRED CHECK IDS block must parse"
