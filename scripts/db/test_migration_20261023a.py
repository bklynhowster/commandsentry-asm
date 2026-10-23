"""(KB 12 job 3r, 2026-10-23) The one-time cleanup: known, not guessed.

Howie, 2026-10-22 20:34: "There are risks and there are things that are known, that's all."
2026-10-23 07:21-07:25 on the hand assessment's Mega Main Menu row: "drop it to moderate".
3r plan review (GLM-5.3) must-fix 1: retiring the guesses is a human-run, audited batch
(migration 20260902b's contract), never the advisory watch's daily act.

Pins: three bounded-batch guards, then four steps in the house pattern (20261013b): WITH
changed AS (UPDATE ... RETURNING) INSERT INTO admin_audit_log FROM changed — the log holds
exactly the rows that changed; guesses -> detector_retired WITH its timestamp (20260902c's
invariant); the four 7.0.x-only Slider Revolution advisories -> false_positive only on rows
recording a version below 7.0 (the parser and this agree on the live texts); out of date ->
MODERATE / MODERATE-HIGH by kev_listed, never touching a closed row; Howie's ruling touches
exactly one row; nothing deleted, no schema change; the meta auto-applies.
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261023a_known_not_guessed.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "normalize"))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import evidence  # noqa: E402
import migration_meta  # noqa: E402

OPEN = "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')"


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL)]


def _where(s):
    return s.split(" WHERE ", 1)[1].split(" RETURNING ")[0].split(" ), changed AS")[0]


def test_guards_then_four_audited_steps():
    st = _stmts()
    assert len(st) == 7
    for g in st[:3]:
        assert g.startswith("SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END)")
    for step in st[3:]:
        assert step.startswith(("WITH changed AS ( UPDATE public.findings f SET", "WITH was AS ( SELECT"))
        assert "INSERT INTO public.admin_audit_log" in step and step.endswith("FROM changed c")
    assert [_where(g) for g in st[:3]] == [_where(x) for x in st[3:6]], "each guard counts exactly its step's rows"
    assert " FROM was w WHERE f.finding_id = w.finding_id " in st[5], "step 3 logs the severity it replaced"
    actions = [re.search(r"SELECT NULL, '(\w+)'", x).group(1) for x in st[3:]]
    assert actions == ["detector_retired_finding", "job_3r_false_match", "job_3r_out_of_date", "job_3r_howie_ruling"]


def test_guesses_retired_with_their_timestamp_by_the_manual_transition_rule():
    st = _stmts()[3]
    assert "SET current_status = 'detector_retired', detector_retired_at = now()" in st
    assert "'rule', '4.7_ruling_57_detector_retired_manual_transition'" in st, "retire_detector_findings.py's rule"
    w = _where(st)
    assert "f.source::text = 'advisory_watch'" in w and "LIKE '%:advisory_watch:advisory:%'" in w and OPEN in w
    assert ":out-of-date:" not in SQL.split("END-META", 1)[1], "never the new out-of-date identity"


def test_false_matches_are_the_four_7_0_only_advisories_on_rows_below_7_0():
    st = _stmts()[4]
    assert "SET current_status = 'false_positive'" in st
    w = _where(st)
    assert "< ARRAY[7, 0]" in w and OPEN in w
    rx = re.compile(r":light:wpvuln-cve-2026-(6692|7542|9048|57678)$")
    assert rx.search("www.commandcompanies.com:light:wpvuln-cve-2026-6692")
    assert not rx.search("www.commandcompanies.com:light:wpvuln-cve-2026-6728"), "6728 covers 6.7.x: it stays"
    from test_evidence_3r import LIVE
    for cve in ("CVE-2026-6692", "CVE-2026-7542", "CVE-2026-9048", "CVE-2026-57678"):
        assert evidence.range_excludes("6.9.99", LIVE[cve]) and not evidence.range_excludes("7.0.9", LIVE[cve]), cve
    assert not evidence.range_excludes("6.7.58", LIVE["CVE-2026-6728"])


def test_the_wpscan_import_copy_of_a_false_match_is_closed_too():
    """3r second check (Grok, 09:05): the WPScan-import row
    commandmarketinginnovations.com:wpvulnerability:wpvuln:revslider:CVE-2026-6692:... carries no
    advisory text, so the weekly cannot drop it by range; it must not survive to "Overdue". Step 2
    closes it: its identity matches the second pattern and its title gives the version (live,
    2026-10-23: it is one of the 24)."""
    w = _where(_stmts()[4])
    fid = "commandmarketinginnovations.com:wpvulnerability:wpvuln:revslider:CVE-2026-6692:fix=7.0.11:f7acecd"
    title = "revslider 6.7.54 \u2014 < 7.0.11 (CVE-2026-6692)"
    desc = "Plugin **revslider** version **6.7.54** is currently vulnerable."
    pats = re.findall(r"f\.finding_id ~ '([^']+)'", w)
    assert len(pats) == 2 and any(re.search(p, fid) for p in pats)
    assert re.search(r"at version ([0-9]+(\.[0-9]+)*)", desc) is None, "falls through to the title"
    m = re.search(r"\^revslider \(\[0-9\]\+\(\\\.\[0-9\]\+\)\*\) ", w)
    assert m, "the title fallback is in the WHERE"
    assert re.match(r"^revslider ([0-9]+(\.[0-9]+)*) ", title).group(1) == "6.7.54"
    assert not re.search(pats[1], "x:wpvulnerability:wpvuln:revslider:CVE-2026-6728:fix=7.0.10:f7acecd"), \
        "6728 covers 6.7.x: its import copy stays"


def test_out_of_date_rerated_by_kev_and_only_when_different():
    st = _stmts()[5]
    assert "SET severity = (CASE WHEN f.kev_listed THEN 'MODERATE-HIGH' ELSE 'MODERATE' END)::severity_t" in st
    assert "jsonb_build_object('severity', c.severity_was)" in st
    w = _where(st)
    for p in ("LIKE '%:light:wpvuln-%'", "LIKE '%:light:libflaw-%'", "LIKE '%:wpvulnerability:wpvuln:%'", OPEN,
              "f.severity::text <> CASE WHEN f.kev_listed THEN 'MODERATE-HIGH' ELSE 'MODERATE' END"):
        assert p in w, p
    assert "manual" not in w, "a person's row is never re-rated by rule"


def test_howies_ruling_touches_exactly_one_row_and_records_his_words():
    st = _stmts()[6]
    assert _where(st) == "f.finding_id = 'unimacgraphics.com:manual:F-01' AND f.severity::text = 'HIGH'"
    assert "'ruled_by', 'Howie'" in st and "drop it to moderate" in st


def test_nothing_deleted_no_schema_change_no_dollar_quoting():
    low = " ".join(_stmts()).lower()
    for bad in ("delete from", "drop table", "drop function", "drop type", "truncate", "alter table",
                "alter type", "create "):
        assert bad not in low, bad
    assert "$$" not in SQL.split("END-META", 1)[1]


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
