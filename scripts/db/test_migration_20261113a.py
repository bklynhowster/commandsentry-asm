"""(KB 12, 2026-11-13) Migration 20261113a: the 96 path rows one misjudged scan wrote on
tour.prodexlabs.com are closed as false alarms, and nothing else is.

The deep scan 626f9631 of 2026-11-12 wrote 84 "Accessible path" findings for the one page that
site gives every address (two of them MODERATE and announced to the team) and 12 "Forbidden
endpoint" findings for refusals that followed the scanner's exit. The reading that let that
happen was fixed by push-438; the rows stay until something closes them. Howie, 2026-11-13 11:18,
to marking them false alarms: "yes...approved".

Pinned here: one UPDATE, on public.findings, of exactly the status (to false_positive) and
updated_at; it can only match rows of that one site with that id shape, FIRST written by that one
scan and still open; each row must match what that scan's own ffuf records hold for its word (the
3080-byte page, or a refusal); only while those records show the page at least 80 times and the
site's summary row is open; a row a person closed, /health, the redirect row, the summary row and
every other site are out of reach; remediated_at is never written; one audit row per closed row,
written from the rows the UPDATE returned, carrying the old values, the scan, the batch, the
reason, the evidence, the approval and the undo; a guard that stops a double recording; nothing
deleted, no schema change, no dollar quotes; one transaction; the meta auto-applies. Proven on
PostgreSQL 17.6 in the build note (today's shape, each condition broken on purpose, a row a person
closed, a row with its own answer, a row from an older scan, a Command-like copy, the guard
tripped, two applies, the undo, by hand and through the repo runner).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261113a_tour_path_rows_false_alarms.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

ASSET = "tour.prodexlabs.com"
SCAN = "626f9631-78bd-4a4c-891b-030caee35f2f"
PREFIX = "tour.prodexlabs.com:medium:ffuf-found-"
SUMMARY = "tour.prodexlabs.com:medium:ffuf-catchall-status-200"
BATCH = "20261113a-tour-path-rows-false-alarms"
ACTION = "path_rows_close_false_positive"
OPEN = "('detected', 'confirmed', 'open', 'regressed')"


def _body():
    return runner._strip_comments(SQL)


def _flat():
    return " ".join(_body().split())


def _statements():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _part(start, end):
    f = _flat()
    return f[f.index(start):f.index(end, f.index(start))].rstrip()


def _answers():
    return _part("WITH answers AS (", "), target AS (")


def _target():
    return _part("target AS (", "), closed AS (")


def _closed():
    return _part("closed AS (", ") INSERT INTO")


def test_two_statements_the_change_then_the_guard():
    st = [s for s in _statements() if s not in ("BEGIN", "COMMIT")]
    assert len(st) == 2
    assert st[0].startswith("WITH answers AS ( SELECT r.res -> 'input' ->> 'FUZZ' AS word, ")
    assert st[1].startswith("SELECT 1 / (CASE WHEN count(*) <= 96 AND count(*) = count(DISTINCT details ->> 'finding_id') "
                            "THEN 1 ELSE 0 END) AS guard_each_row_recorded_once")


def test_one_update_of_the_status_and_nothing_else():
    b = _body()
    assert b.count("UPDATE ") == 1
    c = _closed()
    assert c.startswith("closed AS ( UPDATE public.findings f SET ")
    sets = c[c.index(" SET ") + 5:c.index(" FROM ")]
    assert [s.strip() for s in sets.split(",")] == ["current_status = 'false_positive'", "updated_at = now()"]
    assert c.endswith("FROM target t WHERE f.finding_id = t.finding_id RETURNING f.finding_id")
    for never in ("remediated_at", "severity =", "title =", "description", "'remediated'", "'closed_reclassified'"):
        assert never not in c, never
    assert "remediated_at" not in b, "nothing was fixed: remediated_at is never written"


def test_the_answers_come_only_from_that_scans_own_ffuf_records():
    a = _answers()
    assert "FROM public.scan_run_artifacts a " in a
    assert a.endswith(f"WHERE a.scan_run_id = '{SCAN}' AND a.tool_name = 'ffuf'")
    assert "r.res ->> 'status' AS status, r.res ->> 'length' AS bytes" in a
    # a record whose results are not a list is read as no answers, never as an error
    assert ("jsonb_array_elements( CASE WHEN jsonb_typeof(a.content_jsonb -> 'results') = 'array' "
            "THEN a.content_jsonb -> 'results' ELSE '[]'::jsonb END) AS r(res)") in a


def test_it_can_only_match_this_site_this_id_shape_this_scan_and_open_rows():
    t = _target()
    assert (f"FROM public.findings f WHERE f.asset_id = '{ASSET}' "
            f"AND f.finding_id LIKE '{PREFIX}%' "
            f"AND f.first_detected_scan = '{SCAN}' "
            f"AND f.current_status::text IN {OPEN} AND (") in t
    f = _flat()
    assert set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", f)) == {SCAN}
    assert set(re.findall(r"asset_id = '([^']+)'", f)) == {ASSET}
    # every site name written anywhere in the statement is this one
    assert set(re.findall(r"[a-z0-9.-]+\.prodexlabs\.com", f)) == {ASSET}
    for other in ("atlantis", "pulse.uat", "false_positive', 'wont_fix"):
        assert other not in t, other


def test_each_row_must_match_what_that_scan_recorded_for_its_word():
    t = _target()
    page = ("(f.title LIKE 'Accessible path: /% (HTTP 200)' AND EXISTS (SELECT 1 FROM answers w "
            f"WHERE '{PREFIX}' || w.word = f.finding_id AND w.status = '200' AND w.bytes = '3080'))")
    refusal = ("(f.title LIKE 'Forbidden endpoint: /% (HTTP 403)' AND EXISTS (SELECT 1 FROM answers w "
               f"WHERE '{PREFIX}' || w.word = f.finding_id AND w.status = '403'))")
    assert f"AND ( {page} OR {refusal}) AND (SELECT count(*)" in t
    assert t.count(" OR ") == 1, "two kinds of row and no third"


def test_only_while_the_scan_shows_one_page_and_the_summary_row_is_open():
    t = _target()
    assert "AND (SELECT count(*) FROM answers w WHERE w.status = '200' AND w.bytes = '3080') >= 80 AND EXISTS" in t
    assert t.endswith("AND EXISTS (SELECT 1 FROM public.findings s "
                      f"WHERE s.finding_id = '{SUMMARY}' "
                      f"AND s.current_status::text IN {OPEN})")


def test_one_audit_row_per_closed_row_with_the_old_values():
    f = _flat()
    assert f.count("INSERT INTO") == 1
    ins = f[f.index("INSERT INTO public.admin_audit_log"):f.index("; SELECT 1 /")]
    assert ins.startswith("INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, "
                          f"after_state, details) SELECT NULL, '{ACTION}', ")
    assert ("jsonb_build_object('current_status', t.old_status, 'severity', t.severity, "
            "'last_observed_at', t.last_observed_at)") in ins
    assert "jsonb_build_object('current_status', 'false_positive')" in ins
    # no row unless the UPDATE changed that finding
    assert ins.endswith("FROM target t JOIN closed c ON c.finding_id = t.finding_id") and " VALUES " not in ins
    assert "f.current_status::text AS old_status" in _target() and "f.severity::text AS severity" in _target()
    for key in ("'finding_id', t.finding_id", "'asset_id', t.asset_id", "'title', t.title", "'answer', t.answer",
                f"'scan_run_id', '{SCAN}'", f"'batch', '{BATCH}'", "'reason', '", "'evidence', '",
                "'approved_by', 'howie@prodexlabs.com (chat approval 2026-11-13 11:18 ET)'",
                "'changed_by', 'migration 20261113a (built by Claude)'",
                "'undo', 'Set current_status back to detected on this finding.'"):
        assert key in ins, key
    assert "push-438" in ins and "3,080-byte page" in ins


def test_the_answer_kept_with_each_row_says_which_kind_it_was():
    t = _target()
    assert ("CASE WHEN f.title LIKE 'Accessible path: /% (HTTP 200)' "
            "THEN 'the one page the site gives every address (HTTP 200, 3080 bytes)' "
            "ELSE 'a refusal that followed the scanner''s exit (HTTP 403)' END AS answer") in t


def test_the_guard_counts_this_files_own_audit_rows():
    g = [s for s in _statements() if s.startswith("SELECT 1 /")][0]
    assert g.endswith(f"FROM public.admin_audit_log WHERE action = '{ACTION}' "
                      f"AND details ->> 'batch' = '{BATCH}'")
    b = _body()
    assert b.index("INSERT INTO public.admin_audit_log") < b.index("guard_each_row_recorded_once")


def test_the_undo_in_the_header_names_this_batch():
    flat = " ".join(line.lstrip("- ").strip() for line in SQL.splitlines() if line.startswith("--"))
    assert ("Reversal: UPDATE public.findings SET current_status = 'detected' WHERE finding_id IN "
            "(SELECT details ->> 'finding_id' FROM public.admin_audit_log WHERE action = "
            f"'{ACTION}' AND details ->> 'batch' = '{BATCH}');") in flat


def test_nothing_else_is_touched():
    b = _body()
    for word in ("DELETE ", "DROP ", "TRUNCATE", "ALTER ", "CREATE ", "GRANT", "REVOKE",
                 "public.assets", "public.scan_queue", "public.scan_run ", "public.finding_history",
                 "INSERT INTO public.findings", "INSERT INTO public.scan_run_artifacts"):
        assert word not in b, word
    assert b.count("public.scan_run_artifacts") == 1, "read once, never written"
    assert "$$" not in SQL


def test_one_transaction_and_the_meta_auto_applies():
    b = _body()
    assert b.count("\nBEGIN;\n") == 1 and b.rstrip().endswith("COMMIT;")
    assert b.index("BEGIN;") < b.index("UPDATE public.findings") < b.index("COMMIT;")
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
