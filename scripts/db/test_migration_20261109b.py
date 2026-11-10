"""(KB 12, five-visitor item 7, 2026-11-09) Migration 20261109b: twins counted once, higher wins.

Howie, 2026-11-09 14:20: "Once, higher wins." Plan v3 (Kimi K3.1 Pro: ready), 20:01: "go". The open
rows a rescan would key (push-426's same-fact list) keyed now; v_open_findings_dedup shows the
higher row's words; the names whose words change through the view alone recomputed by hand.
Pinned here: six statements in order (two guards, record the view-only names, the view, key and
audit, recompute); the chosen set written once for the guard and once for the update, byte for byte;
its patterns are common.py's list (the same sources, the same anchored words) and its new words the
parser's (testssl.TITLE_LABELS, 100 characters); the view is 20261023b's with only the title's
ORDER BY changed (open first, worst severity, longest, finding id); open rows only; nothing deleted,
no schema change, no dollar quotes; the meta auto-applies. Proven on PostgreSQL 16 in the build
note (production's own view, function and trigger definitions, md5-equal; Command and Prodex
shapes; the guards tripped on purpose; two applies; reversed from the audit rows).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261109b_twins_counted_once.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "normalize"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402
from cs_parsers.common import CROSS_SOURCE_EQUIVALENCE  # noqa: E402
from cs_parsers.common import stable_finding_id  # noqa: E402
from cs_parsers.testssl import TITLE_LABELS, shared_key_for_port  # noqa: E402

OPEN = "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')"
KEYS = ("missing-header-strict-transport-security", "tls-beast", "tls-ocsp-stapling-missing")


def _stmts():
    return [s.strip() for s in runner._split(SQL) if s.strip()]


def _norm(s):
    return " ".join(s.split())


def test_six_statements_in_order():
    st = [_norm(s) for s in _stmts()]
    assert len(st) == 6, [s[:60] for s in st]
    assert "AS guard_bounded" in st[0] and "AS guard_nothing_serious" in st[0] and "AS guard_no_other_key_overwritten" in st[0]
    assert "AS guard_no_stranger" in st[1]
    assert st[2].startswith("INSERT INTO public.admin_audit_log") and "'twins_view_words'" in st[2]
    assert st[3].startswith("CREATE OR REPLACE VIEW public.v_open_findings_dedup WITH (security_invoker = true) AS")
    assert "UPDATE public.findings f SET normalized_key = c.new_key, title = c.new_title" in st[4] and "'twins_keyed'" in st[4]
    assert st[5].startswith("SELECT public.recompute_asset_current_risk_for(x.asset_id)") and "'twins_view_words'" in st[5]


def test_the_chosen_set_is_one_rule():
    st = _stmts()
    guard = st[0].split("SELECT 1 / (CASE WHEN count(*) <= 100")[0]
    update = st[4].split(",\nchanged AS (")[0]
    assert guard.strip() == update.strip(), "the guard counts exactly the rows the update changes"
    assert OPEN in guard, "open rows only"
    assert "t.new_key IS NOT NULL" in guard and "t.old_key IS DISTINCT FROM t.new_key OR t.new_title IS DISTINCT FROM t.title" in guard


def test_the_patterns_are_common_py_s_list():
    guard = _norm(_stmts()[0])
    by_key = {e["canonical_key"]: e for e in CROSS_SOURCE_EQUIVALENCE}
    for key in KEYS:
        for src, pat in by_key[key]["patterns"]:
            if key == "tls-ocsp-stapling-missing" and src != "testssl":
                continue   # June's hand-entered rows were keyed by 20260618a; the live path missed only testssl's
            sql_pat = pat.pattern.replace("(?:", "(")
            assert _norm(f"f.title ~* '{sql_pat}'") in guard, (key, src, sql_pat)
            assert f"'{sql_pat}'" in _stmts()[0], "byte for byte, two spaces before (N reports) kept"
            assert f"f.source::text = '{src}'" in guard, (key, src)
            assert f"THEN '{key}'" in guard


def test_the_old_nikto_line_is_matched_and_nothing_wider():
    guard = _norm(_stmts()[0])
    assert ("f.source::text = 'commandsentry_medium' AND f.title ~* "
            "'^nikto: .*suggested security header missing: strict-transport-security' "
            "THEN 'missing-header-strict-transport-security'") in guard
    assert guard.count("THEN '") == 5 + 1, "five key rules and one reword rule"


def test_the_new_words_are_the_parser_s():
    guard = _norm(_stmts()[0])
    label = TITLE_LABELS["BEAST_CBC_TLS1"]
    assert label == "BEAST attack possible on TLS 1.0"
    assert (f"WHEN f.source::text = 'testssl' AND f.title ~ '^TLS · BEAST_CBC_TLS1: .' "
            f"THEN '{label} — ' || left(substr(f.title, char_length('TLS · BEAST_CBC_TLS1: ') + 1), 100) "
            f"ELSE f.title END AS new_title") in guard, "the parser keeps 100 characters after a label"


def test_the_view_is_20261023b_with_only_the_title_order_changed():
    old = (DB / "migrations" / "20261023b_open_members_rate_a_group.sql").read_text()
    old_view = [s for s in runner._split(old) if "CREATE OR REPLACE VIEW public.v_open_findings_dedup" in s][0]
    new_view = _stmts()[3]
    before = """'detector_retired'::finding_status_t])),
            (length(findings.title)) DESC NULLS LAST))[1] AS title,"""
    after = """'detector_retired'::finding_status_t])),
            (CASE findings.severity
              WHEN 'CRITICAL'::severity_t      THEN 1
              WHEN 'HIGH'::severity_t          THEN 2
              WHEN 'MODERATE-HIGH'::severity_t THEN 3
              WHEN 'MODERATE'::severity_t      THEN 4
              WHEN 'LOW'::severity_t           THEN 5
              WHEN 'INFO'::severity_t          THEN 6
              ELSE 9
            END),
            (length(findings.title)) DESC NULLS LAST,
            findings.finding_id))[1] AS title,"""
    assert old_view.count(before) == 1
    assert old_view.strip().replace(before, after) == new_view.strip()


def test_the_view_only_names_are_recorded_before_the_view_and_recomputed_after():
    st = [_norm(s) for s in _stmts()]
    rec = st[2]
    assert "AND NOT bool_or(k.id IS NOT NULL)" in rec, "a group keyed by this file is the trigger's to recompute"
    assert "HAVING bool_or(f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed'))" in rec
    assert "WHERE g.old_title IS DISTINCT FROM g.new_title" in rec
    assert "AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l WHERE l.action = 'twins_view_words'" in rec
    # the old order is the old view's (open first, longest); the new one the new view's
    assert "(length(f.title)) DESC NULLS LAST))[1] AS old_title" in rec
    assert "(length(f.title)) DESC NULLS LAST, f.finding_id))[1] AS new_title" in rec
    assert "l.details ->> 'batch' = '20261109b-twins'" in st[5]


def test_each_batch_name_and_audit_action_is_this_file_s():
    assert SQL.count("'20261109b-twins'") == 5
    assert set(re.findall(r"'(twins_\w+)'", SQL)) == {"twins_view_words", "twins_keyed"}


def test_the_guards():
    st = [_norm(s) for s in _stmts()]
    assert "1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_bounded" in st[0]
    assert ("1 / (CASE WHEN count(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')) = 0 "
            "THEN 1 ELSE 0 END) AS guard_nothing_serious") in st[0]
    assert ("1 / (CASE WHEN count(*) FILTER (WHERE old_key IS NOT NULL AND old_key <> new_key) = 0 "
            "THEN 1 ELSE 0 END) AS guard_no_other_key_overwritten") in st[0]
    g4 = st[1]
    assert "f.normalized_key = 'tls-beast' AND NOT (f.source::text = 'testssl'" in g4
    assert ("f.normalized_key = 'missing-header-strict-transport-security' "
            "AND f.source::text <> 'commandsentry_light'") in g4


def test_safe_shape():
    body = runner._strip_comments(SQL)
    assert "$$" not in SQL and not re.search(r"\$[a-z_]*\$", body)
    for bad in (r"\bDELETE\b", r"\bDROP\b", r"\bALTER\b", r"\bCREATE TABLE\b", r"\bTRUNCATE\b", r"\bINSERT INTO public\.findings\b"):
        assert not re.search(bad, body, flags=re.I), bad
    sets = re.findall(r"\bSET\b(.+?)\bFROM\b", body, flags=re.S)
    assert [_norm(s) for s in sets] == ["normalized_key = c.new_key, title = c.new_title, updated_at = now()"], \
        "one UPDATE, and it changes the key and the words only: no status, no severity"


def test_the_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert meta.get("transactional") in (True, "true") and meta.get("idempotent") in (True, "true")


def test_only_the_default_port_shares_a_key():
    """The parser keys a testssl row bare only on 443 or no port (shared_key_for_port); the
    migration can only tell the port from the finding_id's hash, so it keys those two and leaves
    any other port's row to its next deep scan (code review 2026-11-09, must-fix)."""
    guard = _norm(_stmts()[0])
    h443 = stable_finding_id("a", "testssl", "HSTS", "port-443").rsplit(":", 1)[1]
    hnone = stable_finding_id("a", "testssl", "HSTS", "port-None").rsplit(":", 1)[1]
    assert (h443, hnone) == ("33ad838", "c51b944")
    assert ("CASE WHEN f.source::text = 'testssl' AND right(f.finding_id, 8) NOT IN (':33ad838', ':c51b944') "
            "THEN NULL WHEN f.source::text = 'testssl' AND f.title ~* '^hsts not enabled") in guard, "the first rule"
    assert shared_key_for_port("k", 443) == "k" and shared_key_for_port("k", None) == "k"
    assert shared_key_for_port("k", 8443) == "k:port-8443"
