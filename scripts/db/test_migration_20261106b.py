"""(KB 12 job 5c, 2026-11-06) Migration 20261106b: a missing Content-Security-Policy and a static CSP
nonce are LOW.

Howie, 2026-11-06 11:40: "Yes, recategorize them as low for the emails, please."; by 11:44, on the
static-nonce checks: "Yes, include them". The push writes LOW from now on; this lowers the open MODERATE
rows once (Command 45, Prodex 6 on 2026-11-06). Pinned: a bounded guard whose WHERE is the batch's;
the audited batch keeps the old severity; one recompute; nothing deleted; the meta auto-applies; and
the migration lowers only rows the scanner now writes LOW, never more. Proven on PostgreSQL 16 in the
build note.
"""
import inspect
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261106b_csp_header_findings_low.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402
import run_light  # noqa: E402

WHERE = ("f.severity::text = 'MODERATE' "
         "AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed') "
         "AND f.source::text = 'commandsentry_light' "
         "AND (f.finding_id LIKE '%:light:missing-header-content-security-policy' "
         "OR f.finding_id LIKE '%:light:csp-static-nonce' "
         "OR f.finding_id LIKE '%:light:csp-static-nonce-_%')")


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_guard_batch_recompute():
    st = _stmts()
    assert len(st) == 3, st
    assert st[0].startswith("SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_job5c_rated_low")
    assert st[1].startswith("WITH target AS ( SELECT f.finding_id, f.severity::text AS old_severity")
    assert "UPDATE public.findings f SET severity = 'LOW'::severity_t, updated_at = now()" in st[1]
    assert "INSERT INTO public.admin_audit_log" in st[1] and st[1].endswith("FROM changed c")
    assert "'job5c_rated_low'" in st[1] and "'rule', 'job 5c'" in st[1]
    assert "jsonb_build_object('severity', c.old_severity)" in st[1], "the old severity is what is logged"
    assert st[2] == "SELECT public.refresh_all_asset_posture()"


def test_the_batch_touches_exactly_what_the_guard_counts():
    g = _stmts()[0].split(" WHERE ", 1)[1].rstrip(";")
    t = _stmts()[1].split(" WHERE ", 1)[1].split(" ), changed AS (")[0]
    assert g == WHERE and t == WHERE
    up = _stmts()[1].split("UPDATE public.findings f", 1)[1].split(" RETURNING ")[0]
    assert "WHERE f.finding_id = t.finding_id AND f.severity::text = 'MODERATE'" in up


def _like(fid, pattern):
    """SQL LIKE: % is any run of characters (or none), _ is exactly one character."""
    import re
    rx = "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, fid, re.S) is not None


def _sql_lowers(fid, source, sev="MODERATE", status="detected"):
    return (sev == "MODERATE" and status in ("detected", "confirmed", "open", "regressed")
            and source == "commandsentry_light"
            and (_like(fid, "%:light:missing-header-content-security-policy")
                 or _like(fid, "%:light:csp-static-nonce") or _like(fid, "%:light:csp-static-nonce-_%")))


CORPUS = [
    # (finding_id, source, lowered?) — the open rows' shapes, 2026-11-06
    ("portal.unimacgraphics.com:light:missing-header-content-security-policy", "commandsentry_light", True),
    ("www.prodexlabs.com:light:missing-header-content-security-policy", "commandsentry_light", True),
    ("geisinger.commandcommcentral.com:light:csp-static-nonce", "commandsentry_light", True),
    ("geisinger.commandcommcentral.com:light:csp-static-nonce-script_src", "commandsentry_light", True),
    ("commandcommcentral.com:light:csp-static-nonce-style_src", "commandsentry_light", True),
    # left as they are
    ("h:light:missing-header-strict-transport-security", "commandsentry_light", False),
    ("h:light:missing-header-x-frame-options", "commandsentry_light", False),
    ("h:light:missing-header-content-security-policy-report-only", "commandsentry_light", False),
    ("h:light:csp-scripts-not-limited", "commandsentry_light", False),
    ("h:light:csp-static-noncex", "commandsentry_light", False),
    ("h:light:csp-static-nonce-", "commandsentry_light", False),   # no directive (code review must-fix 1)
    ("h:testssl:security_headers:33ad838", "testssl", False),
    ("h:medium:nikto-013587-suggested-security-header-missing-content-security-p", "commandsentry_medium", False),
    ("h:nuclei:http-missing-security-headers:content-security-policy:791869a", "nuclei", False),
    ("commandcommcentral.com:manual:M-02", "manual_named", False),
    ("test3.commandcommcentral.com:manual:A-02", "manual_named", False),
    ("h:light:missing-header-content-security-policy", "commandsentry_heavy", False),
]


def test_the_open_rows_today_and_the_rows_left_alone():
    for fid, src, expect in CORPUS:
        assert _sql_lowers(fid, src) == expect, fid


def test_the_migration_lowers_only_what_the_scanner_now_writes_low():
    table = {h: s for h, s, _ in run_light.SECURITY_HEADERS}
    assert table["Content-Security-Policy"] == "LOW"
    for fn in (run_light.check_csp_nonce, run_light.probe_static_csp_nonces_per_directive):
        src = inspect.getsource(fn)
        assert 'severity="LOW"' in src and 'severity="MODERATE"' not in src, fn.__name__
    for fid, src, _ in CORPUS:
        if _sql_lowers(fid, src):
            check = fid.split(":light:", 1)[1]
            assert check == "missing-header-content-security-policy" or check.startswith("csp-static-nonce"), fid
    for sev in ("CRITICAL", "HIGH", "MODERATE-HIGH", "LOW", "INFO"):
        assert not _sql_lowers(CORPUS[0][0], CORPUS[0][1], sev)
    for st in ("remediated", "validated_remediated", "false_positive", "accepted_risk",
               "wont_fix", "detector_retired", "closed_reclassified"):
        assert not _sql_lowers(CORPUS[2][0], CORPUS[2][1], "MODERATE", st)


def test_nothing_deleted_no_schema_no_dollar_quoting():
    low = " ".join(_stmts()).lower()
    for bad in ("delete from", "drop ", "truncate", "alter ", "create ", "grant ", "revoke "):
        assert bad not in low, bad
    assert "$$" not in SQL.split("END-META", 1)[1]


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
