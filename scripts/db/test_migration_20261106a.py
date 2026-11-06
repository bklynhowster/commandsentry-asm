"""(KB 12 job 4v, 2026-11-06) Migration 20261106a: two checks are LOW.

Howie, 2026-11-04 15:33 (compressed pages, testssl's BREACH): "Change it to a low. I agree with
you."; 2026-11-06 08:03 (the script rule): "yes". The push writes LOW from now on; this lowers the
open MODERATE rows once (Command 12, Prodex 42 on 2026-11-06). Pinned: a bounded guard whose WHERE
is the batch's; the audited batch keeps the old severity; one recompute; nothing deleted; the meta
auto-applies; and, the point of it, the migration lowers only rows the scanner now writes LOW,
never more (the upsert keeps the less severe value, so a row wrongly lowered here could never
climb back). Its compressed-pages pattern is held equal to the scanner's (code review 2026-11-06,
must-fix 1: compression alone, never compression and something more). Proven on PostgreSQL 16 in
the build note.
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261106a_two_checks_low.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))
sys.path.insert(0, str(DB.parent / "normalize"))

import apply_pending_migrations as runner  # noqa: E402
import csp_policy  # noqa: E402
import migration_meta  # noqa: E402
from cs_parsers.testssl import breach_is_compression_only  # noqa: E402

DESC_RE_SQL = ("^potentially VULNERABLE, (gzip|deflate|compress|br|zstd)( (gzip|deflate|compress|br|zstd))* "
               "HTTP compression detected +- only supplied (''[^'']*''|\"[^\"]*\") tested(  \\(CWE-[0-9]+\\))?$")
DESC_RE = re.compile(DESC_RE_SQL.replace("''", "'"))   # the same pattern as PostgreSQL reads it
WHERE = ("f.severity::text = 'MODERATE' "
         "AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed') "
         "AND ((f.source::text = 'commandsentry_light' AND f.finding_id LIKE '%:light:csp-scripts-not-limited') "
         "OR (f.source::text = 'testssl' AND f.finding_id LIKE '%:testssl:BREACH:%' "
         f"AND f.description ~ '{DESC_RE_SQL}'))")


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_guard_batch_recompute():
    st = _stmts()
    assert len(st) == 3, st
    assert st[0].startswith("SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_job4v_rated_low")
    assert st[1].startswith("WITH target AS ( SELECT f.finding_id, f.severity::text AS old_severity")
    assert "UPDATE public.findings f SET severity = 'LOW'::severity_t, updated_at = now()" in st[1]
    assert "INSERT INTO public.admin_audit_log" in st[1] and st[1].endswith("FROM changed c")
    assert "'job4v_rated_low'" in st[1] and "'rule', 'job 4v'" in st[1]
    assert "jsonb_build_object('severity', c.old_severity)" in st[1], "the old severity is what is logged"
    assert st[2] == "SELECT public.refresh_all_asset_posture()"


def test_the_batch_touches_exactly_what_the_guard_counts():
    g = _stmts()[0].split(" WHERE ", 1)[1].rstrip(";")
    t = _stmts()[1].split(" WHERE ", 1)[1].split(" ), changed AS (")[0]
    assert g == " ".join(WHERE.split()) and t == " ".join(WHERE.split())
    assert SQL.count(f"AND f.description ~ '{DESC_RE_SQL}'") == 2, "the exact pattern, spaces and all, in guard and batch"
    up = _stmts()[1].split("UPDATE public.findings f", 1)[1].split(" RETURNING ")[0]
    assert "WHERE f.finding_id = t.finding_id AND f.severity::text = 'MODERATE'" in up


def _sql_lowers(fid, source, desc="", sev="MODERATE", status="detected"):
    """WHERE above, in Python (each clause pinned by the test before). LIKE's % is any text."""
    return (sev == "MODERATE" and status in ("detected", "confirmed", "open", "regressed")
            and ((source == "commandsentry_light" and fid.endswith(":light:csp-scripts-not-limited"))
                 or (source == "testssl" and ":testssl:BREACH:" in fid
                     and DESC_RE.search(desc or "") is not None)))


GZIP = "potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested  (CWE-310)"
CORPUS = [
    # (finding_id, source, description, lowered?) — the open rows' shapes, 2026-11-06
    ("bitec.prodexlabs.com:light:csp-scripts-not-limited", "commandsentry_light", "", True),
    ("24.157.51.70:light:csp-scripts-not-limited", "commandsentry_light", "", True),
    ("bitec.prodexlabs.com:testssl:BREACH:33ad838", "testssl", GZIP, True),
    ("cooked.prodexlabs.com:testssl:BREACH:33ad838", "testssl",
     GZIP.replace("gzip", "gzip deflate"), True),
    ("commandcompanies.com:testssl:BREACH:33ad838", "testssl", GZIP.replace("gzip", "br gzip"), True),
    # left as they are
    ("h:light:csp-allows-eval", "commandsentry_light", "", False),
    ("h:light:missing-header-content-security-policy", "commandsentry_light", "", False),
    ("h:light:csp-scripts-not-limited-x", "commandsentry_light", "", False),
    ("h:testssl:BREACH:33ad838", "testssl", "VULNERABLE, secrets reflected  (CWE-310)", False),
    ("h:testssl:BREACH:33ad838", "testssl", "VULNERABLE, secrets reflected; HTTP compression detected  (CWE-310)", False),
    ("h:testssl:BREACH:33ad838", "testssl", GZIP.replace("tested", "tested; secrets reflected"), False),
    ("h:testssl:BREACH:33ad838", "testssl", GZIP.replace("detected", "detected; token reflected"), False),
    ("h:testssl:BREACH:33ad838", "testssl", GZIP + " extra", False),
    ("h:testssl:BREACH:33ad838", "testssl", "potentially NOT ok, uses gzip HTTP compression.  (CWE-310)", False),
    ("h:testssl:LUCKY13:33ad838", "testssl", "potentially vulnerable, CBC  (CWE-310)", False),
    ("h:testssl:BREACH:33ad838", "commandsentry_heavy", GZIP, False),
    ("ftp.sciimage.com:manual:F-04", "manual_named", "Content-Security-Policy weak", False),
    ("unimacgraphics.com:manual:F-07", "manual_named", "BREACH, compression", False),
    ("commandcompanies.com:medium:nikto-999966-the-content-encoding-header-is-set-to-deflate-which",
     "commandsentry_medium", "Content-Encoding deflate, BREACH, compression", False),
]


def test_the_open_rows_today_and_the_rows_left_alone():
    for fid, src, desc, expect in CORPUS:
        assert _sql_lowers(fid, src, desc) == expect, fid


def test_the_migration_lowers_only_what_the_scanner_now_writes_low():
    weak = csp_policy.finding_fields("h", "script-src 'self' 'unsafe-inline'")
    assert (weak["check_name"], weak["severity"]) == ("csp-scripts-not-limited", "LOW")
    for fid, src, desc, _ in CORPUS:
        if not _sql_lowers(fid, src, desc):
            continue
        if src == "commandsentry_light":
            assert fid.split(":light:", 1)[1] == weak["check_name"], fid
        else:
            grouped_id = fid.split(":testssl:", 1)[1].split(":", 1)[0]
            finding_text = re.sub(r"  \(CWE-[0-9]+\)$", "", desc)   # the parser appends the CWE
            assert breach_is_compression_only(grouped_id, finding_text), fid
    for sev in ("CRITICAL", "HIGH", "MODERATE-HIGH", "LOW", "INFO"):
        assert not _sql_lowers(CORPUS[0][0], CORPUS[0][1], "", sev)
    for st in ("remediated", "validated_remediated", "false_positive", "accepted_risk",
               "wont_fix", "detector_retired", "closed_reclassified"):
        assert not _sql_lowers(CORPUS[2][0], CORPUS[2][1], GZIP, "MODERATE", st)


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


# testssl texts: the scanner's rule and the migration's pattern must agree on every one, with
# and without the CWE the parser appends to the description.
TEXTS = (
    "potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, gzip deflate HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, br gzip HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, compress zstd HTTP compression detected - only supplied \"/x\" tested",
    "VULNERABLE, secrets reflected; HTTP compression detected",
    "potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested; secrets reflected",
    "potentially VULNERABLE, gzip HTTP compression detected; token reflected  - only supplied '/' tested",
    "VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, gzip and a secret HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, GZIP HTTP compression detected  - only supplied '/' tested",
    "potentially NOT ok, uses gzip HTTP compression.",
    "no gzip/deflate/compress/br HTTP compression (OK)  - only supplied '/' tested",
    "Test failed: HTTP compression check timed out",
    "potentially VULNERABLE, gzip HTTP compression detected",
    "",
)


def test_the_migration_and_the_scanner_agree_on_every_text():
    for t in TEXTS:
        rule = breach_is_compression_only("BREACH", t)
        for desc in (t, f"{t}  (CWE-310)" if t else "CWE-310"):
            assert (DESC_RE.search(desc) is not None) == rule, (t, desc)
    assert sum(breach_is_compression_only("BREACH", t) for t in TEXTS) == 4
