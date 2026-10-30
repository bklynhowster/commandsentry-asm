"""(KB 12 job 3v / D-074, 2026-10-29) Migration 20261029b: High and Critical mean it could be exploited.

Howie, 2026-10-29 19:30: "It has to be something that could actually be exploited." push-376 caps
at write time (evidence.harm_rating); this caps the open rows no scan reaches (Command 5, Prodex 0).
Pinned: a bounded guard whose WHERE is the batch's; the audited batch keeps the old severity; one
recompute; nothing deleted; the meta auto-applies; and, the point of it, the migration caps a
SUBSET of what the scanner's rule caps, never more (the upsert keeps the less severe value, so a
row wrongly capped here could never climb back). Proven on PostgreSQL 16 in the build note.
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261029b_high_means_exploitable.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import evidence  # noqa: E402
import migration_meta  # noqa: E402

WHERE = ("f.severity::text IN ('HIGH', 'CRITICAL') "
         "AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed') "
         "AND f.source::text <> 'manual_named' "
         "AND f.finding_id NOT LIKE '%:manual:%' "
         "AND f.finding_id NOT LIKE '%:light:exposed-path-%' "
         "AND f.finding_id NOT LIKE '%waf-absent-exposed%' "
         "AND f.finding_id NOT LIKE '%nuclei%' "
         "AND f.finding_id !~* ':(testssl|sslyze):(heartbleed|ticketbleed|robot)(:|$)'")


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_guard_batch_recompute():
    st = _stmts()
    assert len(st) == 3, st
    assert st[0].startswith("SELECT 1 / (CASE WHEN count(*) <= 20 THEN 1 ELSE 0 END) AS guard_d074_harm_cap")
    assert st[1].startswith("WITH target AS ( SELECT f.finding_id, f.severity::text AS old_severity")
    assert "UPDATE public.findings f SET severity = 'MODERATE'::severity_t, updated_at = now()" in st[1]
    assert "INSERT INTO public.admin_audit_log" in st[1] and st[1].endswith("FROM changed c")
    assert "'d074_harm_cap'" in st[1] and "'rule', 'D-074'" in st[1]
    assert "jsonb_build_object('severity', c.old_severity)" in st[1], "the old severity is what is logged"
    assert st[2] == "SELECT public.refresh_all_asset_posture()"


def test_the_batch_touches_exactly_what_the_guard_counts():
    g = _stmts()[0].split(" WHERE ", 1)[1]
    t = _stmts()[1].split(" WHERE ", 1)[1].split(" ), changed AS (")[0]
    assert g == WHERE and t == WHERE
    up = _stmts()[1].split("UPDATE public.findings f", 1)[1].split(" RETURNING ")[0]
    assert "WHERE f.finding_id = t.finding_id AND f.severity::text IN ('HIGH', 'CRITICAL')" in up


def _sql_caps(fid, source, sev="HIGH", status="detected"):
    """WHERE above, in Python (each line pinned by the test before)."""
    return (sev in ("HIGH", "CRITICAL") and status in ("detected", "confirmed", "open", "regressed")
            and source != "manual_named" and ":manual:" not in fid
            and ":light:exposed-path-" not in fid and "waf-absent-exposed" not in fid
            and "nuclei" not in fid
            and not re.search(r":(testssl|sslyze):(heartbleed|ticketbleed|robot)(:|$)", fid, re.I))


CORPUS = [
    # the open rows, 2026-10-29 19:45
    ("52.119.65.5:testssl:cert_extlifeSpan:33ad838", "testssl", True),
    ("52.119.65.5:testssl:cert_revocation:33ad838", "testssl", True),
    ("52.119.65.6:testssl:cert_extlifeSpan:33ad838", "testssl", True),
    ("52.119.65.6:testssl:cert_revocation:33ad838", "testssl", True),
    ("demo.testfire.net:testssl:LOGJAM-common_primes:33ad838", "testssl", True),
    ("ftp.sciimage.com:manual:F-01", "manual_named", False),
    # every other kind
    ("h:testssl:heartbleed:1", "testssl", False), ("h:testssl:ROBOT:1", "testssl", False),
    ("ip:1.2.3.4:sslyze:ticketbleed", "sslyze", False), ("h:testssl:robotics:1", "testssl", True),
    ("h:light:exposed-path-env", "commandsentry_light", False),
    ("h:light:tls-cert-expired", "commandsentry_light", True),
    ("h:light:method-put-enabled", "commandsentry_light", True),
    ("u:commandsentry_heavy:waf-absent-exposed:9", "commandsentry_heavy", False),
    ("u:commandsentry_heavy:waf-absent-differential:9", "commandsentry_heavy", True),
    ("h:medium:nuclei-tech-x", "commandsentry_medium", False),          # waits for its scan
    ("h:medium:ffuf-env", "commandsentry_medium", True),
    ("h:exposure:open-mysql-3306", "commandsentry_exposure", True),
    ("h:advisory_watch:advisory:x:1", "advisory_watch", True),
]


def test_the_open_rows_today_cap_five_and_keep_the_hand_test():
    capped = [fid for fid, src, _ in CORPUS[:6] if _sql_caps(fid, src)]
    assert len(capped) == 5 and "ftp.sciimage.com:manual:F-01" not in capped


def test_the_migration_caps_a_subset_of_what_the_scanner_caps():
    for fid, src, expect in CORPUS:
        for sev in ("HIGH", "CRITICAL"):
            sql = _sql_caps(fid, src, sev)
            py = evidence.harm_rating(sev, finding_id=fid, source=src)[0] == "MODERATE"
            assert sql == expect, fid
            assert (not sql) or py, f"{fid}: the migration would cap what the scanner keeps"
    for sev in ("MODERATE-HIGH", "MODERATE", "LOW"):
        assert not _sql_caps("52.119.65.5:testssl:cert_revocation:33ad838", "testssl", sev)
    for st in ("remediated", "false_positive", "accepted_risk", "detector_retired", "closed_reclassified"):
        assert not _sql_caps("52.119.65.5:testssl:cert_revocation:33ad838", "testssl", "HIGH", st)


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
