"""(KB 12, RULED 2026-11-08 07:39 "Recheck.") Migration 20261110a: the 118 hand-entered Command
findings re-checked against Sentry's own evidence; 48 of them close, each only while its own
condition still holds.

Pinned here: three statements, the guards first; the guard counts with exactly the rule the change
applies (the same text); the 48 rows are named one by one and by kind (21 superseded, 4 remediated,
2 reclassified, 21 ghost) and the 12 held back by "Once, higher wins" are not among them; only an
open manual_named row can be chosen; a superseding row is Sentry's own (never manual_named), open as a
scanner writes it (detected, confirmed, regressed; never the import status 'open'), seen after the
hand row, at the same or a higher grade; a fix is read from the asset's newest record of the named
tool, after the hand row, and dated by that scan; only the four fixed rows become remediated, the rest
closed_reclassified; the only HIGH that may close is ftp.sciimage.com F-01; one audit row per closed
row; the tag is new; nothing deleted, no asset touched, no schema change, no dollar quotes; the meta
auto-applies. Proven on PostgreSQL 16 in the build note (every kind, each condition broken on purpose,
the guards tripped, two applies, by hand, the repo runner, the Prodex shape).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261110a_hand_findings_rechecked.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

TAG = "recheck-20261110a"
BATCH = "20261110a-hand-recheck"

SUPERSEDED = {
    "api.commandcommcentral.com:manual:A-01", "api.commandcommcentral.com:manual:A-04",
    "commandcommcentral.com:manual:L-01", "commandcommcentral.com:manual:L-02",
    "commandcommcentral.com:manual:L-05", "commandcommcentral.com:manual:I-04",
    "commandmarketinginnovations.com:manual:F-02", "insite.sciimage.com:manual:F-11",
    "test.commandcommcentral.com:manual:L-02", "test.commandcommcentral.com:manual:I-02",
    "testapi.commandcommcentral.com:manual:A-03", "unimacgraphics.com:manual:F-01",
    "unimacgraphics.com:manual:F-07", "vpn.sciimage.com:manual:A-04", "vpn.sciimage.com:manual:A-06",
    "vpn.sciimage.com:manual:A-07", "vpn.sciimage.com:manual:S-04", "vpn2.sciimage.com:manual:A-04",
    "vpn2.sciimage.com:manual:A-06", "vpn2.sciimage.com:manual:A-07", "vpn2.sciimage.com:manual:S-04",
}
REMEDIATED = {
    "ftp.sciimage.com:manual:F-01": "testssl_chain_passed",
    "ftp.sciimage.com:manual:F-04": "csp_no_unsafe",
    "insite.sciimage.com:manual:F-05": "plain_http_to_https",
    "api.commandcommcentral.com:manual:A-05": "naabu_no_8080",
}
RECLASSIFIED = {
    "test.commandcommcentral.com:manual:L-05": "apex_owns_the_gap",
    "vpn2.sciimage.com:manual:S-05": "tool_note",
}
GHOST = {f"test3.commandcommcentral.com:manual:{i}": "name_does_not_exist"
         for i in ("A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-07", "A-08", "A-09", "A-10",
                   "W-01", "W-02", "W-03", "W-04", "W-05")}
GHOST.update({f"ip-range:cablenet-nodns:manual:{i}": "placeholder_split"
              for i in ("I-01", "I-07", "I-08", "I-09", "I-10", "I-11")})
# Moderate by hand where Sentry's own row for the same problem is Low or Info: Howie 2026-11-09
# "Once, higher wins" keeps the higher, so these stay open (and so do the other 58).
HELD_BACK = {
    "commandcommcentral.com:manual:M-02", "test.commandcommcentral.com:manual:M-02",
    "ftp.sciimage.com:manual:F-03", "ftp.sciimage.com:manual:F-05", "ftp.sciimage.com:manual:F-09",
    "insite.sciimage.com:manual:F-04", "insite.sciimage.com:manual:F-09",
    "testapi.commandcommcentral.com:manual:A-02", "unimacgraphics.com:manual:F-03",
    "vpn.sciimage.com:manual:A-02", "vpn.sciimage.com:manual:S-01", "vpn2.sciimage.com:manual:A-02",
}
# Read again and found still true with no Sentry row of its own, or not answerable from what Sentry
# holds: the plan said otherwise, the pinning did not bear it out. They stay open.
PLAN_CORRECTIONS = {
    "ftp.sciimage.com:manual:F-06", "test.commandcommcentral.com:manual:I-03",
    "commandcommcentral.com:manual:I-02", "test.commandcommcentral.com:manual:I-01",
    "enrollment2.edelivery-bessemer.com:manual:A-01", "api.commandcommcentral.com:manual:A-02",
    "api.commandcommcentral.com:manual:W-05", "api.commandcommcentral.com:manual:A-06",
    "testapi.commandcommcentral.com:manual:A-01", "testapi.commandcommcentral.com:manual:W-03",
    "insite.sciimage.com:manual:F-08", "unimacgraphics.com:manual:F-04",
    "commandmarketinginnovations.com:manual:F-06", "vpn.sciimage.com:manual:A-01",
    "vpn2.sciimage.com:manual:A-01",
}


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _rows():
    """The VALUES list of the change statement: (finding_id, kind, evidence, source, key, title)."""
    st = _stmts()[2]
    vals = st[st.index("AS ( VALUES (") + len("AS ( VALUES "):st.index(" ), hand AS (")]
    out = []
    for m in re.finditer(r"\(('(?:[^']|'')*'|NULL)(?:, ('(?:[^']|'')*'|NULL))*\)", vals):
        parts = re.findall(r"'(?:[^']|'')*'|NULL", m.group(0))
        out.append(tuple(None if p == "NULL" else p[1:-1] for p in parts))
    return out


def test_three_statements_guards_first():
    st = _stmts()
    assert len(st) == 3, [s[:60] for s in st]
    assert "AS guard_bounded" in st[0] and "AS guard_nothing_serious" in st[0] and st[0].endswith("FROM chosen")
    assert st[1].startswith("SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_tag_unused")
    assert "UPDATE public.findings f SET current_status" in st[2] and "INSERT INTO public.admin_audit_log" in st[2]


def test_the_guard_counts_exactly_what_the_change_applies():
    st = _stmts()
    g = st[0][st[0].index("WITH list (finding_id"):st[0].index(" ) SELECT 1 / (CASE WHEN count(*) <= 60")]
    c = st[2][st[2].index("WITH list (finding_id"):st[2].index(" ), closed AS (")]
    assert g == c, "the guard must count with the change's own rule, text for text"


def test_the_48_rows_by_kind():
    rows = _rows()
    assert len(rows) == 48 and len({r[0] for r in rows}) == 48
    got = {r[0]: (r[1], r[2]) for r in rows}
    want = {**{i: ("superseded", None) for i in SUPERSEDED},
            **{i: ("remediated", e) for i, e in REMEDIATED.items()},
            **{i: ("reclassified", e) for i, e in RECLASSIFIED.items()},
            **{i: ("ghost", e) for i, e in GHOST.items()}}
    assert got == want


def test_held_back_and_corrected_rows_are_not_touched():
    ids = {r[0] for r in _rows()}
    assert not (ids & HELD_BACK), ids & HELD_BACK
    assert not (ids & PLAN_CORRECTIONS), ids & PLAN_CORRECTIONS
    assert len(HELD_BACK) == 12


def test_every_id_is_a_hand_entered_id_on_its_own_asset():
    for fid, *_ in _rows():
        assert re.fullmatch(r"[a-z0-9.:-]+:manual:[A-Z]-\d\d", fid), fid


def test_superseding_rows_are_sentrys_own_at_the_same_or_a_higher_grade():
    rows = [r for r in _rows() if r[1] == "superseded"]
    for fid, _k, ev, src, key, title in rows:
        assert ev is None and src in ("commandsentry_light", "testssl"), (fid, src)
        assert (key is None) != (title is None), fid
        if key and key.endswith("%"):
            assert key in ("missing-header-%", "dns-missing-%"), key
        if title:
            assert title.startswith("^"), title
    c = _stmts()[2]
    assert "AND t.source::text = h.twin_source" in c
    assert "AND t.current_status::text IN ('detected', 'confirmed', 'regressed')" in c, "never the import status 'open'"
    assert "AND t.last_observed_at > h.last_observed_at" in c
    rank_t = ("(CASE t.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3 "
              "WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END) <= h.sev_rank")
    assert rank_t in c, "Once, higher wins: the superseding row is at least as severe"
    assert ("CASE f.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3 "
            "WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END AS sev_rank") in c
    assert ("left(t.normalized_key, length(h.twin_key) - 1) = left(h.twin_key, length(h.twin_key) - 1)") in c, "prefix, not LIKE"
    assert " LIKE h.twin_key" not in c


def test_only_open_hand_entered_rows_can_be_chosen():
    c = _stmts()[2]
    assert ("FROM list l JOIN public.findings f ON f.finding_id = l.finding_id "
            "WHERE f.source::text = 'manual_named' AND f.current_status::text = 'open' ), twin AS (") in c
    assert "FROM chosen c WHERE f.finding_id = c.finding_id RETURNING f.finding_id" in c


def test_a_fix_is_read_from_the_newest_record_after_the_hand_row():
    c = _stmts()[2]
    assert "ORDER BY s.started_at DESC NULLS LAST LIMIT 1) x" in c
    assert "(h.kind = 'remediated' AND rd.at > h.last_observed_at AND (" in c
    for ev, tool in (("testssl_chain_passed", "testssl.sh"), ("csp_no_unsafe", "headers_check"),
                     ("plain_http_to_https", "plain_http"), ("naabu_no_8080", "naabu"),
                     ("apex_owns_the_gap", "dns_posture")):
        assert f"WHEN '{ev}' THEN '{tool}'" in c, ev
    assert "e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443' AND coalesce(e ->> 'finding', '') NOT LIKE 'passed%'" in c
    # the newest record that READS the fact (review 2026-11-10, must-fix 1): no shape or size filter
    # that could skip a newer contrary reading; a scan that never reached the check is no reading
    assert "jsonb_array_length" not in c and "> 20" not in c
    for reads in ("WHEN 'testssl_chain_passed' THEN EXISTS ( SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.content_jsonb) = 'array' "
                  "THEN r.content_jsonb ELSE '[]'::jsonb END) e WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443')",
                  "WHEN 'csp_no_unsafe' THEN jsonb_typeof(r.content_jsonb -> 'header') = 'object'",
                  "WHEN 'plain_http_to_https' THEN (r.content_jsonb -> 'outcome') IS NOT NULL",
                  "WHEN 'naabu_no_8080' THEN coalesce(r.content_jsonb ->> 'raw', '') ~ 'open ports: \\['",
                  "WHEN 'apex_owns_the_gap' THEN (r.content_jsonb -> 'dmarc') IS NOT NULL"):
        assert reads in c, reads
    assert "!~* 'unsafe-inline|unsafe-eval'" in c
    assert "rd.c ->> 'outcome' = 'sent_to_https'" in c
    assert "!~ '(^|[^0-9])8080([^0-9]|$)'" in c


def test_statuses_and_dates():
    c = _stmts()[2]
    assert ("SET current_status = (CASE WHEN c.kind = 'remediated' THEN 'remediated' ELSE 'closed_reclassified' END)"
            "::public.finding_status_t") in c
    assert "remediated_at = CASE WHEN c.kind = 'remediated' THEN c.reading_at ELSE f.remediated_at END" in c
    body = runner._strip_comments(SQL)
    for s in ("false_positive", "wont_fix", "accepted_risk", "validated_remediated", "detector_retired"):
        assert s not in body, s


def test_nothing_serious_and_the_limit():
    g = _stmts()[0]
    assert "CASE WHEN count(*) <= 60 THEN 1 ELSE 0 END" in g
    assert "count(*) FILTER (WHERE severity IN ('CRITICAL', 'MODERATE-HIGH')) = 0" in g
    assert "count(*) FILTER (WHERE severity = 'HIGH' AND finding_id <> 'ftp.sciimage.com:manual:F-01') = 0" in g


def test_the_tag_and_one_audit_row_per_closed_row():
    st = _stmts()
    assert f"tags = array_append(coalesce(f.tags, '{{}}'::text[]), '{TAG}')" in st[2]
    assert f"WHERE '{TAG}' = ANY (coalesce(f.tags, '{{}}'::text[]))" in st[1]
    assert "l.action = 'hand_recheck_close' AND l.details ->> 'finding_id' = f.finding_id" in st[1]
    assert st[2].endswith("FROM chosen c JOIN closed x ON x.finding_id = c.finding_id")
    assert "'hand_recheck_close'" in st[2] and f"'batch', '{BATCH}'" in st[2] and "'migration', '20261110a'" in st[2]


def test_a_second_copy_needs_both_of_the_domains_rows_open():
    c = _stmts()[2]
    assert ("AND (SELECT count(DISTINCT p.normalized_key) FROM public.assets a JOIN public.findings p ON p.asset_id = a.apex_domain "
            "WHERE a.asset_id = h.asset_id AND a.apex_domain IS DISTINCT FROM a.asset_id AND p.source::text = 'commandsentry_light' "
            "AND p.normalized_key IN ('dns-missing-dmarc', 'dns-missing-spf') "
            "AND p.current_status::text IN ('detected', 'confirmed', 'regressed')) = 2") in c


def test_ghosts_only_while_still_ghosts():
    c = _stmts()[2]
    assert "a.asset_id = h.asset_id AND a.discovery_status = 'ct_ghost'" in c
    assert "a.asset_id = h.asset_id AND a.discovery_status = 'unverified'" in c
    assert "WHERE a.asset_id IN ('24.157.51.84', '24.157.51.86', '24.157.51.88') AND a.discovery_status = 'confirmed_live'" in c
    assert "AND s.started_at > '2026-10-01'::timestamptz)) = 3)))" in c, "all three addresses live and scanned, not one"
    assert c.count("NOT EXISTS (SELECT 1 FROM public.scan_run s WHERE s.asset_id = h.asset_id AND s.status::text = 'complete')") == 2


def test_nothing_deleted_no_asset_touched_no_schema():
    body = runner._strip_comments(SQL)
    for word in ("DELETE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE"):
        assert not re.search(rf"\b{word}\b", body, re.I), word
    assert "UPDATE public.assets" not in body and "INSERT INTO public.findings" not in body
    assert body.count("UPDATE public.findings") == 1
    assert "$$" not in SQL and not re.search(r"\$[A-Za-z_]*\$", SQL), "splitter-safe: no dollar quotes"
    assert re.search(r"^BEGIN;$", SQL, re.M) and re.search(r"^COMMIT;$", SQL, re.M), "a hand run stops at a guard"


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
