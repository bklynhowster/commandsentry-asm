"""(KB 12 job 4 step 5, plan v4.1 part B, 2026-11-09) Migration 20261109a: the other name's old
deep-scan rows and Prodex's false www DNS rows (20261104b's rules a and b, exactly as reviewed on
2026-11-04), and the three names only the unimacgraphics.com wildcard answers, retired with their
open rows closed.

Howie, 2026-11-08 07:44: "when I click on the www domain, I want to see the www domain". Pinned
here: seven statements, the four guards first; B1 and B2 byte for byte the reviewed 20261104b
statement (whitespace aside), only its migration, batch and ruling names changed; every guard
counts exactly what its transition changes; B3 names only the three ghosts and retires one only
while site_members still reads it as wildcard-only; the update retires only names this batch
audited, the close closes only their rows; the B1 tag is the one both findings upserts reopen on,
the ghost tag one that nothing reopens; closed_reclassified, never remediated; nothing deleted, no
schema change, no dollar quotes; the meta auto-applies. Proven on PostgreSQL 16 in the build note
(both repos: Command and Prodex shapes, the waiting pair, the guards tripped on purpose, the
limits, two applies, by hand, the reopen rules).
"""
import hashlib
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261109a_site_name_and_ghosts_retired.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

TAG_A = "job4-name-retired"
TAG_G = "job4-ghost-retired"
GHOSTS = ("'www.firewall.unimacgraphics.com', 'www.portal.unimacgraphics.com', "
          "'www.zoetislabs.unimacgraphics.com'")
# sha256 of 20261104b's reviewed statements (stamp 78eb00f5b98b4e56, approved 2026-11-04 10:32),
# whitespace-normalised: its choose-close-audit statement, and its guard's rule (the CTEs).
REVIEWED_TRANSITION = "aa0e9a7d1ffb890aaa5cd00ae855f2cdcf53a6d7f843bc5a3e860eb39d21e08c"
REVIEWED_GUARD_RULE = "4834acfcf08909f89eadbf20c1f1baa256785ebe654bf53c88168ecf3cacbb88"


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def test_seven_statements_guards_first():
    st = _stmts()
    assert len(st) == 7, [s[:60] for s in st]
    assert "AS guard_b1_b2_bounded" in st[0] and "AS guard_b1_b2_nothing_serious" in st[0]
    assert "AS guard_b3_bounded" in st[1] and "AS guard_b3_nothing_serious" in st[1]
    assert st[2].startswith("SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_tags_unused")
    assert "UPDATE public.findings f SET current_status = 'closed_reclassified'" in st[3]
    assert st[4].startswith("INSERT INTO public.admin_audit_log") and "'retire_wildcard_ghost'" in st[4]
    assert st[5].startswith("UPDATE public.assets a SET discovery_status = 'retired', last_transition_at = now()")
    assert "UPDATE public.findings f SET current_status = 'closed_reclassified'" in st[6] and TAG_G in st[6]


def test_b1_b2_are_20261104b_exactly_as_reviewed():
    back = (_stmts()[3]
            .replace("'migration', '20261109a'", "'migration', '20261104b'")
            .replace("'batch', '20261109a-site-name-retired'", "'batch', '20261104b-site-name-retired'")
            .replace("'ruling', 'Howie 2026-11-04 D6 and 2026-11-08 07:44; KB 12 job 4 step 5 plan v4.1 "
                     "B1/B2 (20261104b rules a and b as reviewed)'",
                     "'ruling', 'Howie 2026-11-04 D6; KB 12 job 4 plan v1.3 step 4'"))
    assert _sha(back) == REVIEWED_TRANSITION, "B1/B2 must be the reviewed statement, only three names changed"
    rule = _stmts()[0].split(" SELECT 1 / (CASE WHEN count(*) <= 50")[0]
    assert _sha(rule) == REVIEWED_GUARD_RULE, "guard 1 counts with the reviewed rule"


def test_guard_1_counts_what_b1_b2_close():
    g = _stmts()[0].split(" SELECT 1 / (CASE WHEN count(*) <= 50")[0]
    t = _stmts()[3].split(" ), closed AS (")[0]
    for part in ("f.source::text IN ('commandsentry_heavy', 'commandsentry_medium', 'httpx')",
                 "AND f.last_observed_at < fc.face_since",
                 "s.asset_id = fc.face_asset_id AND s.intensity::text = 'heavy' AND s.status::text = 'complete' "
                 "AND s.completed_at > fc.face_since",
                 "s.asset_id = fc.other AND s.intensity::text = 'light' AND s.status::text = 'complete' "
                 "AND s.completed_at > fc.face_since",
                 "f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')",
                 "AND f.last_observed_at < fx.fixed_at"):
        assert g.count(part) == 1 and t.count(part) == 1, part
    for w in re.findall(r" WHERE .*?(?= UNION | \)$| \), )", t):
        assert w in g, w


def _ghost_rule(stmt):
    end = "<@ (sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')"
    i = stmt.index(f"a.asset_id IN ({GHOSTS})")
    return stmt[i:stmt.index(end, i) + len(end)]


def test_b3_names_the_three_ghosts_and_only_while_wildcard_only():
    st = _stmts()
    for s in (st[1], st[4]):
        assert s.count(f"a.asset_id IN ({GHOSTS})") == 1
        assert "AND a.discovery_status IS DISTINCT FROM 'retired'" in s
        assert "(sm.evidence -> 'last' -> 'readings' -> 'zone' ->> 'wildcard') = 'true'" in s
        assert "jsonb_array_length(coalesce(sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs', '[]'::jsonb)) > 0" in s
        assert ("(sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') @> "
                "(sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')") in s
        assert ("(sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') <@ "
                "(sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')") in s
    assert _ghost_rule(st[1]) == _ghost_rule(st[4]), "guard 2 counts the ghosts B3 retires"
    named = {n for s in st for n in re.findall(r"'([a-z0-9.-]+\.unimacgraphics\.com)'", s)}
    assert named == {g.strip("'") for g in GHOSTS.split(", ")}, f"only the three ghosts are named, never the real site: {named}"


def test_b3_retires_and_closes_only_what_this_batch_audited():
    st = _stmts()
    batch = ("l.action = 'retire_wildcard_ghost' AND l.details ->> 'batch' = '20261109a-ghost-retired' "
             "AND l.details ->> 'asset_id' = ")
    assert batch + "a.asset_id" in st[5] and "WHERE a.discovery_status IS DISTINCT FROM 'retired'" in st[5]
    assert batch + "f.asset_id" in st[6]
    assert "JOIN public.assets a ON a.asset_id = f.asset_id AND a.discovery_status = 'retired'" in st[6]
    assert "'batch', '20261109a-ghost-retired'" in st[4] and "'batch', '20261109a-ghost-retired'" in st[6]
    assert "jsonb_build_object('discovery_status', a.discovery_status)" in st[4], "the old status is what is logged"


def test_guard_2_counts_what_b3_closes():
    g, c = _stmts()[1], _stmts()[6]
    open_ = "f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')"
    assert open_ in g and open_ in c
    assert "CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END" in g


def test_nothing_serious_and_the_limits():
    st = _stmts()
    for s in st[:2]:
        assert "IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')) = 0" in s
        assert "CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END" in s


def test_the_tags():
    st = _stmts()
    assert f"array_append(coalesce(f.tags, '{{}}'::text[]), '{TAG_A}')" in st[3]
    assert f"array_append(coalesce(f.tags, '{{}}'::text[]), '{TAG_G}')" in st[6]
    assert f"'{TAG_A}' = ANY (coalesce(f.tags, '{{}}'::text[]))" in st[2]
    assert f"'{TAG_G}' = ANY (coalesce(f.tags, '{{}}'::text[]))" in st[2]
    # the B1/B2 tag is exactly what both findings upserts reopen on (push-404); the ghost tag is not
    for runner_file in ("run_light.py", "run_medium.py"):
        src = (DB.parent / "scanner" / runner_file).read_text()
        assert f"'{TAG_A}' = ANY (coalesce(findings.tags, '{{}}'::text[]))" in src, runner_file
        assert TAG_G not in src, f"{runner_file} must never reopen a retired ghost's rows"


def test_closed_reclassified_never_remediated_nothing_deleted_no_schema():
    body = runner._strip_comments(SQL)
    assert "remediated" not in body.replace("closed_reclassified", "")
    for word in ("DELETE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE"):
        assert not re.search(rf"\b{word}\b", body, re.I), word
    assert "$$" not in SQL and not re.search(r"\$[A-Za-z_]*\$", SQL), "splitter-safe: no dollar quotes"
    assert re.search(r"^BEGIN;$", SQL, re.M) and re.search(r"^COMMIT;$", SQL, re.M), "a hand run stops at a guard"


def test_one_audit_row_per_change():
    st = _stmts()
    assert st[3].endswith("FROM target t JOIN closed c ON c.finding_id = t.finding_id")
    assert st[6].endswith("FROM target t JOIN closed c ON c.finding_id = t.finding_id")
    assert "'site_name_retired_close_reclassified'" in st[3] and "'ghost_retired_close_reclassified'" in st[6]


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
