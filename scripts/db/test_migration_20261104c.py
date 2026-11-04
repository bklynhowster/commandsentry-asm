"""(KB 12 job 4u, plan v2 push 1, 2026-11-04) Migration 20261104c: room for a plain explanation of each finding.

Howie, 2026-11-04 12:33: "we need to have an AI explanatory area. This is hard for a non-expert to
understand." Ruled "Saved plain-words"; 15:35 one per finding; 15:37 no review step ("nobody ever
uses the approval, or basically the admin page"). Pinned here: exactly twelve statements in this
order; seven new findings columns, all nullable with no default (no row is rewritten), named
plain_* and nothing else; the three parts are all set or all NULL; a switched-off row carries no
words; D-029's columns and every other table are untouched; nothing dropped but this file's own
constraints (dropped only to re-add them); no grants; no dollar quotes (the runner can't split
them); the meta auto-applies. Proven on PostgreSQL 16 in the build note (both repos' migration
histories, then this file twice).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261104c_plain_words.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

COLUMNS = [
    ("plain_what", "text"),
    ("plain_worry", "text"),
    ("plain_todo", "text"),
    ("plain_input_hash", "text"),
    ("plain_model", "text"),
    ("plain_written_at", "timestamptz"),
    ("plain_rejected_at", "timestamptz"),
]
ALL_OR_NONE = ("CHECK ((plain_what IS NULL) = (plain_worry IS NULL) "
               "AND (plain_what IS NULL) = (plain_todo IS NULL))")
OFF_MEANS_EMPTY = "CHECK (plain_rejected_at IS NULL OR plain_what IS NULL)"


def _stmts(sql: str = SQL):
    return [" ".join(s.split()) for s in runner._split(sql) if s.strip()]


def test_the_statements_in_order():
    st = _stmts()
    want = [
        "ALTER TABLE public.findings ADD COLUMN IF NOT EXISTS plain_what text,",
        "ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS findings_plain_words_all_or_none",
        "ALTER TABLE public.findings ADD CONSTRAINT findings_plain_words_all_or_none " + ALL_OR_NONE,
        "ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS findings_plain_words_off_means_empty",
        "ALTER TABLE public.findings ADD CONSTRAINT findings_plain_words_off_means_empty " + OFF_MEANS_EMPTY,
    ] + [f"COMMENT ON COLUMN public.findings.{c} IS " for c, _ in COLUMNS]
    assert len(st) == len(want) == 12, st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:100], w)
    assert st[2] == want[2] and st[4] == want[4]


def test_seven_nullable_columns_with_no_default_and_nothing_else():
    add = _stmts()[0]
    got = re.findall(r"ADD COLUMN IF NOT EXISTS (\w+) (\w+)", add)
    assert got == COLUMNS
    assert add.count("ADD COLUMN") == 7
    assert "NOT NULL" not in add.upper() and "DEFAULT" not in add.upper()
    assert "REFERENCES" not in add.upper()


def test_touches_findings_only_and_never_d029s_columns():
    body = SQL.split("END-META", 1)[1]
    code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("--"))
    assert "$$" not in body, "the runner is not dollar-quote aware"
    for s in _stmts():
        u = s.upper()
        assert u.startswith(("ALTER TABLE PUBLIC.FINDINGS ", "COMMENT ON COLUMN PUBLIC.FINDINGS.PLAIN_")), s[:80]
        assert not u.startswith(("DELETE", "TRUNCATE", "DROP", "UPDATE", "INSERT", "GRANT", "REVOKE", "CREATE")), s[:60]
        assert "DROP COLUMN" not in u and "DROP TABLE" not in u and "DROP VIEW" not in u, s[:60]
        if "DROP CONSTRAINT" in u:
            assert re.search(r"DROP CONSTRAINT IF EXISTS FINDINGS_PLAIN_WORDS_(ALL_OR_NONE|OFF_MEANS_EMPTY)$", u), s
    statements_only = re.sub(r"COMMENT ON COLUMN [^;]+;", "", code, flags=re.S)
    for d029 in ("description_synth", "impact", "remediation", "description_source"):
        assert d029 not in statements_only, d029


def test_the_two_rules():
    assert ALL_OR_NONE in _stmts()[2]
    assert OFF_MEANS_EMPTY in _stmts()[4]


def test_every_column_is_described():
    comments = _stmts()[5:]
    for (c, _), s in zip(COLUMNS, comments):
        assert s.startswith(f"COMMENT ON COLUMN public.findings.{c} IS 'KB 12 job 4u"), s[:90]
    assert "--force included" in comments[-1]
    # code review (Kimi, handoff 006, must-fix 2): the column's own description matches the code
    # (plain_words.input_hash): the scan excerpt is NOT in the hash.
    h = comments[3]
    assert h.startswith("COMMENT ON COLUMN public.findings.plain_input_hash IS")
    assert "Not the scan excerpt" in h and "best scan excerpt" not in h
    for part in ("prompt version", "title", "severity", "scanner description", "description_synth", "impact", "remediation"):
        assert part in h, part


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
