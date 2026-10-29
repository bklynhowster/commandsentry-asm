"""(KB 12 job 3u, 2026-10-29) Migration 20261029a: the test box on hold; it blocks Sentry, it is not down.

Howie, 2026-10-29 15:14: "you can definitely mark it as blocked by our scanner". 15:31: nothing to
Command until he checks from the office. Pinned here: data only, exactly two statements; the hold
lands on test.commandcommcentral.com and 52.119.65.6 only, and only where no hold is set (never
overwrites one); the reason starts with the words the audit insert looks for; the audit is written
once per host for this migration; no dollar quotes (the runner can't split them); the meta
auto-applies. Proven on PostgreSQL 16 in the build note (two applies; pm.unimacgraphics.com's hold
untouched; a no-op where the hosts are absent).
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261029a_hold_test_box.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

HOSTS = "WHERE asset_id IN ('test.commandcommcentral.com', '52.119.65.6')"
PREFIX = "Held by Howie (2026-10-29, job 3u):"


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_two_statements_data_only():
    st = _stmts()
    assert len(st) == 2, st
    assert st[0].startswith("UPDATE public.assets SET dark_hold_reason = ")
    assert st[1].startswith("INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details) SELECT NULL, 'dark_rule_hold',")
    body = SQL.split("END-META", 1)[1].upper()
    for word in ("CREATE ", "ALTER ", "DROP ", "DELETE ", "TRUNCATE ", "GRANT ", "REVOKE "):
        assert word not in body, word
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_the_hold_lands_on_the_two_rows_only_and_never_overwrites():
    up = _stmts()[0]
    assert HOSTS in up
    assert up.endswith("AND dark_hold_reason IS NULL")
    assert f"SET dark_hold_reason = '{PREFIX}" in up


def test_audited_once_per_host_for_this_migration():
    ins = _stmts()[1]
    assert "a.asset_id IN ('test.commandcommcentral.com', '52.119.65.6')" in ins
    assert f"a.dark_hold_reason LIKE '{PREFIX}%'" in ins
    assert "l.details ->> 'migration' = '20261029a'" in ins
    assert "'migration', '20261029a'" in ins


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
