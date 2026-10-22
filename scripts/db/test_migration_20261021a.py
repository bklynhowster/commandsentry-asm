"""(KB 12 job 3d, 2026-10-21) Migration 20261021a adds the enum value the advisory
watcher writes, and nothing else. Its value must equal advisory_watch.SOURCE."""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261021a_finding_source_advisory_watch.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "scanner"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402
import advisory_watch  # noqa: E402


def test_one_statement_adds_the_value_and_uses_nothing():
    stmts = runner._split(SQL)
    assert stmts == ["ALTER TYPE public.finding_source_t ADD VALUE IF NOT EXISTS 'advisory_watch'"]


def test_the_value_is_the_watchers_source():
    assert f"'{advisory_watch.SOURCE}'" in SQL


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta) and migration_meta.is_transactional(meta)
