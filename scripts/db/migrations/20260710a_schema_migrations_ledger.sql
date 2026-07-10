-- MIGRATION-META:
--   idempotent: true
--   transactional: true
--   safe_auto_apply: false
--   requires_backup: false
--   estimated_duration_ms: 50
--   notes: create schema_migrations ledger (4.7 Q2) — cross-instance migration-parity foundation
-- END-META
-- 20260710a_schema_migrations_ledger.sql
-- Applied-migration ledger — SCANNER_MIGRATION_LEDGER_SPEC.md (4.7 rulings 2026-07-10).
-- One row per scripts/db/migrations/*.sql applied to THIS DB. Backfilled by
-- seed_ledger.py (verify-then-seed); migrate.yml / manual applies insert going forward.
-- Per-instance: the Command and Prodex scanner DBs each keep their own ledger.
BEGIN;

CREATE TABLE IF NOT EXISTS public.schema_migrations (
  filename            text PRIMARY KEY,
  applied_at          timestamptz NOT NULL DEFAULT now(),
  applied_by          text,                 -- backfill | ci | <operator>
  content_sha256      text NOT NULL,        -- SHA-256 of file bytes at apply (gate refuses on post-apply edit)
  git_commit_sha      text,                 -- commit that applied (NULL for manual)
  applied_duration_ms integer,              -- apply telemetry
  notes               text
);

COMMENT ON TABLE public.schema_migrations IS
  'Applied-migration ledger (4.7 2026-07-10). content_sha256 catches a migration file edited '
  'after apply; the scanner gate refuses on unapplied files or sha mismatch. Per-instance ledger.';

COMMIT;
