-- ============================================================================
-- MIGRATION — 2026-07-07c — assets.cloud_drift (4.7 ruling E7)
--
-- Mirrors kind_drift (HOST_CHARACTERIZATION). Set true when the derived cloud
-- classification (derive_cloud_endpoint.py) DISAGREES with a sticky MANUAL flag
-- (cloud_source='manual'). The importer flips it + writes an admin_audit_log
-- 'cloud_classification_drift' entry; it is portal-surfaced (chip) and the manual
-- value is NEVER auto-overwritten (4.7 D9). Without this, a manual override that
-- diverges from ground truth is invisible — the whole sticky-manual discipline
-- depends on drift being VISIBLE.
--
-- Idempotent. Txn-safe. Apply to BOTH instances (Command + Prodex) for parity.
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260707c_cloud_drift_col.sql
--   -- or paste into the Supabase SQL editor and Run.
-- ============================================================================

begin;

alter table public.assets
  add column if not exists cloud_drift boolean not null default false;

commit;

-- SANITY: select column_name from information_schema.columns
--   where table_schema='public' and table_name='assets' and column_name='cloud_drift';
