-- ============================================================================
-- MIGRATION — 2026-07-07a — portal characterization columns (unblock dashboard)
--
-- WHY: the commandsentry-portal dashboard (src/app/dashboard/page.tsx line 67)
-- and the Fleet Composition card select assets.kind / is_staging / kind_drift
-- (portal commits dcac4ec, 2e71f5d — "Host Characterization Phase A"). Those
-- columns exist on the PRODEX db (migrations 20260705a/b) but were never ported
-- to Command, so every dashboard load fails with:
--     column assets.is_staging does not exist
--
-- WHAT: adds ONLY the three columns the portal reads, with safe defaults, so
-- the dashboard renders immediately. The portal only READS them; nothing on
-- Command writes them yet, so `kind` stays NULL and is_staging/kind_drift
-- default false (Fleet Composition will show every host as prod / unknown-kind
-- until the derive_asset_kind step is ported — separate follow-on, NOT required
-- to un-break the view).
--
-- kind is TEXT here (not Prodex's asset_kind_t enum): the portal reads it as a
-- string, and Command has no derivation step writing enum values yet. If/when
-- the full Host Characterization port lands on Command, convert to a typed enum
-- then (create asset_kind_t + kind_conf_t + the remaining 20260705b columns).
--
-- SAFE: idempotent (ADD COLUMN IF NOT EXISTS); additive only; no data rewrite.
--
-- APPLY (either one):
--   psql "$COMMAND_SUPABASE_DSN" -f scripts/db/migrations/20260707a_portal_characterization_cols.sql
--   -- or: paste the ALTER block below into the Supabase SQL editor for the
--   --     Command project and Run.
-- ============================================================================

begin;

alter table public.assets
  add column if not exists kind        text,
  add column if not exists is_staging  boolean not null default false,
  add column if not exists kind_drift  boolean not null default false;

commit;

-- ============================================================================
-- SANITY — after apply, the dashboard query should succeed:
--   select asset_id, kind, is_staging, kind_drift from public.assets limit 5;
-- Expect: 3 columns present, is_staging/kind_drift = false, kind = null.
-- ============================================================================
