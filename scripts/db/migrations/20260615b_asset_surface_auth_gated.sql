-- ============================================================================
-- MIGRATION — 2026-06-15b — asset_surface.auth_gated column
--
-- Part of #24 Phase 2 — auth-gated target detection.
--
-- Adds a derived boolean signaling whether the asset is fronted by an
-- identity provider login (Entra / Okta / Auth0 / Cognito / B2C / etc).
-- Computed at asm-discover time by import_asm_to_surface.py via the
-- AND-gate: subdomain[0].reachability.title matches a login pattern
-- AND subdomain[0].services[443].cert.san matches an IdP SAN suffix.
--
-- WHY derived not stored-input:
--   Q2 (advisor 2026-06-15): "(a): re-evaluate every asm-discover surface
--   scan. Sticky (b) = silent-skip-forever when an asset goes public.
--   Derive the flag, never latch it."
--   The UPSERT in import_asm_to_surface SETs auth_gated = EXCLUDED
--   (not COALESCE) so the flag refreshes every 6h asm-discover cron.
--
-- USED BY:
--   - scripts/scanner/run_medium.py — at scan start, reads
--     asset_surface.auth_gated. If true, mark_tool_skipped on nikto +
--     ffuf chunks + nuclei[critical,high|medium:cve|medium:exposure,config|
--     medium:wordpress,cms|medium:iis,...|medium:php|medium:drupal,cms|
--     medium:joomla,cms]. KEEP wafw00f + httpx + nuclei[medium:tech].
--     The skipped run stays scan_quality='clean', status='complete' —
--     skipped is a third state, not degraded. See run_medium.py
--     mark_tool_skipped docstring (Phase 1, commit eb77b44 (next-after-eb77b44)).
--
-- NO INDEX (advisor 2026-06-15): at ~70 assets a seq scan is fine, and
-- the per-scan read is by asset_id (PK, already indexed). A partial
-- index WHERE auth_gated=true would only help fleet-scale "list all
-- auth-gated assets" reporting; not needed today. Add later if such
-- reporting becomes a real need.
--
-- DEFAULT: false. New rows + existing rows backfill to false on apply.
-- The next asm-discover surface scan (≤6h after deploy) recomputes
-- per-asset; assets that ARE auth-gated flip to true at that point.
-- No backfill SQL needed — the flag is derived, not historical.
--
-- KNOWN LIMITATION (advisor 2026-06-15, accepted for Phase 2): custom-
-- domain IdP (Entra/Okta/Auth0 behind a vanity domain like
-- login.company.com) presents the customer's OWN cert, not an *.idp
-- SAN. Cert match fails → auth_gated=false → medium still wastes time
-- on it. Common cases (Entra/Cognito/B2C/standard Okta) ARE covered by
-- the suffix list. Future enhancement: detect IdP redirect or
-- login-form structure, not cert-suffix alone.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260615b_asset_surface_auth_gated.sql
--
-- Idempotent (ADD COLUMN IF NOT EXISTS).
-- ============================================================================

begin;

alter table public.asset_surface
  add column if not exists auth_gated boolean not null default false;

comment on column public.asset_surface.auth_gated is
  'True if the asset is fronted by an identity provider login (Entra / '
  'Okta / Auth0 / Cognito / B2C / etc), derived from '
  'subdomain[0].reachability.title matching a login pattern AND '
  'subdomain[0].services[443].cert.san matching an IdP SAN suffix. '
  'Computed and refreshed by import_asm_to_surface.py on every '
  'asm-discover run (6h cron) — NEVER latched, always derived from '
  'current signals. Read by run_medium.py at scan start to skip '
  'unauth attack tools (nikto + ffuf + nuclei attack/cve/exposure '
  'chunks) on auth-gated targets where they cannot produce useful '
  'output. See scripts/db/migrations/20260615b_asset_surface_auth_gated.sql '
  'header for full design rationale.';

-- Verification — confirm column exists with correct default
select 'asset_surface.auth_gated column state' as info,
       column_name, data_type, is_nullable, column_default
  from information_schema.columns
 where table_schema = 'public'
   and table_name = 'asset_surface'
   and column_name = 'auth_gated';

select 'asset_surface auth_gated distribution (all false at apply time)' as info,
       auth_gated, count(*) as n
  from public.asset_surface
 group by auth_gated;

commit;

-- ============================================================================
-- Post-apply expectations:
--   column exists: auth_gated, boolean, NOT NULL, default false
--   distribution at apply: all rows auth_gated=false (default)
--
-- After import_asm_to_surface.py deploys + next 6h asm-discover cron:
--   myordersauth-test.unimacgraphics.com — auth_gated=true (Entra + IdP cert)
--   myordersauthlive.unimacgraphics.com — auth_gated=true (same shape)
--   test.commandcommcentral.com — auth_gated=false (FortiWeb + own cert)
--   Other assets — auth_gated=false (normal web surface)
--
-- Verify with:
--   SELECT asset_id, auth_gated FROM asset_surface
--    WHERE asset_id IN ('myordersauth-test.unimacgraphics.com',
--                       'test.commandcommcentral.com');
-- ============================================================================
