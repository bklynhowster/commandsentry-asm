-- ============================================================================
-- MIGRATION — 2026-06-15a — Drop refresh_all_asset_last_observed()
--
-- Part (c) of the [2] last_observed semantics fix (advisor-approved 2026-06-15).
--
-- Drops the B-semantic function refresh_all_asset_last_observed() which
-- recomputed assets.last_observed = MAX(scans.completed_at). This
-- contradicted the A semantic — assets.last_observed is the DISCOVERY
-- clock, owned by scripts/db/import_asm_to_surface.py (asm-discover path,
-- monotonic via GREATEST). The B-semantic writer was actively clobbering
-- the discovery clock with scan-time on every import_jsonl run.
--
-- Companion changes in the same PR:
--   (a) scripts/normalize/schemas/asset.schema.json:15 — doc updated to
--       reflect A semantic explicitly
--   (b) scripts/db/import_jsonl.py — last_observed full-ejected from the
--       asset UPSERT (column list + VALUES + ON CONFLICT SET) AND the
--       refresh_all_asset_last_observed() call removed from line 518
--   (c2) scripts/db/maintenance.sql — function definition removed,
--        replaced with a tombstone comment block referencing this migration
--
-- Caller audit (done 2026-06-15 before this drop):
--   1. import_jsonl.py:518 — active caller (now removed in this PR)
--   2. backfills/20260518_close_revalidated_findings.sql:114 — one-time
--      backfill, completed 2026-05-18. Tombstoned on 2026-06-15. If re-run
--      after this migration applies, it'll fail with "function does not
--      exist" which is the correct signal that the backfill is obsolete.
--   (Exhaustive — verified via repo-wide grep for the function name.)
--
-- Independence check: refresh_all_asset_posture() (maintenance.sql) is a
-- SEPARATE function that recomputes assets.current_risk + reason only.
-- Does NOT touch last_observed, does NOT call the dropped function. Zero
-- collateral from this drop.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260615a_drop_refresh_all_asset_last_observed.sql
--
-- Idempotent (DROP FUNCTION IF EXISTS).
-- ============================================================================

begin;

drop function if exists public.refresh_all_asset_last_observed();

-- Verification — function should NOT exist after this migration
select 'refresh_all_asset_last_observed presence' as info,
       count(*) as count_should_be_zero
  from pg_proc
 where proname = 'refresh_all_asset_last_observed'
   and pronamespace = 'public'::regnamespace;

commit;

-- ============================================================================
-- Post-apply expectations:
--   count_should_be_zero = 0
--
-- After this migration applies AND the companion code changes deploy:
--   • assets.last_observed is owned exclusively by import_asm_to_surface
--     (asm-discover path, 6h cron, GREATEST-monotonic)
--   • import_jsonl never touches assets.last_observed
--   • Alerter staleness logic (run_alerter.py:247) reads the discovery
--     clock cleanly; NULL = "not yet discovered" (alerter handles this)
--
-- Rollback: if for some reason the function needs to come back, restore
-- from git history (was at maintenance.sql lines 42-68 pre-2026-06-15).
-- But re-introducing the B semantic re-introduces the clobber — solve
-- the original problem differently before restoring this function.
-- ============================================================================
