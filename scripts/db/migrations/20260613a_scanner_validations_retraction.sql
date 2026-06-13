-- ============================================================================
-- MIGRATION — 2026-06-13a — scanner_validations retraction column
--
-- Part 1 of the post-mint trust-layer fix (advisor-approved 2026-06-13).
-- See SPEC_TRUST_LAYER_FIX.md (this PR) for the full 5-part design.
--
-- The invariant to enforce everywhere:
--   findings.validation_status = 'validated'
--     ⟺ findings.scanner_version ∈ public.scanner_validations
--          WHERE retracted_at IS NULL
--       AND findings.scan_quality = 'clean'
--
-- This migration adds the `retracted_at` column so retraction becomes a
-- structural mechanism (timestamped UPDATE in scanner_validations) rather
-- than a notes-edit. Before this column existed, the only way to retract
-- a SHA was to edit the `notes` text field, which:
--   • didn't filter the active set (derive_validation_status still
--     returned 'validated' for findings stamped with the retracted SHA)
--   • left no structural audit trail
--
-- After this migration, retracting a SHA = `UPDATE scanner_validations
-- SET retracted_at = now() WHERE scanner_version = '<sha>'`. All
-- consumers filter on `retracted_at IS NULL` (Parts 2, 3 of the trust-
-- layer fix).
--
-- Backfill: 0864fd3 is the one known retraction (the nikto-died-silently
-- SHA, retracted via notes-edit 2026-06-10 after fixture-driven detector
-- testing exposed that Bug E was real but the SHA had been minted
-- anyway). Stamped retracted_at='2026-06-10 12:00:00+00' to preserve the
-- timeline.
--
-- Apply order:
--   20260613a_scanner_validations_retraction.sql   ← THIS FILE (Part 1)
--   --- Parts 2-4 land via code (run_medium.py) in the same PR ---
--   20260613b_findings_validation_resweep.sql      (Part 5 — MANUAL apply
--                                                   AFTER code is live)
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260613a_scanner_validations_retraction.sql
--
-- Idempotent.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Column add
-- ---------------------------------------------------------------------------
alter table public.scanner_validations
  add column if not exists retracted_at timestamptz;

comment on column public.scanner_validations.retracted_at is
  'When this SHA was retracted from the validated-SHA active set. NULL '
  '= active (findings stamped with this scanner_version may carry '
  'validation_status=''validated''). Non-NULL = retracted; '
  'derive_validation_status MUST filter `WHERE retracted_at IS NULL`, '
  'and the one-time re-derive sweep (20260613b) demotes any '
  'findings.validation_status=''validated'' rows that point at a '
  'retracted SHA. Set with: UPDATE public.scanner_validations SET '
  'retracted_at = now() WHERE scanner_version = ''<sha>'';';

-- Partial index — the active-set filter is the hot path for
-- derive_validation_status, called once per scan_run.
create index if not exists scanner_validations_active_idx
  on public.scanner_validations (intensity, scanner_version)
  where retracted_at is null;

-- ---------------------------------------------------------------------------
-- 2. Backfill — the one known retraction: 0864fd3 (nikto-died-silently)
--    Idempotent guards: only set if currently NULL.
-- ---------------------------------------------------------------------------
update public.scanner_validations
   set retracted_at = '2026-06-10 12:00:00+00'::timestamptz
 where scanner_version like '0864fd3%'
   and retracted_at is null;

-- ---------------------------------------------------------------------------
-- 3. Verification
-- ---------------------------------------------------------------------------
select 'scanner_validations active vs retracted' as info,
       count(*) filter (where retracted_at is null)     as active_count,
       count(*) filter (where retracted_at is not null) as retracted_count,
       count(*)                                          as total
  from public.scanner_validations;

select scanner_version,
       intensity,
       validated_at,
       retracted_at
  from public.scanner_validations
 order by validated_at;

commit;

-- ============================================================================
-- Post-apply expectations:
--
--   active_count   = 4   (5121cd8, cd29c4e, 1f0cbb4, 32db39d)
--   retracted_count = 1  (0864fd3, retracted_at='2026-06-10 12:00:00+00')
--   total          = 5
--
-- After Parts 2 + 5 also land + the sweep runs, this invariant query must
-- return zero rows (the "validated row stamped with a SHA NOT in the
-- active set" hole):
--
--   SELECT count(*) AS violations
--     FROM public.findings f
--    WHERE f.validation_status = 'validated'
--      AND NOT EXISTS (
--            SELECT 1 FROM public.scanner_validations sv
--             WHERE sv.scanner_version = f.scanner_version
--               AND sv.retracted_at IS NULL
--          );
--
-- And this one (validated + degraded contradiction) must also return zero:
--
--   SELECT count(*) AS violations
--     FROM public.findings
--    WHERE validation_status = 'validated'
--      AND scan_quality      = 'degraded';
-- ============================================================================
