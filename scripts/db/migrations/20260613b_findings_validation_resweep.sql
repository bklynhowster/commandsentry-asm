-- ============================================================================
-- MIGRATION — 2026-06-13b — Findings validation_status re-derive sweep
--
-- Part 5 of the post-mint trust-layer fix (advisor-approved 2026-06-13).
-- See SPEC_TRUST_LAYER_FIX.md (this PR) for the full 5-part design.
--
-- ⚠️  DO NOT AUTO-APPLY  ⚠️
--
-- This migration is MANUAL-APPLY ONLY, in this strict order:
--
--   1. PR merges with Parts 1-4 (migration 20260613a + run_medium.py
--      derive-on-write semantics).
--   2. Code is DEPLOYED and the next scanner run is observed using the
--      new UPSERT_FINDING_SQL (confirm via scan_run logs).
--   3. Then — and only then — apply this migration MANUALLY:
--        psql "$SUPABASE_DSN" -f scripts/db/migrations/20260613b_findings_validation_resweep.sql
--
-- Why the ordering matters: if this sweep runs BEFORE the new code is
-- live, the next scanner run uses the old preserve-on-write UPSERT and
-- silently re-corrupts the rows the sweep just cleaned. Sweep + code
-- must be sequenced — sweep-after-code is the safe path. (Advisor lean
-- 5: "Code first, sweep last.")
--
-- Idempotent: pure derive-from-current-state UPDATE. Re-runnable on
-- any schedule without producing different results, because the rule
-- it enforces is the same on every run:
--
--   "validation_status='validated' iff scanner_version is in the active
--    set AND scan_quality='clean' AND source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')."
--
-- ----------------------------------------------------------------------------
-- BLAST RADIUS (advisor lean 3 — NARROW)
-- ----------------------------------------------------------------------------
-- Filter: `source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')`. The scanner_version invariant
-- is defined only for findings produced by THIS runner. Imports (~35%
-- of findings — wpscan, nuclei pre-runner, etc.) and manual (~21%)
-- validate by different, non-scanner-provenance rules. A broad sweep
-- would wrongly demote ALL non-runner findings to 'unvalidated'. Tight
-- scope is the safety bar — legacy non-runner findings re-validate
-- naturally if/when the current runner re-emits them.
--
-- ----------------------------------------------------------------------------
-- WHAT THE SWEEP DOES (single UPDATE, three demotion classes)
-- ----------------------------------------------------------------------------
-- For commandsentry-sourced findings currently stamped 'validated':
--
--   Class A — scanner_version not in active scanner_validations set
--             (NULL, unknown SHA, or a SHA whose retracted_at IS NOT NULL).
--             Includes the post-mint hole the advisor caught: 28 rows
--             stamped 'validated' under SHAs not in scanner_validations.
--
--   Class B — scanner_version IS in the active set BUT scan_quality is
--             'degraded'. The launder-block lock at write-time prevents
--             this going forward; the sweep cleans up any pre-fix rows
--             where scan_quality was flipped to 'degraded' after the
--             validation_status was already 'validated'.
--
--   Class C — historical drift / orphan validated rows not covered by
--             A or B. Fall-through reads as "validation_status doesn't
--             match the current rule" — demote and let re-emission
--             re-validate naturally.
--
-- All three demote together: validation_status='unvalidated' +
-- validated_at=NULL. Matches the derive-on-write UPSERT semantics so
-- the live path and the sweep produce identical resulting state.
--
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 0. Pre-sweep snapshot — record what we're about to demote.
--    Saves to a one-off audit table so the change is reversible /
--    forensics-friendly. Idempotent: drops + recreates per run.
-- ---------------------------------------------------------------------------
drop table if exists public.findings_validation_resweep_20260613b;

create table public.findings_validation_resweep_20260613b as
select f.finding_id,
       f.asset_id,
       f.source,
       f.scanner_version,
       f.scan_quality,
       f.validation_status as old_validation_status,
       f.validated_at      as old_validated_at,
       now()               as snapshotted_at
  from public.findings f
 where f.source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')
   and f.validation_status = 'validated'
   and (
         -- Class A: not in active set (NULL SHA, unknown SHA, retracted SHA)
         NOT EXISTS (
           SELECT 1 FROM public.scanner_validations sv
            WHERE sv.scanner_version = f.scanner_version
              AND sv.retracted_at IS NULL
         )
         -- Class B: in active set but scan_quality='degraded'
      OR f.scan_quality = 'degraded'
       );

comment on table public.findings_validation_resweep_20260613b is
  'Snapshot of findings.validation_status=''validated'' rows that the '
  '20260613b sweep is about to demote. Captures pre-sweep state for '
  'forensics. Safe to drop after the sweep is verified — same query '
  'can re-derive the snapshot if needed.';

-- ---------------------------------------------------------------------------
-- 1. The sweep itself — single UPDATE, derive-from-current-state.
-- ---------------------------------------------------------------------------
update public.findings f
   set validation_status = 'unvalidated',
       validated_at      = NULL
 where f.source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')
   and f.validation_status = 'validated'
   and (
         NOT EXISTS (
           SELECT 1 FROM public.scanner_validations sv
            WHERE sv.scanner_version = f.scanner_version
              AND sv.retracted_at IS NULL
         )
      OR f.scan_quality = 'degraded'
       );

-- ---------------------------------------------------------------------------
-- 2. Verification — acceptance gate queries
-- ---------------------------------------------------------------------------
select 'sweep snapshot — rows demoted' as info,
       count(*) as demoted_count
  from public.findings_validation_resweep_20260613b;

select 'invariant check A — validated rows with no active scanner_validations row'
         as info,
       count(*) as violations
  from public.findings f
 where f.source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')
   and f.validation_status = 'validated'
   and NOT EXISTS (
         SELECT 1 FROM public.scanner_validations sv
          WHERE sv.scanner_version = f.scanner_version
            AND sv.retracted_at IS NULL
       );

select 'invariant check B — validated AND degraded (contradiction class)'
         as info,
       count(*) as violations
  from public.findings
 where source IN ('commandsentry_light','commandsentry_medium','commandsentry_heavy')
   and validation_status = 'validated'
   and scan_quality      = 'degraded';

select 'sanity — confirm 0864fd3 is excluded from active set' as info,
       count(*) filter (where retracted_at is null) as active,
       count(*) filter (where retracted_at is not null) as retracted
  from public.scanner_validations
 where scanner_version like '0864fd3%';

-- ---------------------------------------------------------------------------
-- 3. Per-source distribution after the sweep — eyeball check
-- ---------------------------------------------------------------------------
select 'post-sweep validation_status distribution by source' as info,
       source,
       validation_status,
       count(*) as n
  from public.findings
 where current_status = 'detected'
 group by source, validation_status
 order by source, validation_status;

commit;

-- ============================================================================
-- Post-apply expectations (both invariant checks):
--
--   violations = 0  on BOTH queries above.
--
-- Roll-back recipe (if the sweep needs to be reverted):
--
--   UPDATE public.findings f
--      SET validation_status = s.old_validation_status,
--          validated_at      = s.old_validated_at
--     FROM public.findings_validation_resweep_20260613b s
--    WHERE f.finding_id = s.finding_id;
--
-- (The snapshot table is the rollback surface — don't drop it until
-- the sweep has been verified across at least one full scan cycle.)
-- ============================================================================
