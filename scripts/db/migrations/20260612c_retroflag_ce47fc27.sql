-- ============================================================================
-- MIGRATION — 2026-06-12 — Retro-flag ce47fc27 scan_run as 'degraded'
--
-- Apply order (advisor catch ①: split forced by Postgres 55P04):
--   20260612a_add_degraded_enum.sql     — enum labels only
--   20260612b_scan_degradation.sql      — trigger + columns + finding backfill
--   20260612c_retroflag_ce47fc27.sql    ← THIS FILE — scan_run.status flip
--
-- The split is forced because Postgres forbids using a newly-added enum
-- value in the same txn that added it. Each file is its own begin/commit.
--
-- The ce47fc27 scan_run row is currently sitting at status='complete' —
-- the poster-child success-shaped-lie that motivated this whole spec
-- (testfire banned Mullvad mid-scan, 3 chunks skipped, nikto-FAIL
-- stamped as a finding). Flipping its status to 'degraded' makes the
-- record consistent with reality and lets downstream queries (digest,
-- coverage, /admin/dashboard) treat it as the degraded run it actually
-- was.
--
-- Migration 20260612b already flipped this run's findings to
-- scan_quality='degraded'. This one flips the scan_run row itself.
-- The trg_scan_queue_sync_on_scan_run_terminal trigger (extended in
-- 20260612b to fire on 'degraded') will propagate to the corresponding
-- scan_queue row.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260612c_retroflag_ce47fc27.sql
--
-- Idempotent.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Retro-flag the ce47fc27 scan_run.status to 'degraded'
--
--    Guard: only flip if currently 'complete'. If someone (or a future
--    migration) has already moved it to 'failed' or back to 'running',
--    skip — we don't clobber other state.
-- ---------------------------------------------------------------------------
update public.scan_run
   set status = 'degraded',
       error_message = coalesce(
         error_message,
         'retro-flagged 2026-06-12: degraded by SPEC_SCANNER_DEGRADATION_'
         'HARDENING — testfire banned Mullvad mid-scan, 3 chunks skipped '
         '(nuclei[medium:exposure,config] + 2x ffuf[25w]), nikto-FAIL '
         'stamped as INFO finding (now scan_quality=degraded). See '
         'asm GH run 27424680860 + ce47fc27''s tools_run vs tool_status '
         'gap (8 ran, only 3 stamped).'
       )
 where scan_run_id = 'ce47fc27-d478-45c4-beac-bc2ba2c6be75'
   and status      = 'complete';

-- ---------------------------------------------------------------------------
-- 2. Verify the trigger propagated to scan_queue
--
--    The trigger fires after the UPDATE above. If the corresponding
--    scan_queue row didn't pick up 'degraded', either the trigger
--    didn't fire (shouldn't happen — 20260612a extended its WHEN
--    clause) or the queue row had moved to a non-'running' state
--    independently. Print the state so the apply log shows both.
-- ---------------------------------------------------------------------------
select 'ce47fc27 post-flip — scan_run.status' as info,
       status,
       error_message
  from public.scan_run
 where scan_run_id = 'ce47fc27-d478-45c4-beac-bc2ba2c6be75';

select 'ce47fc27 post-flip — scan_queue.status (via trigger sync)' as info,
       q.status,
       q.notes
  from public.scan_queue q
 where q.queue_id = '12f4145f-0541-417d-8b6c-51b1afa947df';

select 'ce47fc27 findings — sanity check' as info,
       count(*) filter (where scan_quality = 'degraded') as degraded,
       count(*) filter (where scan_quality = 'clean')    as still_clean,
       count(*) as total
  from public.findings
 where first_detected_scan = 'ce47fc27-d478-45c4-beac-bc2ba2c6be75';

commit;
