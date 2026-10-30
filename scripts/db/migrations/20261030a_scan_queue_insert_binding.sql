-- 20261030a_scan_queue_insert_binding.sql
--
-- KB 12 job 3x (2026-10-30). WHO CAN START THE BIG SCANS: THE DATABASE CHECKS IT, NOT ONLY THE BUTTON.
--
-- Howie, 2026-10-30 12:52: "Confirm that the vulnerability actually exists." 13:00: "Build it."
-- The portal security audit of 2026-10-30 (finding scan_queue_insert-role-only-bypasses-portal-
-- scan-limits, medium) and Claude's live read the same day (both projects, read-only) found:
-- the ONLY insert rule on scan_queue was "the caller is an active admin or Operator"; the
-- signed-in role held a table-wide INSERT grant (every column); no trigger; nothing limits queued
-- rows. Every other rule lived only in the portal's buttons: heavy is admin-only, a manual scan is
-- never credentialed, the row carries the caller's own id, one scan in flight per asset. So an
-- Operator (Command has 3) could skip the buttons, call the database API with their own session
-- and the public key, and queue a heavy or logged-in scan under anyone's name, as many as they
-- liked. No visible misuse on Command (every attributed row is an admin's, none credentialed),
-- but a forged name is exactly what the hole allows.
--
-- What this does (both projects, byte-identical):
--   1. The signed-in role and anon lose the table-wide INSERT; the signed-in role gets back
--      exactly the six columns the portal's two session-client inserts send (triggerScan and
--      bulkScanNeverScanned: asset_id, intensity, authenticated, triggered_by_user_id, source,
--      notes). supabase-js sends authenticated:false explicitly, so that column stays grantable
--      and the policy pins its value. status, enforcement_probe_live, scheduled_for and the
--      rest are no longer writable by a signed-in user.
--   2. The insert rule binds the row to the caller and to the shape of a manual trigger: the
--      caller's own id, source 'manual', never credentialed, never the enforcement probe,
--      queued, and heavy only for an admin.
--   3. At most one QUEUED MANUAL row per asset. Manual only, on purpose: the automated writers
--      (enqueue-fleet, scanner.yml's ad-hoc fire, scan-tick, the enforcement sweep) run with the
--      service key and check for queued work themselves; their rows ('workflow_dispatch') are
--      untouched. Queued only: 'running' rows from dead runners stay in place by design.
-- The service role (the portal's server routes, the add-asset form, the scanner) bypasses RLS
-- and keeps its own grants: nothing automated changes. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 100
-- notes: Job 3x (Howie 2026-10-30 13:00, audit 2026-10-30 medium). scan_queue: revoke table-wide INSERT from anon and authenticated, re-grant authenticated the six portal columns; scan_queue_insert binds the caller (own id, manual, not credentialed, not the probe, queued, heavy admin-only); unique index scan_queue_one_manual_queued_per_asset. No data change. No dollar-quoting. Byte-identical in both repos.
-- END-META

REVOKE INSERT ON public.scan_queue FROM anon, authenticated;
GRANT INSERT (asset_id, intensity, authenticated, triggered_by_user_id, source, notes)
   ON public.scan_queue TO authenticated;

DROP POLICY IF EXISTS scan_queue_insert ON public.scan_queue;
CREATE POLICY scan_queue_insert ON public.scan_queue
  FOR INSERT TO authenticated
  WITH CHECK (
        (public.is_admin() OR public.is_asset_owner())
    AND triggered_by_user_id = (SELECT auth.uid())
    AND source = 'manual'
    AND authenticated = false
    AND enforcement_probe_live = false
    AND status = 'queued'
    AND (intensity <> 'heavy' OR public.is_admin())
  );

CREATE UNIQUE INDEX IF NOT EXISTS scan_queue_one_manual_queued_per_asset
  ON public.scan_queue (asset_id)
  WHERE status = 'queued' AND source = 'manual';
