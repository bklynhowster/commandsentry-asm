-- ============================================================================
-- 20260921a — per-scan enforcement-live flag on scan_queue (relay 382-live-1)
-- ============================================================================
--
-- Path A (relay 384 ruling) for the enforcement sweep: one operator action
-- fires N hosts by enqueuing a scan_queue row per host, each carrying its own
-- live signal that run_light reads — instead of N workflow dispatches. This is
-- the SECOND source of the enforcement probe's live half, beside the fleet
-- ENFORCEMENT_PROBE_LIVE env (354a-FIRE). run_light's live half becomes
-- (env truthy) OR (this per-scan flag true); the per-ASSET auth half is
-- unchanged, so BOTH gates still hold.
--
--   * PER-SCAN, EPHEMERAL — scan_queue.enforcement_probe_live. Set on ONE queued
--     row, consumed by that scan, gone when the row is. DISTINCT from
--     assets.enforcement_probe_authorized (20260920a), which is the durable
--     per-ASSET "this host MAY be probed" opt-in. Do NOT collapse them: the
--     asset flag says WHO may be probed, the queue flag says THIS scan should.
--   * 376 portal-control (routed) fires by writing this column on a queued row,
--     so the column is designed to serve both the sweep and the portal.
--
-- SCHEMA ONLY. Enables nothing on its own: default FALSE, no cron sets it, and
-- the sweep's arm+enqueue (382-live-2) does not exist yet — after this lands the
-- only way a row carries the flag is a manual DB write. Firing still ALSO needs
-- the per-asset enforcement_probe_authorized. Additive, idempotent,
-- splitter-safe, byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive scan_queue.enforcement_probe_live (boolean, not null, default false — per-SCAN live signal for the relay 382 enforcement sweep path A, distinct from the per-ASSET assets.enforcement_probe_authorized). Enables nothing alone: default false, nothing sets it until 382-live-2, and firing still requires the per-asset auth flag. No table added. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- scan_queue.enforcement_probe_live — per-scan live signal (relay 382-live-1).
-- Default FALSE: a queued scan does not fire the enforcement probe unless this
-- row was explicitly flagged AND the asset is enforcement_probe_authorized.
-- Ephemeral: it lives and dies with the queue row (no backfill, no history).
-- ----------------------------------------------------------------------------
alter table public.scan_queue
  add column if not exists enforcement_probe_live boolean not null default false;

comment on column public.scan_queue.enforcement_probe_live is
  'Per-scan live signal for the relay 382 enforcement sweep (path A). run_light '
  'fires the differential enforcement probe when (ENFORCEMENT_PROBE_LIVE env OR '
  'this flag) AND the per-asset assets.enforcement_probe_authorized are both '
  'true. Default false; ephemeral (lives with the queue row). DISTINCT from the '
  'durable per-asset opt-in. Set by the sweep arm+enqueue (382-live-2) or the '
  '376 portal control surface — never by cron.';
