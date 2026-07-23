-- ============================================================================
-- 20260722a — assets.not_web_scannable marker (Obsidian 156, 4.7 Q3)
-- ============================================================================
--
-- Some confirmed_live + owned assets have NO web surface (nameservers, mail
-- infra, firewall mgmt hosts). A HEAVY web scan of them always DEGRADES — and a
-- degraded heavy writes no stack_id_passive artifact, so the seed-device-class
-- artifact-absence gate never excludes them: they got re-enqueued every cycle,
-- degraded again, and (pre-156-Fix-1) exited non-zero -> a GitHub failure email
-- per scan. This marker lets EVERY subsystem preemptively skip heavy-web-scanning
-- these hosts, instead of each one re-learning "this degrades" the hard way.
--
-- 4.7 Q3: this COMPLEMENTS the seed gate's date-anchored exclusion (156 Fix 2) —
-- it does not supersede it. Consumers:
--   * seed-device-class gate  -> exclude not_web_scannable = true
--   * Coverage Watchdog denom -> exclude not_web_scannable = true (don't count as
--                                expected heavy coverage)
--   * (future) rescan-stale   -> exclude from heavy re-scan; portal user-heavy warns
--
-- SCHEMA ONLY + additive. Default false = zero behavior change on existing rows.
-- The initial ~6 infra degraders are set MANUALLY (empirically observed); the
-- auto-marker (mark after N consecutive degraded heavies) is a separate follow-up
-- PR with its own soak (4.7 Q3 correction). Splitter-safe, idempotent, byte-
-- identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive assets.not_web_scannable (boolean, default false) + reason + marked_at. Marks infra hosts with no web surface so nothing heavy-web-scans them. Default false = no behavior change; the 6 known degraders are marked manually post-apply. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- assets.not_web_scannable — true = this asset has no web surface; heavy web
-- scans degrade. Default FALSE (every existing asset stays scannable). Set true
-- only for confirmed infra hosts (nameservers/mail/firewall).
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists not_web_scannable boolean not null default false;

comment on column public.assets.not_web_scannable is
  'Obsidian 156 / 4.7 Q3. true = asset has no web surface (nameserver / mail / '
  'firewall infra); a HEAVY web scan will degrade, so subsystems (seed walker, '
  'Coverage Watchdog, future rescan-stale) skip heavy-web-scanning it. Default '
  'false. Set manually for known infra hosts; auto-marker is a follow-up.';

-- ----------------------------------------------------------------------------
-- Provenance for the marker — why + when it was set (audit/debug).
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists not_web_scannable_reason text;

alter table public.assets
  add column if not exists not_web_scannable_marked_at timestamptz;

comment on column public.assets.not_web_scannable_reason is
  'Human-readable reason the asset was marked not_web_scannable (e.g. "nameserver '
  '— no web surface; heavy degrades").';
