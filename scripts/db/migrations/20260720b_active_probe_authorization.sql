-- ============================================================================
-- 20260720b — active-probe authorization + audit (fwbbot_check Phase B, 4.7 Q3/Q8)
-- ============================================================================
--
-- The first ACTIVE-PROBE infrastructure. 4.7 ruled that introducing an active
-- probe (FortiWeb /fwbbot_check challenge elicitation) requires the P3 active-tier
-- guardrails applied inline:
--   * PER-ASSET OPT-IN — assets.active_probe_authorized. A probe fires ONLY when
--     this is true for the asset; false = the probe is never attempted (and is
--     the KILL SWITCH — flip false to stop probing an asset immediately).
--   * AUDIT TRAIL — active_probe_audit: one row per probe evaluation (dry-run AND
--     live), for full traceability (which asset, which egress, was it authorized,
--     was it a dry-run, was the challenge observed).
--
-- Dedicated audit table (NOT the user-admin admin_audit_log, which is
-- auth.users-centric): a scanner probe has no user actor, and the probe trail is
-- a scanner concern with its own shape.
--
-- SCHEMA ONLY. Enables nothing on its own: active_probe_authorized defaults FALSE
-- (no asset is probeable until an operator opts it in), and the probe collector
-- (next commit) ships in dry-run. Additive, idempotent, splitter-safe, byte-identical
-- both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive assets.active_probe_authorized (boolean, default false — opt-in + kill switch) + new active_probe_audit table (per-probe trail, dry-run and live). No asset is probeable until opted in; collector ships dry-run. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- assets.active_probe_authorized — per-asset opt-in (4.7 Q3). Default FALSE:
-- absence of an explicit opt-in means NO active probing. This flag is also the
-- kill switch — set false and the next scan skips the probe entirely.
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists active_probe_authorized boolean not null default false;

comment on column public.assets.active_probe_authorized is
  'Per-asset opt-in for active probing (4.7 Q3, fwbbot_check). A probe (e.g. '
  'FortiWeb /fwbbot_check challenge elicitation) fires ONLY when true. Default '
  'false — no asset is probed until an operator explicitly authorizes it. Also '
  'the kill switch: set false to stop probing an asset on the next scan.';

-- ----------------------------------------------------------------------------
-- active_probe_audit — one row per probe EVALUATION (authorized-and-fired,
-- authorized-dry-run, or skipped-unauthorized). The traceability record 4.7
-- required: target, egress, authorization state, dry-run state, and observation.
-- ----------------------------------------------------------------------------
create table if not exists public.active_probe_audit (
  id            uuid primary key default gen_random_uuid(),
  asset_id      text not null references public.assets(asset_id) on delete cascade,
  probe_class   text not null,             -- e.g. 'fwbbot_check_elicit'
  authorized    boolean not null,          -- was active_probe_authorized true at probe time
  dry_run       boolean not null,          -- true = logged only, no request sent
  egress_ip     text,                      -- egress the probe used (null in dry-run / when unknown)
  observed      boolean,                    -- was the artifact (/fwbbot_check) seen (null if not fired)
  corroborated  boolean,                    -- was the corroborating WAF-shape context present (4.7 Q7)
  scan_run_id   text,                       -- the scan_run this evaluation belongs to
  details       jsonb,                      -- probe request class, response class, notes
  created_at    timestamptz not null default now()
);

comment on table public.active_probe_audit is
  'Active-probe audit trail (4.7 Q3/Q8). One row per probe evaluation — including '
  'dry-run and skipped-unauthorized — so every decision to probe (or not) is '
  'traceable: which asset, which egress, authorized?, dry-run?, observed?. '
  'Written by the scanner probe phase, never by user-facing code.';

create index if not exists idx_active_probe_audit_asset
  on public.active_probe_audit(asset_id, created_at desc);
