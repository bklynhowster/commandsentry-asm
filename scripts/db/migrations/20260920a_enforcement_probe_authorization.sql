-- ============================================================================
-- 20260920a — enforcement-probe authorization (relay 354a-live / 360)
-- ============================================================================
--
-- The per-asset opt-in that lets the differential enforcement probe (relay
-- 354a, scripts/scanner/enforcement_probe.py) fire against ONE owned host.
-- The probe sends a benign baseline plus one URL-encoded attack-signature GET
-- on the same path to tell "WAF present" from "WAF enforcing" — heavier than a
-- bot GET, so it gets its OWN opt-in, DISTINCT from active_probe_authorized
-- (fwbbot / waf_differential, 20260720b) and exploit_authorized (20260721a).
--
--   * PER-ASSET OPT-IN — assets.enforcement_probe_authorized. The probe fires
--     ONLY when this is true for the asset; false = the probe is never sent
--     (and is the KILL SWITCH — flip false to stop probing an asset at once).
--   * poll_queue.py carries this flag to the descriptor top level, where
--     run_light.probe_enforcement reads it via probe_is_authorised.
--
-- SCHEMA ONLY. Enables nothing on its own — TWO independent gates guard firing
-- and this migration only opens the first:
--   1. assets.enforcement_probe_authorized — defaults FALSE, so no asset is
--      probeable until an operator opts it in.
--   2. ENFORCEMENT_PROBE_LIVE in the runner env — cron never sets it; the
--      probe stays dry-run everywhere until an operator sets it for one run.
-- With the column added and every value false, the probe remains dry-run on
-- every asset. Additive, idempotent, splitter-safe, byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive assets.enforcement_probe_authorized (boolean, not null, default false — per-asset opt-in + kill switch for the relay 354a differential enforcement probe, distinct from active_probe_authorized and exploit_authorized). Enables nothing alone: default false + the runner also requires ENFORCEMENT_PROBE_LIVE in env. No table added. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- assets.enforcement_probe_authorized — per-asset opt-in (relay 354a-live/360).
-- Default FALSE: absence of an explicit opt-in means NO enforcement probing.
-- This flag is also the kill switch — set false and the next scan's probe goes
-- back to dry-run (plan recorded, nothing sent) for that asset.
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists enforcement_probe_authorized boolean not null default false;

comment on column public.assets.enforcement_probe_authorized is
  'Per-asset opt-in for the differential enforcement probe (relay 354a). The '
  'probe (benign baseline + one URL-encoded attack-signature GET on the same '
  'path, to distinguish WAF-present from WAF-enforcing) fires ONLY when true. '
  'Default false — no asset is probed until an operator explicitly authorizes '
  'it; also the kill switch. DISTINCT from active_probe_authorized and '
  'exploit_authorized. Firing additionally requires ENFORCEMENT_PROBE_LIVE in '
  'the runner env (two AND-ed gates); this flag alone never sends anything.';
