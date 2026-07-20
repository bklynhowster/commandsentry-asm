-- ============================================================================
-- 20260720c — per-asset active-probe egress (fwbbot_check Phase D, 4.7 Q1)
-- ============================================================================
--
-- 4.7 Q1 ruled the probe egress vantage must be PER-ASSET, driven by observed ban
-- behaviour — not one global default. Rationale:
--   * Assets that do NOT ban Mullvad → the VPN vantage works, zero attribution cost.
--     Direct-runner egress would be over-exposure for no benefit.
--   * Assets that DO ban Mullvad (e.g. commandcommcentral.com — FortiGate/FortiWeb,
--     bans Mullvad exits on content/TLS fingerprint) → the VPN vantage can't land the
--     probe; the direct GitHub-runner IP is the only remaining vantage that might
--     elicit /fwbbot_check.
--
-- Two additive columns on public.assets:
--   * active_probe_egress        — {vpn|direct}, DEFAULT 'vpn'. The vantage the probe
--     uses for this asset. Default vpn = the low-exposure choice; an asset is escalated
--     to 'direct' ONLY when a VPN ban is DOCUMENTED (see reason).
--   * active_probe_egress_reason — free text documenting WHY an asset is on 'direct'
--     (4.7 Q1 safeguard: "Mullvad ban observed on <date> (scan_run_X, _Y, _Z)"). Prevents
--     "why is this asset on direct egress?" archaeology later. Empty for vpn (default).
--
-- SCHEMA ONLY. Enables nothing on its own: every asset defaults to 'vpn', and the probe
-- still ships DRY-RUN (ACTIVE_PROBE_LIVE unset → fires nothing). Escalating a specific
-- asset to 'direct' is a separate, evidence-gated data change. Additive, idempotent,
-- splitter-safe, byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 80
-- notes: Additive assets.active_probe_egress ({vpn|direct} default vpn) + active_probe_egress_reason (text). Per-asset probe vantage (4.7 Q1). Default vpn = low-exposure; escalate to direct only on documented VPN ban. Enables nothing (probe still dry-run). Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

alter table public.assets
  add column if not exists active_probe_egress text not null default 'vpn';

-- Constrain to the two known vantages. Guarded so re-run is a no-op.
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'assets_active_probe_egress_chk'
  ) then
    alter table public.assets
      add constraint assets_active_probe_egress_chk
      check (active_probe_egress in ('vpn', 'direct'));
  end if;
end $$;

alter table public.assets
  add column if not exists active_probe_egress_reason text;

comment on column public.assets.active_probe_egress is
  'Per-asset active-probe egress vantage (4.7 Q1, fwbbot_check Phase D): vpn|direct. '
  'Default vpn (low-exposure). Escalate to direct ONLY when a VPN/Mullvad ban is '
  'documented for the asset (see active_probe_egress_reason).';

comment on column public.assets.active_probe_egress_reason is
  'Why this asset is on direct egress (4.7 Q1 safeguard). e.g. "Mullvad ban observed '
  '2026-07-19 (scan_run_X,_Y,_Z)". Empty for vpn (the default vantage).';
