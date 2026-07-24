-- 20260724a_asset_liveness_verdict.sql
-- Dark-signal liveness gate FOUNDATION (Obsidian 161, 4.7-ratified 2026-07-24).
--
-- ONE shared per-sweep liveness verdict (4.7 Q4), read by BOTH the went_dark demotion writer AND
-- the dark-digest alert suppression via asset_liveness.get_fresh_verdict(). Two computed booleans
-- capture the two 4.7-Q3 semantics at WRITE time:
--   any_port_responded  -> dark-ALERT suppression (open OR refused/RST = host answered = not dark)
--   any_port_open       -> went_dark STATE          (open service only)
-- Plus assets.last_probe_alive_at (4.7 Q6): the probe-healed clock, kept SEPARATE from
-- assets.last_observed (discovery clock) so probe-alive never conflates with discovery-alive;
-- freshness consumers compose (last_observed OR last_probe_alive_at).
--
-- Additive ONLY: new table + new nullable column. No backfill, no behavior change — nothing reads
-- these until the probe worker + digest gate ship in later pushes (enum-before-code discipline in
-- spirit: the substrate lands first). Splitter-safe (plain DDL, no dollar-quoted blocks),
-- idempotent (IF NOT EXISTS), byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive asset_liveness_verdict table + assets.last_probe_alive_at column. No backfill,
--   no reader yet (probe worker + digest gate are later pushes). Byte-identical both repos.
-- END-META

create table if not exists public.asset_liveness_verdict (
  asset_id            text        not null,
  sweep_id            uuid        not null,
  probed_at           timestamptz not null default now(),
  any_port_responded  boolean     not null,
  any_port_open       boolean     not null,
  per_port_results    jsonb       not null default '{}'::jsonb,
  probe_source        text        not null default 'liveness_sweep',
  primary key (asset_id, sweep_id)
);

create index if not exists idx_alv_asset_latest
  on public.asset_liveness_verdict (asset_id, probed_at desc);

comment on table public.asset_liveness_verdict is
  'Obsidian 161 / 4.7 Q4. One shared per-sweep liveness verdict read by the went_dark demotion '
  'writer AND the dark-digest suppression via asset_liveness.get_fresh_verdict(). '
  'any_port_responded = open OR refused (dark-alert suppression, 4.7 Q3); any_port_open = open '
  'only (went_dark state). per_port_results = {port: {result, latency_ms}}.';

alter table public.assets
  add column if not exists last_probe_alive_at timestamptz;

comment on column public.assets.last_probe_alive_at is
  'Obsidian 161 / 4.7 Q6. Probe-healed liveness clock, SEPARATE from last_observed (discovery '
  'clock). Bumped when a liveness probe confirms the asset responds on any port; freshness = '
  'last_observed OR last_probe_alive_at.';
