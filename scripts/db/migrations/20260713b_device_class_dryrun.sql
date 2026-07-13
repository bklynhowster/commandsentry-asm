-- ============================================================================
-- 20260713b — device_class_dryrun (soak audit trail) [4.7 E3]
-- ============================================================================
--
-- Persistent, queryable audit trail for the device-class classifier's Phase A
-- soak. 4.7 E3 (2026-07-13): the D4 "structured logs, not text" discipline
-- applies — text / CI-log output is not sufficient for a 14-day, high-blast-
-- radius soak (retention limits, not queryable, can't answer "when did asset X
-- first classify as Y?"). device_class_runner.py writes one row here per
-- actionable evaluation, EVERY pass (dry-run AND --write); weekly soak review +
-- post-Phase-B forensics query this table, not the CI logs.
--
-- Corrections to 4.7's illustrative SQL:
--   * asset_id is TEXT (assets.asset_id is text, not uuid — same as asset_fronting).
--   * event_type carries the UPGRADE/DOWNGRADE granularity 4.7 added in the E3
--     failure-mode ruling (a confidence/class DOWNGRADE is a red flag and resets
--     the soak clock); would_reroute is its own boolean flag, not an event_type.
--   * soak_generation increments on a soak-clock reset so post-reset review reads
--     only current-generation rows; purge policy retains the last 2 generations.
--
-- Additive, idempotent, splitter-safe (no do-blocks, no ';' in strings, no '--'
-- in string literals). Byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Adds device_class_dryrun (soak audit trail, 4.7 E3) — asset_id text FK, event_type UPGRADE/DOWNGRADE granularity, would_reroute bool, soak_generation, 3 indexes. Written by device_class_runner.py every pass. Additive, splitter-safe, byte-identical both repos.
-- END-META
-- ============================================================================

create table if not exists public.device_class_dryrun (
  entry_id        uuid primary key default gen_random_uuid(),
  asset_id        text not null references public.assets(asset_id) on delete cascade,
  evaluated_at    timestamptz not null default now(),
  event_type      text not null
    check (event_type in ('STAMP','CHANGE','TRANSITION_UPGRADE','TRANSITION_DOWNGRADE')),
  device_class    text,
  confidence      text,
  evidence        jsonb not null default '{}'::jsonb,
  vendor_product  jsonb,
  prior_state     jsonb,
  would_reroute   boolean not null default false,
  scan_run_id     uuid references public.scan_run(scan_run_id) on delete set null,
  soak_generation integer not null default 1
);

comment on table public.device_class_dryrun is
  'Device-class classifier soak audit trail (4.7 E3). One row per actionable '
  'evaluation, written every runner pass (dry-run and write). event_type '
  'TRANSITION_DOWNGRADE is a red flag that resets the soak clock; soak_generation '
  'increments on reset. Retain the last 2 generations, archive/purge older.';

create index if not exists idx_dcd_asset_time
  on public.device_class_dryrun(asset_id, evaluated_at desc);
create index if not exists idx_dcd_event
  on public.device_class_dryrun(event_type, evaluated_at desc);
create index if not exists idx_dcd_generation
  on public.device_class_dryrun(soak_generation, evaluated_at desc);
