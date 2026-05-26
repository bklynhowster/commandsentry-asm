-- ============================================================================
-- 20260526a — Asset surface event log (port_opened / port_closed history)
-- ============================================================================
--
-- Adds the temporal layer Howie asked for: when did port X open on host Y,
-- when did it close. The asset_surface table from 20260525b is a snapshot —
-- it overwrites itself every 6h cron tick, losing prior state. This table
-- is append-only: every diff produces rows here, so we can answer
-- "what changed between today and last week" forever.
--
-- Conversation thread: 2026-05-25 EOD ("I do want the history. Port A was
-- open, Port B closed, right?") + 2026-05-26 morning ("Go for it" on task #24).
--
-- Spec: Obsidian / COMMANDsentry / 41 - Tomorrow Queue 2026-05-26.md
--
-- DIFF MODEL
-- ----------
-- Service identity = (host, port, proto). On every import_asm_to_surface
-- run, the importer:
--   - SELECTs existing surface_data for the asset
--   - Builds two sets of (host, port, proto) tuples (old vs new)
--   - new - old → emit port_opened
--   - old - new → emit port_closed
--   - intersection → no event
-- First time an asset is imported (no prior row) → emit asset_first_seen,
-- but NOT per-port events (avoids first-run flood for a new asset
-- discovered with 10 services already running).
--
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: asset_surface_event
-- ----------------------------------------------------------------------------
create table if not exists public.asset_surface_event (
  id            bigserial primary key,

  asset_id      text       not null
                           references public.assets(asset_id) on delete cascade,

  event_type    text       not null,
                           -- 'port_opened' | 'port_closed'
                           -- | 'asset_first_seen'
                           -- | 'service_changed'  (reserved for later — name flip on same host:port)
                           -- | 'host_added' | 'host_removed' (reserved — likely roll-up of port events)

  -- Flat columns for the common queries ("show me everything that opened
  -- on this host in the last 7d", "show me every port_closed across the
  -- fleet today"). Nullable because asset_first_seen has no port context.
  host          text,
  port          integer,
  proto         text,
  service       text,
  tls           boolean,

  -- Richer payloads for future expansion. prev_value/new_value let us
  -- record service_changed events later without schema changes
  -- (e.g., {service:"http"} → {service:"https-alt"} on the same host:port).
  prev_value    jsonb,
  new_value     jsonb,

  observed_at   timestamptz not null default now(),
  source_tag    text        not null
                            -- 'asm_cron' | 'legacy_asm_import' | 'cloud_scanner_v1' | 'manual_backfill'
);

comment on table public.asset_surface_event is
  'Append-only log of changes to asset_surface. One row per discrete change '
  '(port opened, port closed, asset first seen). Populated by the importer '
  'after each ASM scan diff. Read by the Surface tab timeline strip on '
  '/assets/[asset_id] and (future) by the notification trigger that fires '
  'Resend emails to users with matching prefs.';

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------
-- Primary read pattern: "show me the last N events on this asset"
create index if not exists idx_asset_surface_event_asset_time
  on public.asset_surface_event (asset_id, observed_at desc);

-- Cross-fleet read pattern: "show me every port_opened across the fleet today"
create index if not exists idx_asset_surface_event_type_time
  on public.asset_surface_event (event_type, observed_at desc);

-- Notification-fan-out pattern: "find unprocessed events for the digest"
-- (covered by the asset+time index above + WHERE observed_at > $cutoff).

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
-- Mirror asset_surface: authenticated reads everything, only service_role
-- writes (used by the importer + future scanner). The events are admin/
-- audit data — per-org scoping ships with the same iteration that scopes
-- the rest of the portal.

alter table public.asset_surface_event enable row level security;

create policy "asset_surface_event_select"
  on public.asset_surface_event
  for select
  to authenticated
  using (true);

-- No insert/update/delete policies — service_role bypasses RLS, which is
-- the only writer.
