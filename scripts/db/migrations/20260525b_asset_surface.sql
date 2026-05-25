-- ============================================================================
-- 20260525b — Asset surface (ASM-shape inventory data)
-- ============================================================================
--
-- Adds the data layer for the Surface tab on /assets/[asset_id] — answers
-- "what IS this asset" (services, ports, ASN, hosting org, reverse DNS,
-- subdomains, cert info) alongside the Posture tab's "what's WRONG with it"
-- (findings, claims, remediation).
--
-- Required by Phase 3 Design Principle #7 — Posture vs Surface as separate
-- views. The asset detail page footer already says "Surface tab arrives at
-- M3" — this is M3.
--
-- Howie 2026-05-25 EOD ask: IP-type assets currently look "empty" on the
-- dashboard because the portal only renders findings. They're not empty —
-- they have ASM-shape inventory data in
--   ~/Downloads/ISMS Procedures/COMMANDsentry/data/assets/*.json
-- but the portal never imports it. This schema is the destination.
--
-- v1 scope: one table (asset_surface) with a JSONB blob for the full ASM
-- shape plus convenience columns for the queries we actually care about.
-- Denormalized service-level table (asset_open_services) deferred until
-- cross-asset port queries become a real need — Surface tab UI only needs
-- the JSONB.
--
-- Spec: Obsidian / COMMANDsentry / 38 - Session Log 2026-05-25.md
--       (Surface tab queued item)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: asset_surface
-- ----------------------------------------------------------------------------
-- One row per asset. Populated by the importer (legacy ASM JSON → here)
-- on initial backfill, then continuously refreshed by future cloud scans.
--
-- Convenience columns are denormalized FROM surface_data for filtering
-- + dashboard-list display. Treat them as read-only projections of the
-- blob; the importer rewrites them on every refresh.

create table if not exists public.asset_surface (
  asset_id                text primary key
                          references public.assets(asset_id) on delete cascade,

  -- Asset-shape (denormalized convenience)
  asset_type              text,            -- 'ip' | 'apex' | 'fqdn' | 'cidr' | 'asn'
  alive                   boolean,         -- true if any subdomain reachable

  -- Hosting context — these are the columns Howie's "what is this machine"
  -- question needs at a glance.
  top_hosting_org         text,            -- 'Cablevision Systems Corp.', 'Amazon Technologies Inc.'
  platforms               text[]  not null default '{}',
                                           -- ['Microsoft .NET / IIS', 'WordPress 6.9.1']
  primary_asn             text,            -- 'AS6128', 'AS16509' — single string,
                                           -- many assets only have one
  primary_ptr             text,            -- '189d3344.cst.lightpath.net' — reverse DNS
                                           -- of the primary IP

  -- Inventory counts (denormalized from summary)
  subdomain_count         integer not null default 0,
  live_subdomain_count    integer not null default 0,
  host_count              integer not null default 0,
  service_count           integer not null default 0,
  newest_cert_expiry_days integer,         -- nullable; only set for HTTPS-enabled

  -- Provenance + lifecycle
  discovered_via          text,            -- 'manual' | 'subdomain_enum' | 'dns_sweep' | 'ct_log' | etc.
  first_discovered        timestamptz,
  last_seen               timestamptz,

  -- Full ASM blob — subdomains[], services[], hosts[], dns, waf, certs,
  -- fingerprint, history. The UI reads this for the Surface tab's deep
  -- views (service table, subdomain tree, cert details, etc.).
  surface_data            jsonb   not null default '{}'::jsonb,

  -- Bookkeeping
  updated_at              timestamptz not null default now(),
  updated_by              text                       -- 'legacy_asm_import' | 'cloud_scanner_v1' | etc.
);

comment on table public.asset_surface is
  'ASM-shape inventory data per asset (what IS this machine). Complements '
  'the findings table (what is WRONG with it). Read by the Surface tab on '
  '/assets/[asset_id]. Populated by the importer that reads legacy ASM '
  'JSON, and eventually by the cloud scanner directly.';

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------
-- Most reads are per-asset (PK lookup, already covered). Cross-asset
-- queries we want to support:
--   - "show me all assets at AS6128" (admin/audit)
--   - "show me everything Cablevision is hosting" (admin/audit)
--   - "show me assets I haven't seen in 30+ days" (staleness)
--   - "show me alive vs not-alive" (posture rollup)

create index if not exists idx_asset_surface_hosting
  on public.asset_surface (top_hosting_org);

create index if not exists idx_asset_surface_asn
  on public.asset_surface (primary_asn);

create index if not exists idx_asset_surface_alive
  on public.asset_surface (alive)
  where alive = true;

create index if not exists idx_asset_surface_last_seen
  on public.asset_surface (last_seen desc nulls last);

create index if not exists idx_asset_surface_updated
  on public.asset_surface (updated_at desc);

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
-- Mirror the findings/assets policy:
--   - authenticated users CAN read all rows (RLS is the portal's primary
--     gate; per-org scoping ships in a later iteration)
--   - no direct INSERT/UPDATE/DELETE from authenticated — only service_role
--     (used by the importer + the cloud scanner) writes here

alter table public.asset_surface enable row level security;

create policy "asset_surface_select"
  on public.asset_surface
  for select
  to authenticated
  using (true);

-- No insert/update/delete policies — service_role bypasses RLS, which is
-- the only writer.
