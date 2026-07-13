-- ============================================================================
-- 20260713a — Asset device-class + fronting relationship + WAF-efficacy source
-- ============================================================================
--
-- Phase A foundation for the device-class + WAF-aware scan-routing design
-- (spec ASSET_DEVICE_CLASS_AND_WAF_ROUTING_SPEC.md, 4.7-ruled D1-D7 2026-07-13).
-- SCHEMA ONLY. Writes nothing, classifies nothing, routes nothing. This lands
-- the columns/table/enum-value so the classifier (next increment) and the
-- 14-day Phase A soak can begin without further migration churn.
--
-- Provenance: the Heavy Phase 1 net-depth pilot proved ftp.sciimage.com's
-- external surface is the SCI/Fortinet EDGE appliance (24.157.51.76), not the
-- origin. That topology fact belongs on the asset and must drive scan routing.
--
-- Orthogonal to assets.kind (asset_kind_t = FUNCTION: web/portal/api/mail/...).
-- device_class = TOPOLOGY ROLE (origin vs edge_firewall vs waf vs cdn ...). A
-- kind=web asset can be device_class=waf-fronted; the two axes do not overlap.
--
-- Two deliberate deviations from the spec's illustrative SQL:
--   * asset_fronting FKs are TEXT (assets.asset_id is text, not uuid).
--   * device_class is text + CHECK, not a CREATE TYPE enum: idempotent enum
--     creation needs a do-block the migration splitter cannot parse (it is not
--     dollar-quote aware). Text + CHECK is idempotent, splitter-safe, and
--     evolves without ALTER TYPE ceremony. Matches the confidence columns.
--
-- Default device_class is 'unknown' (4.7 D2): absence of evidence must NOT be
-- read as origin_host. Only positive evidence asserts a class. Only a CONFIRMED
-- class may ever change scan routing (4.7 D3) — enforced later in classifier
-- code + classifier_thresholds.yaml, not here.
--
-- Additive, idempotent, splitter-safe (no do-blocks, no ';' inside strings,
-- no '--' inside string literals). Byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 150
-- notes: Additive device-class (assets.device_class text+CHECK + confidence + evidence jsonb + vendor_product) + asset_fronting (many-to-many, TEXT FKs) + scan_run.origin_direct + finding_source_t += waf_efficacy (unused in-migration, 55P04-safe). Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- assets — device-class attribute (topology role) + confidence + evidence
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists device_class text not null default 'unknown'
    check (device_class in ('origin_host','edge_firewall','waf','adc_lb','cdn','cloud_endpoint','unknown')),
  add column if not exists device_class_confidence text not null default 'unknown'
    check (device_class_confidence in ('confirmed','suspected','unknown')),
  add column if not exists device_class_evidence jsonb,
  add column if not exists vendor_product jsonb;

comment on column public.assets.device_class is
  'Topology role of the device that answers for this asset externally: '
  'origin_host, edge_firewall, waf, adc_lb, cdn, cloud_endpoint, or unknown. '
  'Orthogonal to assets.kind (function). Default unknown; only positive '
  'evidence asserts a class, and only a confirmed class changes scan routing.';

comment on column public.assets.device_class_confidence is
  'confirmed / suspected / unknown, per the multi-signal thresholds in '
  'classifier_thresholds.yaml (4.7 D3). Only confirmed changes routing.';

comment on column public.assets.device_class_evidence is
  'jsonb array of the signals that drove the class + confidence (ssh banner, '
  'wafw00f verdict, fwbbot_check hit, cert issuer/CN, ip-range match, service '
  'pattern), each with an observed_at so freshness gating can drop stale signals.';

comment on column public.assets.vendor_product is
  'jsonb sub-field, orthogonal to device_class: vendor, product, version, '
  'build (e.g. Fortinet / FortiGate). Populated when a product is identified.';

-- ----------------------------------------------------------------------------
-- asset_fronting — hostname -> edge device -> origin(s), many-to-many (4.7 D1)
-- ----------------------------------------------------------------------------
-- An edge can front many origins (backend pool); a hostname can have many
-- edges (DNS round-robin); origin may be unknown while the edge is identified.
-- invalidated_at (not delete) preserves history when a relationship shifts.
create table if not exists public.asset_fronting (
  fronting_id       uuid primary key default gen_random_uuid(),
  hostname_asset_id text not null references public.assets(asset_id) on delete cascade,
  edge_asset_id     text not null references public.assets(asset_id) on delete cascade,
  origin_asset_id   text references public.assets(asset_id) on delete set null,
  evidence          jsonb not null default '{}'::jsonb,
  confidence        text not null default 'suspected'
    check (confidence in ('confirmed','suspected','unknown')),
  discovered_at     timestamptz not null default now(),
  invalidated_at    timestamptz
);

comment on table public.asset_fronting is
  'Fronting relationships: a hostname asset reached externally via an edge '
  'device, optionally forwarding to an origin behind it. Many-to-many. '
  'invalidated_at marks a relationship that a re-scan proved changed, '
  'preserving history rather than deleting it.';

create index if not exists idx_asset_fronting_hostname
  on public.asset_fronting(hostname_asset_id) where invalidated_at is null;
create index if not exists idx_asset_fronting_edge
  on public.asset_fronting(edge_asset_id) where invalidated_at is null;

-- ----------------------------------------------------------------------------
-- scan_run — label the vantage (through-WAF vs origin-direct) (4.7 D5)
-- ----------------------------------------------------------------------------
alter table public.scan_run
  add column if not exists origin_direct boolean not null default false;

comment on column public.scan_run.origin_direct is
  'true = scan reached the origin directly (internal vantage or WAF allowlist), '
  'so findings are app truth; false = through-the-WAF (attacker view + WAF '
  'efficacy). origin_direct findings are excluded from external-facing risk '
  'metrics and must verify WAF-absence at scan start (4.7 D5).';

-- ----------------------------------------------------------------------------
-- finding_source_t += waf_efficacy (4.7 D6) — register now, phase lands later
-- ----------------------------------------------------------------------------
-- Cheap forward-compat: one enum label now vs a data migration later. The
-- run_waf_efficacy_phase + producer-map ('waf-bypass-*') come in a later build;
-- this only makes the source usable so WAF-gap findings never get filed as
-- origin app vulns.
alter type public.finding_source_t add value if not exists 'waf_efficacy';
