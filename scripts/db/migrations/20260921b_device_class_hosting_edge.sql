-- ============================================================================
-- 20260921b — device_class += hosting_edge (relay 414 Axis 1)
-- ============================================================================
--
-- ⛔ WHAT WAS WRONG. Automattic/Pressable assets classified `cdn`, and `cdn`
-- silently EXCLUDED them from enforcement verification ("a CDN caches;
-- enforcement is not its job"). But an Automattic managed-WordPress edge is not
-- a passive cache: it terminates TLS, actively mediates traffic to an origin
-- Automattic also operates, and it 403-filters for abuse. The only other value
-- that would have put it in the population was `waf`, which OVER-CLAIMS a
-- configured security policy that does not exist. Neither is true, so the
-- taxonomy gained the value that is.
--
--   * hosting_edge — a managed-hosting provider's OWN edge. Renders
--     "Fronted by <vendor>", NEVER "Protected by". Distinct from `cdn`
--     (passive caching), from `cloud_endpoint` (raw IaaS — where the asset
--     RUNS, not something in front of it), and from `waf` / `edge_firewall`
--     (security appliances enforcing a configured policy).
--
-- ⚠ WHETHER ENFORCEMENT IS TESTABLE IS A SEPARATE AXIS AND NOT THIS COLUMN'S
-- JOB (relay 414 Axis 2). Population membership is derived from the enforcement
-- MECHANISM — scripts/scanner/enforcement_mechanism.py and its portal mirror
-- src/lib/enforcement-mechanism.mjs — not from a hardcoded class list. A
-- hosting_edge resolves `rate_behavioral`: it IS in the population, and the
-- honest verdict there today is "not verified — no applicable detector", never
-- "not enforcing".
--
-- ⚠ ADDITIVE AND INERT ON ITS OWN. Nothing classifies as hosting_edge until the
-- matching code lands (the two Automattic rows in device_fingerprints.yaml) AND
-- a classifier pass runs. This migration only WIDENS a CHECK; it changes no row,
-- no routing, and cannot reclassify anything by itself. Deploy order is
-- therefore safe either way: applying this before the code is a no-op, and the
-- code without this would be rejected by the CHECK rather than writing a bad
-- value.
--
-- ⚠ RE-SOAK (relay 414 O4, 4.7's ruling). cdn -> hosting_edge is a
-- RECLASSIFICATION, not the additive no-reset case: routing changes for the
-- affected (Automattic x-ac) assets, so the anti-flap soak clock is reset for
-- them by bumping --soak-generation on the next device_class_runner pass. That
-- is an operator step, NOT part of this migration — schema changes must not
-- quietly move a soak clock. Belt-and-suspenders regardless, since --write
-- stays Howie's.
--
-- notes: Taxonomy only. Widens assets_device_class_check to accept
-- 'hosting_edge' (relay 414 Axis 1 — managed-hosting edge, distinct from cdn
-- which excluded it from enforcement verification and from waf which would have
-- over-claimed a policy). No code, no data change, no routing change, no row
-- rewritten. Constraint name matches 20260806a. Splitter-safe, idempotent,
-- byte-identical both repos.
-- ============================================================================

begin;

-- ----------------------------------------------------------------------------
-- 1. assets.device_class — add 'hosting_edge'
-- ----------------------------------------------------------------------------
-- Rebuilt rather than ALTERed because Postgres has no "add value to a CHECK".
-- Dropping by the exact name 20260806a created keeps this idempotent and keeps
-- the constraint's identity stable across both instances.
alter table public.assets drop constraint if exists assets_device_class_check;

alter table public.assets add constraint assets_device_class_check
  check (device_class in (
    'origin_host','edge_firewall','waf','adc_lb','cdn','cloud_endpoint',
    'hosting_edge','unknown','unreadable'
  ));

comment on column public.assets.device_class is
  'Fronting-device classification. hosting_edge = a managed-hosting provider''s '
  'OWN edge: it terminates TLS and actively mediates traffic to an origin the '
  'same provider operates, and its filtering is abuse/rate protection rather '
  'than a configured security policy. Renders "Fronted by", never "Protected '
  'by". Distinct from cdn (passive caching), cloud_endpoint (where the asset '
  'runs), and waf/edge_firewall (a policy-enforcing appliance). Whether '
  'enforcement can be TESTED is a separate axis — see enforcement_mechanism. '
  'unknown means evidence was gathered and nothing matched, so the asset is '
  'empirically unclassifiable. unreadable means evidence collection FAILED and '
  'we could not determine anything. It is a transient input failure, not a '
  'verdict. The two are distinct so that unreadable can never overwrite a '
  'positive classification (4.7 G1, Obsidian 169/170). Anything reading this '
  'column must treat unreadable as no-information, NOT as a classification.';

-- ----------------------------------------------------------------------------
-- 2. device_class_dryrun.device_class — the audit twin
-- ----------------------------------------------------------------------------
-- The dry-run table records what the classifier WOULD write. If its CHECK does
-- not also accept hosting_edge, every dry-run pass over an Automattic asset
-- fails to record its verdict — and the dry-run is precisely where this class
-- lives until Howie runs --write. Guarded: only rebuild if the constraint is
-- actually present, so this stays safe on an instance that never had it.
do $$
begin
  if exists (
    select 1 from pg_constraint
     where conname = 'device_class_dryrun_device_class_check'
  ) then
    alter table public.device_class_dryrun
      drop constraint device_class_dryrun_device_class_check;
    alter table public.device_class_dryrun
      add constraint device_class_dryrun_device_class_check
      check (device_class in (
        'origin_host','edge_firewall','waf','adc_lb','cdn','cloud_endpoint',
        'hosting_edge','unknown','unreadable'
      ));
  end if;
end $$;

commit;
