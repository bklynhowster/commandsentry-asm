-- ============================================================================
-- 20260713c — cloud-endpoint column parity (ports 20260707b/c columns to Prodex)
-- ============================================================================
--
-- The cloud classifier (20260707b cloud_endpoint cols + 20260707c cloud_drift)
-- was Command-first. Prodex only got `is_cloud_endpoint` (parity add 20260712b),
-- so `cloud_provider` / `cloud_source` / `cloud_endpoint_classified_at` /
-- `cloud_drift` were absent — which is why the device-class runner's cloud read
-- crashed on Prodex, and why the ported cloud classifier would have nowhere to
-- stamp. This adds the remaining columns so Prodex can classify its own (GCP)
-- cloud endpoints. Provenance: Howie's 2026-07-13 Prodex-first shift.
--
-- BYTE-IDENTICAL both repos: add-if-not-exists is a clean NO-OP on Command (the
-- columns already exist there via 20260707b/c — the adds are skipped, and
-- Command's `cloud_provider` stays its `cloud_provider_t` ENUM); it adds the
-- columns on Prodex.
--
-- DELIBERATE DIVERGENCE: Prodex `cloud_provider` is TEXT, not the `cloud_provider_t`
-- enum. Idempotent enum creation needs a do-block the migration splitter cannot
-- parse (not dollar-quote aware), so text keeps this migration idempotent +
-- splitter-safe. Functionally identical — derive_cloud_endpoint stores the same
-- provider-id strings, bounded by scripts/asm/cloud_providers.yaml.
--
-- Additive, idempotent, splitter-safe (no do-blocks, no ';' in strings, no '--'
-- in string literals).
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 80
-- notes: Cloud-endpoint column parity — adds cloud_provider (text) / cloud_source / cloud_endpoint_classified_at / cloud_drift. No-op on Command (exist via 20260707b/c); adds on Prodex. Byte-identical both repos, splitter-safe, idempotent.
-- END-META
-- ============================================================================

alter table public.assets
  add column if not exists cloud_provider               text,
  add column if not exists cloud_source                 text not null default 'derived'
    check (cloud_source in ('derived','manual')),
  add column if not exists cloud_endpoint_classified_at timestamptz,
  add column if not exists cloud_drift                  boolean not null default false;

comment on column public.assets.cloud_provider is
  'Managed cloud/CDN provider id from derive_cloud_endpoint (null until classified). '
  'Command: cloud_provider_t enum (20260707b). Prodex: text, same provider-id '
  'strings, bounded by cloud_providers.yaml. Documented instance divergence.';
