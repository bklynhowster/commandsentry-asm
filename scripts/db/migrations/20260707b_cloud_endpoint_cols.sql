-- ============================================================================
-- MIGRATION — 2026-07-07b — cloud-endpoint modifier columns
--
-- Part of the cloud/rotating-endpoint change-tracking fix (4.7 rulings D6-D10,
-- V3_GUARD_AND_CLOUD_ENDPOINT_SPEC.md). A cloud/CDN-fronted asset (O365 mail,
-- Cloudflare/Akamai edge, etc.) rotates across a large IP pool by design, so
-- tracking it per-IP produces mass churn alerts — the 2026-07-07 "95 surface
-- change(s)" email on email.commandcompanies.com (31 O365 IPs "removed" + 64
-- mail-port "closed", host still up). These columns let the alerter SUPPRESS
-- per-IP surface changes for classified cloud endpoints and track them by
-- DNS name / CNAME target / cert instead.
--
-- Modifier, NOT a functional kind (4.7 D8) — mirrors is_staging. An O365 mail
-- endpoint is kind='mail' AND is_cloud_endpoint=true.
--
-- Columns:
--   is_cloud_endpoint            bool — suppress per-IP change tracking when true
--   cloud_provider               enum — which managed provider (null until classified)
--   cloud_source                 'derived' | 'manual' — a MANUAL flag is NEVER
--                                auto-overwritten by the classifier (4.7 D9,
--                                mirrors kind_source/kind_drift): a high-confidence
--                                disagreement is surfaced for review, never auto-flipped.
--   cloud_endpoint_classified_at timestamptz — last classification time; enables
--                                the weekly re-eval cadence (4.7 D6).
--
-- Idempotent (CREATE TYPE guarded; ADD COLUMN IF NOT EXISTS; constraint guarded).
-- Txn-safe: cloud_provider_t is CREATEd here and used in the same txn (allowed —
-- the ADD VALUE restriction applies only to pre-existing enums).
--
-- APPLY (both instances, Command + Prodex, for parity):
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260707b_cloud_endpoint_cols.sql
--   -- or paste the block below into the Supabase SQL editor and Run.
-- ============================================================================

begin;

do $$ begin
  if not exists (select 1 from pg_type where typname = 'cloud_provider_t') then
    create type public.cloud_provider_t as enum
      ('microsoft_o365', 'cloudflare', 'akamai', 'aws', 'azure', 'gcp', 'other');
  end if;
end $$;

alter table public.assets
  add column if not exists is_cloud_endpoint            boolean     not null default false,
  add column if not exists cloud_provider               public.cloud_provider_t,
  add column if not exists cloud_source                 text        not null default 'derived',
  add column if not exists cloud_endpoint_classified_at timestamptz;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'assets_cloud_source_chk') then
    alter table public.assets
      add constraint assets_cloud_source_chk check (cloud_source in ('derived','manual'));
  end if;
end $$;

commit;

-- ============================================================================
-- SANITY — after apply:
--   select column_name from information_schema.columns
--    where table_schema='public' and table_name='assets'
--      and (column_name like 'cloud%' or column_name='is_cloud_endpoint')
--    order by 1;
--   -- expect: cloud_endpoint_classified_at, cloud_provider, cloud_source, is_cloud_endpoint
--   select unnest(enum_range(null::public.cloud_provider_t));
-- ============================================================================
