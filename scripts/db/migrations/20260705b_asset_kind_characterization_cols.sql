-- ============================================================================
-- MIGRATION — 2026-07-05b — assets characterization columns + kind_conf_t
--
-- Part of the Host Characterization redesign (HOST_CHARACTERIZATION_SPEC.md,
-- Phase A). Adds the per-host derivation columns written by
-- scripts/normalize/derive_asset_kind.py.
--
-- Phase A is SCAN-BEHAVIOR-NEUTRAL (4.7 ruling 8): this file only creates the
-- column shape. NO backfill here — derive_asset_kind.py populates them; and
-- run_medium.py does NOT read them yet (that's Phase B).
--
-- Applied AFTER 20260705a. This file does NOT reference the new
-- 'redirect'/'dead' asset_kind_t values, so it is txn-safe (begin/commit).
-- kind_conf_t is CREATEd here and used in the same txn (allowed — the ADD
-- VALUE restriction applies only to pre-existing enums, not fresh CREATEs).
--
-- Columns (spec §4; 4.7 rulings 4, 5, 7; holes §5.7):
--   scan_url         resolved canonical/redirect target; set ONLY when the
--                    target is an owned asset (ROE guard, ruling 4). NULL else.
--   kind_confidence  TYPED enum kind_conf_t (high|medium|low), NOT text
--                    (ruling 7). NULL until derived.
--   kind_source      'derived' | 'manual'. manual NEVER overwritten by
--                    derivation; a high-confidence disagreement sets kind_drift.
--   kind_evidence    jsonb: signals used, STAMPED with surface_data.schema_
--                    version at derive time (ruling 7) so a discovery-schema
--                    change is detectable.
--   kind_updated_at  last derivation timestamp.
--   kind_drift       true when derived != manual AND derived confidence=high
--                    (ruling 5); portal-surfaced, NEVER auto-applied.
--   is_staging       non-prod MODIFIER, not a functional kind (hole §5.7). The
--                    4 assets currently kind='staging' re-derive to their
--                    functional kind + is_staging=true on next derivation.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260705b_asset_kind_characterization_cols.sql
--
-- Idempotent (CREATE TYPE guarded; ADD COLUMN IF NOT EXISTS; constraint guarded).
-- ============================================================================
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 200
-- notes: Host Characterization Phase A columns on public.assets (scan_url, kind_confidence kind_conf_t, kind_source, kind_evidence, kind_updated_at, kind_drift, is_staging) + guarded CREATE TYPE kind_conf_t. Ported to Command 2026-07-29 under 4.7 ruling Q1/Q3 (PR 1, inert). Original filename PRESERVED so compare_migrations.py sees set-parity. Additive only, no data DML, no ALTER TYPE — txn-safe.
-- END-META
-- ============================================================================
-- PORTED TO COMMAND 2026-07-29 (4.7 rulings Q1/Q3, PR 1 of 2).
--   Landed INERT: the modules that read these columns (derive_asset_kind.py,
--   dispatch.py, matrix_loader.py, surface_read.py) ship in the same PR but are
--   NOT wired into run_medium.py. Zero behaviour change on Command.
--   Filename deliberately UNCHANGED from Prodex: compare_migrations.py diffs
--   migration sets by basename, so renaming would make the sets permanently
--   unequal and the .migration-divergence.yaml entry undeletable.
--   MIGRATION-META added here — the Prodex original predates the ledger
--   (first META migration is 20260710a) and carries none.
-- ============================================================================

begin;

do $$ begin
  if not exists (select 1 from pg_type where typname = 'kind_conf_t') then
    create type public.kind_conf_t as enum ('high', 'medium', 'low');
  end if;
end $$;

alter table public.assets
  add column if not exists scan_url        text,
  add column if not exists kind_confidence public.kind_conf_t,
  add column if not exists kind_source     text        not null default 'derived',
  add column if not exists kind_evidence   jsonb,
  add column if not exists kind_updated_at timestamptz,
  add column if not exists kind_drift      boolean     not null default false,
  add column if not exists is_staging      boolean     not null default false;

-- kind_source is a closed 2-value set — enforce it (typed-column discipline).
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'assets_kind_source_chk') then
    alter table public.assets
      add constraint assets_kind_source_chk check (kind_source in ('derived','manual'));
  end if;
end $$;

comment on column public.assets.scan_url is
  'Resolved canonical/redirect target URL. Set ONLY when the target resolves '
  'to an ownership=owned asset (ROE guard, 4.7 ruling 4). NULL for off-scope '
  'redirect targets (shell-only scanning). Written by derive_asset_kind.py.';
comment on column public.assets.kind_confidence is
  'Typed derivation confidence (kind_conf_t: high|medium|low). NULL until '
  'derived. 4.7 ruling 7.';
comment on column public.assets.kind_source is
  'derived | manual. manual is never overwritten by derive_asset_kind.py; a '
  'high-confidence derived disagreement sets kind_drift instead (ruling 5).';
comment on column public.assets.kind_evidence is
  'jsonb: signals used to derive kind, stamped with surface_data.schema_version '
  'at derive time so a downstream discovery-schema change is detectable (ruling 7).';
comment on column public.assets.kind_drift is
  'True when derived kind != manual kind at high confidence (ruling 5). Portal-'
  'surfaced; NEVER auto-applied over a manual label.';
comment on column public.assets.is_staging is
  'Non-prod modifier (hole 5.7). staging is a modifier, not a functional kind. '
  'Assets currently kind=staging re-derive to functional kind + is_staging=true.';

-- Verification --------------------------------------------------------------
select 'new assets columns' as info, column_name, data_type, udt_name, is_nullable, column_default
  from information_schema.columns
 where table_schema='public' and table_name='assets'
   and column_name in ('scan_url','kind_confidence','kind_source','kind_evidence',
                       'kind_updated_at','kind_drift','is_staging')
 order by column_name;

select 'kind_conf_t values' as info,
       string_agg(e.enumlabel, ', ' order by e.enumsortorder) as labels
  from pg_type t join pg_enum e on e.enumtypid = t.oid
 where t.typname = 'kind_conf_t';

commit;
