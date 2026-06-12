-- ============================================================================
-- MIGRATION — 2026-06-12 — Add 'degraded' to scan_run_status_t + scan_status_t
--
-- Specification:
--   ~/Downloads/ISMS Procedures/COMMANDsentry/SPEC_SCANNER_DEGRADATION_HARDENING.md
--
-- This migration ONLY adds the new enum labels. The trigger update, new
-- columns, indexes, and finding backfill all live in 20260612b, which
-- references the new 'degraded' label in its CREATE TRIGGER WHEN clause
-- (`NEW.status in ('complete', 'failed', 'degraded')`).
--
-- WHY THIS IS A SEPARATE FILE (advisor catch ① 2026-06-12):
--   Postgres forbids using a newly-added enum value in the same
--   transaction that defined it (error 55P04 "unsafe use of new value
--   of enum type"). The original consolidated 20260612a_scan_degradation
--   bundled BOTH `ALTER TYPE ... ADD VALUE 'degraded'` AND
--   `CREATE TRIGGER ... WHEN (NEW.status in ('degraded'))` in one
--   begin/commit, which fails at trigger-create time because the WHEN
--   clause coerces 'degraded' to the enum at parse time.
--
--   Split so the enum value is COMMITTED before anything references it.
--   The split is forced by Postgres, not by stylistic preference.
--
-- Companion migrations (apply in order):
--   20260612a_add_degraded_enum.sql           ← THIS FILE (enum only)
--   20260612b_scan_degradation.sql            ← trigger + columns + backfill
--   20260612c_retroflag_ce47fc27.sql          ← ce47fc27 scan_run flip
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260612a_add_degraded_enum.sql
--
-- Idempotent.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- Add 'degraded' to scan_run_status_t (the narrow execution-state enum used
-- by scan_run.status). Values pre-existing: 'running', 'complete', 'failed'.
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (
    select 1
      from pg_enum e
      join pg_type t on t.oid = e.enumtypid
     where t.typname = 'scan_run_status_t'
       and e.enumlabel = 'degraded'
  ) then
    alter type public.scan_run_status_t add value 'degraded';
  end if;
end$$;

-- ---------------------------------------------------------------------------
-- Add 'degraded' to scan_status_t (the wider queue lifecycle enum used by
-- scan_queue.status). Values pre-existing: 'queued', 'running', 'complete',
-- 'failed', 'canceled'.
--
-- Both enums need the label because the trg_scan_queue_sync_on_scan_run_
-- terminal trigger (extended in 20260612b) text-casts scan_run.status
-- through scan_status_t when propagating to scan_queue. Without 'degraded'
-- on scan_status_t too, the cast would fail at sync time.
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (
    select 1
      from pg_enum e
      join pg_type t on t.oid = e.enumtypid
     where t.typname = 'scan_status_t'
       and e.enumlabel = 'degraded'
  ) then
    alter type public.scan_status_t add value 'degraded';
  end if;
end$$;

-- ---------------------------------------------------------------------------
-- Verification — confirm both labels are present before allowing the next
-- migration to reference them.
-- ---------------------------------------------------------------------------
select 'enum scan_run_status_t labels' as info,
       array_agg(enumlabel order by enumsortorder) as labels
  from pg_enum e
  join pg_type t on t.oid = e.enumtypid
 where t.typname = 'scan_run_status_t';

select 'enum scan_status_t labels' as info,
       array_agg(enumlabel order by enumsortorder) as labels
  from pg_enum e
  join pg_type t on t.oid = e.enumtypid
 where t.typname = 'scan_status_t';

commit;
