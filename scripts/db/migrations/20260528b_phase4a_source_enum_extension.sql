-- ============================================================================
-- 20260528b — Phase 4a finding_source_t enum extension
-- ============================================================================
--
-- Extends finding_source_t with three new values so the Phase 4a tier-
-- specific scanners (Light / Medium / Heavy) can identify the source of
-- the finding distinctly from the existing scanner-specific sources
-- (nuclei, zap, sqlmap, etc.) and the legacy 'commandsentry_asm' which
-- referred to the passive ASM Discover pipeline.
--
-- WHY THREE VALUES instead of one:
--   • UI filtering by tier ("show me everything Heavy tier surfaced")
--   • Tracking per-tier signal-to-noise ratio
--   • Different remediation SLAs may apply per tier (Heavy findings often
--     warrant a faster turnaround than Light header recommendations)
--
-- ADDITIVE ONLY. Existing source values are unchanged. Existing findings
-- rows with source IN (...) continue to work.
--
-- This migration must be applied BEFORE running run_light.py (or any
-- Medium/Heavy runners that follow), otherwise INSERTs fail with:
--   InvalidTextRepresentation: invalid input value for enum
--   finding_source_t: "commandsentry_light"
--
-- Apply:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260528b_phase4a_source_enum_extension.sql
-- ============================================================================

do $$
begin
  if not exists (
    select 1 from pg_enum
    where enumlabel = 'commandsentry_light'
      and enumtypid = (select oid from pg_type where typname = 'finding_source_t')
  ) then
    alter type public.finding_source_t add value 'commandsentry_light';
  end if;
end $$;

do $$
begin
  if not exists (
    select 1 from pg_enum
    where enumlabel = 'commandsentry_medium'
      and enumtypid = (select oid from pg_type where typname = 'finding_source_t')
  ) then
    alter type public.finding_source_t add value 'commandsentry_medium';
  end if;
end $$;

do $$
begin
  if not exists (
    select 1 from pg_enum
    where enumlabel = 'commandsentry_heavy'
      and enumtypid = (select oid from pg_type where typname = 'finding_source_t')
  ) then
    alter type public.finding_source_t add value 'commandsentry_heavy';
  end if;
end $$;

-- ============================================================================
-- POST-APPLY VERIFICATION
-- ============================================================================
--   select enumlabel from pg_enum
--   where enumtypid = (select oid from pg_type where typname = 'finding_source_t')
--   order by enumsortorder;
--
-- Expected to include the three new values at the end:
--   commandsentry_light, commandsentry_medium, commandsentry_heavy
-- ============================================================================
