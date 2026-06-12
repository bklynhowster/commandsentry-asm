-- ============================================================================
-- MIGRATION — 2026-06-12 — Scanner degradation hardening (trigger + columns)
--
-- Specification:
--   ~/Downloads/ISMS Procedures/COMMANDsentry/SPEC_SCANNER_DEGRADATION_HARDENING.md
--
-- Triggers + columns + index + ce47fc27 finding backfill. The 'degraded'
-- enum label this references was added in 20260612a_add_degraded_enum.sql,
-- which MUST be committed before this migration runs (Postgres 55P04
-- forbids using a newly-added enum value in the same txn — see migration
-- 20260612a header for the why).
--
-- Apply order:
--   20260612a_add_degraded_enum.sql          (enum labels)
--   20260612b_scan_degradation.sql           ← THIS FILE
--   20260612c_retroflag_ce47fc27.sql         (ce47fc27 scan_run flip)
--
-- Contents:
--
--   1. Extend trg_scan_queue_sync_on_scan_run_terminal so 'degraded' on
--      scan_run also syncs to scan_queue. Without this, the queue row
--      hangs at 'running' forever for degraded runs and the partial
--      unique index scan_queue_one_running_per_asset blocks every
--      future scan on that asset.
--
--   2. findings.scan_quality: NEW column, CHECK (scan_quality IN
--      ('clean','degraded')). INDEPENDENT of validation_status. The
--      re-validation UPSERT must filter WHERE scan_quality='clean' so
--      degraded rows never flip to validated when the SHA is minted.
--
--   3. scan_run.rotation_log: NEW jsonb column. Forensics surface —
--      count, distinct egress IPs, ban events (cap 500), healthcheck
--      failures (cap 500), rotation_storm flag.
--
--   4. Backfill: stamp scan_quality='degraded' on the one known case —
--      ce47fc27's findings (today's nikto-FAIL row). Historical CTE
--      backfill explicitly NOT included per advisor ruling ①
--      (constrained version commented for future reference only).
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260612b_scan_degradation.sql
--
-- Idempotent.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Extend the sync trigger so 'degraded' on scan_run also syncs scan_queue
--    Without this, the queue row hangs at 'running' forever for degraded
--    runs and the partial unique index blocks future scans on the asset.
--
--    The function itself uses text cast for the round-trip so it works as
--    soon as both enums have 'degraded' (committed in 20260612a). Only the
--    WHEN clause changes here — the function body is untouched.
-- ---------------------------------------------------------------------------
drop trigger if exists trg_scan_queue_sync_on_scan_run_terminal
  on public.scan_run;

create trigger trg_scan_queue_sync_on_scan_run_terminal
  after update of status on public.scan_run
  for each row
  when (
    NEW.status in ('complete', 'failed', 'degraded')
    and OLD.status is distinct from NEW.status
    -- Restore the original 20260531a guard. Functional no-op (the
    -- function's WHERE self-protects on NULL queue_id) but recreating
    -- the trigger without this was unintended drift. The advisor catch
    -- here is the audit-record principle: the recreated DDL must match
    -- the original byte-for-byte except for the change being added.
    and NEW.queue_id is not null
  )
  execute function public.sync_scan_queue_on_scan_run_terminal();

comment on trigger trg_scan_queue_sync_on_scan_run_terminal on public.scan_run is
  'Self-heal sync: when scan_run reaches any terminal state '
  '(complete / failed / degraded), propagate to the matching scan_queue '
  'row so the partial unique index scan_queue_one_running_per_asset '
  'releases. Without this, a degraded scan_run would leave its queue '
  'row stuck at running and block all future scans on that asset.';

-- ---------------------------------------------------------------------------
-- 2. findings.scan_quality — INDEPENDENT of validation_status
-- ---------------------------------------------------------------------------
alter table public.findings
  add column if not exists scan_quality text
    not null default 'clean'
    check (scan_quality in ('clean', 'degraded'));

comment on column public.findings.scan_quality is
  'Quality of the scan_run that produced this finding. INDEPENDENT of '
  'validation_status. clean = produced by a scan_run that completed '
  'without any degradation event (no VPN failure, no target-unreachable '
  'after rotation, no tool_status gap). degraded = produced by a '
  'scan_run whose status was flipped to ''degraded''. The re-validation '
  'UPSERT must filter WHERE scan_quality=''clean'' — degraded findings '
  'must NEVER flip to validation_status=''validated'' when the SHA is '
  'minted. Junk does not launder. See SPEC_SCANNER_DEGRADATION_HARDENING.';

-- Partial index — supports the re-validation gate query
--   WHERE validation_status='unvalidated' AND scan_quality='clean'
-- on detected (open) findings.
create index if not exists findings_scan_quality_validation_idx
  on public.findings (scan_quality, validation_status)
  where current_status = 'detected';

-- ---------------------------------------------------------------------------
-- 3. scan_run.rotation_log — mid-scan forensics
-- ---------------------------------------------------------------------------
alter table public.scan_run
  add column if not exists rotation_log jsonb not null default '{}'::jsonb;

comment on column public.scan_run.rotation_log is
  'Mid-scan VPN rotation forensics. Schema: '
  '{count: int, distinct_egress_ips: text[], ban_events: [{at: ts, '
  'from_ip: text, to_ip: text, chunk: text}], healthcheck_failures: '
  '[{at: ts, attempt: int, after_chunk: text}], rotation_storm: bool}. '
  'Hard cap of 500 entries each on ban_events + healthcheck_failures '
  '(advisor ruling Q2 2026-06-12). When either cap is hit, runner sets '
  'rotation_storm=true and stops appending; the cap-hit itself is '
  'independent evidence of severe degradation. Populated by run_medium.py '
  'end-of-scan write. Forensics: every "why didn''t this find X" question '
  'reads this column instead of the GH Actions log.';

-- ---------------------------------------------------------------------------
-- 4. Backfill — ONLY the known ce47fc27 case (advisor ruling ① 2026-06-12)
--    Historical CTE backfill explicitly NOT performed; see migration header.
--    Belt + suspenders guards: only update unvalidated + currently-clean.
-- ---------------------------------------------------------------------------
update public.findings
   set scan_quality = 'degraded'
 where first_detected_scan = 'ce47fc27-d478-45c4-beac-bc2ba2c6be75'
   and validation_status   = 'unvalidated'  -- never flip a validated row
   and scan_quality        = 'clean';       -- idempotent

-- For reference if a constrained historical sweep is ever wanted later,
-- it MUST include BOTH guards below (the original spec CTE missed both):
--   AND sr.tool_status IS NOT NULL
--   AND sr.tool_status <> '{}'::jsonb       -- exclude pre-feature null era
--   AND f.validation_status = 'unvalidated' -- never flip validated rows
--   AND f.scan_quality      = 'clean'       -- idempotent
-- File it as a separate later migration, not as part of this one.

-- ---------------------------------------------------------------------------
-- 5. Verification — print state after apply for audit
-- ---------------------------------------------------------------------------
select 'trigger trg_scan_queue_sync_on_scan_run_terminal — exists?' as info,
       count(*) as exists_count
  from pg_trigger
 where tgname = 'trg_scan_queue_sync_on_scan_run_terminal';

select 'findings.scan_quality distribution' as info,
       scan_quality,
       count(*) as n
  from public.findings
 group by scan_quality
 order by scan_quality;

select 'scan_run.rotation_log column present' as info,
       count(*) filter (where rotation_log is not null) as nonnull_rows,
       count(*) as total_rows
  from public.scan_run;

select 'ce47fc27 finding backfill check' as info,
       count(*) filter (where scan_quality = 'degraded') as degraded_count,
       count(*) as total_findings_from_run
  from public.findings
 where first_detected_scan = 'ce47fc27-d478-45c4-beac-bc2ba2c6be75';

commit;

-- ============================================================================
-- Post-apply manual smoke tests:
--
--   1. Pre-mint sanity query should run cleanly AFTER 20260612c also lands:
--        SELECT scan_quality, count(*) FROM findings
--         WHERE scanner_version = '651140cb1c5b97107d1d41408f1c6eaf6bcc5a97'
--         GROUP BY scan_quality;
--      Expected: at least 1 row with (scan_quality='degraded') — the nikto-FAIL.
--
--   2. Re-validation gate query must EXCLUDE degraded rows:
--        SELECT count(*) FROM findings
--         WHERE scanner_version = :any_sha
--           AND validation_status = 'unvalidated'
--           AND scan_quality = 'clean';
--      Expected: only the clean+unvalidated rows for that SHA — degraded ones
--      stay invisible to the launderer.
--
--   3. Trigger sync test (do this AFTER 20260612c lands and ce47fc27.status
--      flips to 'degraded'): confirm the scan_queue row for ce47fc27 also
--      updated to status='degraded' via the trigger.
-- ============================================================================
