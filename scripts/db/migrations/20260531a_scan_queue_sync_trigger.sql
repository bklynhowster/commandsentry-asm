-- ============================================================================
-- 20260531a_scan_queue_sync_trigger.sql
-- ----------------------------------------------------------------------------
-- Phase 4a operational fix — keep `scan_queue.status` in sync with
-- `scan_run.status` automatically.
--
-- Why: STEP 2 of the PATIENT_MODE / CRAWL_FIRST experiment chain (see
-- Obsidian note 64) ate ~90 min today to stale `scan_queue` rows blocking
-- re-fires via `scan_queue_one_running_per_asset` unique constraint.
-- Root cause investigation: `run_medium.py::close_out()` DOES issue
-- `CLOSE_SCAN_QUEUE_SQL`, but the row stayed 'running' anyway — either
-- silent exception, missed close_out path, or stale connection commit gap.
--
-- Rather than chasing the proximate cause in Python (where it could
-- recur in any future code path that mutates scan_run without remembering
-- the queue), make the database self-heal:
--
--   scan_run.status → 'complete' or 'failed'  ===>
--     trigger fires  ===>
--       scan_queue (matching queue_id) → same terminal state
--
-- This is the same pattern as `assets.current_risk` auto-sync trigger
-- (migration 20260527) — invariant enforced at the DB layer, drift
-- impossible regardless of application bugs.
--
-- ============================================================================

set check_function_bodies = off;

-- ----------------------------------------------------------------------------
-- Function: sync_scan_queue_on_scan_run_terminal
-- ----------------------------------------------------------------------------
-- Fires after scan_run.status transitions to a terminal state ('complete'
-- or 'failed'). Updates the matching scan_queue row (via scan_run.queue_id
-- FK) to the same status, plus completed_at / duration / findings_count /
-- error_message synced from scan_run.
--
-- Only acts on queue rows still in 'running' status to avoid stomping on
-- queue rows that were explicitly cancelled or already cleaned up via
-- some other path.
-- ----------------------------------------------------------------------------

create or replace function public.sync_scan_queue_on_scan_run_terminal()
returns trigger
language plpgsql
security definer
as $$
declare
  new_queue_status public.scan_status_t;
begin
  -- scan_run_status_t and scan_status_t are different enum types that happen
  -- to share string values. Cast via text.
  new_queue_status := NEW.status::text::public.scan_status_t;

  update public.scan_queue
     set status           = new_queue_status,
         completed_at     = coalesce(NEW.completed_at, now()),
         duration_seconds = coalesce(
                              NEW.duration_seconds,
                              extract(epoch from (now() - started_at))::int
                            ),
         findings_count   = coalesce(
                              NEW.findings_added + NEW.findings_updated,
                              findings_count
                            ),
         error_message    = coalesce(NEW.error_message, error_message),
         notes            = coalesce(notes, '')
                         || ' [auto-sync from scan_run terminal trigger '
                         || to_char(now(), 'YYYY-MM-DD HH24:MI:SS')
                         || ']'
   where queue_id   = NEW.queue_id
     and status     = 'running';

  return NEW;
end $$;

comment on function public.sync_scan_queue_on_scan_run_terminal() is
  'Phase 4a self-heal: when scan_run reaches terminal, sync matching '
  'scan_queue row so the unique constraint scan_queue_one_running_per_asset '
  'doesn''t block re-fires due to application-layer bugs in close_out.';

-- ----------------------------------------------------------------------------
-- Trigger wiring
-- ----------------------------------------------------------------------------
-- AFTER UPDATE so we observe the committed terminal state. WHEN clause
-- filters the fire path to only transitions INTO a terminal state — no-op
-- for updates that don't change status, no-op for queue_id IS NULL
-- (orphan scan_run with no parent queue row).
-- ----------------------------------------------------------------------------

drop trigger if exists trg_scan_queue_sync_on_scan_run_terminal
  on public.scan_run;

create trigger trg_scan_queue_sync_on_scan_run_terminal
  after update of status on public.scan_run
  for each row
  when (
    NEW.status in ('complete', 'failed')
    and OLD.status is distinct from NEW.status
    and NEW.queue_id is not null
  )
  execute function public.sync_scan_queue_on_scan_run_terminal();

-- ----------------------------------------------------------------------------
-- Backfill: heal any existing drift right now
-- ----------------------------------------------------------------------------
-- For every scan_run that's already in terminal state but whose scan_queue
-- row is still 'running', sync them. One-shot cleanup so future re-fires
-- aren't blocked by today's drift.
-- ----------------------------------------------------------------------------

update public.scan_queue q
   set status           = sr.status::text::public.scan_status_t,
       completed_at     = coalesce(sr.completed_at, now()),
       duration_seconds = coalesce(
                            sr.duration_seconds,
                            extract(epoch from (now() - q.started_at))::int
                          ),
       findings_count   = coalesce(
                            sr.findings_added + sr.findings_updated,
                            q.findings_count
                          ),
       error_message    = coalesce(sr.error_message, q.error_message),
       notes            = coalesce(q.notes, '')
                       || ' [backfill 20260531a — synced from scan_run terminal]'
  from public.scan_run sr
 where sr.queue_id   = q.queue_id
   and sr.status    in ('complete', 'failed')
   and q.status      = 'running';

-- ----------------------------------------------------------------------------
-- Verification view (optional, useful for spot-checks)
-- ----------------------------------------------------------------------------

create or replace view public.v_scan_queue_drift as
select
  q.queue_id,
  q.asset_id,
  q.status               as queue_status,
  sr.status              as run_status,
  q.triggered_at         as queue_triggered_at,
  q.started_at           as queue_started_at,
  q.completed_at         as queue_completed_at,
  sr.completed_at        as run_completed_at,
  case
    when q.status = 'running' and sr.status in ('complete', 'failed')
      then 'DRIFT — queue still running, run terminal'
    when q.status in ('complete', 'failed') and sr.status = 'running'
      then 'DRIFT — queue terminal, run still running'
    when q.status::text != sr.status::text
      then 'STATUS_MISMATCH'
    else 'OK'
  end                    as drift_state
from public.scan_queue q
left join public.scan_run sr using (queue_id)
where sr.scan_run_id is not null;

comment on view public.v_scan_queue_drift is
  'Diagnostic view: shows any scan_queue row whose status disagrees with '
  'its matching scan_run.status. After 20260531a, drift_state should be '
  'OK for all completed runs.';
