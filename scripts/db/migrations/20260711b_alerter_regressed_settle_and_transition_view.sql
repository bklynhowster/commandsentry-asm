-- 20260711b_alerter_regressed_settle_and_transition_view.sql
-- Fix the "regressed-forever" mislabel. Spec: ALERTER_REGRESSED_SEMANTICS_SPEC.md
-- (4.7-verified 2026-07-11, Q1-Q7 applied). Byte-identical on both scanner repos.
--
-- Root cause: `regressed` is a sticky status (regress_observed flips remediated→regressed
-- once, nothing ever settles it), so the per-scan finding_history logger re-stamps
-- 'regressed' every scan and v_alerter_changes fires REGRESSED on every observation.
--
-- This migration ships the DDL half (Fix 1 data lifecycle + Fix 2 alerter view). The
-- scanner half (call settle in the close-out; stamp last_regressed_at after
-- regress_observed) rides the run_medium/run_heavy change in the same push.
--
-- Objects (all splitter-safe — the ledger applier's _split is single-quote aware but
-- NOT dollar-quote aware, so settle is LANGUAGE sql with a SINGLE cte statement, and the
-- view/backfill carry no internal semicolons):
--   1. findings.last_regressed_at  — preserves the "was regressed" signal for the portal
--      after a finding settles to confirmed (Q4). NOTE: risk/posture are UNAFFECTED by
--      the settle — every consumer keys on the open-set ('detected','confirmed','open',
--      'regressed') which treats regressed == confirmed, so no score/count moves.
--   2. index finding_history(finding_id, observed_at) — for the view's LAG window (Q5).
--   3. settle_regressed_for_scan_run(scan_run, source) — sibling of regress_observed:
--      a previously-regressed finding re-observed this scan → confirmed (+audit). Called
--      BEFORE regress_observed in the clean close-out (Q3), so only PRIOR-scan
--      regressions settle; this scan's fresh regressions are produced afterward.
--   4. v_alerter_changes reworked to fire on LAG-based TRANSITIONS, not observations
--      (Q5). REGRESSED only on the flip INTO regressed; CONFIRMED/CONFIRMED_HIGH only on
--      a real transition INTO confirmed/open — a settle (regressed→confirmed) fires
--      NOTHING (the load-bearing rule, anchor-tested against the live OCSP finding: 5
--      regressed history rows → exactly 1 REGRESSED).
--   5. Backfill: settle existing stuck-regressed findings observed in the last 30 days
--      (Q6 scope — don't resurrect genuinely-stale ones), audited per row.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 600
-- notes: last_regressed_at col + finding_history LAG index + settle_regressed_for_scan_run (LANGUAGE sql single-stmt) + v_alerter_changes transition-only rework + 30-day-scoped audited backfill. All statements splitter-safe (no dollar-quoted body has internal semicolons). Byte-identical both repos.
-- END-META

alter table public.findings add column if not exists last_regressed_at timestamptz;

create index if not exists idx_finding_history_finding_observed
  on public.finding_history (finding_id, observed_at);

create or replace function public.settle_regressed_for_scan_run(p_scan_run_id text, p_source text)
returns integer
language sql
as $$
  with targets as (
    select f.finding_id,
           f.asset_id,
           f.source::text         as source,
           f.current_status::text as old_status
      from public.findings f
     where f.source::text = p_source
       and f.current_status = 'regressed'
       and f.last_seen_scan_run = p_scan_run_id
     for update
  ),
  upd as (
    update public.findings f
       set current_status = 'confirmed',
           updated_at     = now()
      from targets t
     where f.finding_id = t.finding_id
    returning f.finding_id
  ),
  aud as (
    insert into public.admin_audit_log
      (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
    select
      null, 'auto_settle_regressed', null, null,
      jsonb_build_object('current_status', t.old_status),
      jsonb_build_object('current_status', 'confirmed'),
      jsonb_build_object('finding_id', t.finding_id, 'asset_id', t.asset_id,
                         'source', t.source, 'scan_run_id', p_scan_run_id,
                         'rule', 'settle_regressed_for_scan_run_v1')
      from targets t
    returning 1
  )
  select count(*)::integer from upd
$$;

comment on function public.settle_regressed_for_scan_run(text, text) is
  'Alerter regressed-semantics fix (spec 2026-07-11): sibling of regress_observed_for_scan_run. A finding that is currently regressed AND was re-observed by this scan_run (last_seen_scan_run match) is settled to confirmed — regressed becomes a one-scan transition state, not sticky. Call BEFORE regress_observed in the clean close-out only (a degraded scan is not trustworthy evidence of presence).';

create or replace view v_alerter_changes as
with hist as (
  select
    fh.finding_id,
    fh.scan_id,
    fh.observed_at,
    fh.status,
    lag(fh.status) over (partition by fh.finding_id order by fh.observed_at, fh.id) as prev_status
  from public.finding_history fh
)
select
  f.finding_id,
  f.asset_id,
  f.title,
  f.severity,
  f.current_status,
  f.source,
  h.scan_id,
  h.observed_at as event_at,
  h.status      as event_status,
  case
    when h.status = 'regressed'
         and h.prev_status is distinct from 'regressed'
      then 'REGRESSED'
    when h.status in ('confirmed', 'open')
         and h.prev_status is distinct from 'confirmed'
         and h.prev_status is distinct from 'open'
         and h.prev_status is distinct from 'regressed'
         and f.severity in ('CRITICAL', 'HIGH', 'MODERATE-HIGH')
      then 'CONFIRMED_HIGH'
    when h.status in ('confirmed', 'open')
         and h.prev_status is distinct from 'confirmed'
         and h.prev_status is distinct from 'open'
         and h.prev_status is distinct from 'regressed'
      then 'CONFIRMED'
    else null
  end as alert_kind
from hist h
join public.findings f on f.finding_id = h.finding_id
where (h.status = 'regressed'
       and h.prev_status is distinct from 'regressed')
   or (h.status in ('confirmed', 'open')
       and h.prev_status is distinct from 'confirmed'
       and h.prev_status is distinct from 'open'
       and h.prev_status is distinct from 'regressed');

with targets as (
  select f.finding_id,
         f.asset_id,
         f.source::text         as source,
         f.current_status::text as old_status,
         (select max(fh.observed_at)
            from public.finding_history fh
           where fh.finding_id = f.finding_id
             and fh.status = 'regressed') as regressed_at
    from public.findings f
   where f.current_status = 'regressed'
     and f.last_observed_at > now() - interval '30 days'
   for update
),
upd as (
  update public.findings f
     set current_status    = 'confirmed',
         last_regressed_at  = coalesce(f.last_regressed_at, t.regressed_at, now()),
         updated_at         = now()
    from targets t
   where f.finding_id = t.finding_id
  returning f.finding_id
),
aud as (
  insert into public.admin_audit_log
    (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
  select
    null, 'auto_settle_regressed_backfill', null, null,
    jsonb_build_object('current_status', t.old_status),
    jsonb_build_object('current_status', 'confirmed'),
    jsonb_build_object('finding_id', t.finding_id, 'asset_id', t.asset_id,
                       'source', t.source, 'rule', 'settle_regressed_backfill_v1')
    from targets t
  returning 1
)
select count(*) from upd;
