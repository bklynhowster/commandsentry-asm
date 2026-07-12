-- 20260712a_asset_dark_debounce_p2.sql
-- P2 went-dark demotion writer — ADDITIVE FOUNDATION (columns + single-source read fn).
-- Spec: P2_DEMOTION_WRITER_BUILD_SPEC.md; extends ASSET_LIFECYCLE_SPEC.md v2 (R1-R6) +
-- WENT_DARK_OBSERVABILITY_SPEC.md v3 (Q1-Q10).
--
-- NON-DESTRUCTIVE. This migration adds four nullable indicator columns to public.assets,
-- the read-only function asset_dark_debounce_state(text), and the p2_demotion_dryrun
-- observation table. It writes NO asset state and demotes NOTHING. It is safe to apply
-- during the last_alive_at soak so the P4 portal indicator + the demotion writer can both
-- be developed/tested against a real function, and so the dry-run writer has a durable,
-- queryable place to record would-demote rows for the ~07-25 review.
--
-- 4.7 Q1/Q8 (single source of truth): asset_dark_debounce_state() is the ONE place the
-- fade/countdown is computed. BOTH the demotion writer (scripts/db/demotion_writer.py)
-- and the P4 portal indicator call it — same input, same output, drift impossible.
-- 4.7 Q4: countdown anchors on assets.last_alive_at (the writer's own trigger); the new
-- fade_detected_at is the "first noticed" AUDIT stamp, NOT the countdown anchor.
--
-- CONSTANTS PENDING 4.7 (§9 of the build spec): show threshold 72h (reused from the
-- existing detect_dark_assets DARK_THRESHOLD_HOURS), dwell D dns_gone=7 / service_gone=14 /
-- unreachable=HOLD. CREATE OR REPLACE makes any retune a one-line follow-up migration.
--
-- Splitter-safe (apply_pending_migrations.py::_split is single-quote-aware but NOT $$-aware):
-- each ALTER is its own statement; the function body is a SINGLE LANGUAGE sql statement with
-- NO ';' anywhere inside the $$...$$ and all single quotes balanced, so the top-level ';'
-- after the closing $$ splits cleanly. No DO blocks. Byte-identical in both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 250
-- notes: Adds 4 nullable fade columns (fade_detected_at, dark_reason, fade_dismissed_until, dark_patience_override_days) to public.assets + read-only asset_dark_debounce_state(text) single-source fade/countdown fn + p2_demotion_dryrun observation table (dry-run + shadow log with gate_state jsonb + write_enabled per 4.7 Q8). Non-destructive; writes no asset state. Constants (72h show, D 7/14, unreachable HOLD) 4.7-ratified; CREATE OR REPLACE = cheap retune. LANGUAGE sql single-stmt body, no internal semicolon (splitter-safe). Byte-identical both repos.
-- END-META

alter table public.assets add column if not exists fade_detected_at          timestamptz;
alter table public.assets add column if not exists dark_reason               text;
alter table public.assets add column if not exists fade_dismissed_until      timestamptz;
alter table public.assets add column if not exists dark_patience_override_days integer;

create or replace function public.asset_dark_debounce_state(p_asset_id text)
returns table(
  is_fading           boolean,
  dark_reason         text,
  fade_detected_at    timestamptz,
  age_hours           numeric,
  days_remaining      integer,
  writer_will_flip_at timestamptz
)
language sql
stable
as $$
  select
    (x.discovery_status = 'confirmed_live'
       and x.last_alive_at is not null
       and now() - x.last_alive_at >= interval '72 hours'
       and (x.fade_dismissed_until is null or x.fade_dismissed_until < now())) as is_fading,
    x.dark_reason,
    x.fade_detected_at,
    round(extract(epoch from (now() - x.last_alive_at)) / 3600.0, 1) as age_hours,
    case
      when x.dark_reason = 'unreachable' then null
      else greatest(0, ceil(extract(epoch from (x.last_alive_at + make_interval(days => x.d_days) - now())) / 86400.0))::int
    end as days_remaining,
    case
      when x.dark_reason = 'unreachable' then null
      else x.last_alive_at + make_interval(days => x.d_days)
    end as writer_will_flip_at
  from (
    select
      a.discovery_status,
      a.last_alive_at,
      a.dark_reason,
      a.fade_detected_at,
      a.fade_dismissed_until,
      coalesce(
        a.dark_patience_override_days,
        case a.dark_reason
          when 'dns_gone' then 7
          when 'unreachable' then 0
          else 14
        end
      ) as d_days
    from public.assets a
    where a.asset_id = p_asset_id
  ) x
$$;

comment on function public.asset_dark_debounce_state(text) is
  'P2 single source of truth (4.7 Q1/Q8): computes is_fading, dark_reason, days_remaining, writer_will_flip_at from assets.last_alive_at + fade fields. Called by BOTH demotion_writer.py and the P4 portal indicator so the badge can never disagree with when the writer flips. Constants pending 4.7 (72h show / D 7,14 / unreachable HOLD). Spec: P2_DEMOTION_WRITER_BUILD_SPEC.md.';

-- Dry-run + shadow observation log (4.7 Q8): the demotion writer records one row per fade
-- candidate per sweep here (writes NO asset state). would_demote=true means the writer WOULD
-- have flipped this asset this run; false = candidate held, hold_reason says why (within_dwell /
-- not_eligible_7d / rate_limited / reprobe_alive / reprobe_mixed_reason / unreachable_hold /
-- unknown_reason / sweep_unhealthy). gate_state jsonb captures the per-run sweep-health decision
-- (fraction_observed, non_cloud_fraction, consecutive_healthy, fleet_size, coverage_ok) so the
-- ~07-25 review can see WHY a run did/didn't demote. write_enabled records whether that run was
-- live (true) or dry-run (false) — the writer keeps logging here as a SHADOW even after
-- write-enable, so did-vs-would-have diffs surface regressions. Durable + queryable.
create table if not exists public.p2_demotion_dryrun (
  id                  uuid primary key default gen_random_uuid(),
  observed_at         timestamptz not null default now(),
  run_tag             text,
  sweep_healthy       boolean not null,
  asset_id            text not null,
  discovery_status    text,
  last_alive_at       timestamptz,
  age_hours           numeric,
  dark_reason         text,
  days_remaining      integer,
  writer_will_flip_at timestamptz,
  would_demote        boolean not null,
  hold_reason         text,
  gate_state          jsonb,
  write_enabled       boolean not null default false
);

create index if not exists idx_p2_demotion_dryrun_observed on public.p2_demotion_dryrun (observed_at desc);
create index if not exists idx_p2_demotion_dryrun_asset    on public.p2_demotion_dryrun (asset_id);

comment on table public.p2_demotion_dryrun is
  'P2 dry-run would-demote log (soak review before write-enable). Populated by demotion_writer.py in dry-run mode each 6h sweep; no asset state is changed. Spec: P2_DEMOTION_WRITER_BUILD_SPEC.md section 7.';
