-- ============================================================================
-- 20260601b_current_risk_reason_dedup.sql
-- ----------------------------------------------------------------------------
-- Phase B follow-up: switch recompute_asset_current_risk_for() to count
-- from v_open_findings_dedup (deduped) instead of raw public.findings.
--
-- Background:
--   • 2026-06-01 morning: Phase B portal switch shipped — the asset
--     detail page now renders dedup groups from v_open_findings_dedup.
--   • 2026-06-01 afternoon: portal header still showed inflated count.
--     CMI rendered 49 deduped rows in the body but the headline prose
--     "58 open findings (2 HIGH, 16 MODERATE, ...)" was server-persisted
--     in assets.current_risk_reason from the prior raw count.
--   • Root cause: recompute_asset_current_risk_for() (added 20260529)
--     aggregates from public.findings, not from the new dedup view.
--
-- Fix:
--   • Replace the function's count and top-finding queries with view
--     queries. Same OPEN_STATUSES filter; same severity-rank ordering;
--     same breakdown string format. Only the source table changes.
--   • One-time backfill at end re-runs the function for every asset so
--     all existing current_risk_reason text refreshes immediately.
--
-- The historical-count branch (Case 1, v_total=0) intentionally keeps
-- counting against raw findings — its purpose is to detect "this asset
-- HAD findings, all closed now" and that requires the full historical
-- denominator, not the dedup view's open-only window.
--
-- Idempotent. Safe to re-run — CREATE OR REPLACE + backfill is harmless.
-- ============================================================================

begin;

create or replace function public.recompute_asset_current_risk_for(p_asset_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_total      int;
  v_critical   int;
  v_high       int;
  v_mod_high   int;
  v_moderate   int;
  v_low        int;
  v_info       int;
  v_worst_sev  text;
  v_top_title  text;
  v_breakdown  text;
  v_reason     text;
  v_risk       risk_t;
begin
  -- Aggregate DEDUPED open-finding counts. The v_open_findings_dedup view
  -- collapses (asset_id, normalized_key) groups so a cross-source merge
  -- counts as one row not N. Each group's severity is the worst severity
  -- of its members — exactly what should drive the badge + chips.
  select
    count(*)::int,
    count(*) filter (where severity = 'CRITICAL')::int,
    count(*) filter (where severity = 'HIGH')::int,
    count(*) filter (where severity = 'MODERATE-HIGH')::int,
    count(*) filter (where severity = 'MODERATE')::int,
    count(*) filter (where severity = 'LOW')::int,
    count(*) filter (where severity = 'INFO')::int
  into
    v_total, v_critical, v_high, v_mod_high, v_moderate, v_low, v_info
  from public.v_open_findings_dedup
  where asset_id = p_asset_id
    and current_status in ('detected', 'confirmed', 'open', 'regressed');

  -- ──────────────────────────────────────────────────────────────────────
  -- Case 1: zero open findings (deduped).
  --
  -- Historical count still queries raw findings — we want the full
  -- denominator ("all 12 previously-detected findings are resolved")
  -- not the dedup window's view of history.
  -- ──────────────────────────────────────────────────────────────────────
  if v_total = 0 then
    v_risk := 'UNKNOWN'::risk_t;

    declare
      v_historical_count int;
    begin
      select count(*)::int into v_historical_count
      from public.findings
      where asset_id = p_asset_id;

      if v_historical_count > 0 then
        v_reason := 'All ' || v_historical_count
                    || ' previously-detected finding'
                    || case when v_historical_count = 1 then '' else 's' end
                    || ' are resolved.';
      else
        update public.assets
        set current_risk = v_risk
        where asset_id = p_asset_id;
        return;
      end if;
    end;

    update public.assets
    set current_risk        = v_risk,
        current_risk_reason = v_reason
    where asset_id = p_asset_id;
    return;
  end if;

  -- ──────────────────────────────────────────────────────────────────────
  -- Case 2: open findings exist. Worst severity + top title also pulled
  -- from the deduped view so the "top: ..." prose matches what the user
  -- sees rendered as the first row of the open-findings list.
  -- ──────────────────────────────────────────────────────────────────────
  select severity::text, title
    into v_worst_sev, v_top_title
  from public.v_open_findings_dedup
  where asset_id = p_asset_id
    and current_status in ('detected', 'confirmed', 'open', 'regressed')
  order by
    case severity
      when 'CRITICAL'      then 0
      when 'HIGH'          then 1
      when 'MODERATE-HIGH' then 2
      when 'MODERATE'      then 3
      when 'LOW'           then 4
      when 'INFO'          then 5
    end,
    coalesce(last_observed_at, first_detected_at) desc nulls last
  limit 1;

  v_risk := v_worst_sev::risk_t;

  -- Per-severity breakdown — "2 HIGH, 4 MODERATE, 1 LOW, 2 INFO".
  v_breakdown := '';
  if v_critical  > 0 then v_breakdown := v_breakdown || v_critical  || ' CRITICAL, ';      end if;
  if v_high      > 0 then v_breakdown := v_breakdown || v_high      || ' HIGH, ';          end if;
  if v_mod_high  > 0 then v_breakdown := v_breakdown || v_mod_high  || ' MODERATE-HIGH, '; end if;
  if v_moderate  > 0 then v_breakdown := v_breakdown || v_moderate  || ' MODERATE, ';      end if;
  if v_low       > 0 then v_breakdown := v_breakdown || v_low       || ' LOW, ';           end if;
  if v_info      > 0 then v_breakdown := v_breakdown || v_info      || ' INFO, ';          end if;
  v_breakdown := regexp_replace(v_breakdown, ', $', '');

  v_reason := v_total
              || ' open finding'
              || case when v_total = 1 then '' else 's' end
              || ' (' || v_breakdown || ')';

  if v_top_title is not null and v_top_title <> '' then
    v_reason := v_reason || '; top: ' || left(v_top_title, 120);
  end if;

  update public.assets
  set current_risk        = v_risk,
      current_risk_reason = v_reason
  where asset_id = p_asset_id;
end;
$$;

comment on function public.recompute_asset_current_risk_for(text) is
  'Phase B (2026-06-01): recompute asset current_risk + current_risk_reason '
  'using DEDUPED counts from v_open_findings_dedup. A cross-source merge '
  'counts as one row with the worst severity of its members. Format: '
  '"N open finding(s) (severity breakdown); top: title". Open = current_status '
  'IN (detected, confirmed, open, regressed). Called by trigger '
  'trg_findings_sync_current_risk on findings table mutations.';

-- ----------------------------------------------------------------------------
-- ONE-TIME BACKFILL — refresh every asset's reason text with deduped counts.
-- ----------------------------------------------------------------------------
do $$
declare
  r record;
  n_total          int := 0;
  n_risk_changed   int := 0;
  n_reason_changed int := 0;
begin
  create temporary table _pre_state on commit drop as
    select asset_id,
           current_risk::text       as risk_before,
           current_risk_reason      as reason_before
    from public.assets;

  for r in select asset_id from public.assets loop
    perform public.recompute_asset_current_risk_for(r.asset_id);
    n_total := n_total + 1;
  end loop;

  select
    count(*) filter (where a.current_risk::text is distinct from p.risk_before),
    count(*) filter (where a.current_risk_reason is distinct from p.reason_before)
  into n_risk_changed, n_reason_changed
  from public.assets a
  join _pre_state p on a.asset_id = p.asset_id;

  raise notice
    'Phase B reason-text backfill complete: % assets processed · risk changed: % · reason changed: %',
    n_total, n_risk_changed, n_reason_changed;
end $$;

commit;
