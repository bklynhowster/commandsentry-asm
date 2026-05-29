-- ============================================================================
-- 20260529 — Extend the recompute function to also maintain current_risk_reason
-- ============================================================================
--
-- Background — what this fixes:
-- 20260527 introduced the auto-sync trigger for assets.current_risk. It works
-- great for the BADGE (the colored risk pill in the upper-right of asset
-- cards). But the headline UNDER the badge — assets.current_risk_reason,
-- the text that says "4 open findings (2 MODERATE, 1 LOW, 1 INFO); top:
-- Missing security header: HSTS" — is still NOT trigger-maintained.
--
-- It's set by Python posture_rollup.py via the JSONL import pipeline. The
-- Phase 4a Light scanner (and any direct SQL writes, ad-hoc imports,
-- sandbox probes) bypass that pipeline entirely, so the reason text drifts
-- the moment new findings land via any of those paths.
--
-- Surfaced 2026-05-29 morning: portal.unimacgraphics.com had 7 open
-- findings from new Light scans but the headline still said "4 open
-- findings (2 MODERATE, 1 LOW, 1 INFO)" — stale prose from the previous
-- enrichment.
--
-- This migration replaces recompute_asset_current_risk_for() with a
-- version that computes BOTH current_risk AND current_risk_reason in
-- one pass and writes them in a single atomic UPDATE. Wiring to the
-- existing trg_findings_sync_current_risk trigger is unchanged — the
-- trigger just calls the same function name and gets both columns
-- maintained for free now.
--
-- Reason text format mirrors what posture_rollup.py was producing AND
-- what the portal's AI enrichment was overwriting it with:
--
--   Zero findings ever  → NULL
--   Open findings exist → "N open finding(s) (counts breakdown); top: title"
--                         e.g. "7 open findings (4 MODERATE, 1 LOW, 2 INFO);
--                               top: DNS missing SPF record"
--   All resolved        → "All N previously-detected findings are resolved."
--
-- Severity mapping for the badge is unchanged — still pure worst-severity
-- of any open finding. The Python posture_rollup escalates to MODERATE-HIGH
-- when MODERATE >= 3; we deliberately do NOT replicate that here. Keeping
-- the verdict logic simple (worst severity wins) means the badge and the
-- reason agree, which is what users want.
-- ============================================================================

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
  -- Aggregate open-finding counts in one scan of the findings table.
  -- OPEN_STATUSES set matches the portal's OPEN_STATUSES constant + the
  -- 20260528c hotfix to the current_risk function.
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
  from public.findings
  where asset_id = p_asset_id
    and current_status in ('detected', 'confirmed', 'open', 'regressed');

  -- ──────────────────────────────────────────────────────────────────────
  -- Case 1: zero open findings.
  --   - If the asset has NO findings at all (historically too), reason
  --     is NULL — the AI enrichment may have written something else
  --     describing the asset itself ("v0 portal", "Cisco ASA endpoint",
  --     etc.) which we don't want to clobber. Setting NULL means "no
  --     active threat to summarize"; the UI falls back to other text.
  --   - If the asset HAD findings that are now all closed, give a
  --     positive signal that says so.
  -- ──────────────────────────────────────────────────────────────────────
  if v_total = 0 then
    v_risk := 'UNKNOWN'::risk_t;

    -- Was there ever a finding on this asset? If yes, celebrate the
    -- clean state. If no, leave the existing reason alone (probably
    -- AI-generated asset description).
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
        -- Leave whatever was there (could be AI-generated asset description).
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
  -- Case 2: there are open findings. Compute worst severity for the
  -- badge, top finding's title for the headline, and the per-severity
  -- breakdown.
  -- ──────────────────────────────────────────────────────────────────────

  -- Pull the worst-severity (and within that, most-recently-observed)
  -- open finding's severity + title in one query.
  select severity::text, title
    into v_worst_sev, v_top_title
  from public.findings
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

  -- Build the per-severity breakdown string — "4 MODERATE, 1 LOW, 2 INFO".
  -- Severities with zero count are omitted to keep the headline tight.
  v_breakdown := '';
  if v_critical  > 0 then v_breakdown := v_breakdown || v_critical  || ' CRITICAL, ';      end if;
  if v_high      > 0 then v_breakdown := v_breakdown || v_high      || ' HIGH, ';          end if;
  if v_mod_high  > 0 then v_breakdown := v_breakdown || v_mod_high  || ' MODERATE-HIGH, '; end if;
  if v_moderate  > 0 then v_breakdown := v_breakdown || v_moderate  || ' MODERATE, ';      end if;
  if v_low       > 0 then v_breakdown := v_breakdown || v_low       || ' LOW, ';           end if;
  if v_info      > 0 then v_breakdown := v_breakdown || v_info      || ' INFO, ';          end if;
  v_breakdown := regexp_replace(v_breakdown, ', $', '');

  -- Assemble the reason. Truncate the top title to 120 chars so the
  -- headline doesn't run past the card width on long nuclei titles.
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
  'Recompute an asset''s current_risk AND current_risk_reason in one '
  'atomic UPDATE from its open findings. Reason format: '
  '"N open finding(s) (severity breakdown); top: title". '
  'Open = current_status IN (detected, confirmed, open, regressed). '
  'Called by the trg_findings_sync_current_risk trigger.';

-- ----------------------------------------------------------------------------
-- ONE-TIME BACKFILL with before/after report
-- ----------------------------------------------------------------------------
-- Re-run the recompute over every asset so both columns are fresh under
-- the new logic. Reports the change count so we can spot-check.

do $$
declare
  r record;
  n_risk_changed   int := 0;
  n_reason_changed int := 0;
  n_total          int := 0;
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
    'Backfill complete: % of % assets · risk changed: % · reason changed: %',
    n_total, n_total, n_risk_changed, n_reason_changed;
end $$;
