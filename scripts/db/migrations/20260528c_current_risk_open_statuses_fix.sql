-- ============================================================================
-- 20260528c — Widen current_risk trigger to all open statuses
-- ============================================================================
--
-- HOTFIX for 20260527_assets_current_risk_trigger.sql.
--
-- BUG: recompute_asset_current_risk_for() only matched current_status = 'open'.
-- But the findings table actually uses four "open" statuses:
--   - detected    (default for newly-discovered findings — what Phase 4a
--                  Light scans write)
--   - confirmed   (a human or automation has verified the finding)
--   - open        (legacy / generic open state)
--   - regressed   (a previously-remediated finding came back)
--
-- The portal already treats all four as open via OPEN_STATUSES in
-- src/app/assets/[asset_id]/page.tsx, but the DB trigger didn't agree.
-- Result: portal.unimacgraphics.com had 7 open findings from the Phase 4a
-- Light scanner but its current_risk stayed at UNKNOWN because every one
-- of those 7 was status='detected', not 'open'.
--
-- This migration:
--   1. Replaces the function with the widened IN (...) check.
--   2. Re-runs the backfill so every asset's current_risk is recomputed
--      against the correct open-status set. Idempotent.
-- ============================================================================

create or replace function public.recompute_asset_current_risk_for(p_asset_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.assets a
  set current_risk = coalesce((
    select f.severity::text::risk_t
    from public.findings f
    where f.asset_id = p_asset_id
      -- WIDENED 2026-05-28: was current_status = 'open' which missed
      -- 'detected' (the default for new findings written by Phase 4a
      -- Light scans), 'confirmed', and 'regressed'. Match the portal's
      -- OPEN_STATUSES set.
      and f.current_status in ('detected', 'confirmed', 'open', 'regressed')
    order by
      case f.severity
        when 'CRITICAL'      then 0
        when 'HIGH'          then 1
        when 'MODERATE-HIGH' then 2
        when 'MODERATE'      then 3
        when 'LOW'           then 4
        when 'INFO'          then 5
      end
    limit 1
  ), 'UNKNOWN'::risk_t)
  where a.asset_id = p_asset_id;
end;
$$;

comment on function public.recompute_asset_current_risk_for(text) is
  'Recompute a single asset''s current_risk from its open findings. '
  'Open = current_status IN (detected, confirmed, open, regressed). '
  'Called by the trg_findings_sync_current_risk trigger.';

-- ----------------------------------------------------------------------------
-- ONE-TIME BACKFILL with before/after report
-- ----------------------------------------------------------------------------
-- Snapshot current_risk before, recompute every asset, then report on the
-- net change. Verifies the migration did something visible and gives us a
-- count to spot-check.

do $$
declare
  r record;
  n_changed int := 0;
  n_total int := 0;
begin
  create temporary table _pre_risk on commit drop as
    select asset_id, current_risk::text as risk_before
    from public.assets;

  for r in select asset_id from public.assets loop
    perform public.recompute_asset_current_risk_for(r.asset_id);
    n_total := n_total + 1;
  end loop;

  select count(*) into n_changed
  from public.assets a
  join _pre_risk p on a.asset_id = p.asset_id
  where a.current_risk::text is distinct from p.risk_before;

  raise notice 'current_risk backfill complete: % of % assets changed.',
    n_changed, n_total;
end $$;
