-- ============================================================================
-- 20260527 — Auto-sync assets.current_risk with worst open finding
-- ============================================================================
--
-- BACKGROUND: assets.current_risk is a denormalized column that, until now,
-- was only kept in sync by whatever code path INSERTed findings. Manual SQL
-- writes, ad-hoc imports, and (eventually) the Phase 4a scan runner all
-- bypass that sync. Surfaced 2026-05-27 when a sandbox probe inserted
-- 4 findings on portal.unimacgraphics.com but its tile on /attack-surface
-- still showed UNKNOWN.
--
-- This migration kills that whole class of drift bug by:
--   1. Function recompute_asset_current_risk_for(asset_id) — recomputes
--      ONE asset's risk from its open findings. Sets UNKNOWN when there
--      are no open findings.
--   2. Trigger on findings (INSERT/UPDATE/DELETE) that calls the function
--      for the affected asset(s). UPDATE handles asset_id changes by
--      recomputing both OLD and NEW asset_ids.
--   3. One-time backfill at the end that fixes any drift already present
--      in the fleet.
--
-- SEVERITY → RISK MAPPING:
--   CRITICAL severity      → CRITICAL risk
--   HIGH severity          → HIGH risk
--   MODERATE-HIGH severity → MODERATE-HIGH risk
--   MODERATE severity      → MODERATE risk
--   LOW severity           → LOW risk
--   INFO severity          → INFO risk
--   (no open findings)     → UNKNOWN risk
-- ============================================================================

-- ----------------------------------------------------------------------------
-- FUNCTION: recompute_asset_current_risk_for(asset_id)
-- ----------------------------------------------------------------------------
-- Sets the given asset's current_risk to the severity of its worst-severity
-- open finding (or UNKNOWN if it has no open findings).
-- SECURITY DEFINER so triggers can update the assets table even when the
-- session role is restricted.

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
      and f.current_status = 'open'
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
  'Called by the trg_findings_sync_current_risk trigger.';

-- ----------------------------------------------------------------------------
-- TRIGGER FUNCTION
-- ----------------------------------------------------------------------------
-- Routes INSERT/UPDATE/DELETE on findings to the recompute function.
-- UPDATEs that change asset_id recompute BOTH the old and new asset's risk.
-- All other UPDATEs and INSERT/DELETE recompute the one affected asset.

create or replace function public.findings_sync_current_risk()
returns trigger
language plpgsql
as $$
begin
  if (tg_op = 'DELETE') then
    perform public.recompute_asset_current_risk_for(old.asset_id);
    return old;
  elsif (tg_op = 'UPDATE') then
    if (new.asset_id is distinct from old.asset_id) then
      perform public.recompute_asset_current_risk_for(old.asset_id);
    end if;
    perform public.recompute_asset_current_risk_for(new.asset_id);
    return new;
  else -- INSERT
    perform public.recompute_asset_current_risk_for(new.asset_id);
    return new;
  end if;
end;
$$;

-- ----------------------------------------------------------------------------
-- TRIGGER
-- ----------------------------------------------------------------------------
-- AFTER trigger so we fire on the committed row state. Row-level so we
-- handle batch operations correctly (one fire per row, but the function
-- short-circuits when nothing meaningful changed since we just recompute
-- from scratch each time — cheap enough at fleet scale).

drop trigger if exists trg_findings_sync_current_risk on public.findings;
create trigger trg_findings_sync_current_risk
  after insert or update or delete on public.findings
  for each row
  execute function public.findings_sync_current_risk();

comment on trigger trg_findings_sync_current_risk on public.findings is
  'Auto-sync assets.current_risk with the worst severity of open findings. '
  'Eliminates drift between the denormalized column and the findings table.';

-- ----------------------------------------------------------------------------
-- ONE-TIME BACKFILL
-- ----------------------------------------------------------------------------
-- Fix any existing drift in the fleet. This is idempotent — re-running is
-- safe.

do $$
declare
  r record;
  n_changed int := 0;
begin
  for r in select asset_id, current_risk::text as before from public.assets loop
    perform public.recompute_asset_current_risk_for(r.asset_id);
  end loop;

  select count(*) into n_changed
  from public.assets a
  join (select asset_id, current_risk from public.assets) b
    on a.asset_id = b.asset_id
  where a.current_risk is distinct from b.current_risk;

  raise notice 'Backfill complete. assets.current_risk synced.';
end $$;
