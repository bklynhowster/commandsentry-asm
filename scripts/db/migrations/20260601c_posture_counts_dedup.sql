-- ============================================================================
-- 20260601c_posture_counts_dedup.sql
-- ----------------------------------------------------------------------------
-- Phase B follow-up #3: dedup the dashboard PostureCard chip counts.
--
-- Background:
--   • Phase B set up v_open_findings_dedup as the source of truth for
--     "how many open findings does this asset have, deduped across sources."
--   • The asset detail page (commandsentry-portal) queries the view directly.
--   • assets.current_risk_reason text was dedup'd via 20260601b.
--   • The dashboard fleet view (one PostureCard per asset) still reads
--     v_asset_posture_counts, which JOINS to v_open_findings (raw, not
--     deduped). So every asset card on the dashboard shows inflated
--     numbers — same per-asset delta we just removed elsewhere.
--
-- Fix:
--   • Redefine v_asset_posture_counts to LEFT JOIN against
--     v_open_findings_dedup instead of v_open_findings.
--   • Inline the status filter into the JOIN clause since the dedup view
--     doesn't pre-filter (its grouped/ungrouped branches emit all statuses,
--     consumers filter as needed).
--   • COUNT(dedup_id) replaces COUNT(finding_id) — the dedup view exposes
--     dedup_id (which is either a normalized_key or a finding_id for
--     ungrouped singletons). For the LEFT JOIN no-match case, COUNT()
--     returns 0 either way because the joined row is NULL.
--
-- Intentionally NOT touching:
--   • v_dashboard_30d_metrics — "opened/closed in last 30d" is a velocity
--     metric. Each detection event is an event regardless of whether it
--     dedups into a group later. Raw counts are defensible there.
--   • Global /findings list — its job is to show every detection record;
--     deduping the global list would hide the audit trail.
--
-- Idempotent. CREATE OR REPLACE; no data changes.
-- ============================================================================

begin;

create or replace view public.v_asset_posture_counts as
select
  a.asset_id,
  a.name,
  a.organization,
  a.current_risk,
  count(f.dedup_id) filter (where f.severity = 'CRITICAL')      as critical_open,
  count(f.dedup_id) filter (where f.severity = 'HIGH')          as high_open,
  count(f.dedup_id) filter (where f.severity = 'MODERATE-HIGH') as mod_high_open,
  count(f.dedup_id) filter (where f.severity = 'MODERATE')      as moderate_open,
  count(f.dedup_id) filter (where f.severity = 'LOW')           as low_open,
  count(f.dedup_id) filter (where f.severity = 'INFO')          as info_open,
  count(f.dedup_id)                                              as total_open
from public.assets a
left join public.v_open_findings_dedup f
  on f.asset_id = a.asset_id
  and f.current_status in ('detected', 'confirmed', 'open', 'regressed')
group by a.asset_id, a.name, a.organization, a.current_risk;

comment on view public.v_asset_posture_counts is
  'Per-asset open severity rollup, DEDUPED across sources (Phase B, 2026-06-01). '
  'A cross-source group counts as one finding with the worst severity of its '
  'members. Drives the dashboard PostureCard chips. To see raw per-source '
  'detection counts, query v_open_findings or findings directly.';

-- Grant unchanged — view perms inherited from prior CREATE OR REPLACE.
grant select on public.v_asset_posture_counts to authenticated;

commit;

-- ----------------------------------------------------------------------------
-- Spot-check after applying:
--
-- 1. Compare deduped vs raw open counts per asset:
--    SELECT
--      d.asset_id,
--      d.total_open                              AS deduped_total,
--      (SELECT COUNT(*) FROM v_open_findings r
--        WHERE r.asset_id = d.asset_id)          AS raw_total,
--      (SELECT COUNT(*) FROM v_open_findings r
--        WHERE r.asset_id = d.asset_id)
--        - d.total_open                          AS rows_collapsed
--    FROM v_asset_posture_counts d
--    WHERE d.total_open > 0
--    ORDER BY rows_collapsed DESC NULLS LAST;
--
--    Expect CMI to show ~9 rows collapsed (58 raw → 49 deduped).
-- ----------------------------------------------------------------------------
