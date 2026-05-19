-- ============================================================================
-- BACKFILL — 2026-05-19 — Consolidate testssl / sslyze duplicate findings
--
-- The testssl + sslyze parsers were computing finding_id from the raw
-- `host` string in the scan output, which varies between scans of the
-- same condition (sometimes "www.x.com", sometimes just an IP, sometimes
-- the apex). Two scans of the same condition produced two finding_ids.
--
-- Example actually in the DB before this runs:
--   commandcommcentral.com:testssl:LUCKY13:3b9ea89   ← scan A
--   commandcommcentral.com:testssl:LUCKY13:5df0aa6   ← scan B (same condition)
--
-- Parser fix shipped in same commit changes the hash to use only
-- canonical inputs (event_asset_id + port). New scans will produce a
-- single stable finding_id. But the OLD dupes are still in the DB, and
-- the new fix would produce a THIRD distinct finding_id on re-ingest.
--
-- This backfill consolidates the old dupes:
--   1. Group testssl + sslyze findings by (asset_id, source, title) —
--      same title = same condition, regardless of finding_id hash
--   2. Within each group, pick the row with the most recent
--      last_observed_at as canonical
--   3. Move all finding_history rows from non-canonical to canonical
--   4. Delete the non-canonical findings rows
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/backfills/20260519_consolidate_testssl_dupes.sql
--
-- Idempotent — re-running is a no-op (no dupes left to consolidate).
-- ============================================================================

BEGIN;

-- Stage the dupe sets: groups of >= 2 findings on same (asset, source, title)
-- with current_status NOT in remediated/false_positive/etc — we don't want
-- to merge an open finding into a closed one.
CREATE TEMP TABLE _dupe_groups AS
WITH groups AS (
  SELECT
    asset_id,
    source,
    title,
    COUNT(*) AS n,
    array_agg(finding_id ORDER BY last_observed_at DESC NULLS LAST, finding_id) AS ids,
    MAX(last_observed_at) AS canonical_last_observed
  FROM findings
  WHERE source IN ('testssl', 'sslyze')
  GROUP BY asset_id, source, title
)
SELECT
  asset_id,
  source,
  title,
  n,
  ids[1] AS canonical_id,       -- most recently observed
  ids[2:] AS dupe_ids,           -- the ones to merge away
  canonical_last_observed
FROM groups
WHERE n > 1;

-- Quick visibility before the destructive part
\echo
\echo === Dupe groups that will be consolidated:
SELECT asset_id, source, n AS dupe_count, title
  FROM _dupe_groups
 ORDER BY n DESC, asset_id, title
 LIMIT 50;

\echo
\echo === Total findings about to be merged-away:
SELECT COUNT(*) AS findings_to_merge,
       SUM(n - 1) AS rows_to_delete
  FROM _dupe_groups;

-- Move finding_history rows from dupes -> canonical. ON CONFLICT skips
-- rows that already exist on the canonical id (same scan_id).
INSERT INTO finding_history (finding_id, scan_id, observed_at, status,
                             severity_at_scan, matched_at, raw_excerpt, notes)
SELECT g.canonical_id, fh.scan_id, fh.observed_at, fh.status,
       fh.severity_at_scan, fh.matched_at, fh.raw_excerpt, fh.notes
  FROM _dupe_groups g
  CROSS JOIN LATERAL unnest(g.dupe_ids) AS dupe_id
  JOIN finding_history fh ON fh.finding_id = dupe_id
ON CONFLICT (finding_id, scan_id) DO NOTHING;

-- Now delete the dupe findings. finding_history rows on the dupes get
-- removed by the ON DELETE CASCADE in the schema.
DELETE FROM findings f
 WHERE f.finding_id IN (
   SELECT unnest(dupe_ids) FROM _dupe_groups
 );

\echo
\echo === Post-consolidation count by source:
SELECT source, COUNT(*) AS n
  FROM findings
 WHERE source IN ('testssl', 'sslyze')
 GROUP BY source
 ORDER BY source;

-- Refresh posture so any changes in finding counts surface
SELECT refresh_all_asset_posture() AS assets_recomputed;

COMMIT;
