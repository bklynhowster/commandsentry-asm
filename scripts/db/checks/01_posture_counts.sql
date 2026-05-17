-- Reproduce the dashboard's per-asset severity-by-status breakdown.
-- Compare against run_normalize.py's bottom-of-output summary.
SELECT
  asset_id,
  critical_open AS "C",
  high_open     AS "H",
  mod_high_open AS "MH",
  moderate_open AS "M",
  low_open      AS "L",
  info_open     AS "I",
  total_open    AS "total"
FROM v_asset_posture_counts
ORDER BY
  critical_open DESC,
  high_open     DESC,
  mod_high_open DESC,
  moderate_open DESC,
  asset_id;
