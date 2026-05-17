-- The Howie smoke test:
-- commandcommcentral.com should currently show exactly 4 MODERATE open findings
-- (M-01, M-02, M-03, M-04). Curated baseline shows 2 (M-02, M-03); the delta
-- is a known status-tracking refinement.
SELECT
  finding_id,
  title,
  current_status,
  severity,
  source,
  first_detected_at::date,
  last_observed_at::date
FROM findings
WHERE asset_id = 'commandcommcentral.com'
  AND severity = 'MODERATE'
ORDER BY finding_id;
