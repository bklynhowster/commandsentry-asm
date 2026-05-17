-- Catch any cross-source duplicates that escaped run_normalize.py's dedup.
-- Should return zero rows after a clean import. If it returns anything,
-- the canonicalization step is broken.
SELECT
  asset_id,
  REGEXP_REPLACE(finding_id, '^(.+):(?:manual|curated):([A-Z]+-\d+)$', '\1:NAMED:\2') AS canonical_short,
  COUNT(*)                                                                            AS n,
  ARRAY_AGG(finding_id)                                                               AS dupes
FROM findings
WHERE finding_id ~ ':(manual|curated):'
GROUP BY 1, 2
HAVING COUNT(*) > 1
ORDER BY 1, 2;
