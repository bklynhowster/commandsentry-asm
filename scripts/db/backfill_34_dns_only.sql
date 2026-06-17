-- ===========================================================================
-- #34 Gate #1 backfill — reclassify resolve-but-no-service phantoms
--   confirmed_live + service_count=0  →  dns_only
--
-- Pairs with the promotion-gate change in import_asm_to_surface.py (same PR
-- unit — do NOT run this without that change live, or the next asm-discover
-- cycle re-stamps these rows confirmed_live and they boomerang back into the
-- alerts. The gate makes the reclassify STICK.)
--
-- Run STEP 1 (dry-run) first and eyeball the rows. Only then run STEP 2.
-- Expected at time of writing (2026-06-17): 9 rows — sciimage.com apex +
-- 8 bare IPs (24.38.70.6/.7/.9/.10/.11/.12, 24.157.51.68/.94). Recount at
-- apply time; the count is whatever genuinely matches the guard.
--
-- SIGNAL = asset_surface.service_count (NOT the `alive` flag — alive is
-- HTTP-only and would wrongly catch DNS-serving infra like ns01/ns02).
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- STEP 1 — DRY RUN. Read-only. Confirm the set before changing anything.
-- ---------------------------------------------------------------------------
SELECT a.asset_id,
       a.discovery_status,
       a.ownership,
       s.service_count,
       s.alive,
       s.last_seen
  FROM public.assets a
  JOIN public.asset_surface s ON s.asset_id = a.asset_id
 WHERE a.discovery_status = 'confirmed_live'
   AND a.ownership IN ('owned', 'test_target')
   AND s.service_count = 0
 ORDER BY a.asset_id;

-- ---------------------------------------------------------------------------
-- STEP 2 — APPLY. Wrapped in a transaction. The final SELECT prints exactly
-- which asset_ids were flipped (keep that output — it IS the reversal list:
-- to undo, UPDATE those ids back to 'confirmed_live').
--
-- NOTE: if this errors with a check-constraint / invalid-enum violation on
-- 'dns_only', discovery_status is constrained at the DB level
-- (a Supabase-side CHECK or enum not in the repo). In that case, add the
-- value first (ALTER TYPE ... ADD VALUE, or widen the CHECK) and re-run.
-- ---------------------------------------------------------------------------
BEGIN;

WITH flipped AS (
  UPDATE public.assets a
     SET discovery_status = 'dns_only'
    FROM public.asset_surface s
   WHERE s.asset_id = a.asset_id
     AND a.discovery_status = 'confirmed_live'
     AND a.ownership IN ('owned', 'test_target')
     AND s.service_count = 0
  RETURNING a.asset_id
)
SELECT asset_id AS reclassified_to_dns_only
  FROM flipped
 ORDER BY asset_id;

-- Sanity: how many confirmed_live + svc=0 remain? Should be 0 after the flip.
SELECT count(*) AS remaining_confirmed_live_svc0
  FROM public.assets a
  JOIN public.asset_surface s ON s.asset_id = a.asset_id
 WHERE a.discovery_status = 'confirmed_live'
   AND a.ownership IN ('owned', 'test_target')
   AND s.service_count = 0;

-- Review the two result sets above. If correct: COMMIT;  If not: ROLLBACK;
COMMIT;
