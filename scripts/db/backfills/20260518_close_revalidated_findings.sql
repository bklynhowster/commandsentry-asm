-- ============================================================================
-- ⚠️  OBSOLETE — DO NOT RE-RUN (tombstoned 2026-06-15)
--
-- This backfill calls `refresh_all_asset_last_observed()` at line 114,
-- which was DROPPED in migration 20260615a as part of the [2]
-- last_observed semantics fix (B → A). If re-run after that migration
-- applies, this script will fail with "function does not exist" at the
-- line 114 SELECT — that error is the correct signal that the backfill
-- has been superseded.
--
-- Preserved as historical record of the 2026-05-18 close. The closure
-- work itself (sections 1-3 of this file) is complete and durable in
-- the DB. The refresh calls in section 4 were one-time recomputes for
-- that backfill; the new A-semantic regime makes them moot.
--
-- DO NOT REVIVE without re-doing the [2] fix design — re-introducing
-- the B semantic re-introduces the discovery-clock clobber that fix
-- closed.
-- ============================================================================

-- ============================================================================
-- BACKFILL — 2026-05-18 — Close 5/13-5/14 re-validated findings
--
-- Howie's CCC Scan 11 (5/13 PROD) + Scan 12 (5/14 TEST + Dave memos) +
-- API CCC Re-Validation (5/14) confirmed several findings as remediated or
-- recharacterized. None of those closures ever made it back to Supabase
-- because the importer is currently additive only. This backfill applies
-- them by hand.
--
-- Sources:
--   ~/Documents/Obsidian Vault/2026-05-13 - CCC Scan 11 - PROD Re-Validation + Test Stringent Setup.md
--   ~/Documents/Obsidian Vault/2026-05-14 - CCC Scan 12 - TEST Re-Validation + Dave Memos.md
--   ~/Documents/Obsidian Vault/2026-05-14 - API Re-Validation + Tooling Buildout.md
--   ~/Documents/Obsidian Vault/Vulnerability Assessments/API - api.commandcommcentral.com/Assessment Overview.md
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/maintenance.sql
--   psql "$SUPABASE_DSN" -f scripts/db/backfills/20260518_close_revalidated_findings.sql
--
-- Idempotent — uses close_findings_by_id() which only updates currently-open
-- rows. Re-running it is a no-op.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. api.commandcommcentral.com — re-validated 2026-05-14
--    Per Assessment Overview:
--      - W-02 (WAF XSS/SQLi)         -> recharacterized POSITIVE (FortiGate
--                                       actively blocking, not transparent)
--      - A-03 (Suspicious 500s)      -> recharacterized POSITIVE (FortiGate
--                                       block page, not IIS misconfig)
--      - W-03 (HTTP methods allowed) -> recharacterized POSITIVE (only
--                                       GET/HEAD/POST/OPTIONS via Allow header)
--      - W-04 (Bot check empty 200)  -> recharacterized POSITIVE (active
--                                       blocking observed)
-- ---------------------------------------------------------------------------
SELECT close_findings_by_id(
  ARRAY[
    'api.commandcommcentral.com:manual:W-02',
    'api.commandcommcentral.com:manual:A-03',
    'api.commandcommcentral.com:manual:W-03',
    'api.commandcommcentral.com:manual:W-04'
  ]::text[],
  '2026-05-14 18:00:00+00'::timestamptz,
  'Re-validated 2026-05-14 — recharacterized POSITIVE during 4-scan re-validation'
) AS api_ccc_closed;


-- A-01 (Missing Security Headers) on api.ccc — overview says headers are
-- still missing but this is now a defense-in-depth gap, not a direct exploit.
-- Downgrade MODERATE -> LOW rather than closing.
--
-- Two finding_ids cover this in practice: the manual A-01 (stable id) and
-- the testssl security_headers row (whose hash format changed when the
-- 2026-05-19 testssl parser fix migrated finding_ids). Target by title +
-- (asset, source) instead of literal finding_id so this backfill keeps
-- working after future hash-format migrations.
UPDATE findings
   SET severity = 'LOW'
 WHERE current_status IN ('detected','confirmed','open','regressed')
   AND severity = 'MODERATE'
   AND (
     finding_id = 'api.commandcommcentral.com:manual:A-01'
     OR (asset_id = 'api.commandcommcentral.com'
         AND source = 'testssl'
         AND title ILIKE '%security headers missing%')
   );


-- ---------------------------------------------------------------------------
-- 2. www.commandcommcentral.com (PROD) — CCC Scan 11, 2026-05-13
--    Per scan note "### CLOSED (2 re-validated)":
--      - H-01 (Sprocket #12821 auth bypass) — REMEDIATED
--      - C-01 (Hardcoded AES key in encryption.js) — REMEDIATED
--    Finding IDs in DB follow the `<asset>:<source>:<finding-tag>` pattern.
-- ---------------------------------------------------------------------------
SELECT close_findings_by_id(
  ARRAY[
    'commandcommcentral.com:manual:H-01',
    'commandcommcentral.com:manual:C-01',
    'www.commandcommcentral.com:manual:H-01',
    'www.commandcommcentral.com:manual:C-01'
  ]::text[],
  '2026-05-13 22:36:00+00'::timestamptz,
  'Re-validated 2026-05-13 during CCC Scan 11 (PROD deep-validate)'
) AS ccc_prod_closed;


-- M-02 on PROD — partially remediated (script-src nonces now random,
-- style-src still static). Per note, leave open at MODERATE because the
-- style-src injection vector is still live. No change.


-- ---------------------------------------------------------------------------
-- 3. test.commandcommcentral.com — CCC Scan 12, 2026-05-14
--    Per scan-12 note: M-01 REMEDIATED in TEST (delta from PROD).
--    M-03 (legacy aes.js) still present in TEST — no change.
-- ---------------------------------------------------------------------------
SELECT close_findings_by_id(
  ARRAY[
    'test.commandcommcentral.com:manual:M-01',
    'test3.commandcommcentral.com:manual:M-01'
  ]::text[],
  '2026-05-14 16:00:00+00'::timestamptz,
  'Re-validated 2026-05-14 in TEST environment during CCC Scan 12'
) AS ccc_test_closed;


-- ---------------------------------------------------------------------------
-- 4. Recompute current_risk + current_risk_reason + last_observed for
--    every affected asset so the next alerter run reflects reality.
-- ---------------------------------------------------------------------------
SELECT refresh_all_asset_last_observed() AS assets_last_observed_refreshed;
SELECT refresh_all_asset_posture()       AS assets_posture_refreshed;


-- ---------------------------------------------------------------------------
-- 5. Verification — show the new posture for the affected assets
-- ---------------------------------------------------------------------------
SELECT asset_id, current_risk, current_risk_reason, last_observed
  FROM assets
 WHERE asset_id IN (
   'api.commandcommcentral.com',
   'commandcommcentral.com',
   'www.commandcommcentral.com',
   'test.commandcommcentral.com',
   'test3.commandcommcentral.com'
 )
 ORDER BY asset_id;

COMMIT;
