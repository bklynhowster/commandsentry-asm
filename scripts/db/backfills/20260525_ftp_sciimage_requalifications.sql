-- ============================================================================
-- BACKFILL — 2026-05-25 — ftp.sciimage.com DAST requalifications  [NOT APPLIED]
--
-- STATUS: DRAFTED BUT NOT APPLIED. Decision (Howie, 2026-05-25) was to KEEP
-- the curator's MODERATE ratings on F-02/F-03/F-04. This file is retained so
-- the requalification can be applied later if that decision changes.
--
-- Source: 2026-05-25 intensive scan phase08-dast (ZAP passive + Playwright).
-- The DAST output was curated into manual findings F-02..F-04. The phase-8
-- requalification notes argued for lower severities than the curator assigned:
--
--   F-02  CSRF Token Passed in URL Query Parameter   MODERATE -> LOW
--         Rationale: the token IS present and this is the double-submit
--         delivery mechanism, not an "absence of anti-CSRF". Residual risk is
--         token leakage via Referer / browser history / server logs = LOW.
--
--   F-03  CSRF Token Cookie Missing HttpOnly Flag     MODERATE -> LOW
--         Rationale: Secure + SameSite=Lax ARE set; only HttpOnly is missing.
--         Real exposure is XSS-reads-token -> defeats double-submit, but with
--         SameSite=Lax + Secure in place the residual risk is LOW.
--
--   F-04  CSP Allows unsafe-inline and unsafe-eval    NO CHANGE (MODERATE)
--         ZAP's CSP finding is correct (default-src carries 'unsafe-inline'
--         'unsafe-eval' with no script-src, so scripts inherit it). The
--         Playwright csp_eval.allows_unsafe_inline_script:false was a false
--         negative (only checked script-src). Trust ZAP — keep MODERATE.
--
-- Apply with (ONLY if the keep-MODERATE decision is reversed):
--   psql "$SUPABASE_DSN" -f scripts/db/backfills/20260525_ftp_sciimage_requalifications.sql
--
-- Idempotent. Note: F-02/F-03 are manual_named; if their curated source file
-- re-asserts MODERATE on a future ingest, this backfill must be re-applied
-- (or the severity changed at the curated source).
-- ============================================================================

BEGIN;

UPDATE findings
   SET severity = 'LOW',
       description = COALESCE(description, '') ||
         E'\n\n--- 2026-05-25 requalification ---\n' ||
         'Downgraded MODERATE -> LOW. Token is present (double-submit pattern); ' ||
         'URL-query placement is a minor leak vector (Referer/history/logs), not ' ||
         'a missing-anti-CSRF MODERATE.'
 WHERE finding_id = 'ftp.sciimage.com:manual:F-02'
   AND current_status IN ('detected','confirmed','open','regressed')
   AND COALESCE(description, '') NOT LIKE '%2026-05-25 requalification%';

UPDATE findings
   SET severity = 'LOW',
       description = COALESCE(description, '') ||
         E'\n\n--- 2026-05-25 requalification ---\n' ||
         'Downgraded MODERATE -> LOW. Secure + SameSite=Lax are set; only ' ||
         'HttpOnly is missing. Residual XSS-defeats-double-submit risk is LOW ' ||
         'given the other cookie protections.'
 WHERE finding_id = 'ftp.sciimage.com:manual:F-03'
   AND current_status IN ('detected','confirmed','open','regressed')
   AND COALESCE(description, '') NOT LIKE '%2026-05-25 requalification%';

-- F-04 intentionally unchanged — ZAP's CSP MODERATE is correct.

SELECT refresh_all_asset_posture() AS assets_recomputed;

SELECT finding_id, severity::text, current_status, LEFT(title,55) AS title_preview
  FROM findings
 WHERE finding_id IN (
   'ftp.sciimage.com:manual:F-02',
   'ftp.sciimage.com:manual:F-03',
   'ftp.sciimage.com:manual:F-04'
 )
 ORDER BY finding_id;

COMMIT;
