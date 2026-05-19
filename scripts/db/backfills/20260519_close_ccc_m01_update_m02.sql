-- ============================================================================
-- BACKFILL — 2026-05-19 — Close PROD CCC M-01 + update M-02 partial status
--
-- Evidence: 2026-05-19 authenticated scan against www.commandcommcentral.com
-- from Clouvider egress (209.87.169.183).
--
--   M-01 session fixation
--     Confirmed remediated via Phase 2 Playwright login — pre-login cookie
--     value vs post-login cookie value differ; summary.json reports
--     sessionRotated: true. Same result on the resume-auth probe (different
--     fresh session).
--     Evidence file: prod-stringent-20260519-163036/auth/session/summary.json
--
--   M-02 CSP nonces
--     PARTIALLY REMEDIATED. 5 captures of /Account/Login show:
--       - script-src: 5 unique random nonces with 'strict-dynamic' ✓
--         (newly remediated since 5/13 partial)
--       - style-src: identical CSS_10001..10010 static placeholders ✗
--         (still vulnerable for CSS-injection vectors)
--     Evidence file: prod-stringent-20260519-163036/probes/m02-summary.txt
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/backfills/20260519_close_ccc_m01_update_m02.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Close M-01 session fixation
-- ---------------------------------------------------------------------------
SELECT close_findings_by_id(
  ARRAY['commandcommcentral.com:manual:M-01']::text[],
  '2026-05-19 13:30:00+00'::timestamptz,
  'Re-validated remediated 2026-05-19 — Playwright auth flow confirms sessionRotated:true on pre/post-login cookie comparison'
) AS m01_closed;


-- ---------------------------------------------------------------------------
-- 2. Update M-02 title + description to reflect partial remediation
--    (NOT closing — style-src half is still vulnerable)
-- ---------------------------------------------------------------------------
UPDATE findings
   SET title = 'M-02: Static/Predictable CSP Nonces (style-src) — script-src remediated 2026-05-19',
       description = COALESCE(description, '') ||
         E'\n\n--- 2026-05-19 update ---\n' ||
         'PARTIAL REMEDIATION. 5 captures of /Account/Login confirm:' || E'\n' ||
         '  - script-src: 5 unique random nonces + strict-dynamic ✓ (closed)' || E'\n' ||
         '  - style-src: identical CSS_10001..10010 across all 5 captures ✗ (still open)' || E'\n' ||
         'Style-src injection vectors (CSS keylogger, UI redress via visibility, ' ||
         'attribute-selector exfiltration) remain viable. Apply per-request random ' ||
         'nonce to style-src directive to fully close.'
 WHERE finding_id = 'commandcommcentral.com:manual:M-02'
   AND current_status IN ('detected','confirmed','open','regressed');


-- ---------------------------------------------------------------------------
-- 3. Recompute posture
-- ---------------------------------------------------------------------------
SELECT refresh_all_asset_posture() AS assets_recomputed;


-- ---------------------------------------------------------------------------
-- 4. Verify
-- ---------------------------------------------------------------------------
SELECT finding_id, current_status, remediated_at, severity,
       LEFT(title, 80) AS title_preview
  FROM findings
 WHERE finding_id IN (
   'commandcommcentral.com:manual:M-01',
   'commandcommcentral.com:manual:M-02',
   'commandcommcentral.com:manual:M-03',
   'commandcommcentral.com:manual:M-04'
 )
 ORDER BY finding_id;

COMMIT;
