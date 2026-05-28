-- ============================================================================
-- BACKFILL — 2026-05-25 — Consolidate ftp.sciimage.com cert-chain dupe
--
-- Evidence: 2026-05-25 intensive scan against ftp.sciimage.com (24.157.51.76)
-- from ExpressVPN egress. testssl re-detected the incomplete certificate
-- chain on port 443:
--   "Certificate chain of trust issue — failed (chain incomplete)."
--   Evidence file: intensive-scan-2026-05-25/phase03-tls/testssl.json
--                  + phase03-tls/cert-chain-443.txt
--
-- This is the SAME condition already curated as:
--   ftp.sciimage.com:manual:F-01  "F-01: Incomplete TLS Certificate Chain"
--   (HIGH, CVSS 7.0, from the 2026-03-26 assessment — still open)
--
-- testssl auto-rates chain-of-trust failures CRITICAL, which created a
-- cross-source duplicate at a higher severity:
--   ftp.sciimage.com:testssl:cert_chain_of_trust:33ad838  (CRITICAL, open)
--
-- The auto-consolidation backfill (20260519_consolidate_testssl_dupes.sql)
-- does NOT catch this — that only merges same-source / same-title rows.
-- This is cross-source (manual_named vs testssl), different titles.
--
-- Decision (Howie, 2026-05-25): keep the curated F-01 HIGH as authoritative.
-- So we:
--   1. Annotate F-01 that testssl re-confirmed the issue on 2026-05-25
--      (the finding is NOT remediated — it persists).
--   2. Close the testssl CRITICAL as a duplicate consolidated into F-01.
-- Net posture effect: CRITICAL 1 -> 0; F-01 stays HIGH/open.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/backfills/20260525_consolidate_ftp_sciimage_cert_chain.sql
--
-- Idempotent. Safe to re-run (the close is a no-op once the testssl row is
-- already closed; the F-01 note appends only if not already present).
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Annotate curated F-01 — testssl re-confirmed the incomplete chain.
--    Keep it HIGH and open; only append the note once (idempotent guard).
-- ---------------------------------------------------------------------------
UPDATE findings
   SET description = COALESCE(description, '') ||
         E'\n\n--- 2026-05-25 re-confirmation ---\n' ||
         'testssl re-detected the incomplete certificate chain on port 443 ' ||
         'during the 2026-05-25 intensive scan ("Certificate chain of trust ' ||
         'issue — failed (chain incomplete)"). Finding is NOT remediated; it ' ||
         'persists. Curated severity held at HIGH (testssl auto-rated it ' ||
         'CRITICAL; that auto-dupe consolidated into this finding).'
 WHERE finding_id = 'ftp.sciimage.com:manual:F-01'
   AND current_status IN ('detected','confirmed','open','regressed')
   AND COALESCE(description, '') NOT LIKE '%2026-05-25 re-confirmation%';

-- ---------------------------------------------------------------------------
-- 2. Close the testssl CRITICAL duplicate, consolidated into curated F-01.
-- ---------------------------------------------------------------------------
SELECT close_findings_by_id(
  ARRAY['ftp.sciimage.com:testssl:cert_chain_of_trust:33ad838']::text[],
  '2026-05-25 16:50:00+00'::timestamptz,
  'Duplicate of curated ftp.sciimage.com:manual:F-01 (authoritative, HIGH). '
  || 'testssl auto-rated the incomplete-chain condition CRITICAL on the '
  || '2026-05-25 scan; consolidated into F-01 per 2026-05-25 requalification '
  || 'decision to hold curated HIGH. The underlying condition is NOT '
  || 'remediated — see F-01.'
) AS testssl_dupe_closed;

-- ---------------------------------------------------------------------------
-- 3. Recompute posture
-- ---------------------------------------------------------------------------
SELECT refresh_all_asset_posture() AS assets_recomputed;

-- ---------------------------------------------------------------------------
-- 4. Verify
-- ---------------------------------------------------------------------------
SELECT finding_id, severity, current_status, remediated_at,
       LEFT(title, 60) AS title_preview
  FROM findings
 WHERE finding_id IN (
   'ftp.sciimage.com:manual:F-01',
   'ftp.sciimage.com:testssl:cert_chain_of_trust:33ad838'
 )
 ORDER BY finding_id;

COMMIT;
