-- ============================================================================
-- MIGRATION — 2026-06-18a — Cross-source semantic dedup: DMARC + OCSP (#36)
--
-- Backfill normalized_key on existing findings so that semantically-identical
-- single-fact findings from different sources collapse into one dedup group.
-- Currently the same fact is counted 2-3× because each source computes its
-- own normalized_key (or none, in the case of manual_named + testssl). Caught
-- on ftp.sciimage.com 2026-06-17:
--
--   DMARC group:  manual_named F-07 (NULL key) + commandsentry_light
--                 'DNS Missing DMARC' (key 'dns-missing-dmarc')
--   OCSP  group:  manual_named F-09 (NULL key) + testssl
--                 'OCSP stapling not enabled' (NULL key)
--
-- ----------------------------------------------------------------------------
-- SCOPE (advisor + Opus verify call — DO NOT BROADEN)
-- ----------------------------------------------------------------------------
-- Curated map. Two classes only:
--
--   dns-missing-dmarc:
--     manual_named         title ~* 'no dmarc record'           (matches F-07 ONLY;
--                                                                excludes F-02 + L-05
--                                                                which are multi-issue)
--     commandsentry_light  title ~* 'dns missing dmarc'         (already this key)
--
--   tls-ocsp-stapling-missing:
--     manual_named         title ~* 'no ocsp stapling'
--     testssl              title ~* 'ocsp stapling not enabled'
--
-- NEVER MERGE (locked in by test #3 in scripts/normalize/test_cross_source_equivalence.py):
--   • ciphers (LUCKY13 != CBC-enabled != obsoleted — distinct fixes)
--   • HSTS-present vs HSTS-missing (OPPOSITES — merging hides the gap)
--   • CSRF F-02 vs F-03 (distinct)
--   • nuclei `dmarc-detect` (INFO DETECTION — opposite semantic of "missing")
--
-- DEFERRED: CSP, forward-secrecy.
--
-- Principle: same-fact ONLY. Curated, never keyword-broad. Earn each entry —
-- and each pattern within each entry.
--
-- ----------------------------------------------------------------------------
-- IDEMPOTENCY PREDICATE: IS DISTINCT FROM, NOT !=
-- ----------------------------------------------------------------------------
-- The WHERE clause uses `normalized_key IS DISTINCT FROM <canonical>` rather
-- than `!=`. This is the OPPOSITE polarity from #35's delta-close predicate.
--
-- In #35 (last_seen_scan_run): NULL means "pre-existing, don't act on this row"
-- → `!=` correct (NULL stays null-poisoned, row excluded from close set).
-- In #36 (normalized_key on manual_named): NULL means "no key yet, please
-- populate me" → `IS DISTINCT FROM` correct (NULL is treated as a value,
-- manual_named NULL rows ARE included in the UPDATE and get their key set).
--
-- If we used `!=` here, every manual_named NULL-keyed row would be silently
-- skipped (NULL != value → NULL → row falls out of WHERE), and the migration
-- would no-op against the most important class of finding it's supposed to
-- fix. See feedback_null_safe_idiom_inverts_ratchet.md for the general rule.
--
-- Same memory file, opposite correct operator, because the semantic of NULL
-- is opposite in the two cases.
--
-- Idempotent: re-runs touch 0 rows because converged rows match the canonical
-- key and the IS DISTINCT FROM predicate excludes them.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Pre-sweep snapshot — capture rows about to change for rollback / audit.
--    Idempotent: drops + recreates per run.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS public.findings_dedup_resweep_20260618a;

CREATE TABLE public.findings_dedup_resweep_20260618a AS
SELECT f.finding_id,
       f.asset_id,
       f.source,
       f.title,
       f.normalized_key AS old_normalized_key,
       CASE
         WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
         WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
         WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
         WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
       END AS new_normalized_key,
       now() AS snapshotted_at
  FROM public.findings f
 WHERE (
         (f.source = 'manual_named'         AND f.title ~* 'no dmarc record')
      OR (f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc')
      OR (f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling')
      OR (f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled')
       )
   AND f.normalized_key IS DISTINCT FROM CASE
         WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
         WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
         WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
         WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
       END;

COMMENT ON TABLE public.findings_dedup_resweep_20260618a IS
  'Snapshot of findings rows that the 20260618a cross-source dedup migration '
  'about to update. Pre-sweep state for rollback / forensics. Safe to drop '
  'after one full scan cycle confirms the new keys are correct.';

-- ---------------------------------------------------------------------------
-- 1. The backfill — single UPDATE, four (source, pattern) → canonical entries.
--    Title pattern MUST match (the WHERE prevents bogus shared keys).
--    Idempotency guard: IS DISTINCT FROM, NOT != (see header comment).
-- ---------------------------------------------------------------------------
UPDATE public.findings f
   SET normalized_key = CASE
         WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
         WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
         WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
         WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
       END
 WHERE (
         (f.source = 'manual_named'         AND f.title ~* 'no dmarc record')
      OR (f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc')
      OR (f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling')
      OR (f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled')
       )
   -- Idempotency — IS DISTINCT FROM (not !=). NULL-keyed manual_named rows
   -- MUST be included; `!=` would silently skip them. See header comment.
   AND f.normalized_key IS DISTINCT FROM CASE
         WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
         WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
         WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
         WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
       END;

-- ---------------------------------------------------------------------------
-- 2. Verification — acceptance gate queries
-- ---------------------------------------------------------------------------

-- 2a. Snapshot row count = number of rows changed by the sweep.
SELECT 'rows updated by 20260618a' AS info,
       count(*) AS rows_changed
  FROM public.findings_dedup_resweep_20260618a;

-- 2b. Per-(source, canonical_key) breakdown of what landed.
SELECT 'post-sweep distribution' AS info,
       source,
       normalized_key,
       count(*) AS n
  FROM public.findings
 WHERE normalized_key IN ('dns-missing-dmarc', 'tls-ocsp-stapling-missing')
 GROUP BY source, normalized_key
 ORDER BY normalized_key, source;

-- 2c. Negative test — NEVER-MERGE classes must keep DISTINCT keys.
-- Any non-zero count is a regression that means the conservative scope was
-- broken. Expected: 0 (none of these patterns are in the map).
SELECT 'never-merge regression check' AS info,
       count(*) FILTER (WHERE title ~* 'lucky.?13|cbc.cipher|obsoleted')                  AS cipher_findings_unchanged,
       count(*) FILTER (WHERE title ~* 'hsts.*present|strict.transport.*present')         AS hsts_present_unchanged,
       count(*) FILTER (WHERE title ~* 'csrf')                                            AS csrf_unchanged,
       count(*) FILTER (WHERE title ~* 'dmarc-detect|dmarc.*detect')                      AS nuclei_dmarc_detect_unchanged
  FROM public.findings
 WHERE normalized_key IN ('dns-missing-dmarc', 'tls-ocsp-stapling-missing');
-- Expected: 0 across the board. If any non-zero, a never-merge pattern leaked
-- in — investigate immediately before the dedup view re-renders.

-- 2d. ftp.sciimage.com asset-specific before/after (the canonical example).
SELECT 'ftp.sciimage.com dedup groups post-sweep' AS info,
       normalized_key,
       count(*) AS source_count,
       array_agg(source ORDER BY source) AS sources,
       array_agg(LEFT(title, 60) ORDER BY source) AS title_snippets
  FROM public.findings
 WHERE asset_id = 'ftp.sciimage.com'
   AND normalized_key IN ('dns-missing-dmarc', 'tls-ocsp-stapling-missing')
 GROUP BY normalized_key
 ORDER BY normalized_key;
-- Expected for ftp.sciimage.com (per Opus verify spec):
--   dns-missing-dmarc:        2 rows (manual_named F-07 + commandsentry_light)
--   tls-ocsp-stapling-missing: 2 rows (manual_named F-09 + testssl)

COMMIT;

-- ============================================================================
-- DRY-RUN (run this WITHOUT executing the migration to preview impact):
--
-- SELECT f.finding_id, f.asset_id, f.source, f.title,
--        f.normalized_key AS old_key,
--        CASE
--          WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
--          WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
--          WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
--          WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
--        END AS new_key
--   FROM public.findings f
--  WHERE (
--          (f.source = 'manual_named'         AND f.title ~* 'no dmarc record')
--       OR (f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc')
--       OR (f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling')
--       OR (f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled')
--        )
--    AND f.normalized_key IS DISTINCT FROM CASE
--          WHEN f.source = 'manual_named'         AND f.title ~* 'no dmarc record'        THEN 'dns-missing-dmarc'
--          WHEN f.source = 'commandsentry_light'  AND f.title ~* 'dns missing dmarc'      THEN 'dns-missing-dmarc'
--          WHEN f.source = 'manual_named'         AND f.title ~* 'no ocsp stapling'       THEN 'tls-ocsp-stapling-missing'
--          WHEN f.source = 'testssl'              AND f.title ~* 'ocsp stapling not enabled' THEN 'tls-ocsp-stapling-missing'
--        END
--  ORDER BY f.asset_id, f.source;
--
-- Roll-back recipe (if the sweep needs reverting):
--
--   UPDATE public.findings f
--      SET normalized_key = s.old_normalized_key
--     FROM public.findings_dedup_resweep_20260618a s
--    WHERE f.finding_id = s.finding_id;
--
-- (Snapshot table is the rollback surface — don't drop until at least one
-- full scan cycle confirms the new keys are correct.)
-- ============================================================================
