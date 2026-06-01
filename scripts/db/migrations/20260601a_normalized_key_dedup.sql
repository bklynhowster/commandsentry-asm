-- ============================================================================
-- 20260601a_normalized_key_dedup.sql
-- ----------------------------------------------------------------------------
-- Phase B of cross-source dedup. Replaces the portal's render-time
-- groupBySharedCve() (asset detail page line 785) with a single source-
-- of-truth view that groups findings by (asset_id, normalized_key).
--
-- Architecture (per Opus advisor brief #6, 2026-06-01):
--   • findings stays append-only — every source's detection of the same
--     vuln stays as its own durable row (audit provenance preserved).
--   • New `normalized_key` text column groups rows across sources.
--   • New `v_open_findings_dedup` view does the grouping in SQL so the
--     headline count + render both read from the same source of truth
--     (today the headline counts raw rows → 58 on CMI, but only ~52
--     unique vulns once duplicates collapse).
--   • Portal switches its asset-findings query to the view; the existing
--     groupBySharedCve() retires (replaced, not stacked).
--
-- normalized_key derivation rules:
--   • CVE-bearing rows (any source) →
--       lower(array_to_string(SORTED cve, ','))
--     so cve=['CVE-2026-6692'] → 'cve-2026-6692', and multi-CVE rows
--     key on the full sorted set so finding-A with [CVE-1, CVE-2] and
--     finding-B with [CVE-1] are NOT merged (correctly different scopes).
--   • Non-CVE rows — explicit mapping table inline below. Cloud Light
--     tier writes its check_name slug directly. Manual_named/nuclei/
--     wpscan rows that don't have a CVE need a mapping rule.
--
-- The backfill is a non-destructive UPDATE — no DELETEs, no row collapses.
-- All existing rows stay. Only `normalized_key` gets populated. If we
-- decide a mapping was wrong, we just re-run the UPDATE with a different
-- expression. Fully reversible.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. ADD COLUMN
-- ---------------------------------------------------------------------------

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS normalized_key text;

COMMENT ON COLUMN public.findings.normalized_key IS
  'Cross-source dedup key. Same vuln from different sources (cloud + wpscan + manual_named + nuclei) shares one normalized_key. Derived from CVE for CVE-bearing rows, from check_name slug or explicit mapping for non-CVE rows. Drives v_open_findings_dedup.';

-- Index supports the view''s GROUP BY (asset_id, normalized_key).
-- Partial because rows without normalized_key (legacy unmappable rows)
-- should not be in the dedup view at all — they render as themselves.
CREATE INDEX IF NOT EXISTS idx_findings_normalized_key
  ON public.findings (asset_id, normalized_key)
  WHERE normalized_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. BACKFILL — populate normalized_key on existing rows
-- ---------------------------------------------------------------------------
-- Order of precedence (matters for rows that satisfy multiple rules):
--   2a. Explicit mapping table for known special cases (F-10, etc.) — first
--   2b. CVE-based derivation (sorted full set) — second
--   2c. check_name slug from finding_id — fallback for cloud's :light: format
--   2d. Best-effort slug for nuclei/wpscan/other — last resort

-- 2a. Explicit cross-source mappings — ONLY for manual_named rows that
-- LACK a CVE column. Rows WITH cve populated are handled by 2b's CVE-
-- based derivation, which is consistent across all sources (cloud, nuclei,
-- manual_named all converge to the same lower(cve) key).
--
-- Mapping targets are matched to what cloud probes emit OR would emit:
--   - Cloud's probe_static_csp_nonces_per_directive emits
--     'csp-static-nonce-style_src' (UNDERSCORE — re-verified against
--     today's smoke-test output)
--   - Cloud's probe_hardcoded_client_crypto emits per-suffix slugs like
--     'client-js-hardcoded-passphrase-string'
--   - aes.js probe doesn't exist yet (reference-chain can't reach the
--     unreferenced /Scripts/aes.js); reserved slug = 'aes-js-leftover'
--
-- These mappings get refined as we observe (a) which manual rows ingest
-- without CVE, and (b) what cloud slugs we actually settle on. Add new
-- rules below over time.
UPDATE public.findings
SET normalized_key = CASE
  -- CSP static nonce, M-02 class. Style-src half still live on test.ccc
  -- (script-src was remediated 5/2). Use cloud's underscore-style slug.
  WHEN finding_id LIKE '%:manual:M-02' THEN 'csp-static-nonce-style_src'

  -- aes.js leftover (M-03). Reserved — placeholder slug for when we add
  -- the probe (probably an authenticated or katana-discovered detector).
  WHEN finding_id LIKE '%:manual:M-03' THEN 'aes-js-leftover'

  -- Hardcoded client-side crypto key (C-01). Map to cloud's specific
  -- suffix for hardcoded-passphrase-string detection. Remediated on CCC
  -- but kept for future fleet-wide application.
  WHEN finding_id LIKE '%:manual:C-01' THEN 'client-js-hardcoded-passphrase-string'

  ELSE NULL
END
WHERE finding_id LIKE '%:manual:%'
  AND normalized_key IS NULL
  -- cardinality() returns 0 for '{}' (empty array); array_length(arr, 1)
  -- returns NULL for empty arrays which would break this check. Burned
  -- 30 min on this 2026-06-01 — M-02/M-03 had cve='{}' and got filtered.
  AND (cve IS NULL OR cardinality(cve) = 0);

-- Manual rows that DO have a CVE (e.g. F-10 WPS Hide Login with
-- cve=['CVE-2024-2473']) are intentionally NOT mapped explicitly here.
-- They get keyed by 2b below to lower(cve), which merges them with the
-- nuclei + cloud findings that share the same CVE. Don't add F-10 type
-- rules here — that would override the CVE-based merge and break dedup.

-- 2b. CVE-based derivation for any row with a populated cve array.
-- Sorted, comma-joined, lowercased. Applies to all sources (cloud, wpscan,
-- nuclei, manual_named when they have CVE).
UPDATE public.findings
SET normalized_key = (
  SELECT lower(string_agg(c, ',' ORDER BY c))
  FROM unnest(cve) AS c
)
WHERE normalized_key IS NULL
  AND cve IS NOT NULL
  AND array_length(cve, 1) > 0;

-- 2c. Cloud Light tier slug. Cloud finding_ids are of the form
-- '<asset_id>:light:<check_name>'. The check_name IS the slug.
UPDATE public.findings
SET normalized_key = split_part(finding_id, ':light:', 2)
WHERE normalized_key IS NULL
  AND source = 'commandsentry_light'
  AND finding_id LIKE '%:light:%';

-- 2d. Cloud Medium tier — same pattern for the future when Medium starts
-- emitting findings (today everything ends in 0 findings on FortiGate).
UPDATE public.findings
SET normalized_key = split_part(finding_id, ':medium:', 2)
WHERE normalized_key IS NULL
  AND source = 'commandsentry_medium'
  AND finding_id LIKE '%:medium:%';

-- 2e. Nuclei rows — finding_id format is varied. Common patterns:
--   'commandmarketinginnovations.com:nuclei:CVE-2024-2473:bfb4e3b'
--   'commandmarketinginnovations.com:nuclei:http-missing-security-headers:content-security-policy'
--   'asset:nuclei:<template-id>[:<sub-id>]'
-- The 'http-missing-security-headers:<header>' pattern naturally aligns
-- with cloud's 'missing-header-<header>' slug if we map it. Different
-- templates need different rules — best-effort fallback to the last
-- segment for now, refine as we see more patterns.
UPDATE public.findings
SET normalized_key = CASE
  -- 'http-missing-security-headers:content-security-policy' → 'missing-header-content-security-policy'
  WHEN finding_id ~ ':nuclei:http-missing-security-headers:'
    THEN 'missing-header-' || lower(split_part(finding_id, 'http-missing-security-headers:', 2))
  -- 'wordpress-readme-file' → 'wordpress-readme-exposed'
  WHEN finding_id LIKE '%:nuclei:wordpress-readme-file' THEN 'wordpress-readme-exposed'
  -- Generic fallback: use the part after :nuclei: as the slug
  WHEN finding_id LIKE '%:nuclei:%'
    THEN regexp_replace(split_part(finding_id, ':nuclei:', 2), ':.*$', '')
  ELSE NULL
END
WHERE normalized_key IS NULL
  AND source = 'nuclei';

-- 2f. wpscan rows — finding_id format isn't fully known yet but the title
-- often encodes the plugin + version. For rows we can't map cleanly, leave
-- normalized_key NULL — they'll render as singleton rows in the view,
-- which is correct behavior (we''d rather show a row alone than merge it
-- with the wrong group).
-- Add explicit wpscan mappings here as we observe finding_id patterns.

-- 2g. testssl, other — leave NULL for now. These can stay singletons.

-- ---------------------------------------------------------------------------
-- 3. VIEW — v_open_findings_dedup
-- ---------------------------------------------------------------------------
-- The portal queries this view instead of public.findings directly when
-- rendering the asset detail page. Rows WITH normalized_key get grouped;
-- rows WITHOUT (legacy unmapped rows) pass through as singletons via a
-- UNION ALL.
--
-- Open count = COUNT(*) over the view, not over findings — that's how the
-- headline number drops to the deduped count.

CREATE OR REPLACE VIEW public.v_open_findings_dedup AS
WITH terminal_statuses(s) AS (
  VALUES ('remediated'::finding_status_t),
         ('validated_remediated'::finding_status_t),
         ('false_positive'::finding_status_t),
         ('wont_fix'::finding_status_t),
         ('accepted_risk'::finding_status_t)
),
-- Rows that have a normalized_key — these dedup into groups
grouped AS (
  SELECT
    asset_id,
    normalized_key                                            AS dedup_id,
    -- Worst (highest) severity across the group — see SEVERITY_RANK mapping
    -- inline in the CASE expression. Lower rank = more severe.
    (ARRAY_AGG(severity ORDER BY
      CASE severity
        WHEN 'CRITICAL'      THEN 1
        WHEN 'HIGH'          THEN 2
        WHEN 'MODERATE-HIGH' THEN 3
        WHEN 'MODERATE'      THEN 4
        WHEN 'LOW'           THEN 5
        WHEN 'INFO'          THEN 6
        ELSE 9
      END
    ))[1]                                                     AS severity,
    -- "Open" if any source still detected; "resolved" if all sources are
    -- terminal. Conservative for posture.
    CASE
      WHEN bool_or(current_status NOT IN
        ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))
        THEN 'detected'::finding_status_t
      ELSE (ARRAY_AGG(current_status))[1]
    END                                                       AS current_status,
    -- Pick a canonical title — the longest one wins, which usually means
    -- the most descriptive entry across sources.
    (ARRAY_AGG(title ORDER BY length(title) DESC NULLS LAST))[1] AS title,
    -- Source list — array_agg keeps the audit trail
    ARRAY_AGG(DISTINCT source ORDER BY source)                AS sources,
    COUNT(*)                                                  AS source_count,
    MIN(first_detected_at)                                    AS first_detected_at,
    MAX(last_observed_at)                                     AS last_observed_at,
    -- Aggregate CVE union — flatten and dedupe
    (
      SELECT array_agg(DISTINCT c ORDER BY c)
      FROM unnest(array_remove(array_cat_agg(cve), NULL)) AS c
      WHERE c IS NOT NULL
    )                                                          AS cve,
    -- Carry the constituent finding_ids for the portal's expand-to-see-all
    ARRAY_AGG(finding_id ORDER BY first_detected_at)          AS member_finding_ids
  FROM public.findings
  WHERE normalized_key IS NOT NULL
  GROUP BY asset_id, normalized_key
),
-- Rows without normalized_key — pass through as singletons
ungrouped AS (
  SELECT
    asset_id,
    finding_id                                                AS dedup_id,
    severity,
    current_status,
    title,
    ARRAY[source]                                             AS sources,
    1                                                         AS source_count,
    first_detected_at,
    last_observed_at,
    cve,
    ARRAY[finding_id]                                         AS member_finding_ids
  FROM public.findings
  WHERE normalized_key IS NULL
)
SELECT * FROM grouped
UNION ALL
SELECT * FROM ungrouped;

COMMENT ON VIEW public.v_open_findings_dedup IS
  'Phase B cross-source dedup view. GROUP BY (asset_id, normalized_key) for rows that have a key; passes through ungrouped rows as singletons. Source array preserves audit provenance. Used by the portal asset detail page to replace render-time groupBySharedCve().';

-- ---------------------------------------------------------------------------
-- Helper aggregate: array_cat_agg
-- ---------------------------------------------------------------------------
-- Postgres doesn't ship a built-in aggregate for "concatenate all input
-- arrays into one array." Define one if it doesn't exist. Used by the
-- view's CVE aggregation to flatten cve[][] arrays into a single cve[].

-- Use specific text[] type instead of anyarray — Postgres 14+ requires
-- concrete types for CREATE AGGREGATE since array_cat is no longer
-- defined for the deprecated 'anyarray' polymorphic type. findings.cve
-- is text[], so text[] is the right choice.
DROP AGGREGATE IF EXISTS array_cat_agg(text[]);
CREATE AGGREGATE array_cat_agg(text[]) (
  SFUNC = array_cat,
  STYPE = text[]
);

COMMIT;

-- ============================================================================
-- Spot-check queries to run after migration applies:
-- ============================================================================
--
-- 1. How many rows have normalized_key now?
--    SELECT COUNT(*) FILTER (WHERE normalized_key IS NOT NULL) AS with_key,
--           COUNT(*) FILTER (WHERE normalized_key IS NULL)     AS without_key,
--           COUNT(*)                                            AS total
--    FROM public.findings;
--
-- 2. Top dedup groups (how much consolidation are we getting):
--    SELECT asset_id, normalized_key, COUNT(*) AS source_count
--    FROM public.findings
--    WHERE normalized_key IS NOT NULL
--    GROUP BY asset_id, normalized_key
--    HAVING COUNT(*) > 1
--    ORDER BY COUNT(*) DESC
--    LIMIT 20;
--
-- 3. CMI dedup verification — should show the revslider/mega_main_menu
--    cloud+wpscan pairs collapsed into single dedup_id rows:
--    SELECT dedup_id, severity, source_count, sources, title
--    FROM public.v_open_findings_dedup
--    WHERE asset_id = 'commandmarketinginnovations.com'
--      AND current_status = 'detected'
--      AND source_count > 1
--    ORDER BY source_count DESC;
--
-- 4. Headline open-count drop verification:
--    -- Before (raw): SELECT COUNT(*) FROM findings WHERE asset_id=$1 AND current_status='detected';
--    -- After (deduped): SELECT COUNT(*) FROM v_open_findings_dedup WHERE asset_id=$1 AND current_status='detected';
--    -- The drop = number of duplicates collapsed
