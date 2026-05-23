-- ============================================================================
-- 20260522e_synth_extraction_columns.sql
--
-- Phase F+ — give the AI synth pipeline structured columns to write into
-- alongside the canonical prose. Lets us surface CVSS, affected component +
-- version, and a *suggested* category on /findings/[id] when the scanner
-- output doesn't already populate them as structured data.
--
-- Why a SEPARATE suggested_category column instead of overwriting findings.category?
--   - findings.category is the AUTHORITATIVE value (came from the scanner / human entry)
--   - suggested_category is the AI's read of the scanner data — useful when
--     the original tagging is wrong (e.g. an outdated-plugin finding tagged
--     'info_disclosure' that should be 'sca')
--   - UI shows a warning chip only when the two disagree; admin can accept
--     the suggestion or leave it
--   - Auditor story stays clean: the authoritative value never gets quietly
--     mutated by AI, it gets *suggested* and a human accepts
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

ALTER TABLE findings
  -- CVSS v3.1 base score, 0.0–10.0. Numeric so 7.3 stays 7.3.
  ADD COLUMN IF NOT EXISTS cvss_score                 numeric(3,1),
  -- The full CVSS v3.1 vector string, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
  -- Track 2 lookups will populate this from NVD when CVEs are present.
  ADD COLUMN IF NOT EXISTS cvss_vector                text,
  -- Affected component name + version — split out from the asset because a
  -- single asset can host many vulnerable components (plugin X, plugin Y,
  -- nginx, PHP, etc.).
  ADD COLUMN IF NOT EXISTS affected_component         text,
  ADD COLUMN IF NOT EXISTS affected_component_version text,
  -- AI's suggested category, separate from the authoritative findings.category.
  ADD COLUMN IF NOT EXISTS suggested_category         finding_category_t,
  -- Confidence the synth has in its structured extractions overall.
  ADD COLUMN IF NOT EXISTS extraction_confidence      text;

DO $$ BEGIN
  ALTER TABLE findings
    ADD CONSTRAINT chk_extraction_confidence
    CHECK (extraction_confidence IS NULL
           OR extraction_confidence IN ('high','medium','low'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE findings
    ADD CONSTRAINT chk_cvss_score_range
    CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Index supports "show me all findings with CVSS >= 7" type queries.
CREATE INDEX IF NOT EXISTS idx_findings_cvss_score
  ON findings(cvss_score)
  WHERE cvss_score IS NOT NULL;

-- Index lets the admin queue surface "mismatched category suggestions"
-- without a full scan of findings.
CREATE INDEX IF NOT EXISTS idx_findings_category_mismatch
  ON findings(suggested_category)
  WHERE suggested_category IS NOT NULL AND suggested_category <> category;

COMMENT ON COLUMN findings.cvss_score IS
  'CVSS v3.1 base score, numeric. Populated by AI synth from scanner output, or by Track 2 NVD lookup when CVEs are known.';

COMMENT ON COLUMN findings.cvss_vector IS
  'CVSS v3.1 vector string (AV:N/AC:L/PR:N/...). Populated by Track 2 NVD lookup when CVEs are known.';

COMMENT ON COLUMN findings.affected_component IS
  'Name of the vulnerable component on the asset (e.g. "Email Encoder Bundle", "nginx"). Separate from the asset because one asset hosts many components.';

COMMENT ON COLUMN findings.affected_component_version IS
  'Detected version of the vulnerable component (e.g. "2.8.3"). NULL when scanner did not capture.';

COMMENT ON COLUMN findings.suggested_category IS
  'AI-suggested finding category. NOT authoritative — the authoritative value lives in findings.category. UI flags mismatches for admin review.';

COMMENT ON COLUMN findings.extraction_confidence IS
  'How confident the synth pipeline is in the structured extractions (cve/cwe/tags/cvss/component). high|medium|low. NULL until first synth run.';

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--   BEGIN;
--   DROP INDEX IF EXISTS idx_findings_category_mismatch;
--   DROP INDEX IF EXISTS idx_findings_cvss_score;
--   ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_cvss_score_range;
--   ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_extraction_confidence;
--   ALTER TABLE findings
--     DROP COLUMN IF EXISTS extraction_confidence,
--     DROP COLUMN IF EXISTS suggested_category,
--     DROP COLUMN IF EXISTS affected_component_version,
--     DROP COLUMN IF EXISTS affected_component,
--     DROP COLUMN IF EXISTS cvss_vector,
--     DROP COLUMN IF EXISTS cvss_score;
--   COMMIT;
-- ---------------------------------------------------------------------------
