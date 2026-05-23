-- ============================================================================
-- 20260523a_matched_url_and_frameworks.sql
--
-- Two more structured columns the AI synth can populate, both addressing the
-- "config-style findings have nothing to show in Technical Detail" problem
-- Howie surfaced 2026-05-23 reviewing M-04 (Password Max Length on CCC).
--
--   matched_url text
--     The specific URL / endpoint where the finding was triggered. Nuclei
--     captures this as "matched-at", DAST runs capture as the request URL,
--     wpscan captures as the plugin path. For config findings without a
--     scanner-reported URL (like M-04), the synth can infer it from context
--     ("affects /account/changepassword endpoint per scan notes").
--
--   frameworks text[]
--     Compliance framework references mentioned in source data. Examples
--     drawn from real Command findings:
--       - "NIST 800-63B"  (M-04 password length finding)
--       - "NIST CSF PR.AC-1"
--       - "ISO 27001 A.9.4.3"
--       - "SOC 2 CC6.1"
--       - "HIPAA Security Rule §164.308(a)(5)(ii)(D)"
--       - "PCI DSS 8.3.6"
--     This is the audit-gold column. An auditor opening any finding sees
--     immediately which frameworks it maps to.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS matched_url  text,
  ADD COLUMN IF NOT EXISTS frameworks   text[] NOT NULL DEFAULT '{}';

-- GIN index on frameworks so "show me everything tagged NIST 800-63B" stays
-- fast across the whole portal.
CREATE INDEX IF NOT EXISTS idx_findings_frameworks_gin
  ON findings USING gin(frameworks);

COMMENT ON COLUMN findings.matched_url IS
  'Specific URL/endpoint where the scanner triggered this finding (nuclei matched-at, DAST request URL, etc.). For config findings without a scanner-reported URL, populated by AI synth inference.';

COMMENT ON COLUMN findings.frameworks IS
  'Compliance framework references this finding maps to (NIST 800-63B, ISO 27001 A.9.4.3, SOC 2 CC6.1, etc.). Populated by AI synth from source data. Audit-friendly: an auditor opening a finding immediately sees the framework mapping.';

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--   BEGIN;
--   DROP INDEX IF EXISTS idx_findings_frameworks_gin;
--   ALTER TABLE findings
--     DROP COLUMN IF EXISTS frameworks,
--     DROP COLUMN IF EXISTS matched_url;
--   COMMIT;
-- ---------------------------------------------------------------------------
