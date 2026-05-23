-- ============================================================================
-- 20260523d_email_finding_id_match_method.sql
--
-- Adds 'finding_id_reference' to the email_match_method_t enum.
--
-- Why: test-4 (Deloitte audit follow-up) referenced a literal finding ID
-- in the email body ('commandcommcentral.com:manual:M-04'). The matcher
-- now extracts these via regex and emits HIGH-confidence finding links,
-- but the existing enum had no fitting value:
--   - 'cve_reference'   would mis-state the actual pattern matched
--   - 'manual'          implies admin-asserted via /inbox triage form
--   - 'component_reference' is name-based against tech_profile, not ID-based
--
-- So we add a dedicated value. The /inbox triage UI displays this as
-- 'via finding id reference' (underscores stripped).
--
-- Idempotent. Safe to re-run.
-- ============================================================================

ALTER TYPE email_match_method_t ADD VALUE IF NOT EXISTS 'finding_id_reference';
