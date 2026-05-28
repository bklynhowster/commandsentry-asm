-- ============================================================================
-- MIGRATION — 2026-05-22 (b) — Generalize remediation_requests for all
-- asset-owner claims (not just "I fixed it")
--
-- Asset owners actually make THREE kinds of claims about findings, not one.
-- Original scope was "I fixed it, please retest" → validated_remediated.
-- The full taxonomy:
--
--   remediated            "I fixed it — please retest"
--   false_positive        "The scanner is wrong; the issue isn't really there"
--   compensating_control  "There's a mitigation the scanner doesn't see
--                          (WAF rule, segmentation, MFA on the path, etc.).
--                          Risk is residually acceptable."
--
-- Each one resolves to a different finding status when the admin approves:
--   remediated           → validated_remediated
--   false_positive       → false_positive
--   compensating_control → accepted_risk
--
-- Or, if the admin rejects:
--   remediated           → regressed (or still_open if simply not fixed)
--   false_positive       → rejected (finding stands as detected)
--   compensating_control → rejected
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260522b_claim_types_for_remediation_requests.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Add claim_type column
-- ---------------------------------------------------------------------------
ALTER TABLE public.remediation_requests
  ADD COLUMN IF NOT EXISTS claim_type text NOT NULL DEFAULT 'remediated';

-- Enforce allowed values.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'remediation_requests_claim_type_check'
       AND conrelid = 'public.remediation_requests'::regclass
  ) THEN
    ALTER TABLE public.remediation_requests
      ADD CONSTRAINT remediation_requests_claim_type_check
      CHECK (claim_type IN (
        'remediated',
        'false_positive',
        'compensating_control'
      ));
  END IF;
END$$;

COMMENT ON COLUMN public.remediation_requests.claim_type IS
  'What the asset owner is asserting about the finding: remediated (fixed, please retest), false_positive (scanner is wrong), compensating_control (mitigated by something the scanner cannot see). Default remediated for backward compat with the original retest-only workflow.';

-- Index for the admin queue grouping
CREATE INDEX IF NOT EXISTS idx_remediation_requests_claim_type
  ON public.remediation_requests(claim_type, request_status);

-- ---------------------------------------------------------------------------
-- 2. Expand review_outcome to include accepted_risk + rejected
-- ---------------------------------------------------------------------------
-- The original CHECK only allowed:
--   validated_remediated, regressed, still_open, false_positive
-- We need to add:
--   accepted_risk — admin approved a compensating_control claim
--   rejected      — admin rejected a false_positive or compensating_control
--                   claim (finding stays open as detected)
ALTER TABLE public.remediation_requests
  DROP CONSTRAINT IF EXISTS remediation_requests_review_outcome_check;

ALTER TABLE public.remediation_requests
  ADD CONSTRAINT remediation_requests_review_outcome_check
  CHECK (
    review_outcome IS NULL OR review_outcome IN (
      'validated_remediated',
      'regressed',
      'still_open',
      'false_positive',
      'accepted_risk',
      'rejected'
    )
  );

-- ---------------------------------------------------------------------------
-- 3. Verification
-- ---------------------------------------------------------------------------
SELECT 'remediation_requests columns:' AS info;
SELECT column_name, data_type, column_default
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND table_name = 'remediation_requests'
   AND column_name IN ('claim_type', 'review_outcome')
 ORDER BY column_name;

SELECT 'check constraints:' AS info;
SELECT conname, pg_get_constraintdef(oid) AS definition
  FROM pg_constraint
 WHERE conrelid = 'public.remediation_requests'::regclass
   AND contype = 'c'
 ORDER BY conname;

SELECT 'existing rows by claim_type (should default to remediated):' AS info;
SELECT claim_type, COUNT(*) AS n
  FROM public.remediation_requests
 GROUP BY claim_type;

COMMIT;
