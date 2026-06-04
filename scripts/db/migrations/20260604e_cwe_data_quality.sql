-- ============================================================================
-- 20260604e_cwe_data_quality.sql
-- ----------------------------------------------------------------------------
-- Strip the wrong CWE-1021 (Improper Restriction of Rendered UI Layers /
-- Clickjacking) from findings where it was incorrectly applied by older
-- run_light.py versions:
--
--   • dns-missing-spf       → was [290, 1021] or [1021], should be [290]
--   • dns-missing-dmarc     → was [290, 1021] or [1021], should be [290]
--   • csp-static-nonce      → was [1021],          should be [330]
--   • csp-static-nonce per-directive → was [1021], should be [330]
--
-- CWE-1021 is reserved for findings that actually involve frame/UI
-- restriction (clickjacking). DNS-missing-email-auth findings and
-- predictable-nonce findings are categorically different and were getting
-- copy-pasted CWE tags from an early run_light.py author who didn't look
-- up the right CWE numbers.
--
-- Run-light parser is fixed in parallel commit; this migration cleans
-- the historical data.
--
-- Idempotent.
-- ============================================================================

BEGIN;

DO $$
DECLARE
  before_spf_dmarc integer;
  before_csp integer;
BEGIN
  SELECT count(*) INTO before_spf_dmarc
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND (finding_id LIKE '%:dns-missing-spf' OR finding_id LIKE '%:dns-missing-dmarc')
    AND 1021 = ANY(cwe);

  SELECT count(*) INTO before_csp
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%csp-static-nonce%'
    AND 1021 = ANY(cwe);

  RAISE NOTICE 'DNS-email-auth rows with bogus CWE-1021: %', before_spf_dmarc;
  RAISE NOTICE 'CSP nonce rows with bogus CWE-1021: %', before_csp;
END $$;

-- DNS missing SPF / DMARC: ensure CWE-290 is present, strip CWE-1021.
UPDATE public.findings
SET cwe = (
  SELECT array_agg(DISTINCT c ORDER BY c)
  FROM unnest(cwe || ARRAY[290]) AS c
  WHERE c <> 1021
)
WHERE source = 'commandsentry_light'
  AND (finding_id LIKE '%:dns-missing-spf' OR finding_id LIKE '%:dns-missing-dmarc')
  AND 1021 = ANY(cwe);

-- CSP static nonce: replace CWE-1021 with CWE-330.
UPDATE public.findings
SET cwe = (
  SELECT array_agg(DISTINCT c ORDER BY c)
  FROM unnest(cwe || ARRAY[330]) AS c
  WHERE c <> 1021
)
WHERE source = 'commandsentry_light'
  AND finding_id LIKE '%csp-static-nonce%'
  AND 1021 = ANY(cwe);

DO $$
DECLARE
  remaining_spf_dmarc integer;
  remaining_csp integer;
BEGIN
  SELECT count(*) INTO remaining_spf_dmarc
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND (finding_id LIKE '%:dns-missing-spf' OR finding_id LIKE '%:dns-missing-dmarc')
    AND 1021 = ANY(cwe);

  SELECT count(*) INTO remaining_csp
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%csp-static-nonce%'
    AND 1021 = ANY(cwe);

  RAISE NOTICE 'After migration — DNS-email-auth with CWE-1021: % (expect 0)', remaining_spf_dmarc;
  RAISE NOTICE 'After migration — CSP nonce with CWE-1021: % (expect 0)', remaining_csp;
END $$;

COMMIT;
