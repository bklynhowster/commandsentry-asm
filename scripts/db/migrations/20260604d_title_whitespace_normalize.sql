-- ============================================================================
-- 20260604d_title_whitespace_normalize.sql
-- ----------------------------------------------------------------------------
-- Collapse runs of whitespace in finding titles to a single space, and trim.
-- Fixes 50 fleet-wide titles where nuclei + testssl parsers emitted double-
-- space separators between the title slug and the bracketed/parenthetical
-- metadata, e.g.:
--   "ssl-issuer  [Let's Encrypt]"
--   "testssl: cipher-tls1_2  (22 reports)"
--   "TLS forward secrecy not supported  (2 reports)"
--
-- Paired with parser-side __post_init__ on FindingEvent (cs_parsers/common.py)
-- that normalizes whitespace at write time, so future scans land clean.
-- This migration cleans up the existing fleet.
--
-- Idempotent: re-running doesn't re-touch rows already on the single-space form.
-- ============================================================================

BEGIN;

DO $$
DECLARE
  before_count integer;
BEGIN
  SELECT count(*) INTO before_count
  FROM public.findings
  WHERE title ~ '\s\s' OR title ~ '^\s' OR title ~ '\s$';
  RAISE NOTICE 'Rows with non-single-space whitespace: %', before_count;
END $$;

UPDATE public.findings
SET title = trim(regexp_replace(title, '\s+', ' ', 'g'))
WHERE title ~ '\s\s' OR title ~ '^\s' OR title ~ '\s$';

DO $$
DECLARE
  after_count integer;
BEGIN
  SELECT count(*) INTO after_count
  FROM public.findings
  WHERE title ~ '\s\s' OR title ~ '^\s' OR title ~ '\s$';
  RAISE NOTICE 'Rows still with non-single-space whitespace: % (expect 0)', after_count;
END $$;

COMMIT;
