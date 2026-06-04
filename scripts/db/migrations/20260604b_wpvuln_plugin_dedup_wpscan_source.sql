-- ============================================================================
-- 20260604b_wpvuln_plugin_dedup_wpscan_source.sql
-- ----------------------------------------------------------------------------
-- Extends 20260604_wpvuln_plugin_dedup.sql to the OTHER ingest path —
-- scripts/normalize/cs_parsers/wpvuln_json.py — which writes findings
-- with source='wpscan' and finding_id format:
--
--   <asset>:wpvulnerability:wpvuln:<slug>:<cve_or_no-cve>:fix=<v>:<hash7>
--
-- The first migration scoped to source='commandsentry_light' (run_light's
-- direct emit path). This one catches the offline-artifact ingest path.
--
-- Why both paths exist
-- --------------------
-- 1. run_light scans target with wpvulnerability_client → emits LightFinding →
--    finding_id = '<asset>:light:wpvuln-<cve|uuid|target>'
-- 2. cs_parsers/wpvuln_json reads pre-captured wpvuln-<slug>.json artifacts
--    under intensive scan dirs → emits FindingEvent with source='wpscan' →
--    finding_id = '<asset>:wpvulnerability:wpvuln:<slug>:...'
--
-- Path 2 is for the artifact-walker pipeline (Phase 1 scan_artifact_walker).
-- Found a survivor on CMI 2026-06-04 — a single 'mega_main_menu 2.2.1 —'
-- titled row keyed normalized_key=NULL that was rendering as a visual
-- duplicate of the CVE-tagged sibling once DedupGroupRow stripped trailing
-- CVE parentheticals at display time.
--
-- The slug extraction is structural (via split_part on the template token
-- inside finding_id) rather than title-regex because path-2 titles use a
-- different format than path-1 — title = '<slug> <ver> — <short>' rather
-- than 'Name [slug] <= <ver>' — and the finding_id format is the more
-- reliable source of the slug.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

DO $$
DECLARE
  before_count integer;
BEGIN
  SELECT count(*) INTO before_count
  FROM public.findings
  WHERE source = 'wpscan'
    AND finding_id LIKE '%:wpvulnerability:wpvuln:%:no-cve:%'
    AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

  RAISE NOTICE 'wpscan no-cve rows pending dedup: %', before_count;
END $$;

UPDATE public.findings
SET normalized_key =
  'wpplugin-' ||
  lower(
    split_part(
      split_part(finding_id, ':wpvulnerability:wpvuln:', 2),
      ':',
      1
    )
  )
WHERE source = 'wpscan'
  AND finding_id LIKE '%:wpvulnerability:wpvuln:%:no-cve:%'
  -- Must have an extractable slug — guard against malformed finding_ids.
  AND split_part(
        split_part(finding_id, ':wpvulnerability:wpvuln:', 2),
        ':',
        1
      ) <> ''
  AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

DO $$
DECLARE
  total_wpplugin integer;
  distinct_groups integer;
BEGIN
  SELECT count(*) INTO total_wpplugin
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  SELECT count(DISTINCT (asset_id, normalized_key)) INTO distinct_groups
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE
    'wpplugin-* total now: %    distinct (asset, plugin) groups: %',
    total_wpplugin, distinct_groups;
END $$;

COMMIT;
