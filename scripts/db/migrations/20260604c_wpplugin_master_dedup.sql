-- ============================================================================
-- 20260604c_wpplugin_master_dedup.sql
-- ----------------------------------------------------------------------------
-- Promote wpplugin-{slug} to the MASTER dedup key for ALL wpvulnerability
-- findings — CVE-tagged or not, cloud_light or wpscan path. Plus an explicit
-- manual override for F-01 so the existing F-01 + wpvuln-CVE merge survives
-- on Unimac.
--
-- Why
-- ---
-- After 20260604 + 20260604b, CMI still showed Mega Main Menu as TWO rows:
--   • plugin-level group (wpplugin-mega_main_menu) — 3 UUID-/no-CVE rows
--   • CVE-keyed group   (cve-2023-1575)            — 2 CVE-tagged rows
-- Both about the same plugin install. Two rows. Howie caught it in 5 seconds.
-- Same problem on Slider Revolution where the various per-CVE rows are split.
--
-- This migration collapses BOTH the UUID and the CVE buckets into a single
-- wpplugin-{slug} bucket per plugin per asset. One row per plugin install.
--
-- F-01 override
-- -------------
-- unimacgraphics.com:manual:F-01 is keyed cve-2023-1575 today and merges
-- with the cloud_light + wpscan CVE-tagged rows via shared CVE. If we
-- repoint all wpvuln rows to wpplugin-mega_main_menu but leave F-01 on the
-- CVE key, F-01 stops merging. Explicit override repoints F-01 to
-- wpplugin-mega_main_menu too. The merged group's display title becomes the
-- longest member title — "F-01: Abandoned Plugin — Mega Main Menu 2.2.1
-- (CVE-2023-1575)" — and the portal's strip-trailing-CVE renderer trims to
-- "F-01: Abandoned Plugin — Mega Main Menu 2.2.1" for display. Severity =
-- group MAX = HIGH (F-01's severity).
--
-- Future manual_named WP plugin findings (F-03 Elementor, F-04 WPForms, etc.)
-- can be added below as one-line overrides as they come up. The 'one explicit
-- mapping per asset' pattern keeps each override auditable.
--
-- Idempotent.
-- ============================================================================

BEGIN;

DO $$
DECLARE
  before_total integer;
  before_wpplugin integer;
BEGIN
  SELECT count(*) INTO before_total
  FROM public.findings
  WHERE source IN ('commandsentry_light', 'wpscan')
    AND (finding_id LIKE '%:light:wpvuln-%'
      OR finding_id LIKE '%:wpvulnerability:wpvuln:%');

  SELECT count(*) INTO before_wpplugin
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE 'Total wpvuln rows: %    wpplugin-* keys before: %',
    before_total, before_wpplugin;
END $$;

-- ---------------------------------------------------------------------------
-- Phase 1 — cloud_light wpvuln-cve-* rows → wpplugin-{slug}
-- ---------------------------------------------------------------------------
-- Cloud Light titles always carry the WordPress plugin slug in a [slug]
-- token: 'Slider Revolution [revslider] < 7.0.11'.
UPDATE public.findings
SET normalized_key = 'wpplugin-' || lower(substring(title FROM '\[([^\]]+)\]'))
WHERE source = 'commandsentry_light'
  AND finding_id LIKE '%:light:wpvuln-cve-%'
  AND title ~ '\[[^\]]+\]'
  AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

-- ---------------------------------------------------------------------------
-- Phase 2 — wpscan (cs_parsers) CVE-tagged wpvuln rows → wpplugin-{slug}
-- ---------------------------------------------------------------------------
-- cs_parsers/wpvuln_json.py emits finding_id of the form:
--   <asset>:wpvulnerability:wpvuln:<slug>:CVE-XXXX-XXXX:fix=<v>:<hash7>
-- Slug is structurally extractable via split_part.
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
  AND finding_id LIKE '%:wpvulnerability:wpvuln:%:CVE-%'
  AND split_part(
        split_part(finding_id, ':wpvulnerability:wpvuln:', 2),
        ':',
        1
      ) <> ''
  AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

-- ---------------------------------------------------------------------------
-- Phase 3 — manual_named overrides (one-asset-at-a-time, auditable)
-- ---------------------------------------------------------------------------
-- F-01 Unimac: Mega Main Menu abandoned-plugin manual classification.
-- Re-key to wpplugin-mega_main_menu so it merges with the wpvuln advisories
-- about the same plugin install instead of being a parallel CVE-keyed row.
UPDATE public.findings
SET normalized_key = 'wpplugin-mega_main_menu'
WHERE finding_id = 'unimacgraphics.com:manual:F-01';

-- Add future manual overrides here as new manual_named WP-plugin findings
-- are written. Example template (commented):
--   UPDATE public.findings
--   SET normalized_key = 'wpplugin-elementor'
--   WHERE finding_id = 'commanddigital.com:manual:F-03';
--
-- Each override is one line so any unintended re-keying is easy to spot in
-- code review.

DO $$
DECLARE
  total_wpplugin integer;
  distinct_groups integer;
BEGIN
  SELECT count(*) INTO total_wpplugin
  FROM public.findings WHERE normalized_key LIKE 'wpplugin-%';

  SELECT count(DISTINCT (asset_id, normalized_key)) INTO distinct_groups
  FROM public.findings WHERE normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE 'wpplugin-* total: %    distinct (asset, plugin) groups: %    rows collapsed: %',
    total_wpplugin, distinct_groups, total_wpplugin - distinct_groups;
END $$;

COMMIT;

-- Post-migration spot-check queries:
--   1) Confirm CVE-keyed wpvuln rows are gone:
--      SELECT count(*) FROM public.findings
--      WHERE source IN ('commandsentry_light','wpscan')
--        AND normalized_key LIKE 'cve-%'
--        AND (finding_id LIKE '%:light:wpvuln-%' OR finding_id LIKE '%:wpvulnerability:wpvuln:%');
--      -- expected: 0
--   2) Group sizes on CMI + Unimac:
--      SELECT asset_id, normalized_key, count(*) AS n,
--             array_agg(DISTINCT source) AS sources
--      FROM public.findings
--      WHERE normalized_key LIKE 'wpplugin-%'
--      GROUP BY asset_id, normalized_key
--      ORDER BY asset_id, n DESC;
