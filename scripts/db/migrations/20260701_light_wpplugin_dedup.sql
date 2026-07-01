-- ---------------------------------------------------------------------------
-- 20260701_light_wpplugin_dedup.sql
-- ---------------------------------------------------------------------------
-- Re-key light-tier (commandsentry_light) WordPress plugin advisories to the
-- plugin-level master key normalized_key = wpplugin-<slug>, so all CVEs for
-- one plugin install collapse into ONE group in v_open_findings_dedup instead
-- of rendering as one row per CVE (P-008).
--
-- WHY THIS RECURS (and why the 20260604c backfill didn't hold):
--   run_light.py computed normalized_key = <cve-join> for any cve-populated
--   finding, and the upsert does
--     normalized_key = COALESCE(EXCLUDED.normalized_key, findings.normalized_key)
--   so every re-scan OVERWROTE the 20260604c backfill with a fresh per-CVE
--   key and the rows re-split. The durable fix is the run_light.py change
--   shipped alongside this migration (LightFinding.normalized_key_override →
--   wpplugin-<slug>, which now WINS over the cve-join at upsert time).
--
--   APPLY ORDER: deploy the run_light.py change FIRST, then run this backfill.
--   Any light scan that lands after the scanner fix already writes the
--   wpplugin-<slug> key, so this backfill only needs to catch rows last
--   scanned before the fix — and, unlike 20260604c, it will now STICK.
--
-- Slug source: the wpvulnerability.net title always carries a [slug] token
--   ('Slider Revolution [revslider] < 7.0.11'). Same regex the scanner and
--   20260604c use, so all three agree.
--
-- Safe / idempotent: SELECT-shaped UPDATE, only touches commandsentry_light
--   wpvuln rows that don't already carry a wpplugin-* key. Re-runnable.

DO $$
DECLARE
  before_total    integer;
  before_wpplugin integer;
  after_wpplugin  integer;
  distinct_groups integer;
BEGIN
  SELECT count(*) INTO before_total
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%:light:wpvuln-%';

  SELECT count(*) INTO before_wpplugin
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%:light:wpvuln-%'
    AND normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE 'light wpvuln rows: %    already wpplugin-*: %',
    before_total, before_wpplugin;
END $$;

-- THE FIX — derive wpplugin-<slug> for light wpvuln rows that carry a [slug]
-- token and aren't already plugin-keyed. Catches cve-, uuid-, and
-- target/version-keyed check_names (all share the ':light:wpvuln-' prefix).
UPDATE public.findings
SET normalized_key = 'wpplugin-' || lower(substring(title FROM '\[([^\]]+)\]'))
WHERE source = 'commandsentry_light'
  AND finding_id LIKE '%:light:wpvuln-%'
  AND title ~ '\[[^\]]+\]'
  AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

DO $$
DECLARE
  after_wpplugin  integer;
  distinct_groups integer;
BEGIN
  SELECT count(*) INTO after_wpplugin
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%:light:wpvuln-%'
    AND normalized_key LIKE 'wpplugin-%';

  SELECT count(DISTINCT (asset_id, normalized_key)) INTO distinct_groups
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE 'light wpvuln wpplugin-* keys after: %    distinct (asset, plugin) groups: %',
    after_wpplugin, distinct_groups;
END $$;

-- Verify (informational) — should return one row per (asset, plugin) with the
-- member CVE count; no plugin should appear as multiple rows for one asset:
--   SELECT asset_id, normalized_key, count(*) AS member_cves
--   FROM public.findings
--   WHERE source = 'commandsentry_light' AND normalized_key LIKE 'wpplugin-%'
--   GROUP BY asset_id, normalized_key
--   ORDER BY member_cves DESC;
