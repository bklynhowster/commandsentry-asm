-- ============================================================================
-- 20260604_wpvuln_plugin_dedup.sql
-- ----------------------------------------------------------------------------
-- Patch the cross-source dedup migration (20260601a) for wpvulnerability.net
-- advisories that have no CVE assigned.
--
-- Background — what's broken today
-- --------------------------------
-- wpvulnerability.net returns multiple advisories per plugin. Common pattern:
--   • 1 CVE-tagged entry  → run_light emits check_name = wpvuln-<cve>
--   • N UUID-tagged entries (no CVE) → run_light emits wpvuln-uuid-<hash>
--
-- 20260601a's Phase 2c sets `normalized_key = split_part(finding_id, ':light:', 2)`
-- for all commandsentry_light rows. So each UUID-tagged advisory ends up with
-- its own unique normalized_key:
--   wpvuln-uuid-e39b5d7131f747cb
--   wpvuln-uuid-dd8fa78124a5fdde
--   …etc
--
-- Result: ONE plugin install with 3 wpvulnerability advisories shows up as
-- THREE separate rows in the asset detail page — same plugin, same version,
-- same remediation, three rows of noise. Caught fleet-wide on
-- commandmarketinginnovations.com + unimacgraphics.com 2026-06-04.
--
-- Why we don't just merge them into the CVE-tagged row
-- ----------------------------------------------------
-- The CVE-tagged wpvuln row (normalized_key = cve-2023-1575) currently
-- merges with manual_named F-01 (also keyed cve-2023-1575). That's correct
-- cross-source behavior and we want to keep it. If we collapse the UUID
-- rows into the CVE key, we'd dilute the dedup group with unrelated
-- advisories — and lose audit fidelity ("which advisory triggered which
-- finding").
--
-- The fix
-- -------
-- For commandsentry_light rows with a finding_id matching
-- ':light:wpvuln-uuid-%', extract the plugin slug from the title and use
-- `wpplugin-<slug>` as the normalized_key. The 2 UUID-tagged advisories
-- for the same plugin on the same asset now share a dedup key and collapse
-- into one row.
--
-- Title shape: 'Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)'.
-- The `[slug]` token is the WordPress plugin slug — written by
-- _wpvuln_emit_finding() and consistent across every wpvulnerability
-- detection. Confirmed against the live DB 2026-06-04.
--
-- Idempotent. Safe to re-run after each scan.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- Capture BEFORE state for the changelog
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  before_count_uuid integer;
  before_count_plugin integer;
BEGIN
  SELECT count(*) INTO before_count_uuid
  FROM public.findings
  WHERE source = 'commandsentry_light'
    AND finding_id LIKE '%:light:wpvuln-uuid-%';

  SELECT count(*) INTO before_count_plugin
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE
    'wpvuln-uuid rows: %    wpplugin-* keys before: %',
    before_count_uuid, before_count_plugin;
END $$;

-- ---------------------------------------------------------------------------
-- THE FIX — derive wpplugin-<slug> normalized_key for UUID-only wpvuln rows
-- ---------------------------------------------------------------------------
UPDATE public.findings
SET normalized_key =
  'wpplugin-' ||
  lower(substring(title FROM '\[([^\]]+)\]'))
WHERE source = 'commandsentry_light'
  AND finding_id LIKE '%:light:wpvuln-uuid-%'
  -- title MUST contain a `[slug]` token; without it we have no slug to
  -- key on and we'd produce 'wpplugin-' (a bogus shared key). Skip those
  -- rather than corrupt the dedup.
  AND title ~ '\[[^\]]+\]'
  -- Don't churn rows that are already on the new key (idempotency).
  AND (normalized_key IS NULL OR normalized_key NOT LIKE 'wpplugin-%');

-- ---------------------------------------------------------------------------
-- Capture AFTER state — how much consolidation did we get?
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  after_count_plugin integer;
  distinct_plugin_groups integer;
BEGIN
  SELECT count(*) INTO after_count_plugin
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  SELECT count(DISTINCT (asset_id, normalized_key)) INTO distinct_plugin_groups
  FROM public.findings
  WHERE normalized_key LIKE 'wpplugin-%';

  RAISE NOTICE
    'wpplugin-* keys after: %    distinct (asset, plugin) groups: %    rows collapsed: %',
    after_count_plugin,
    distinct_plugin_groups,
    after_count_plugin - distinct_plugin_groups;
END $$;

COMMIT;

-- ============================================================================
-- Spot-check queries (run after migration):
-- ============================================================================
--
-- 1. Show the new groupings per asset:
--    SELECT asset_id, normalized_key,
--           count(*) AS source_count,
--           array_agg(DISTINCT title) AS titles
--    FROM public.findings
--    WHERE normalized_key LIKE 'wpplugin-%'
--    GROUP BY asset_id, normalized_key
--    ORDER BY asset_id, source_count DESC;
--
-- 2. Verify no over-collapse — should NEVER see > 1 plugin slug in titles
--    for a single (asset_id, normalized_key) tuple:
--    SELECT asset_id, normalized_key,
--           array_agg(DISTINCT substring(title FROM '\[([^\]]+)\]')) AS slugs
--    FROM public.findings
--    WHERE normalized_key LIKE 'wpplugin-%'
--    GROUP BY asset_id, normalized_key
--    HAVING count(DISTINCT substring(title FROM '\[([^\]]+)\]')) > 1;
--
-- 3. Verify CVE-tagged rows untouched (should still be 'cve-XXXX-XXXX'):
--    SELECT asset_id, normalized_key, title
--    FROM public.findings
--    WHERE source = 'commandsentry_light'
--      AND finding_id LIKE '%:light:wpvuln-cve-%'
--      AND normalized_key NOT LIKE 'cve-%';
--    -- expected: 0 rows
