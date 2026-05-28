-- ============================================================================
-- 20260522d_asset_tech_profile.sql
--
-- Surface the *tech profile* of each asset — what application is running, what
-- platform, what WAF, what TLS version, what OS, what WP plugins, etc. — so
-- /assets/[id] in the portal can answer "what IS this thing" without dragging
-- in raw scan output.
--
-- Two layers:
--
--   1. assets.tech_profile JSONB
--      Current snapshot. One denormalized blob per asset. Fast read for the
--      asset detail page (no joins). Schema is open so we can evolve without
--      a migration every time a new scanner produces a new fingerprint type.
--      See tech_profile JSON shape doc in commandsentry-asm/docs/.
--
--   2. asset_tech_history
--      Append-only observations. Every fingerprint event the importer detects
--      writes a row. This is where the *compliance gold* lives: "WordPress
--      6.9.1 → 6.9.4 on 2026-05-15" is patching-cadence evidence for ISO 27001
--      A.12.6.1 and SOC 2 CC7.1. Never DELETE from this table.
--
-- Importer contract (codified later in scripts/normalize/):
--   - On each scan ingest, compute the current tech_profile from the scan
--     outputs (nuclei JSON, httpx JSON, wpscan JSON, nmap XML, testssl JSON,
--     etc.)
--   - Diff against the prior assets.tech_profile.
--   - For each diff row, INSERT into asset_tech_history with change_type =
--     'first_seen' | 'version_changed' | 'removed' | 'reobserved'.
--   - UPDATE assets.tech_profile + tech_profile_updated_at + tech_profile_sources.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. assets — add tech_profile + provenance columns
-- ---------------------------------------------------------------------------

ALTER TABLE assets
  ADD COLUMN IF NOT EXISTS tech_profile             jsonb       NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS tech_profile_updated_at  timestamptz,
  ADD COLUMN IF NOT EXISTS tech_profile_sources     text[]      NOT NULL DEFAULT '{}',
  -- Confidence summary for the whole profile (rolled up at importer time so
  -- the UI can show a chip without reading every leaf). One of
  -- 'high' | 'medium' | 'low' | 'unknown'.
  ADD COLUMN IF NOT EXISTS tech_profile_confidence  text;

-- Lightweight constraint — keep typos out of the confidence chip.
DO $$ BEGIN
  ALTER TABLE assets
    ADD CONSTRAINT chk_tech_profile_confidence
    CHECK (tech_profile_confidence IS NULL
           OR tech_profile_confidence IN ('high','medium','low','unknown'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- GIN index on the JSONB so fleet queries like "every asset where
-- tech_profile @> '{\"application\":{\"name\":\"WordPress\"}}'" stay fast.
CREATE INDEX IF NOT EXISTS idx_assets_tech_profile_gin
  ON assets USING gin(tech_profile);

-- Expression index for the very common "show me everything on TLS 1.2"
-- style query. Kept tight to avoid bloat.
CREATE INDEX IF NOT EXISTS idx_assets_tech_app_name
  ON assets ((tech_profile #>> '{application,name}'));

CREATE INDEX IF NOT EXISTS idx_assets_tech_webserver_name
  ON assets ((tech_profile #>> '{platform,web_server,name}'));

COMMENT ON COLUMN assets.tech_profile IS
  'Current technology fingerprint snapshot. JSON shape: see commandsentry-asm/docs/tech_profile.md. Source of truth for /assets/[id] tech card. Updated by importer on each scan ingest.';

COMMENT ON COLUMN assets.tech_profile_updated_at IS
  'When the tech_profile was last refreshed by the importer. Distinct from assets.updated_at so we can show "last fingerprinted" separately from row touches.';

COMMENT ON COLUMN assets.tech_profile_sources IS
  'Array of scanner names that contributed to the current profile (e.g. {nuclei,wpscan,httpx,testssl}). Used in UI for provenance.';

COMMENT ON COLUMN assets.tech_profile_confidence IS
  'Rolled-up confidence chip for the whole profile. high/medium/low/unknown.';

-- ---------------------------------------------------------------------------
-- 2. asset_tech_history — append-only observation log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS asset_tech_history (
  history_id    bigserial      PRIMARY KEY,
  asset_id      text           NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  observed_at   timestamptz    NOT NULL DEFAULT now(),

  -- The scan that surfaced this observation. ON DELETE SET NULL so we never
  -- lose the historical fact just because the underlying scan record was
  -- pruned in maintenance.
  scan_id       text           REFERENCES scans(scan_id) ON DELETE SET NULL,

  -- Dotted path into the tech_profile schema. Examples:
  --   'platform.web_server'   — nginx / IIS / Apache
  --   'application'           — WordPress / .NET Core / etc.
  --   'wordpress.plugin'      — one row per plugin (use item_key=slug)
  --   'wordpress.theme'
  --   'tls'
  --   'edge.waf'
  --   'os'
  --   'ports'                 — usually summarized; granular events optional
  category      text           NOT NULL,

  -- For multi-item categories (e.g. wordpress.plugin), the canonical key.
  -- For wordpress.plugin → plugin slug (e.g. 'elementor').
  -- For top-level singletons (application, tls, etc.) leave NULL.
  item_key      text,

  -- Friendly name + version for the row, denormalized so the change-log UI
  -- doesn't need to re-parse prior_value/new_value JSON.
  name          text,
  version       text,

  -- Full prior + new JSON snippets so we can diff exactly. NULL prior =
  -- first observation. NULL new (with change_type='removed') = scanner no
  -- longer reports this item.
  prior_value   jsonb,
  new_value     jsonb,

  change_type   text           NOT NULL
                CHECK (change_type IN
                       ('first_seen','version_changed','removed','reobserved','attribute_changed')),

  confidence    text           CHECK (confidence IS NULL
                                      OR confidence IN ('high','medium','low','unknown')),
  source        text,          -- scanner name that drove this observation

  -- Free-form notes from the importer (e.g. why confidence is low, which
  -- nuclei template matched, which wpscan readme line resolved the version).
  notes         text
);

CREATE INDEX IF NOT EXISTS idx_asset_tech_history_asset_observed
  ON asset_tech_history(asset_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_asset_tech_history_category
  ON asset_tech_history(asset_id, category);

CREATE INDEX IF NOT EXISTS idx_asset_tech_history_change_type
  ON asset_tech_history(change_type);

COMMENT ON TABLE asset_tech_history IS
  'Append-only log of every tech-fingerprint observation. Drives the "Change history" panel on /assets/[id] and feeds patching-cadence evidence for ISO 27001 A.12.6.1 / SOC 2 CC7.1.';

-- ---------------------------------------------------------------------------
-- 3. Convenience view — most-recent change per category per asset.
--    Used by the asset detail page "Recent changes" panel.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW asset_tech_recent_changes AS
SELECT DISTINCT ON (asset_id, category, item_key)
  asset_id,
  category,
  item_key,
  name,
  version,
  change_type,
  observed_at,
  source,
  prior_value,
  new_value
FROM asset_tech_history
WHERE change_type IN ('first_seen','version_changed','removed')
ORDER BY asset_id, category, item_key, observed_at DESC;

COMMENT ON VIEW asset_tech_recent_changes IS
  'Latest meaningful change per (asset, category, item). Excludes "reobserved" noise. Drives the change-log card on /assets/[id].';

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--
--   BEGIN;
--   DROP VIEW IF EXISTS asset_tech_recent_changes;
--   DROP TABLE IF EXISTS asset_tech_history;
--   ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_tech_profile_confidence;
--   DROP INDEX IF EXISTS idx_assets_tech_webserver_name;
--   DROP INDEX IF EXISTS idx_assets_tech_app_name;
--   DROP INDEX IF EXISTS idx_assets_tech_profile_gin;
--   ALTER TABLE assets
--     DROP COLUMN IF EXISTS tech_profile_confidence,
--     DROP COLUMN IF EXISTS tech_profile_sources,
--     DROP COLUMN IF EXISTS tech_profile_updated_at,
--     DROP COLUMN IF EXISTS tech_profile;
--   COMMIT;
-- ---------------------------------------------------------------------------
