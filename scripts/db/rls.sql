-- ============================================================================
-- COMMANDsentry — Row Level Security policies (Phase 3, Track 1 — Auth v0)
--
-- Single-user model:
--   - 'authenticated' role can SELECT all rows on every table
--   - 'anon' role gets nothing (anon API key in browser/leaked URL = useless)
--   - service_role bypasses RLS (used by import_jsonl.py and admin tasks)
--
-- Write operations (INSERT / UPDATE / DELETE) are NOT granted to authenticated
-- users in v0 — only the service_role (importer) writes. The SPA is read-only.
-- Add write policies later when the SPA needs them.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/rls.sql
--
-- Idempotent — every CREATE POLICY uses DROP POLICY IF EXISTS first.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Enable RLS on every table
-- ---------------------------------------------------------------------------
ALTER TABLE assets             ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans              ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings           ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_history    ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_artifacts ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 2. Drop any existing policies so this script stays idempotent
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS authenticated_read_assets             ON assets;
DROP POLICY IF EXISTS authenticated_read_scans              ON scans;
DROP POLICY IF EXISTS authenticated_read_findings           ON findings;
DROP POLICY IF EXISTS authenticated_read_finding_history    ON finding_history;
DROP POLICY IF EXISTS authenticated_read_evidence_artifacts ON evidence_artifacts;

-- ---------------------------------------------------------------------------
-- 3. Grant SELECT to authenticated users
-- ---------------------------------------------------------------------------
CREATE POLICY authenticated_read_assets
  ON assets
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY authenticated_read_scans
  ON scans
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY authenticated_read_findings
  ON findings
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY authenticated_read_finding_history
  ON finding_history
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY authenticated_read_evidence_artifacts
  ON evidence_artifacts
  FOR SELECT
  TO authenticated
  USING (true);

-- ---------------------------------------------------------------------------
-- 4. Verification queries (informational — these don't enforce anything,
--    they just let you eyeball what's in place)
-- ---------------------------------------------------------------------------

-- Show RLS status per table
SELECT schemaname, tablename, rowsecurity AS rls_enabled
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('assets','scans','findings','finding_history','evidence_artifacts')
ORDER BY tablename;

-- Show all policies on our tables
SELECT schemaname, tablename, policyname, roles, cmd, qual
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN ('assets','scans','findings','finding_history','evidence_artifacts')
ORDER BY tablename, policyname;
