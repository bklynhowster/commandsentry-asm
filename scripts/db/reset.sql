-- ============================================================================
-- COMMANDsentry — DESTRUCTIVE reset
--
-- Drops all tables, views, types, and triggers managed by schema.sql.
-- Use only during early Phase 2 iteration. Once we start trusting the
-- canonical DB, this file should be retired.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/reset.sql
--   psql "$SUPABASE_DSN" -f scripts/db/schema.sql
-- ============================================================================

DROP VIEW  IF EXISTS v_latest_scan_per_asset CASCADE;
DROP VIEW  IF EXISTS v_asset_posture_counts  CASCADE;
DROP VIEW  IF EXISTS v_open_findings         CASCADE;

DROP TABLE IF EXISTS evidence_artifacts CASCADE;
DROP TABLE IF EXISTS finding_history    CASCADE;
DROP TABLE IF EXISTS findings           CASCADE;
DROP TABLE IF EXISTS scans              CASCADE;
DROP TABLE IF EXISTS assets             CASCADE;

DROP FUNCTION IF EXISTS trg_set_updated_at() CASCADE;

DROP TYPE IF EXISTS artifact_type_t   CASCADE;
DROP TYPE IF EXISTS finding_source_t  CASCADE;
DROP TYPE IF EXISTS scan_source_t     CASCADE;
DROP TYPE IF EXISTS scan_type_t       CASCADE;
DROP TYPE IF EXISTS finding_category_t CASCADE;
DROP TYPE IF EXISTS history_status_t  CASCADE;
DROP TYPE IF EXISTS finding_status_t  CASCADE;
DROP TYPE IF EXISTS organization_t    CASCADE;
DROP TYPE IF EXISTS asset_type_t      CASCADE;
DROP TYPE IF EXISTS risk_t            CASCADE;
DROP TYPE IF EXISTS severity_t        CASCADE;
