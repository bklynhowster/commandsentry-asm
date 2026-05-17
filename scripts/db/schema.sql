-- ============================================================================
-- COMMANDsentry — Postgres schema (Phase 2)
--
-- Mirrors the canonical JSON-Schema definitions in scripts/normalize/schemas/.
-- Natural keys (asset_id, finding_id, scan_id, artifact_id) are PKs — they
-- are already designed to be stable string identifiers, so a surrogate UUID
-- would just be an indirection.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/schema.sql
--
-- This file is idempotent — every CREATE uses IF NOT EXISTS. To wipe and
-- reload during early Phase 2 iteration, run scripts/db/reset.sql first.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Enum types (mirror JSON-Schema enum constraints)
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  CREATE TYPE severity_t AS ENUM (
    'CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE', 'LOW', 'INFO'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE risk_t AS ENUM (
    'CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE', 'LOW', 'INFO', 'UNKNOWN'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE asset_type_t AS ENUM (
    'apex_domain', 'single_host', 'ip', 'ip_range',
    'mail_server', 'vpn_endpoint', 'api_host'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE organization_t AS ENUM (
    'command_companies', 'command_digital', 'command_financial',
    'command_missouri', 'command_marketing', 'unimac', 'sci', 'unknown'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Idempotent backfill for organization_t (ALTER TYPE ADD VALUE can't live
-- inside a DO/transaction block, so it must be a top-level statement).
ALTER TYPE organization_t ADD VALUE IF NOT EXISTS 'unknown';

DO $$ BEGIN
  CREATE TYPE finding_status_t AS ENUM (
    'detected', 'confirmed', 'open',
    'remediated', 'validated_remediated', 'regressed',
    'false_positive', 'wont_fix', 'accepted_risk'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE history_status_t AS ENUM (
    'detected', 'confirmed', 'open', 'remediated', 'validated_remediated',
    'regressed', 'false_positive', 'absent'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 'open' added to match Phase 3 simplified status taxonomy (Principle #4):
-- rollup collapses detected/confirmed into 'open' for UI consumption.
ALTER TYPE history_status_t ADD VALUE IF NOT EXISTS 'open';

DO $$ BEGIN
  CREATE TYPE finding_category_t AS ENUM (
    'sast', 'dast', 'sca', 'secret', 'recon', 'tls', 'headers', 'dns',
    'email', 'auth', 'session', 'csrf', 'ssrf', 'xxe', 'xss', 'sqli',
    'idor', 'rce', 'lfi', 'redirect', 'info_disclosure', 'takeover',
    'typosquat', 'config', 'deprecation', 'supply_chain', 'other'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE scan_type_t AS ENUM (
    'asm_enumeration',
    'vuln_quick_recon',
    'vuln_full_assessment',
    'vuln_full_aggressive',
    'authenticated_scan',
    'authenticated_scan_prod',
    'authenticated_gapfill',
    'auth_bypass_probe',
    'remediation_verification',
    'surgical_validation',
    'dast',
    'api_external',
    'api_hardcore',
    'api_dotnet_probe',
    'wp_stealth_scan',
    'sast_sca',
    'tls_audit',
    'cross_target_recon'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE scan_source_t AS ENUM (
    'commandsentry_asm', 'mac_local_scan', 'manual'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE finding_source_t AS ENUM (
    'nuclei', 'zap', 'semgrep', 'gitleaks', 'trivy', 'osv-scanner',
    'trufflehog', 'testssl', 'sslyze', 'ffuf', 'subzy', 'dnstwist',
    'theharvester', 'nmap', 'nikto', 'wpscan', 'feroxbuster',
    'auth_bypass_probe', 'manual_named', 'sprocket_external',
    'wellgate_external', 'commandsentry_asm', 'other'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE artifact_type_t AS ENUM (
    'response_body', 'response_headers', 'request', 'meta',
    'log_excerpt', 'screenshot', 'poc_html', 'tool_output', 'raw_evidence'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

-- Assets — the canonical target inventory.
CREATE TABLE IF NOT EXISTS assets (
  asset_id        text            PRIMARY KEY,
  name            text            NOT NULL,
  type            asset_type_t    NOT NULL,
  organization    organization_t  NOT NULL,
  tags            text[]          NOT NULL DEFAULT '{}',
  first_observed  timestamptz,
  last_observed   timestamptz,
  current_risk    risk_t          NOT NULL DEFAULT 'UNKNOWN',
  current_risk_reason text,        -- not in JSON schema but emitted by rollup
  metadata        jsonb           NOT NULL DEFAULT '{}'::jsonb,
  created_at      timestamptz     NOT NULL DEFAULT now(),
  updated_at      timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_org           ON assets(organization);
CREATE INDEX IF NOT EXISTS idx_assets_current_risk  ON assets(current_risk);
CREATE INDEX IF NOT EXISTS idx_assets_tags_gin      ON assets USING gin(tags);

-- Scans — one row per dated scan-run.
CREATE TABLE IF NOT EXISTS scans (
  scan_id         text          PRIMARY KEY,
  asset_id        text          NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  scan_type       scan_type_t   NOT NULL,
  -- started_at may be NULL for target-root synthetic scans (no dated wrapper dir).
  -- Phase 3 walker will backfill from file mtimes.
  started_at      timestamptz,
  completed_at    timestamptz,
  command_line    text,
  exit_code       integer,
  output_dir      text,         -- forensic pointer to original Mac directory
  source          scan_source_t NOT NULL DEFAULT 'mac_local_scan',
  notes           text,
  tools_run       jsonb         NOT NULL DEFAULT '[]'::jsonb,
  created_at      timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_asset_id    ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at  ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_scan_type   ON scans(scan_type);

-- Findings — stable identity across scans. One row per (asset, finding).
CREATE TABLE IF NOT EXISTS findings (
  finding_id            text             PRIMARY KEY,
  asset_id              text             NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  title                 text             NOT NULL,
  severity              severity_t       NOT NULL,
  category              finding_category_t NOT NULL,
  description           text,
  cwe                   integer[]        NOT NULL DEFAULT '{}',
  cve                   text[]           NOT NULL DEFAULT '{}',
  "references"          text[]           NOT NULL DEFAULT '{}',
  current_status        finding_status_t NOT NULL DEFAULT 'detected',
  -- first_detected_at may be NULL for findings inherited from undated scans.
  first_detected_at     timestamptz,
  first_detected_scan   text             REFERENCES scans(scan_id) ON DELETE SET NULL,
  last_observed_at      timestamptz,
  remediated_at         timestamptz,
  owner                 text,
  deadline              date,
  source                finding_source_t NOT NULL,
  -- Merger-prep columns (carry-through from FindingEvent; help drill-in UX)
  subdomain             text,
  host_ip               text,
  port                  integer,
  protocol              text,
  tags                  text[]           NOT NULL DEFAULT '{}',
  created_at            timestamptz      NOT NULL DEFAULT now(),
  updated_at            timestamptz      NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id       ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity       ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_current_status ON findings(current_status);
CREATE INDEX IF NOT EXISTS idx_findings_source         ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_category       ON findings(category);
-- Combined index for the most-common dashboard query
CREATE INDEX IF NOT EXISTS idx_findings_asset_status_sev
  ON findings(asset_id, current_status, severity);

-- Finding history — append-only per-scan observations.
CREATE TABLE IF NOT EXISTS finding_history (
  id                bigserial          PRIMARY KEY,
  finding_id        text               NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
  scan_id           text               NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  -- observed_at may be NULL when inherited from an undated scan.
  observed_at       timestamptz,
  status            history_status_t   NOT NULL,
  severity_at_scan  severity_t,
  matched_at        text,
  raw_excerpt       text,
  notes             text,
  created_at        timestamptz        NOT NULL DEFAULT now(),
  -- Same finding can't be recorded twice for the same scan
  UNIQUE (finding_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_fh_finding_id   ON finding_history(finding_id);
CREATE INDEX IF NOT EXISTS idx_fh_scan_id      ON finding_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_fh_observed_at  ON finding_history(observed_at DESC);

-- Evidence artifacts — raw evidence files captured by scans.
CREATE TABLE IF NOT EXISTS evidence_artifacts (
  artifact_id    text             PRIMARY KEY,
  finding_id     text             NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
  scan_id        text             REFERENCES scans(scan_id) ON DELETE SET NULL,
  artifact_type  artifact_type_t  NOT NULL,
  local_path     text             NOT NULL,
  cloud_url      text,
  sha256         text             NOT NULL,
  mime_type      text,
  byte_size      bigint,
  uploaded_at    timestamptz,
  preview_4kb    text,
  captured_at    timestamptz      NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding_id  ON evidence_artifacts(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id     ON evidence_artifacts(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256      ON evidence_artifacts(sha256);

-- ---------------------------------------------------------------------------
-- Views — convenience queries that mirror the dashboard logic
-- ---------------------------------------------------------------------------

-- Open findings only (status filter that the UI applies).
CREATE OR REPLACE VIEW v_open_findings AS
SELECT *
FROM findings
WHERE current_status IN ('detected', 'confirmed', 'open', 'regressed');

-- Per-asset open severity rollup — the numbers shown on each posture card.
-- Note: COUNT(f.finding_id) instead of COUNT(*) so assets with no findings
-- show total_open=0 rather than 1 from the LEFT JOIN NULL row.
CREATE OR REPLACE VIEW v_asset_posture_counts AS
SELECT
  a.asset_id,
  a.name,
  a.organization,
  a.current_risk,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'CRITICAL')      AS critical_open,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'HIGH')          AS high_open,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'MODERATE-HIGH') AS mod_high_open,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'MODERATE')      AS moderate_open,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'LOW')           AS low_open,
  COUNT(f.finding_id) FILTER (WHERE f.severity = 'INFO')          AS info_open,
  COUNT(f.finding_id)                                              AS total_open
FROM assets a
LEFT JOIN v_open_findings f ON f.asset_id = a.asset_id
GROUP BY a.asset_id, a.name, a.organization, a.current_risk;

-- Latest scan per asset.
CREATE OR REPLACE VIEW v_latest_scan_per_asset AS
SELECT DISTINCT ON (asset_id)
  asset_id, scan_id, scan_type, started_at, completed_at
FROM scans
ORDER BY asset_id, started_at DESC;

-- ---------------------------------------------------------------------------
-- Triggers — keep updated_at fresh
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assets_updated_at ON assets;
CREATE TRIGGER trg_assets_updated_at
  BEFORE UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();

DROP TRIGGER IF EXISTS trg_findings_updated_at ON findings;
CREATE TRIGGER trg_findings_updated_at
  BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();

-- ---------------------------------------------------------------------------
-- RLS — disabled for Phase 2 single-user mode. Phase 3 will enable + define
-- policies based on the auth model.
-- ---------------------------------------------------------------------------
-- ALTER TABLE assets             ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scans              ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE findings           ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE finding_history    ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE evidence_artifacts ENABLE ROW LEVEL SECURITY;
