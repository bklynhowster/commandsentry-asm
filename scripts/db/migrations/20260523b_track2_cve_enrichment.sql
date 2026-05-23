-- ============================================================================
-- 20260523b_track2_cve_enrichment.sql
--
-- Track 2 — populate every CVE-bearing finding with authoritative external
-- data from NVD + FIRST.org EPSS + CISA KEV. These come from free public
-- APIs, no key required, no LLM involved — deterministic, citation-able,
-- audit-friendly.
--
-- Adds two things:
--
--   1. cve_enrichments table — one row per unique CVE we've looked up.
--      Acts as a cache so we don't re-hit the NVD/EPSS/KEV APIs every
--      time we backfill. Refresh policy is timestamped (we re-fetch
--      KEV daily because that list changes; EPSS weekly; NVD per-CVE
--      only when first seen).
--
--   2. New columns on findings — denormalized rollup of the most-relevant
--      enrichment fields, so the portal page can read everything from
--      one row without joining.
--
-- Why denormalize on findings vs always join to cve_enrichments?
--   - A finding can have multiple CVEs (CVE arrays). The "worst case"
--     EPSS / KEV / CVSS across them is what we surface on the page.
--   - Reading the finding row should give the full picture without a
--     dependent join. Performance + auditability.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. cve_enrichments — authoritative cache per CVE
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cve_enrichments (
  cve_id              text          PRIMARY KEY,        -- e.g. 'CVE-2024-2473'

  -- NVD fields ------------------------------------------------------------
  nvd_cvss_v3_vector  text,
  nvd_cvss_v3_score   numeric(3,1),
  nvd_severity        text,                              -- 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'NONE'
  nvd_cwe_ids         integer[]     NOT NULL DEFAULT '{}',
  nvd_description     text,                              -- short EN description
  nvd_published_at    timestamptz,
  nvd_last_modified   timestamptz,
  nvd_references      text[]        NOT NULL DEFAULT '{}',
  nvd_fetched_at      timestamptz,

  -- EPSS (Exploit Prediction Scoring System) ------------------------------
  -- score is 0.0–1.0 probability of exploit in next 30 days
  -- percentile is 0.0–1.0 ranking against all CVEs
  epss_score          numeric(5,4),
  epss_percentile     numeric(5,4),
  epss_fetched_at     timestamptz,

  -- CISA KEV (Known Exploited Vulnerabilities) ----------------------------
  kev_listed          boolean       NOT NULL DEFAULT false,
  kev_added_date      date,
  kev_due_date        date,                              -- CISA-imposed remediation deadline
  kev_short_desc      text,
  kev_required_action text,
  kev_fetched_at      timestamptz,

  -- Bookkeeping ----------------------------------------------------------
  first_seen_at       timestamptz   NOT NULL DEFAULT now(),
  updated_at          timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_enrichments_kev_listed
  ON cve_enrichments(kev_listed) WHERE kev_listed = true;
CREATE INDEX IF NOT EXISTS idx_cve_enrichments_epss_score
  ON cve_enrichments(epss_score DESC NULLS LAST);

COMMENT ON TABLE cve_enrichments IS
  'Authoritative external data per CVE — NVD CVSS vector, FIRST.org EPSS, CISA KEV listing. Cache so we do not re-hit free APIs on every backfill.';

-- ---------------------------------------------------------------------------
-- 2. findings — denormalized rollup columns
-- ---------------------------------------------------------------------------

ALTER TABLE findings
  -- EPSS rollup — worst (highest) across all CVEs on the finding
  ADD COLUMN IF NOT EXISTS epss_score          numeric(5,4),
  ADD COLUMN IF NOT EXISTS epss_percentile     numeric(5,4),

  -- KEV rollup — true if ANY CVE on the finding is on the KEV catalog
  ADD COLUMN IF NOT EXISTS kev_listed          boolean       NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS kev_due_date        date,

  -- Provenance bookkeeping
  ADD COLUMN IF NOT EXISTS cve_enriched_at     timestamptz;

-- Index supports the "show me everything on the KEV list" portal query
CREATE INDEX IF NOT EXISTS idx_findings_kev_listed
  ON findings(kev_listed) WHERE kev_listed = true;

CREATE INDEX IF NOT EXISTS idx_findings_epss_score
  ON findings(epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;

COMMENT ON COLUMN findings.epss_score IS
  'Worst (highest) EPSS score across all CVEs on this finding. 0.0–1.0 probability of exploit in next 30 days per FIRST.org EPSS.';

COMMENT ON COLUMN findings.kev_listed IS
  'TRUE if any CVE on this finding is on the CISA Known Exploited Vulnerabilities catalog. Means actively exploited in the wild.';

COMMENT ON COLUMN findings.kev_due_date IS
  'CISA-imposed remediation deadline (the soonest one across CVEs on this finding, if KEV-listed).';

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--   BEGIN;
--   DROP INDEX IF EXISTS idx_findings_epss_score;
--   DROP INDEX IF EXISTS idx_findings_kev_listed;
--   ALTER TABLE findings
--     DROP COLUMN IF EXISTS cve_enriched_at,
--     DROP COLUMN IF EXISTS kev_due_date,
--     DROP COLUMN IF EXISTS kev_listed,
--     DROP COLUMN IF EXISTS epss_percentile,
--     DROP COLUMN IF EXISTS epss_score;
--   DROP INDEX IF EXISTS idx_cve_enrichments_epss_score;
--   DROP INDEX IF EXISTS idx_cve_enrichments_kev_listed;
--   DROP TABLE IF EXISTS cve_enrichments;
--   COMMIT;
-- ---------------------------------------------------------------------------
