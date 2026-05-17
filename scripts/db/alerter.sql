-- ============================================================================
-- COMMANDsentry — Alerter schema + helper queries (Phase 3 Track 3)
--
-- Adds the state table that the daily alerter writes to, plus a couple of
-- helper views that bake the "what changed since X" logic into the database
-- so the runner script stays thin.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/alerter.sql
--
-- Idempotent — re-running this script is safe.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. State table — one row per alerter run, append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS meta_alerter_runs (
  id              bigserial    PRIMARY KEY,
  alerter_name    text         NOT NULL DEFAULT 'daily_digest',
  started_at      timestamptz  NOT NULL DEFAULT now(),
  finished_at     timestamptz,
  -- Window the runner queried: changes BETWEEN window_start AND window_end
  window_start    timestamptz,
  window_end      timestamptz  NOT NULL DEFAULT now(),
  new_confirmed   integer      NOT NULL DEFAULT 0,
  new_regressed   integer      NOT NULL DEFAULT 0,
  new_high_risk   integer      NOT NULL DEFAULT 0,
  email_sent      boolean      NOT NULL DEFAULT false,
  status          text         NOT NULL DEFAULT 'started',  -- started|success|error
  error_message   text,
  notes           text,
  -- Snapshot of every asset_id currently in high-risk posture at end of this
  -- run. Next run diffs the live set against this snapshot to only fire on
  -- newly-elevated assets, even if the underlying assets.updated_at trigger
  -- bumps every row on every import.
  reported_high_risk_assets text[] NOT NULL DEFAULT '{}'
);

-- Idempotent backfill for existing deployments
ALTER TABLE meta_alerter_runs
  ADD COLUMN IF NOT EXISTS reported_high_risk_assets text[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_alerter_runs_name_started
  ON meta_alerter_runs(alerter_name, started_at DESC);

-- Lock down — service_role only (alerter uses the secret key).
ALTER TABLE meta_alerter_runs ENABLE ROW LEVEL SECURITY;
-- No policies = no access for authenticated/anon. service_role bypasses RLS.

-- ---------------------------------------------------------------------------
-- 2. Helper: last successful run window end.
-- Returns NULL if no successful runs yet (first run will pick a sensible
-- default in the alerter script).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION alerter_last_window_end(p_name text DEFAULT 'daily_digest')
RETURNS timestamptz
LANGUAGE sql
STABLE
AS $$
  SELECT window_end
  FROM meta_alerter_runs
  WHERE alerter_name = p_name
    AND status = 'success'
  ORDER BY started_at DESC
  LIMIT 1;
$$;

-- ---------------------------------------------------------------------------
-- 3. View — confirmed-state transitions in a window
--
-- Catches findings that have a finding_history row with status 'confirmed'
-- or 'open' whose observed_at falls inside the alerter's window. The 2-scan
-- confirmation pattern means we only care once a finding is past 'detected'.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_alerter_changes AS
SELECT
  f.finding_id,
  f.asset_id,
  f.title,
  f.severity,
  f.current_status,
  f.source,
  fh.scan_id,
  fh.observed_at  AS event_at,
  fh.status       AS event_status,
  CASE
    WHEN fh.status = 'regressed'             THEN 'REGRESSED'
    WHEN fh.status IN ('confirmed', 'open')
         AND f.severity IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')
                                              THEN 'CONFIRMED_HIGH'
    WHEN fh.status IN ('confirmed', 'open')   THEN 'CONFIRMED'
    ELSE 'OTHER'
  END AS alert_kind
FROM finding_history fh
JOIN findings f ON f.finding_id = fh.finding_id
WHERE fh.status IN ('confirmed', 'open', 'regressed');

-- ---------------------------------------------------------------------------
-- 4. View — assets currently in high-risk posture
--
-- Returns the full live set of CRITICAL / HIGH / MODERATE-HIGH assets.
-- Dedup against the previous run's reported_high_risk_assets snapshot
-- happens in the Python alerter, not here — that lets the snapshot survive
-- the assets.updated_at trigger bumping every row on every import.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_alerter_high_risk_assets AS
SELECT
  asset_id,
  name,
  organization,
  current_risk,
  current_risk_reason,
  last_observed,
  updated_at
FROM assets
WHERE current_risk IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH');

-- ---------------------------------------------------------------------------
-- 5. Helper: prior reported high-risk asset set
-- Returns the latest successful run's snapshot, or empty array if no
-- prior success exists yet.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION alerter_prior_high_risk_set(p_name text DEFAULT 'daily_digest')
RETURNS text[]
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(reported_high_risk_assets, '{}'::text[])
  FROM meta_alerter_runs
  WHERE alerter_name = p_name
    AND status = 'success'
  ORDER BY started_at DESC
  LIMIT 1;
$$;
