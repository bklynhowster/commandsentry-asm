-- ============================================================================
-- COMMANDsentry — Maintenance functions
--
-- Reusable Postgres-side functions for keeping the canonical posture model in
-- sync with the latest scan reality. Called from:
--   - scripts/db/import_jsonl.py (after every import)
--   - manual psql sessions during backfills
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/maintenance.sql
--
-- Idempotent. Safe to re-run.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- refresh_asset_last_observed(asset_id)
--   Set assets.last_observed = max(COALESCE(completed_at, started_at)) for
--   that asset. Falls back to started_at because the current normalizer
--   doesn't always set completed_at (all 60 scans in initial backfill
--   have NULL completed_at as of 2026-05-19). No-op if the asset has no
--   scans at all.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_asset_last_observed(p_asset_id text)
RETURNS void
LANGUAGE sql AS $$
  UPDATE assets a
     SET last_observed = COALESCE(
           (SELECT MAX(COALESCE(s.completed_at, s.started_at))
              FROM scans s WHERE s.asset_id = a.asset_id),
           a.last_observed
         ),
         first_observed = COALESCE(
           a.first_observed,
           (SELECT MIN(COALESCE(s.started_at, s.completed_at))
              FROM scans s WHERE s.asset_id = a.asset_id)
         )
   WHERE a.asset_id = p_asset_id;
$$;


-- ---------------------------------------------------------------------------
-- refresh_all_asset_last_observed() — DROPPED 2026-06-15 (migration 20260615a)
--
-- This function implemented B semantic for assets.last_observed:
-- MAX(scans.completed_at) over the scans table. It conflicted with the
-- A semantic — assets.last_observed is the DISCOVERY clock, owned by
-- scripts/db/import_asm_to_surface.py (asm-discover path), monotonic
-- via GREATEST, NOT bumped by light/medium scans or finding ingestion.
--
-- The B-semantic function was actively called by import_jsonl.py on
-- every JSONL import, clobbering the discovery clock with scan-time
-- whenever new findings were ingested. The 2026-06-15 [2] fix:
--   (a) schema.json doc updated to reflect A semantic explicitly
--   (b) import_jsonl.py full-ejected last_observed from its asset UPSERT
--   (c) this function dropped + import_jsonl.py call removed
--
-- The only other caller was backfills/20260518_close_revalidated_findings.sql
-- (one-time backfill, completed 2026-05-18, tombstoned on 2026-06-15).
--
-- DO NOT re-add this function. If you need to recompute the discovery
-- clock from history, write a NEW function that aggregates over the
-- discovery-source equivalent — never over the general scans table.
-- ---------------------------------------------------------------------------


-- ---------------------------------------------------------------------------
-- refresh_asset_posture(asset_id)
--   Recompute assets.current_risk + current_risk_reason from the
--   *currently open* findings (status in detected/confirmed/open/regressed).
--
--   Risk ladder:
--     any open CRITICAL              -> CRITICAL
--     any open HIGH                  -> HIGH
--     >= 4 open MODERATE-or-higher   -> MODERATE-HIGH
--     any open MODERATE              -> MODERATE
--     any open LOW                   -> LOW
--     else                           -> INFO
--
--   current_risk_reason is a one-line human string with the count + top
--   finding title.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_asset_posture(p_asset_id text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  v_crit  int;
  v_high  int;
  v_modh  int;
  v_mod   int;
  v_low   int;
  v_top_title text;
  v_top_id    text;
  v_risk  risk_t;
  v_reason text;
  v_total_modh_or_higher int;
BEGIN
  SELECT
    COUNT(*) FILTER (WHERE severity = 'CRITICAL'),
    COUNT(*) FILTER (WHERE severity = 'HIGH'),
    COUNT(*) FILTER (WHERE severity = 'MODERATE-HIGH'),
    COUNT(*) FILTER (WHERE severity = 'MODERATE'),
    COUNT(*) FILTER (WHERE severity = 'LOW')
  INTO v_crit, v_high, v_modh, v_mod, v_low
  FROM findings
  WHERE asset_id = p_asset_id
    AND current_status IN ('detected','confirmed','open','regressed');

  v_total_modh_or_higher := v_crit + v_high + v_modh + v_mod;

  -- pick the "top" finding for the reason string
  SELECT finding_id, title INTO v_top_id, v_top_title
  FROM findings
  WHERE asset_id = p_asset_id
    AND current_status IN ('detected','confirmed','open','regressed')
  ORDER BY
    CASE severity
      WHEN 'CRITICAL'      THEN 1
      WHEN 'HIGH'          THEN 2
      WHEN 'MODERATE-HIGH' THEN 3
      WHEN 'MODERATE'      THEN 4
      WHEN 'LOW'           THEN 5
      WHEN 'INFO'          THEN 6
      ELSE 9
    END,
    last_observed_at DESC NULLS LAST,
    finding_id
  LIMIT 1;

  -- compute risk band
  IF v_crit > 0 THEN
    v_risk := 'CRITICAL';
    v_reason := v_crit || ' open CRITICAL finding(s); top: ' || COALESCE(v_top_title, v_top_id);
  ELSIF v_high > 0 THEN
    v_risk := 'HIGH';
    v_reason := v_high || ' open HIGH finding(s); top: ' || COALESCE(v_top_title, v_top_id);
  ELSIF v_total_modh_or_higher >= 4 THEN
    v_risk := 'MODERATE-HIGH';
    v_reason := v_total_modh_or_higher
                || ' open MODERATE-or-higher findings; top: '
                || COALESCE(v_top_title, v_top_id);
  ELSIF v_mod > 0 OR v_modh > 0 THEN
    v_risk := 'MODERATE';
    v_reason := (v_mod + v_modh) || ' open MODERATE finding(s); top: '
                || COALESCE(v_top_title, v_top_id);
  ELSIF v_low > 0 THEN
    v_risk := 'LOW';
    v_reason := v_low || ' open LOW finding(s)';
  ELSE
    v_risk := 'INFO';
    v_reason := 'no open findings above INFO';
  END IF;

  UPDATE assets
     SET current_risk        = v_risk,
         current_risk_reason = v_reason
   WHERE asset_id = p_asset_id;
END $$;


-- ---------------------------------------------------------------------------
-- refresh_all_asset_posture()
--   Walk every asset and recompute current_risk + reason. Returns row count.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_all_asset_posture()
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  r record;
  v_n integer := 0;
BEGIN
  FOR r IN SELECT asset_id FROM assets LOOP
    PERFORM refresh_asset_posture(r.asset_id);
    v_n := v_n + 1;
  END LOOP;
  RETURN v_n;
END $$;


-- ---------------------------------------------------------------------------
-- delta_close_for_scan(scan_id)
--   "Anything not observed in this scan is presumed remediated."
--
--   For every (asset_id, source) combo that produced findings in scan_id,
--   find any *other* findings open on that asset+source that did NOT get a
--   finding_history row for this scan_id, and mark them remediated with
--   remediated_at = scan.completed_at.
--
--   SAFETY RULE — HUMAN-CURATED SOURCES ARE BLACKLISTED.
--   Delta-close only applies to scanner-driven sources (testssl, nuclei,
--   wpscan, nikto, etc.) where every scan re-tests the full surface, so
--   "absent from this scan" reliably means "the condition is gone."
--
--   Human-curated sources (manual_named, summary_md, verdict_md,
--   curated_html) are EXCLUDED. Those findings are authored once and don't
--   re-attach to later scans — delta-closing them would silently mark
--   confirmed-open findings as remediated. Use close_findings_by_id() or
--   a verdict_md re-validation scan to close those.
--
--   Returns the number of findings closed.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION delta_close_for_scan(p_scan_id text)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_asset      text;
  v_completed  timestamptz;
  v_n          integer;
  -- Sources that delta-close is NOT allowed to touch. These represent
  -- human-curated channels (manual writeups, SUMMARY.md verdicts, curated
  -- HTML reports). Their findings persist across scans intentionally.
  v_blacklist  text[] := ARRAY['manual_named','summary_md','verdict_md','curated_html'];
BEGIN
  SELECT asset_id, COALESCE(completed_at, started_at, now())
    INTO v_asset, v_completed
    FROM scans
   WHERE scan_id = p_scan_id;
  IF v_asset IS NULL THEN
    RAISE NOTICE 'delta_close_for_scan: scan_id % not found, skipping', p_scan_id;
    RETURN 0;
  END IF;

  WITH sources_in_scan AS (
    SELECT DISTINCT f.source::text AS source
      FROM finding_history fh
      JOIN findings f ON f.finding_id = fh.finding_id
     WHERE fh.scan_id = p_scan_id
       AND f.source::text <> ALL(v_blacklist)
  ),
  candidates AS (
    SELECT f.finding_id
      FROM findings f
     WHERE f.asset_id = v_asset
       AND f.current_status IN ('detected','confirmed','open','regressed')
       AND f.source::text IN (SELECT source FROM sources_in_scan)
       AND f.source::text <> ALL(v_blacklist)
       AND NOT EXISTS (
             SELECT 1 FROM finding_history fh
              WHERE fh.finding_id = f.finding_id
                AND fh.scan_id    = p_scan_id
           )
  )
  UPDATE findings f
     SET current_status   = 'remediated',
         remediated_at    = v_completed
    FROM candidates c
   WHERE f.finding_id = c.finding_id;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$;


-- ---------------------------------------------------------------------------
-- close_findings_by_id(finding_ids, remediated_at, reason)
--   Manual backfill helper. Mark a known-good list of finding IDs as
--   remediated. Idempotent — won't downgrade something already remediated.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION close_findings_by_id(
  p_finding_ids   text[],
  p_remediated_at timestamptz DEFAULT now(),
  p_note          text DEFAULT NULL
)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_n integer;
BEGIN
  UPDATE findings
     SET current_status = 'remediated',
         remediated_at  = COALESCE(remediated_at, p_remediated_at)
   WHERE finding_id = ANY(p_finding_ids)
     AND current_status IN ('detected','confirmed','open','regressed');
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$;


-- ---------------------------------------------------------------------------
-- v_dashboard_30d_metrics
--   Period summary for the dashboard header — counts of findings newly
--   detected and findings closed in the last 30 days, bucketed by severity.
--
--   "opened" = first_detected_at within the window (the finding identity
--              had never been seen before that date)
--   "closed" = remediated_at within the window AND current_status is one
--              of the closed states (remediated / validated_remediated /
--              false_positive / wont_fix / accepted_risk)
--
--   Note: a single finding can show up in BOTH columns if it was first
--   detected AND closed within the window. That's accurate behavior — the
--   meeting story is "we caught it and shipped a fix in the same period."
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_dashboard_30d_metrics AS
WITH cutoff AS (SELECT now() - interval '30 days' AS d)
SELECT
  30::int AS period_days,

  -- Opened: first_detected_at within the period
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'CRITICAL' AND first_detected_at >= cutoff.d)  AS opened_critical,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'HIGH' AND first_detected_at >= cutoff.d)      AS opened_high,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'MODERATE-HIGH' AND first_detected_at >= cutoff.d) AS opened_mod_high,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'MODERATE' AND first_detected_at >= cutoff.d)  AS opened_moderate,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'LOW' AND first_detected_at >= cutoff.d)       AS opened_low,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'INFO' AND first_detected_at >= cutoff.d)      AS opened_info,

  -- Closed: remediated_at within the period AND in a closed state
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'CRITICAL' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_critical,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'HIGH' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_high,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'MODERATE-HIGH' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_mod_high,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'MODERATE' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_moderate,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'LOW' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_low,
  (SELECT COUNT(*) FROM findings, cutoff
    WHERE severity = 'INFO' AND remediated_at >= cutoff.d
      AND current_status IN ('remediated','validated_remediated','false_positive','wont_fix','accepted_risk'))  AS closed_info
;

-- Grant access so the SPA (authenticated role) can read it via PostgREST.
-- Anon role gets nothing — RLS already gates everything but views need
-- explicit grant for select.
GRANT SELECT ON v_dashboard_30d_metrics TO authenticated;
