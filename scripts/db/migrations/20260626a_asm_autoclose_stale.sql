-- ============================================================================
-- MIGRATION — 2026-06-26a — note 127 coverage-matched auto-close (asm)
--
-- DB-side reconcile that closes stale automated-source findings whose
-- producer tool has actually run on the asset since the finding was
-- last observed. Two modes:
--
--   DRY RUN (default) — RETURNS SETOF candidate rows. Writes nothing.
--                       SHIP THIS FIRST. Review the candidate list
--                       (expect ~66, INFO-heavy, 0 HIGH/CRITICAL,
--                       0 manual_named) before any live run.
--   LIVE              — UPDATE findings + INSERT admin_audit_log per
--                       close. Caller must pass p_dry_run = false
--                       explicitly. Same row set the dry run reported,
--                       materialized once via a CTE so UPDATE / INSERT
--                       / RETURN all see the same set.
--
-- ELIGIBILITY (all must hold):
--   1. current_status IN ('detected','open','regressed')
--   2. severity NOT IN ('CRITICAL','HIGH','MODERATE-HIGH')   [cap]
--   3. source IN the explicit automated-producer set below
--   4. last_observed_at IS NOT NULL (need a baseline to compare against)
--   5. ∃ scan_run on the same asset with:
--        status = 'complete'
--        completed_at > findings.last_observed_at
--        tools_run contains a tool matching this source's producer
--        pattern set (see asm_autoclose_producer_patterns).
--      Earliest covering scan_run is the one credited — that's the
--      first time evidence said "the producer ran and didn't see
--      this finding," i.e. the actual close moment.
--
-- SOURCE → PRODUCER-TOOL PATTERN MAP (explicit, per spec):
--
--   findings.source      tools_run elements that count as coverage
--   ----------------     -----------------------------------------
--   nuclei               'nuclei%'   (LIKE — matches nuclei, nuclei-
--                                    tech, nuclei-cves, etc.)
--   nikto                'nikto'
--   testssl              'testssl.sh' OR 'testssl'
--   commandsentry_light  tls_check / headers_check / csp_nonce_check
--                        / dns_posture / methods_check / common_paths
--                        / httpx_tech / behavioral_probes
--   commandsentry_medium 'nuclei%' / ffuf / nikto / wafw00f
--
-- NEVER eligible — left untouched even when a fresh scan ran:
--   manual_named, wpscan, sslyze, other, and ANY source not in the
--   map above. asm_autoclose_producer_patterns() returns NULL for
--   these, and the candidate filter requires IS NOT NULL.
--
-- INVARIANT — close honors note 126's portal-wide rule: target
-- status = 'remediated' iff remediated_at IS NOT NULL. We set both
-- in the same UPDATE.
--
-- AUDIT — admin_audit_log row per close with:
--   action       = 'autoclose_stale_finding'
--   actor_user_id = NULL   (system action; no auth user)
--   before_state = { current_status, source, severity,
--                    last_observed_at }
--   after_state  = { current_status: 'remediated', remediated_at }
--   details      = { finding_id, asset_id, title, scan_run_id,
--                    scan_completed_at, tools_run, matched_tool,
--                    batch_id, rule: 'note_127_..._v1' }
--   batch_id     = single uuid per asm_autoclose_stale_findings()
--                  invocation, so all closes from one run are
--                  trivially grepable in admin_audit_log.
--
-- finding_history NOTE: finding_history.scan_id is NOT NULL +
-- FK-constrained to scans.scan_id (the legacy importer table). The
-- closure here is driven by a scan_run, which has no scans-table
-- counterpart. v1 omits finding_history; admin_audit_log carries
-- the durable audit trail (also where note 125's portal closure
-- flows write). If we later want a finding_history entry per
-- autoclose, we'll either relax the FK or insert a sentinel scans
-- row per batch — design call deferred.
--
-- v_dashboard_30d_metrics UNCHANGED — closes flow through it
-- naturally via remediated_at + current_status, which is exactly
-- what the closed_* counters were designed to read.
-- ============================================================================

-- Helper: source → producer-tool LIKE patterns. Returns NULL for
-- sources outside the eligible set (manual_named / wpscan / sslyze /
-- other / unknown / NULL). The main function uses IS NOT NULL on
-- this return as the source-eligibility gate.
CREATE OR REPLACE FUNCTION public.asm_autoclose_producer_patterns(p_source text)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE p_source
    WHEN 'nuclei'               THEN ARRAY['nuclei%']
    WHEN 'nikto'                THEN ARRAY['nikto']
    WHEN 'testssl'              THEN ARRAY['testssl.sh','testssl']
    WHEN 'commandsentry_light'  THEN ARRAY['tls_check','headers_check','csp_nonce_check','dns_posture','methods_check','common_paths','httpx_tech','behavioral_probes']
    WHEN 'commandsentry_medium' THEN ARRAY['nuclei%','ffuf','nikto','wafw00f']
    ELSE NULL
  END;
$$;

COMMENT ON FUNCTION public.asm_autoclose_producer_patterns(text) IS
  'note 127: source -> LIKE patterns identifying that source''s '
  'producer tool(s). Used by asm_autoclose_stale_findings to verify '
  'a scan_run actually exercised the producer before crediting it '
  'with closing a stale finding. NULL return = source not eligible '
  'for auto-close (manual_named / wpscan / sslyze / other / NULL).';


-- Main reconcile function.
--
-- USAGE
--   Dry run (default — writes nothing):
--     SELECT * FROM public.asm_autoclose_stale_findings();
--     SELECT * FROM public.asm_autoclose_stale_findings(true);
--
--   Live run (writes UPDATE + INSERT INTO admin_audit_log):
--     SELECT * FROM public.asm_autoclose_stale_findings(false);
--
-- Returns SETOF candidate rows either way. `acted` column:
--   true  = this row was just closed (live mode)
--   false = this row would be closed if you re-ran with p_dry_run=false
CREATE OR REPLACE FUNCTION public.asm_autoclose_stale_findings(
  p_dry_run boolean DEFAULT true
)
RETURNS TABLE (
  finding_id        text,
  asset_id          text,
  severity          text,
  source            text,
  title             text,
  last_observed_at  timestamptz,
  scan_run_id       uuid,
  scan_completed_at timestamptz,
  matched_tool      text,
  acted             boolean
)
LANGUAGE plpgsql
AS $$
DECLARE
  v_batch_id uuid := gen_random_uuid();
  v_now      timestamptz := now();
BEGIN
  -- Single statement: eligibility + candidate selection + (conditional)
  -- writes + return. Data-modifying CTEs in PostgreSQL ALWAYS execute
  -- exactly once, even when unreferenced by the outer SELECT
  -- (PostgreSQL docs, "Data-Modifying Statements in WITH"), so the
  -- UPDATE and INSERT fire when p_dry_run = false and no-op (zero-row
  -- match) when p_dry_run = true via the `AND NOT p_dry_run` predicate.
  --
  -- The `candidates` CTE is computed once and re-used by UPDATE / INSERT
  -- / final SELECT, so all three see exactly the same row set.
  RETURN QUERY
  WITH eligible AS (
    SELECT f.finding_id,
           f.asset_id,
           f.severity::text          AS severity,
           f.source::text            AS source,
           f.title,
           f.current_status::text    AS current_status,
           f.last_observed_at
      FROM public.findings f
     WHERE f.current_status IN ('detected','open','regressed')
       -- Severity cap (per spec): never auto-close HIGH or above.
       -- MODERATE-HIGH excluded explicitly too — same "high signal"
       -- band the dashboard treats as elevated.
       AND f.severity::text NOT IN ('CRITICAL','HIGH','MODERATE-HIGH')
       -- Source must be in the explicit automated-producer set.
       AND public.asm_autoclose_producer_patterns(f.source::text) IS NOT NULL
       -- Need a baseline last-observed to compare scan_run.completed_at
       -- against. Rows without one are EXCLUDED — they can't satisfy
       -- "scan ran AFTER last observation" because there's no AFTER.
       AND f.last_observed_at IS NOT NULL
  ),
  candidates AS (
    -- For each eligible finding, find the EARLIEST covering scan_run
    -- — the first time evidence said the producer ran and didn't
    -- re-observe this finding. ORDER BY completed_at ASC + LIMIT 1.
    SELECT e.finding_id,
           e.asset_id,
           e.severity,
           e.source,
           e.title,
           e.current_status,
           e.last_observed_at,
           cov.scan_run_id,
           cov.completed_at  AS scan_completed_at,
           cov.tools_run,
           cov.matched_tool
      FROM eligible e
      JOIN LATERAL (
        SELECT sr.scan_run_id,
               sr.completed_at,
               sr.tools_run,
               t.tool AS matched_tool
          FROM public.scan_run sr,
               LATERAL unnest(sr.tools_run) AS t(tool),
               LATERAL unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
         WHERE sr.asset_id     = e.asset_id
           AND sr.status::text = 'complete'
           AND sr.completed_at > e.last_observed_at
           AND t.tool LIKE p.pattern
         ORDER BY sr.completed_at ASC
         LIMIT 1
      ) cov ON true
  ),
  upd AS (
    -- LIVE only: flip status + stamp remediated_at (honors note 126
    -- invariant: target status in {remediated, validated_remediated}
    -- iff remediated_at IS NOT NULL — we set both in the same UPDATE).
    UPDATE public.findings f
       SET current_status = 'remediated',
           remediated_at  = v_now,
           updated_at     = v_now
      FROM candidates c
     WHERE f.finding_id = c.finding_id
       AND NOT p_dry_run
    RETURNING f.finding_id
  ),
  aud AS (
    -- LIVE only: one admin_audit_log row per close. actor_user_id NULL
    -- = system action (no auth user). batch_id ties together every
    -- close from this invocation so 4.8 / Howie can grep one run's
    -- worth of audit rows trivially.
    INSERT INTO public.admin_audit_log (
      actor_user_id, action, target_user_id, target_email,
      before_state, after_state, details
    )
    SELECT
      NULL,
      'autoclose_stale_finding',
      NULL,
      NULL,
      jsonb_build_object(
        'current_status',    c.current_status,
        'source',            c.source,
        'severity',          c.severity,
        'last_observed_at',  c.last_observed_at
      ),
      jsonb_build_object(
        'current_status', 'remediated',
        'remediated_at',  v_now
      ),
      jsonb_build_object(
        'finding_id',         c.finding_id,
        'asset_id',           c.asset_id,
        'title',              c.title,
        'scan_run_id',        c.scan_run_id,
        'scan_completed_at',  c.scan_completed_at,
        'tools_run',          to_jsonb(c.tools_run),
        'matched_tool',       c.matched_tool,
        'batch_id',           v_batch_id,
        'rule',               'note_127_coverage_matched_autoclose_v1'
      )
    FROM candidates c
    WHERE NOT p_dry_run
    RETURNING id
  )
  SELECT c.finding_id,
         c.asset_id,
         c.severity,
         c.source,
         c.title,
         c.last_observed_at,
         c.scan_run_id,
         c.scan_completed_at,
         c.matched_tool,
         (NOT p_dry_run) AS acted
    FROM candidates c
   ORDER BY c.scan_completed_at DESC, c.finding_id;
END $$;

COMMENT ON FUNCTION public.asm_autoclose_stale_findings(boolean) IS
  'note 127: DB-side coverage-matched auto-close for automated-source '
  'findings. Default p_dry_run=true returns SETOF candidates without '
  'writing — review before any live run. p_dry_run=false performs the '
  'UPDATE + admin_audit_log INSERT for each candidate. Honors note 126 '
  'invariant. See migration 20260626a for full rule.';

GRANT EXECUTE ON FUNCTION public.asm_autoclose_producer_patterns(text)
  TO authenticated;
-- asm_autoclose_stale_findings is admin-only; not granted to authenticated.
-- Service-role calls (psql / Supabase Studio / a future scheduled job)
-- can run it; the SPA can't.

-- ============================================================================
-- SANITY QUERIES — run after migration applies, before any live run.
-- ============================================================================
--
-- 1) Dry-run candidate count (expected ~66, INFO-heavy):
--      SELECT count(*) FROM public.asm_autoclose_stale_findings();
--
-- 2) Dry-run severity breakdown (expected 0 HIGH/CRITICAL/MODERATE-HIGH):
--      SELECT severity, count(*)
--        FROM public.asm_autoclose_stale_findings()
--       GROUP BY severity
--       ORDER BY severity;
--
-- 3) Dry-run source breakdown (expected 0 manual_named, 0 wpscan,
--    0 sslyze, 0 other):
--      SELECT source, count(*)
--        FROM public.asm_autoclose_stale_findings()
--       GROUP BY source
--       ORDER BY count(*) DESC;
--
-- 4) Spot-check a single candidate end-to-end (paste a finding_id from #1):
--      SELECT * FROM public.asm_autoclose_stale_findings()
--       WHERE finding_id = '<paste>';
--
-- 5) Live run (UPDATE + audit) — ONLY after review of #1-#4:
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(false);
--
-- 6) Find this batch's audit rows after a live run:
--      SELECT created_at, details->>'finding_id' AS finding_id,
--             details->>'matched_tool' AS matched_tool,
--             details->>'batch_id' AS batch_id
--        FROM public.admin_audit_log
--       WHERE action = 'autoclose_stale_finding'
--       ORDER BY created_at DESC
--       LIMIT 20;
