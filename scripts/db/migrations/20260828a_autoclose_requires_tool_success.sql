-- ============================================================================
-- 20260828a — asm_autoclose_stale_findings: the covering tool must have
--             SUCCEEDED, not merely have run.
-- ============================================================================
--
-- 4.7 ruling Q6 (2026-08-28, Obsidian 187) named this the load-bearing risk
-- for Ship 3. Verified against the live schema before writing: CONFIRMED.
--
-- THE DEFECT. The coverage LATERAL joins on membership in `scan_run.tools_run`
-- and NEVER consults `scan_run.tool_status` — zero references to tool_status in
-- the entire 20260626a function. But `ctx.tools_run.append(tool_name)` runs at
-- the TOP of every phase, BEFORE any work. So a tool that ran and DEGRADED is
-- still listed, and still counts as full coverage.
--
-- Concretely: `dns_posture` degrades on an asset (dig failure, network blip),
-- the run still finishes 'complete', and the autocloser reads dns_posture in
-- tools_run + completed_at > last_observed_at, and stamps the asset's DNS
-- findings `remediated` with a remediated_at. A tool that FAILED becomes proof
-- the problem is FIXED. The note-126 invariant is satisfied, so nothing flags
-- it — the same silent-corruption shape 20260827a exists to prevent.
--
-- BLAST RADIUS IS THE WHOLE LIGHT TIER, not one phase. run_light has 11
-- mark_tool_degraded calls and ZERO DegradedRunError raises: every light-tier
-- degradation is degrade-and-continue, leaving status='complete'. And
-- `commandsentry_light`'s producer patterns are exactly those tools
-- (dns_posture, tls_check, headers_check, csp_nonce_check, methods_check,
-- common_paths, httpx_tech, behavioral_probes).
--
-- HAS IT FIRED? NO. Measured on Command 2026-08-28 across all 65 autoclose
-- audit rows: 33 closed on an ok tool, 32 on runs predating tool_status
-- (added 2026-06-09), and **0 CLOSED ON A DEGRADED TOOL**. This is latent, not
-- manifest. No remediation of past data is required.
--
-- THE FIX. One predicate added to the coverage LATERAL:
--     AND coalesce(sr.tool_status -> t.tool ->> 'ok', '') = 'true'
-- Runs with NULL tool_status become ineligible for future closures — the
-- conservative direction, and it only affects closures from here forward.
--
-- ⚠ safe_auto_apply: FALSE — MANUAL APPLY REQUIRED.
-- apply_pending_migrations.py::_split is single-quote-aware but NOT
-- dollar-quote aware (verified: it tracks only `'`). A CREATE OR REPLACE
-- FUNCTION body would be shredded at every `;` inside $$...$$. The function is
-- 149 lines with 36 quote-bearing lines, so rewriting the body as a quoted
-- string literal is not a real option.
--
-- APPLY ORDER MATTERS — an unapplied migration file HALTS ALL SCANNING on that
-- instance, and migrate.yml has no manual path. So:
--   1. run this file's SQL by hand in Supabase (BOTH instances)
--   2. record the ledger row (see RECORD THE LEDGER ROW below)
--   3. THEN push this file
-- Doing it in that order means the ledger already carries the row when the file
-- lands, and scanning never halts.
--
-- Prerequisite for Ship 3 (retire-equivalent + trufflehog), which is the first
-- ship to draw an ABSENCE claim ("no vulnerable library found") from evidence
-- that may have been truncated by Ship 2's fetch bounds.
-- ============================================================================

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
           -- 20260828a: the tool must have SUCCEEDED, not merely run.
           -- ctx.tools_run.append() happens at the TOP of every phase, before
           -- any work, so a tool that ran and DEGRADED still appears there.
           -- Without this, a failed dns_posture counts as proof that DNS
           -- findings are remediated. run_light alone has 11
           -- mark_tool_degraded paths and ZERO DegradedRunError raises, so
           -- every one of them leaves status='complete' with the tool listed.
           -- Runs predating tool_status (added 2026-06-09) have NULL and are
           -- now ineligible — the conservative direction.
           AND coalesce(sr.tool_status -> t.tool ->> 'ok', '') = 'true'
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

-- ============================================================================
-- VERIFY AFTER APPLYING
-- ============================================================================
--
-- 1) The predicate is live (expect 1):
--      SELECT count(*) FROM pg_get_functiondef(
--               'public.asm_autoclose_stale_findings(boolean)'::regprocedure) d
--       WHERE d LIKE '%tool_status -> t.tool%';
--
-- 2) Dry-run candidate count before vs after — it should NOT grow, and may
--    shrink if any candidate rested on a degraded or NULL-status tool:
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(true);
--
-- 3) No past closure rested on a degraded tool (expect 0 — measured 2026-08-28):
--      SELECT count(*) FROM public.admin_audit_log a
--        JOIN public.scan_run r ON r.scan_run_id = (a.details->>'scan_run_id')::uuid
--       WHERE a.action = 'autoclose_stale_finding'
--         AND r.tool_status -> (a.details->>'matched_tool') ? 'degraded';
--
-- ============================================================================
-- RECORD THE LEDGER ROW (step 2 — run after the SQL above, before pushing)
-- ============================================================================
--   INSERT INTO public.schema_migrations
--     (filename, applied_by, content_sha256, git_commit_sha, notes)
--   VALUES ('20260828a_autoclose_requires_tool_success.sql', 'manual',
--           '<SHA256_OF_THIS_FILE>', NULL,
--           'Manual apply: CREATE OR REPLACE FUNCTION body is dollar-quoted '
--           'and the splitter is not $$-aware. 4.7 Q6 prerequisite for Ship 3.')
--   ON CONFLICT (filename) DO NOTHING;
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: false
-- requires_backup: false
-- estimated_duration_ms: 100
-- risk: medium
-- notes: Adds one predicate to asm_autoclose_stale_findings' coverage LATERAL so a DEGRADED tool no longer counts as coverage. MANUAL APPLY — the function body is dollar-quoted and apply_pending_migrations.py::_split is not $$-aware. Verified latent-not-manifest before writing: 0 of 65 past closures rested on a degraded tool. Apply by hand on BOTH instances, record the ledger row, THEN push, so the unapplied-migration gate never halts scanning.
-- END-META
