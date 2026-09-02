-- 20260902a_autoclose_allmatch_and_runtime_guard.sql
--
-- 4.7 rulings ⑰ (all-match coverage predicate) + ⑳ (runtime guard in SQL),
-- shipped together per ㊺ — one migration, one apply window, same function.
--
-- ⑬ (per-chunk tool_status KEYS) and ⑯ (executed_phases guard rework) are NOT
-- in this ship. ㊺ decomposed them out after the ㊺ gate was verified: nuclei
-- lands as ONE flattened tool_status entry carrying its detail in `per_chunk`,
-- so an all-match predicate over phase-level entries needs no per-chunk keys.
-- See Obsidian 208 §1. ⑬'s revival triggers are recorded in
-- scripts/db/AUTOCLOSE_BLOCKER.md — do not revive it on general grounds.
--
-- ============================================================================
-- ⑰ — WHY: any-match silently over-closes
-- ============================================================================
-- 20260828a's coverage LATERAL was ANY-match with LIMIT 1: one tool matching
-- the source's producer pattern with ok='true' closed the finding.
-- commandsentry_medium maps to ARRAY['nuclei%','ffuf','nikto','wafw00f'], so a
-- clean nuclei[php] chunk (~29 counter-units, seconds of work) satisfied it for
-- a finding only nuclei[critical,high] would ever have re-detected — and on
-- WAF-fronted assets that chunk is cut nearly every run.
--
-- MEASURED 2026-09-02 (scripts/db/checks/autoclose_allmatch_compare.sql):
--
--   Command      ANY 230 -> ALL 202   (28 over-closes removed)
--     commandsentry_medium   12 -> 0   ALL 12 medium closures were unsupported
--     commandsentry_light    19 -> 3   16 of 19 unsupported
--   Prodex       ANY  41 -> ALL  39   (2 over-closes removed)
--
-- All-match retains 88% of closures, so it is not inert (4.7 ㊼ risk did not
-- materialise) and no precise-match work is forced.
--
-- 🔴 THE READING MATTERS. Two all-match readings were scored on live data:
--   ALL-A  every producer tool PRESENT in tools_run is ok='true'   <- SHIPPED
--   ALL-B  ALL-A, plus every producer PATTERN was exercised        <- REJECTED
-- ALL-B is unshippable: the patterns array is OVERLOADED. For testssl it is
-- ARRAY['testssl.sh','testssl'] — two ALIASES for one tool, of which only one
-- can ever appear in tools_run — so ALL-B can never be satisfied and zeroed all
-- 27 Prodex testssl closures for a reason unrelated to coverage. For
-- commandsentry_* the same array is a REQUIRED SET. Disambiguating alias-groups
-- from required-sets is a separate, later question; do not attempt it here.
--
-- NOT CHANGED, deliberately: commandsentry_heavy's list stays
-- ARRAY['naabu','fingerprintx']. run_heavy.py can emit source=commandsentry_heavy
-- from three further producers (_emit_passive_cors_finding,
-- _maybe_emit_no_waf_finding, run_safe_exploit_phase), but all 176 such findings
-- on Command are 'Service inventory:' rows from naabu/fingerprintx and none of
-- the other three has ever emitted. Widening the list would change behaviour on
-- 176 correct findings to guard against zero actual ones. Latent, not live.
-- Revisit only if one of those producers starts emitting. Obsidian 208 §5.
--
-- ============================================================================
-- ⑳ — WHY: the live-run blocker was enforced by a memory note, not the database
-- ============================================================================
-- asm_autoclose_stale_findings has NO automatic caller, so the over-closing risk
-- was latent — but nothing in the database stopped a hand-typed
-- SELECT * FROM asm_autoclose_stale_findings(false). ⑳ makes the block a
-- runtime property of the function.
--
-- Removing this guard requires WRITING A MIGRATION, deliberately. That is the
-- point: a settings row or GUC would be removable by anyone with DB access, and
-- 4.7 ruled the guard must not come off casually. The four gates are named in
-- the exception message so whoever hits it sees the conditions.
--
-- Dry-run — asm_autoclose_stale_findings() or (true) — is unaffected.
--
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
  -- ==========================================================================
  -- ⑳ RUNTIME GUARD. Fail closed before any row is read.
  -- ==========================================================================
  IF NOT p_dry_run THEN
    RAISE EXCEPTION
      'asm_autoclose_stale_findings: LIVE RUN BLOCKED by migration 20260902a (4.7 ruling 20).'
      USING DETAIL =
        'Dry-run is unaffected: call asm_autoclose_stale_findings() or (true). '
        'This function has no automatic caller; a live run can only be invoked by hand.',
      HINT =
        'Removing this guard requires a NEW MIGRATION and an explicit decision, not an edit. '
        'All four gates must pass first: '
        '(1) all-match empirically validated as sufficient, or precise-match ready; '
        '(2) the Command dry-run candidates reviewed for calibration; '
        '(3) a live-monitoring plan in place; '
        '(4) an explicit decision that the autocloser should run live. '
        'See scripts/db/AUTOCLOSE_BLOCKER.md.';
  END IF;

  -- Single statement: eligibility + candidate selection + (conditional) writes
  -- + return. Data-modifying CTEs in PostgreSQL ALWAYS execute exactly once,
  -- even when unreferenced by the outer SELECT, so the UPDATE and INSERT fire
  -- when p_dry_run = false and no-op via `AND NOT p_dry_run` when true.
  --
  -- With ⑳ in force p_dry_run can never be false here, so `upd` and `aud` are
  -- currently unreachable. They are RETAINED so that removing the guard
  -- restores a working live path rather than requiring the body be rebuilt.
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
       AND f.severity::text NOT IN ('CRITICAL','HIGH','MODERATE-HIGH')
       -- Source must be in the explicit automated-producer set.
       AND public.asm_autoclose_producer_patterns(f.source::text) IS NOT NULL
       -- Need a baseline last-observed to compare scan_run.completed_at
       -- against. Rows without one can't satisfy "scan ran AFTER last
       -- observation" because there is no AFTER.
       AND f.last_observed_at IS NOT NULL
  ),
  candidates AS (
    -- EARLIEST covering scan_run — the first time evidence said the producer
    -- surface ran CLEANLY and did not re-observe this finding.
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
               -- ⑰: no single "matched tool" exists under all-match, so this
               -- column now carries the FULL matched set, comma-joined. Same
               -- name and type (the RETURNS TABLE signature cannot change under
               -- CREATE OR REPLACE). Verified 2026-09-02: nothing outside
               -- migrations reads this column — it is written to
               -- admin_audit_log.details and never parsed.
               (SELECT string_agg(t2.tool, ',' ORDER BY t2.tool)
                  FROM unnest(sr.tools_run) AS t2(tool)
                 WHERE EXISTS (
                   SELECT 1
                     FROM unnest(public.asm_autoclose_producer_patterns(e.source)) AS p2(pattern)
                    WHERE t2.tool LIKE p2.pattern)
               ) AS matched_tool
          FROM public.scan_run sr
         WHERE sr.asset_id     = e.asset_id
           AND sr.status::text = 'complete'
           AND sr.completed_at > e.last_observed_at
           -- ⑰ (a) PRESENCE: at least one producer tool must have run. Without
           -- this, a run that exercised NONE of the producers would satisfy the
           -- all-match arm vacuously (NOT EXISTS over an empty set is true) and
           -- close the finding on no evidence at all.
           AND EXISTS (
             SELECT 1
               FROM unnest(sr.tools_run) AS t(tool),
                    unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
              WHERE t.tool LIKE p.pattern
           )
           -- ⑰ (b) ALL-MATCH: and EVERY producer tool present must have
           -- SUCCEEDED. Replaces 20260828a's any-match. A tool that is absent
           -- from tools_run is not judged here (see the ALL-B note in the
           -- header for why requiring every PATTERN is wrong).
           --
           -- Runs predating tool_status (added 2026-06-09) have NULL, so
           -- coalesce(...) = '' <> 'true' and they are ineligible — the
           -- conservative direction, unchanged from 20260828a.
           AND NOT EXISTS (
             SELECT 1
               FROM unnest(sr.tools_run) AS t(tool)
              WHERE EXISTS (
                    SELECT 1
                      FROM unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
                     WHERE t.tool LIKE p.pattern)
                AND coalesce(sr.tool_status -> t.tool ->> 'ok', '') <> 'true'
           )
         ORDER BY sr.completed_at ASC
         LIMIT 1
      ) cov ON true
  ),
  upd AS (
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
        'rule',               'note_127_coverage_allmatch_autoclose_v2'
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
  '20260902a: coverage predicate is ALL-MATCH (every producer tool present in '
  'tools_run must be ok=true), replacing 20260828a any-match which over-closed '
  '28 findings on Command / 2 on Prodex. LIVE RUNS ARE BLOCKED at runtime per '
  '4.7 ruling 20 — dry-run only. Removing that block requires a new migration.';

-- ============================================================================
-- VERIFY AFTER APPLYING (run all four)
-- ============================================================================
--
-- 1) All-match predicate is live (expect 1):
--      SELECT count(*) FROM pg_get_functiondef(
--               'public.asm_autoclose_stale_findings(boolean)'::regprocedure) d
--       WHERE d LIKE '%<> ''true''%';
--
-- 2) ⑳ guard fires (expect ERROR, not rows):
--      SELECT * FROM public.asm_autoclose_stale_findings(false);
--    A result set here means the guard did NOT ship — stop and investigate.
--
-- 3) Dry-run still works and SHRANK (never grows):
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(true);
--    Expected: Command 230 -> 202, Prodex 41 -> 39. A LARGER number than the
--    pre-apply count means the predicate got looser, not stricter — roll back.
--
-- 4) No candidate rests on a not-ok tool (expect 0):
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(true) a
--        JOIN public.scan_run r ON r.scan_run_id = a.scan_run_id,
--             LATERAL unnest(string_to_array(a.matched_tool, ',')) AS t(tool)
--       WHERE coalesce(r.tool_status -> t.tool ->> 'ok','') <> 'true';
--
-- ROLLBACK: re-apply 20260828a_autoclose_requires_tool_success.sql verbatim.
-- It is a CREATE OR REPLACE of the same signature, so it restores any-match and
-- removes the ⑳ guard in one statement. No data migration either direction.
--
-- ============================================================================
-- RECORD THE LEDGER ROW (step 2 — run after the SQL above, before pushing)
-- ============================================================================
--   INSERT INTO public.schema_migrations
--     (filename, applied_by, content_sha256, git_commit_sha, notes)
--   VALUES ('20260902a_autoclose_allmatch_and_runtime_guard.sql', 'manual',
--           '<SHA256_OF_THIS_FILE>', NULL,
--           'Manual apply: function body is dollar-quoted and the splitter is '
--           'not $$-aware. 4.7 rulings 17 + 20, decomposed from 13/16 per 45.')
--   ON CONFLICT (filename) DO NOTHING;
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: false
-- requires_backup: false
-- estimated_duration_ms: 100
-- risk: medium
-- notes: Replaces asm_autoclose_stale_findings' any-match coverage LATERAL with all-match (every producer tool present in tools_run must be ok=true) and adds a runtime RAISE blocking p_dry_run=false. MANUAL APPLY on BOTH instances — the body is dollar-quoted and apply_pending_migrations.py::_split is not $$-aware. Apply by hand, record the ledger row, THEN push, so the unapplied-migration gate never halts scanning. Strictly more conservative than 20260828a: closure can only shrink. Measured before writing — Command 230->202, Prodex 41->39. ALL-B reading rejected on live data (testssl pattern list is aliases, not a required set). commandsentry_heavy pattern list deliberately unchanged.
-- END-META
