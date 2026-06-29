-- ============================================================================
-- MIGRATION — 2026-06-29a — note 129 follow-up #5 (round 6)
--                          regress_observed_for_scan_run() — the mirror
--                          image of delta_close_for_scan_run()
--
-- WHY (4.8 round-6 spec, REGRESSION_CENTRALIZATION_SPEC.md):
--   P6 live-QA on ftp.sciimage.com surfaced that delta_close has no
--   reopen branch, and the medium UPSERT_FINDING_SQL preserves
--   terminal status on re-detect — so a tool that re-emits a
--   remediated finding leaves it remediated. Heavy fixed this in
--   Python (commit 56fc329, verified live), but medium has the
--   same gap. Centralize so both tiers share ONE reopen path.
--
-- WHAT this function does:
--   The structural inverse of delta_close_for_scan_run:
--     delta_close:  current_status IN open-set  AND last_seen <> this scan
--                   → mark remediated
--     this fn:      current_status IN terminal  AND last_seen =  this scan
--                   → mark regressed (+ clear remediated_at)
--
--   Source-scoped (same as delta_close) so callers route by tier:
--     medium → 'commandsentry_medium'
--     heavy  → 'testssl' (and later 'commandsentry_heavy' for net depth)
--
--   Honors note-126 invariant:
--     remediated_at NOT NULL  iff  current_status IN
--       ('remediated', 'validated_remediated')
--   regressed ∉ that set → remediated_at MUST be NULL on the flip.
--
--   Writes one admin_audit_log row per flip with action=
--   'auto_regress_observed', rule='regress_observed_for_scan_run_v1'.
--   Mirrors the note-127 auto-closer audit shape.
--
-- WHY SAFE (per the round-6 spec):
--   * Disjoint from delta_close: delta_close touches OPEN-and-not-seen;
--     this touches REMEDIATED-and-seen. Their WHERE clauses are
--     mutually exclusive → order-independent, no double-handling.
--   * Idempotent: once a finding is 'regressed' it's not in
--     (remediated, validated_remediated), so a later scan won't
--     re-flip it or write a duplicate audit row.
--   * Relies on findings.last_seen_scan_run, stamped by the UPSERT
--     on every re-emitted finding (same mechanism delta_close
--     already trusts; column added in migration 20260617a).
--
-- WHY CALLED FROM THE CLEAN PATH ONLY:
--   A degraded scan isn't trustworthy evidence of presence. The
--   reopen action requires positive evidence (the scan directly
--   re-emitted the finding); a degraded scan's last_seen_scan_run
--   stamps are unreliable. Callers must NOT invoke this from a
--   degraded close-out path. Mirrors delta_close's clean-path-only
--   discipline (which guards the inverse: don't infer absence from
--   a degraded scan).
--
-- finding_history NOTE (same trade-off note-127 made):
--   finding_history.scan_id is NOT NULL + FK-constrained to the
--   legacy scans table; scan_run-driven flows have no scans
--   counterpart. admin_audit_log carries the durable trail. Same
--   call: relax the FK or insert a sentinel scans row per batch
--   is deferred design work.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.regress_observed_for_scan_run(
  p_scan_run_id text,
  p_source     text
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_asset text;
  v_n     integer;
BEGIN
  -- scan_run.scan_run_id is UUID; p_scan_run_id arrives as text (same
  -- shape findings.last_seen_scan_run uses, same shape delta_close
  -- accepts). Cast to uuid for the scan_run lookup; the findings
  -- comparison below stays text-vs-text.
  SELECT asset_id
    INTO v_asset
    FROM public.scan_run
   WHERE scan_run_id = p_scan_run_id::uuid;

  IF v_asset IS NULL THEN
    RAISE NOTICE 'regress_observed_for_scan_run: scan_run % not found, skipping',
      p_scan_run_id;
    RETURN 0;
  END IF;

  -- Single statement with three CTEs:
  --   targets — SELECT … FOR UPDATE locks the candidate rows so the
  --             audit before_state is consistent with the value the
  --             UPDATE actually overwrites (no race window between
  --             read of old status and write of new).
  --   upd     — does the flip; one row per target.
  --   aud     — writes one admin_audit_log row per target with the
  --             captured prior status in before_state.
  -- All three CTEs are data-modifying / locking and execute exactly
  -- once per Postgres data-modifying-CTE semantics. Final SELECT
  -- counts the upd rows to populate v_n.
  WITH targets AS (
    SELECT f.finding_id,
           f.asset_id,
           f.source::text         AS source,
           f.current_status::text AS old_status,
           f.remediated_at        AS old_rem
      FROM public.findings f
     WHERE f.asset_id = v_asset
       -- findings.source is enum finding_source_t; cast to compare
       -- against the text param (same pattern delta_close uses).
       AND f.source::text = p_source
       -- Terminal-remediated set — note-126 invariant defines these
       -- two as "carries a remediated_at." Flipping clears it.
       AND f.current_status IN ('remediated','validated_remediated')
       -- SEEN this scan — the `=` mirror of delta_close's `<>`.
       -- The UPSERT stamps last_seen_scan_run on every re-emission
       -- (migration 20260617a + UPSERT_FINDING_SQL), so this gate
       -- only catches findings the live scan actually re-emitted.
       AND f.last_seen_scan_run = p_scan_run_id
     FOR UPDATE
  ),
  upd AS (
    UPDATE public.findings f
       SET current_status = 'regressed',
           remediated_at  = NULL,
           updated_at     = now()
      FROM targets t
     WHERE f.finding_id = t.finding_id
    RETURNING f.finding_id
  ),
  aud AS (
    INSERT INTO public.admin_audit_log (
      actor_user_id, action, target_user_id, target_email,
      before_state, after_state, details
    )
    SELECT
      NULL,
      'auto_regress_observed',
      NULL,
      NULL,
      jsonb_build_object(
        'current_status', t.old_status,
        'remediated_at',  t.old_rem
      ),
      jsonb_build_object(
        'current_status', 'regressed',
        'remediated_at',  NULL
      ),
      jsonb_build_object(
        'finding_id',  t.finding_id,
        'asset_id',    t.asset_id,
        'source',      t.source,
        'scan_run_id', p_scan_run_id,
        'rule',        'regress_observed_for_scan_run_v1'
      )
      FROM targets t
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM upd;

  RETURN v_n;
END $$;

COMMENT ON FUNCTION public.regress_observed_for_scan_run(text, text) IS
  'note 129 round 6: sibling of delta_close_for_scan_run. Reopens '
  'findings of (asset, source) that are currently '
  '{remediated,validated_remediated} AND were re-observed by this '
  'scan_run. Sets status=regressed, clears remediated_at (note-126 '
  'invariant), audits per flip. Clean-path-only — callers must NOT '
  'invoke from a degraded close-out path (a degraded scan is not '
  'trustworthy evidence of presence).';

-- Admin-only function (mirrors delta_close — neither is granted to
-- authenticated; both are called from service-role scanner code).

-- ============================================================================
-- SANITY QUERIES — after migration applies, before wiring callers.
-- ============================================================================
--
-- 1) Function exists + comment:
--      SELECT proname, obj_description(oid)
--        FROM pg_proc WHERE proname = 'regress_observed_for_scan_run';
--
-- 2) No-op against a non-existent scan_run (returns 0, no error):
--      SELECT public.regress_observed_for_scan_run(
--        gen_random_uuid()::text, 'commandsentry_medium'
--      );
--
-- 3) Dry-shape against a real recent scan_run (returns flip count,
--    audit rows in admin_audit_log):
--      SELECT scan_run_id::text, asset_id
--        FROM public.scan_run
--       WHERE status = 'complete' AND intensity = 'medium'
--       ORDER BY completed_at DESC LIMIT 1;
--      -- then:
--      SELECT public.regress_observed_for_scan_run(
--        '<paste scan_run_id>', 'commandsentry_medium'
--      );
--
-- 4) Audit row shape:
--      SELECT created_at,
--             details->>'finding_id' AS finding_id,
--             details->>'source'     AS source,
--             before_state->>'current_status' AS was,
--             after_state->>'current_status'  AS now
--        FROM public.admin_audit_log
--       WHERE action = 'auto_regress_observed'
--       ORDER BY created_at DESC
--       LIMIT 20;
