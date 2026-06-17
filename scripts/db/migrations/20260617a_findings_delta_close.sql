-- ============================================================================
-- MIGRATION — 2026-06-17a — #35 live-path delta-close
--
-- Adds the live scanner's missing remediation engine. Until now run_medium.py
-- only ADDED/UPDATED findings; it never closed ones that are gone. Unblocks
-- #27 Phase 2 (the "cleared this scan" resolved lane).
--
-- TWO PARTS:
--   1. findings.last_seen_scan_run  — per-finding "which scan_run last observed
--      this." Stamped = scan_run_id on EVERY observation by UPSERT_FINDING_SQL
--      (new + re-confirmed). Plain text, no FK — holds scan_run_id (same shape
--      as first_detected_scan, whose FK was relaxed in 20260613c because the
--      live scanner's scan_run_ids aren't rows in `scans`).
--
--      NULL RATCHET: pre-existing rows are NULL until first observed under #35.
--      The close predicate is `<>` (see the function) so NULL rows are excluded
--      from the WHERE — they are NEVER retroactively closed. The first clean
--      scan of each asset post-#35 is a priming pass (stamps the column, closes
--      nothing); closing begins on the 2nd scan once a finding can go stale.
--
--   2. delta_close_for_scan_run(scan_run_id, source) — the close. Called ONLY from
--      run_medium.close_out (the clean exit) and ONLY when every tool ran 'ok'
--      (eligibility computed in Python — a skipped/degraded tool means a partial
--      scan that must not close). degraded_out NEVER calls it → a degraded scan
--      can't close anything (the structural safety guard).
--
--      The live medium writes one source per scan: commandsentry_{intensity}.
--      So the close is source-scoped to that, which AUTO-EXCLUDES the human-
--      curated sources (manual_named / summary_md / verdict_md / curated_html)
--      — they're different source strings the close never touches.
--
-- TRUST LAYER UNTOUCHED: remediation is a current_status change, orthogonal to
-- scanner_validations / validation_status / scan_quality.
-- ============================================================================

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS last_seen_scan_run text;

COMMENT ON COLUMN public.findings.last_seen_scan_run IS
  '#35: scan_run_id that last observed this finding. Stamped every observation '
  '(UPSERT_FINDING_SQL, EXCLUDED not COALESCE). NULL = never observed under #35 '
  '(ratchet — excluded from delta-close by the `<>` predicate). Plain text, no FK.';


CREATE OR REPLACE FUNCTION delta_close_for_scan_run(p_scan_run_id text, p_source text)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_asset      text;
  v_completed  timestamptz;
  v_n          integer;
BEGIN
  -- scan_run.scan_run_id is UUID; p_scan_run_id arrives as text (same string
  -- form the scanner stamps into findings.last_seen_scan_run). Cast to uuid for
  -- this lookup. The findings comparison below stays text-vs-text (both hold the
  -- scan_run_id as text), so it does NOT get cast.
  SELECT asset_id, COALESCE(completed_at, started_at, now())
    INTO v_asset, v_completed
    FROM public.scan_run
   WHERE scan_run_id = p_scan_run_id::uuid;
  IF v_asset IS NULL THEN
    RAISE NOTICE 'delta_close_for_scan_run: scan_run % not found, skipping', p_scan_run_id;
    RETURN 0;
  END IF;

  -- p_source = the EXACT source string the caller wrote findings with this run
  -- (close_out passes f"commandsentry_{ctx.intensity}"). Using the caller's
  -- string — NOT re-deriving from scan_run.intensity — guarantees close-source
  -- == write-source by construction, so a "standard"-vs-"medium" normalization
  -- can never make the close mis-scope. Scoping to this single source also
  -- auto-excludes human-curated channels (manual_named / summary_md /
  -- verdict_md / curated_html) — they carry different source values.

  -- Close open findings on this asset+source NOT re-observed by this run.
  --
  -- ⚠ PREDICATE MUST BE `<>` / `!=`, NOT `IS DISTINCT FROM`. The NULL ratchet
  -- depends on three-valued logic: NULL <> 'scan_id' → NULL → row EXCLUDED from
  -- the WHERE → pre-existing NULL-last_seen rows are never retroactively closed.
  -- `IS DISTINCT FROM` would treat NULL as a value (NULL IS DISTINCT FROM x →
  -- TRUE) → every NULL row closes on the first scan = day-one mass-flip. The
  -- standard "use IS DISTINCT FROM for null-safe equality" idiom is WRONG here:
  -- we WANT NULL to mean "not in the close set." Consequence (by design): the
  -- FIRST clean scan of each asset post-#35 stamps last_seen_scan_run but closes
  -- nothing (every candidate is still NULL → excluded) — a priming pass. Closing
  -- begins on the 2nd scan, once a finding has a non-NULL last_seen that can go
  -- stale. "Shipped and nothing closed yet" is expected for one cycle per asset.
  UPDATE public.findings f
     SET current_status = 'remediated',
         remediated_at  = v_completed
   WHERE f.asset_id = v_asset
     -- findings.source is enum finding_source_t (NOT text). Cast to compare
     -- against the text param — matches the existing delta_close_for_scan,
     -- which casts f.source::text for the same reason. asset_id is text
     -- (no cast); current_status enum coerces the string literals in the IN.
     AND f.source::text = p_source
     AND f.current_status IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_seen_scan_run <> p_scan_run_id;

  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$;
