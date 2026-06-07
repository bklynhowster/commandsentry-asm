-- ============================================================================
-- 20260607b_scan_run_tool_status.sql
--
-- ADR-001 Step 4 — Silent-tool-failure visibility on scan_run.
--
-- Adds a single column to public.scan_run:
--   - tool_status  jsonb DEFAULT '{}'
--
-- Shape: a flat object keyed by tool_name, value is either:
--   { "ok": true }
--   { "degraded": "<reason_slug>" }
--
-- Example:
--   {
--     "wafw00f":  { "ok": true },
--     "nuclei":   { "ok": true },
--     "nikto":    { "degraded": "help_text_returned" },
--     "ffuf":     { "ok": true }
--   }
--
-- WHY:
-- Before this column, a scan could be 'complete' AND have a tool that
-- silently produced nothing useful (Bug D: nikto returned help text for
-- 14+ medium scans, never surfaced because the runner closed cleanly).
-- status='complete' conflated WRITE-PATH success with COMPLETENESS.
--
-- tool_status separates the two:
--   - status                — did the runner finish without crashing?
--   - tool_status           — did each tool produce real output, or fail silently?
--
-- A scan can now be honestly 'complete + degraded:[nikto]'. The findings
-- table stays the same; reports can filter on tool_status to surface
-- "this scan ran but nikto was broken — don't count its absence of
-- nikto findings as a clean signal."
--
-- IMPORTANT: a degraded flag MUST mean "tool failed," NEVER "tool worked,
-- found nothing." Per Howie 2026-06-07 PM: a detector that cries wolf on
-- healthy runs trains the team to ignore 'degraded' and defeats the
-- whole point. Only wire detectors that key on unambiguous failure
-- signals (e.g., nikto's help-text banner, ffuf parse-fail, wafw00f
-- absence-of-verdict). Do NOT wire empty-output detectors on tools where
-- empty IS a healthy outcome (nuclei against a clean stack, etc.).
--
-- IDEMPOTENCY: ADD COLUMN IF NOT EXISTS, no constraints. Re-applying
-- this migration is a no-op.
--
-- NAMING: this is `b` for the second migration of 2026-06-07 (after
-- `a` which added the validation_status key to findings).
-- ============================================================================

BEGIN;

ALTER TABLE public.scan_run
  ADD COLUMN IF NOT EXISTS tool_status jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN public.scan_run.tool_status IS
  'Per-tool completeness map. {tool_name: {"ok": true} | {"degraded": "reason"}}. '
  'A scan can be status=complete AND have tool_status entries marking individual '
  'tools as degraded. Detectors live in scripts/scanner/run_medium.py (and '
  'run_light.py). Adding a detector without empirical evidence of the failure '
  'shape is forbidden — see ADR-001 Step 4 design notes.';

COMMIT;

-- ============================================================================
-- VERIFICATION (run after apply):
--
--   SELECT count(*) FILTER (WHERE tool_status = '{}'::jsonb) AS empty_count,
--          count(*) AS total
--     FROM public.scan_run;
--
-- Expected immediately post-migration: empty_count = total (every existing
-- row is the default '{}', no historical detector backfill — those scans
-- ran before the framework existed, and that's the point of validation
-- regimes: we don't retroactively claim or deny what we didn't observe).
-- ============================================================================
