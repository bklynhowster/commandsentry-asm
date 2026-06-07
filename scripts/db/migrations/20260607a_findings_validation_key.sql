-- ============================================================================
-- 20260607a_findings_validation_key.sql
--
-- ADR-001 — Validated-SHA key for findings.
--
-- Adds three columns to public.findings so each row carries:
--   - validation_status  ENUM-like text: 'validated' | 'unvalidated' | 'legacy'
--   - scanner_version    text — the runner's git SHA (or "unknown") that
--                              produced this finding row. Always written.
--   - validated_at       timestamptz — set when validation_status first
--                              becomes 'validated'. Stable thereafter.
--
-- WHY:
-- Before this migration, "findings_added > 0" was the only signal that a
-- scan produced output. That's a write-path proof, not a completeness or
-- correctness proof. The 2026-06-07 demo.testfire.net work showed:
--
--   * Bug C (ffuf 302-filter discarded real findings) — runner silently
--     produced 0 rows for 14+ medium scans even on a clean no-WAF target.
--   * Bug D (nikto invocation broken — stores help-text instead of scan
--     output) — silently present for 14+ runs, never surfaced because the
--     runner closed status='complete' regardless.
--
-- Solution: separate completeness/correctness from write-path. A finding
-- row stamped 'validated' means "produced by a runner SHA that has been
-- proven end-to-end on the no-WAF positive control (demo.testfire.net)."
-- Nothing is 'validated' on this migration's commit — the VALIDATED_VERSIONS
-- allowlist in the runners starts empty. The first SHA gets promoted only
-- AFTER Bug D + the silent-tool-failure detector land and the proving
-- run on testfire confirms findings_added > 0 with all tools producing
-- real output.
--
-- BACKWARD COMPATIBILITY:
-- Every existing row is set to 'legacy'. They were produced before the
-- validation regime existed. We do not retroactively claim or deny them;
-- we just mark them honestly. Reports / UI can filter 'validated' vs
-- 'legacy' vs 'unvalidated' as they see fit going forward.
--
-- NAMING CONVENTION:
-- Migrations in this directory use YYYYMMDD{letter}_short_description.sql.
-- This is `a` for the first migration of 2026-06-07.
--
-- IDEMPOTENCY:
-- All ADD COLUMN clauses use IF NOT EXISTS. The CHECK constraint uses a
-- named identifier so a second apply gracefully fails the CONSTRAINT
-- creation without blocking the rest. Backfill is gated on
-- WHERE validation_status IS NULL so re-runs don't overwrite real values.
-- ============================================================================

BEGIN;

-- 1. Add the three columns (additive, nullable initially so the backfill
-- can populate without violating NOT NULL).
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS validation_status text;

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS scanner_version   text;

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS validated_at      timestamptz;

-- 2. Backfill every existing row to 'legacy'. These rows were produced
-- before the validation regime existed — we don't retroactively claim
-- or deny correctness, we just mark them honestly.
UPDATE public.findings
  SET validation_status = 'legacy'
  WHERE validation_status IS NULL;

-- 3. Lock in the default for future inserts. New rows default to
-- 'unvalidated' (the runner explicitly stamps 'validated' only when the
-- (tier, scanner_version) tuple is in VALIDATED_VERSIONS).
ALTER TABLE public.findings
  ALTER COLUMN validation_status SET DEFAULT 'unvalidated';

-- 4. Make the column NOT NULL now that every row has a value.
ALTER TABLE public.findings
  ALTER COLUMN validation_status SET NOT NULL;

-- 5. Restrict to the three legal values. Named constraint so a re-apply
-- shows a clear "already exists" error rather than a silent collision.
-- DO block makes it idempotent (skip if a constraint of this name
-- already exists).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'findings_validation_status_chk'
      AND conrelid = 'public.findings'::regclass
  ) THEN
    ALTER TABLE public.findings
      ADD CONSTRAINT findings_validation_status_chk
      CHECK (validation_status IN ('validated', 'unvalidated', 'legacy'));
  END IF;
END $$;

-- 6. Index for the inevitable "show me everything that's still unvalidated"
-- and "count by status" queries that the dashboard + alerter will run.
CREATE INDEX IF NOT EXISTS findings_validation_status_idx
  ON public.findings (validation_status);

COMMIT;

-- ============================================================================
-- VERIFICATION (run after apply):
--
--   SELECT validation_status, count(*)
--     FROM public.findings
--    GROUP BY validation_status
--    ORDER BY validation_status;
--
-- Expected immediately post-migration:
--   legacy  | <every row that existed before this migration>
--
-- (zero 'validated' rows because the runners' VALIDATED_VERSIONS allowlist
--  starts empty — nothing promotes until ADR-001 Step 5).
-- ============================================================================
