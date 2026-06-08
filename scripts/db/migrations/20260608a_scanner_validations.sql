-- ============================================================================
-- 20260608a_scanner_validations.sql
--
-- ADR-001 Step 5 (convergent edition). Moves the validated-SHA allowlist
-- OUT of the hashed runner code and into a Postgres table.
--
-- WHY THIS EXISTS:
--
-- The first attempt (commit eebc45a, reverted before push 2026-06-08)
-- put VALIDATED_VERSIONS as an in-code dict and added e5ad4a7's SHA to
-- it. That commit was held when we noticed it never converges:
--
--   scanner_version is read from GITHUB_SHA at runtime. The commit that
--   ADDS a SHA to the in-code list is itself a new commit with a NEW
--   sha. When that new commit runs, GITHUB_SHA = its_own_sha, which is
--   NOT in the allowlist (only the old proven SHA is). So every future
--   run writes 'unvalidated' — the backfill stamps the proving run, but
--   nothing ever validates again. Silent no-op.
--
-- ROOT CAUSE: an in-code allowlist can't self-reference. The commit
-- recording the validation can't itself BE the validated commit. Never
-- converges.
--
-- FIX (this migration):
-- Move the allowlist to a Postgres table. derive_validation_status()
-- queries the table at runtime. Validating a SHA = INSERTing a row,
-- NOT a commit. HEAD doesn't move. The running SHA can validate itself
-- and the regime converges.
--
-- Auto-invalidation is preserved: any new code change still produces a
-- new SHA. That new SHA isn't in the table until it's proven AND
-- explicitly INSERTed. So bad code can never quietly become 'validated'
-- just by shipping — there's a manual gate (the INSERT) between proving
-- and stamping.
--
-- SHAPE:
--   intensity        text     PK part 1 — 'light' | 'medium' | 'heavy'
--   scanner_version  text     PK part 2 — full 40-char GITHUB_SHA
--   validated_at     tstz     when the INSERT happened (audit)
--   notes            text     freeform — proving scan_run id, reviewer, etc.
--
-- The PK (intensity, scanner_version) gives us free idempotency:
-- INSERT ... ON CONFLICT DO NOTHING for the promotion script. Removing
-- a validation = DELETE (rare; for "we shouldn't have promoted this SHA"
-- corrections). Per ADR-001's design, demotion doesn't retroactively
-- flip rows — it just stops further emissions from stamping validated.
--
-- IDEMPOTENT: ADD TABLE IF NOT EXISTS, no UPDATE on existing schema.
-- Re-apply is a no-op.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.scanner_validations (
  intensity        text         NOT NULL,
  scanner_version  text         NOT NULL,
  validated_at     timestamptz  NOT NULL DEFAULT now(),
  notes            text,
  PRIMARY KEY (intensity, scanner_version)
);

COMMENT ON TABLE public.scanner_validations IS
  'ADR-001 Step 5. Allowlist of (intensity, scanner_version) pairs whose '
  'emissions can be stamped findings.validation_status=validated. Queried '
  'at runtime by derive_validation_status() in scripts/scanner/run_medium.py '
  'and run_light.py. Moved here from in-code VALIDATED_VERSIONS dict because '
  'an in-code allowlist cannot self-reference (the commit that adds a SHA '
  'has a different SHA than the one it adds, so the regime never converges).';

COMMENT ON COLUMN public.scanner_validations.intensity IS
  'Tier name. Must match ctx.intensity in the runner: light/medium/heavy.';
COMMENT ON COLUMN public.scanner_validations.scanner_version IS
  'Full 40-char GITHUB_SHA of the runner commit whose output is trusted. '
  'Exact-string match; never abbreviated.';
COMMENT ON COLUMN public.scanner_validations.validated_at IS
  'When this row was INSERTed. Audit only.';
COMMENT ON COLUMN public.scanner_validations.notes IS
  'Freeform — proving scan_run id, reviewer, rationale.';

-- Lock down — service_role only (runner uses service-role key).
ALTER TABLE public.scanner_validations ENABLE ROW LEVEL SECURITY;
-- No policies for anon/authenticated. service_role bypasses RLS.

COMMIT;

-- ============================================================================
-- VERIFICATION (run after apply):
--   SELECT count(*) FROM public.scanner_validations;
-- Expected immediately post-migration: 0
--
-- Promote the first validated medium SHA (post-Y-deploy proving run):
--   INSERT INTO public.scanner_validations (intensity, scanner_version, notes)
--   VALUES (
--     'medium',
--     '<full 40-char Y SHA>',
--     'First validated medium baseline. Proving scan_run: <id>.'
--   );
-- ============================================================================
