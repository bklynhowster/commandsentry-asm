-- ============================================================================
-- MIGRATION — 2026-05-22 — Phase F: canonical synthesized description columns
--
-- Adds the columns that hold AI-synthesized (and human-curated) canonical
-- descriptions for findings, plus the provenance metadata so we always
-- know where the text came from.
--
-- Design (signed off 2026-05-22):
--   - findings.description_synth / impact / remediation are the canonical
--     three sections rendered on the portal detail page.
--   - description_source enum:
--       'scanner'                — came directly from the scanner output (default)
--       'manual'                 — Howie or another admin wrote/edited it
--       'ai_synthesized'         — Phase F backfill output, NOT yet reviewed
--       'ai_synthesized_reviewed'— AI output that an admin has approved as-is
--   - description_synthesized_at + description_synth_model record when and
--     how the synthesis ran (so we can re-synthesize when scan data drifts
--     and know which model version produced which text).
--   - description_synth_reviewed_by + _reviewed_at capture the human sign-off
--     for audit.
--
-- The portal /findings/[id] page reads from description_synth (and impact,
-- remediation) when populated, falling back to the existing
-- description column + raw_excerpt heuristic when not.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260522_phase_f_finding_synth_columns.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Add the canonical text columns
-- ---------------------------------------------------------------------------
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS description_synth text,
  ADD COLUMN IF NOT EXISTS impact            text,
  ADD COLUMN IF NOT EXISTS remediation       text;

-- ---------------------------------------------------------------------------
-- 2. Provenance metadata
-- ---------------------------------------------------------------------------
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS description_source        text NOT NULL DEFAULT 'scanner',
  ADD COLUMN IF NOT EXISTS description_synthesized_at timestamptz,
  ADD COLUMN IF NOT EXISTS description_synth_model    text,
  ADD COLUMN IF NOT EXISTS description_synth_input_hash text,
  ADD COLUMN IF NOT EXISTS description_synth_reviewed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS description_synth_reviewed_at timestamptz;

-- Enforce the allowed source values.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'findings_description_source_check'
       AND conrelid = 'public.findings'::regclass
  ) THEN
    ALTER TABLE public.findings
      ADD CONSTRAINT findings_description_source_check
      CHECK (description_source IN (
        'scanner',
        'manual',
        'ai_synthesized',
        'ai_synthesized_reviewed'
      ));
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- 3. Index to find pending-review rows quickly
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_findings_description_source
  ON public.findings(description_source)
  WHERE description_source IN ('ai_synthesized', 'ai_synthesized_reviewed');

-- ---------------------------------------------------------------------------
-- 4. Comments for clarity in pgAdmin / Supabase studio
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN public.findings.description_synth IS
  '§1 "What is this?" canonical text. Plain-English explanation. Audience: asset owners. Filled by Phase F backfill or manual edit; falls back to findings.description on the portal when null.';
COMMENT ON COLUMN public.findings.impact IS
  '§2 "What could it do to my system?" canonical text. Concrete impact + business consequence.';
COMMENT ON COLUMN public.findings.remediation IS
  '§3 "How do I get rid of it?" canonical text. Concrete remediation steps specific to the stack.';
COMMENT ON COLUMN public.findings.description_source IS
  'Provenance of description_synth/impact/remediation. One of: scanner, manual, ai_synthesized, ai_synthesized_reviewed.';
COMMENT ON COLUMN public.findings.description_synth_input_hash IS
  'SHA-256 hash of the input blob the synth ran on (title + description + raw_excerpts + CVE/CWE). Lets us detect when source material has changed enough to warrant a re-synth.';

-- ---------------------------------------------------------------------------
-- 5. Verification
-- ---------------------------------------------------------------------------
SELECT 'New columns on findings:' AS info;
SELECT column_name, data_type, column_default
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND table_name = 'findings'
   AND column_name IN (
     'description_synth', 'impact', 'remediation',
     'description_source', 'description_synthesized_at',
     'description_synth_model', 'description_synth_input_hash',
     'description_synth_reviewed_by', 'description_synth_reviewed_at'
   )
 ORDER BY column_name;

SELECT 'description_source check constraint:' AS info;
SELECT pg_get_constraintdef(oid) AS definition
  FROM pg_constraint
 WHERE conname = 'findings_description_source_check';

SELECT 'Rows by current source value (should all be scanner pre-backfill):' AS info;
SELECT description_source, COUNT(*) AS n
  FROM public.findings
 GROUP BY description_source
 ORDER BY description_source;

COMMIT;
