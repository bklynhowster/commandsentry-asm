-- 20261104c_plain_words.sql
--
-- KB 12 job 4u, plan v2 (2026-11-04), push 1. ROOM FOR A PLAIN-ENGLISH EXPLANATION OF EACH FINDING,
-- SAVED ONCE: WHAT IT IS, WHETHER IT MATTERS, WHAT TO DO.
--
-- Howie, 2026-11-04 12:33, on the dashboard's change panel: "This text is barely American English.
-- It's too dense, and we need to have an AI explanatory area. This is hard for a non-expert to
-- understand." Ruled: "Saved plain-words": Sentry's AI writes a plain explanation of each finding
-- once, saves it, and the dashboard's "What does this mean?" box shows the saved words. 15:35: one
-- per finding. 15:37: "nobody ever uses the approval, or basically the admin page, to do anything,
-- so I want you to base the application logic on that assumption" (so: no review state here).
--
-- What this does: seven new, empty columns on findings, and two rules on them.
--   plain_what / plain_worry / plain_todo  the three parts of the explanation (all three or none:
--                                          a box is never half-written)
--   plain_input_hash                       what the words were written from, so a change rewrites them
--   plain_model / plain_written_at         which model wrote them, and when
--   plain_rejected_at                      the off switch: set (by a script Howie runs) when an
--                                          explanation reads wrong; the words are cleared with it and
--                                          the writer never writes that finding's words again
-- The writer (scripts/backfill/plain_words.py, a later push) is the only thing that fills them.
-- Nothing reads them until the portal push. D-029's columns (description_synth, impact,
-- remediation, description_source, description_synth_*) are not touched. No row is changed: every
-- new column starts NULL, which both rules allow.
--
-- No grants change: findings' existing table grants cover new columns, as they did for D-029's.
-- Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 300
-- notes: Job 4u plan v2 push 1 (Howie 2026-11-04 "Saved plain-words"; 15:35 one per finding; 15:37 no review step). findings gains plain_what, plain_worry, plain_todo, plain_input_hash, plain_model (text), plain_written_at, plain_rejected_at (timestamptz), all nullable with no default, so no row is rewritten; CHECK the three parts all set or all NULL; CHECK a switched-off row carries no words. D-029's columns untouched; no grant changes; no dollar-quoting. Byte-identical in both repos.
-- END-META

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS plain_what text,
  ADD COLUMN IF NOT EXISTS plain_worry text,
  ADD COLUMN IF NOT EXISTS plain_todo text,
  ADD COLUMN IF NOT EXISTS plain_input_hash text,
  ADD COLUMN IF NOT EXISTS plain_model text,
  ADD COLUMN IF NOT EXISTS plain_written_at timestamptz,
  ADD COLUMN IF NOT EXISTS plain_rejected_at timestamptz;

ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS findings_plain_words_all_or_none;

ALTER TABLE public.findings ADD CONSTRAINT findings_plain_words_all_or_none
  CHECK ((plain_what IS NULL) = (plain_worry IS NULL) AND (plain_what IS NULL) = (plain_todo IS NULL));

ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS findings_plain_words_off_means_empty;

ALTER TABLE public.findings ADD CONSTRAINT findings_plain_words_off_means_empty
  CHECK (plain_rejected_at IS NULL OR plain_what IS NULL);

COMMENT ON COLUMN public.findings.plain_what IS
  'KB 12 job 4u (2026-11-04): the plain-English "what it is" for someone who is not technical, 1-2 short sentences, written once by scripts/backfill/plain_words.py and shown in the dashboard''s "What does this mean?" box. NULL = no box. Set together with plain_worry and plain_todo, or not at all.';

COMMENT ON COLUMN public.findings.plain_worry IS
  'KB 12 job 4u: whether it matters and how much, one sentence, never alarming and never dismissive. Set together with plain_what and plain_todo.';

COMMENT ON COLUMN public.findings.plain_todo IS
  'KB 12 job 4u: what to do and who does it, one sentence ("Nothing now" allowed for small items). Set together with plain_what and plain_worry.';

COMMENT ON COLUMN public.findings.plain_input_hash IS
  'KB 12 job 4u: SHA-256 of what the plain words were written from: the prompt version, title, severity, scanner description, and D-029''s description_synth, impact and remediation. Not the scan excerpt: each scan writes a new one, and hashing it would rewrite, and pay for, the same words again and again. A different hash means the finding changed and the words are rewritten, or cleared if a good rewrite cannot be had.';

COMMENT ON COLUMN public.findings.plain_model IS
  'KB 12 job 4u: the model that wrote the plain words.';

COMMENT ON COLUMN public.findings.plain_written_at IS
  'KB 12 job 4u: when the plain words were written.';

COMMENT ON COLUMN public.findings.plain_rejected_at IS
  'KB 12 job 4u (Howie 2026-11-04 15:37: nobody uses the admin page): the off switch. Set by a script Howie runs when an explanation reads wrong; the three parts are cleared with it (CHECK findings_plain_words_off_means_empty) and plain_words.py never writes this finding''s words again, on any path, --force included.';
