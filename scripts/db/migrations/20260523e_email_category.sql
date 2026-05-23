-- ============================================================================
-- 20260523e_email_category.sql
--
-- Phase 3 of email linking — classify incoming emails by PURPOSE.
--
-- The earlier matcher links emails to assets/findings/CVEs based on content.
-- That answers WHAT the email is about. Categorization answers WHY it exists:
--
--   vendor_disclosure   — vendor telling us about a vulnerability (Wordfence,
--                         WPScan, Patchstack, CISA KEV advisory, etc.)
--   customer_inquiry    — customer asking about our exposure (vendor risk
--                         questionnaires, security attestation requests)
--   audit_followup      — auditor wants evidence on a specific finding
--                         (Deloitte, KPMG, internal audit team)
--   internal_thread     — Command-internal correspondence (from one of our
--                         own domains)
--   random_outreach     — unknown sender with low-effort security relevance
--                         (random researcher, bug-bounty cold outreach)
--   uncategorized       — default; matcher couldn't classify
--
-- Why this matters: these are fundamentally different in how Howie wants
-- to handle them. Customer inquiries need a RESPONSE drafted. Auditor
-- emails need evidence pulled. Vendor disclosures need triage by severity.
-- Filtering / coloring by category turns the inbox from a flat queue into
-- a workflow.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

DO $$ BEGIN
  CREATE TYPE email_category_t AS ENUM (
    'vendor_disclosure',
    'customer_inquiry',
    'audit_followup',
    'internal_thread',
    'random_outreach',
    'uncategorized'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE email_messages
  ADD COLUMN IF NOT EXISTS category email_category_t NOT NULL DEFAULT 'uncategorized';

-- Partial index on each non-default category so the /inbox filter pills
-- ("show me only vendor disclosures") run fast.
CREATE INDEX IF NOT EXISTS idx_email_messages_category
  ON email_messages(category)
  WHERE category <> 'uncategorized';

COMMENT ON COLUMN email_messages.category IS
  'Classification by email PURPOSE (vendor disclosure / customer inquiry / audit follow-up / internal / random / uncategorized). Set by classifier at ingest time; admin can override via /admin/inbox.';

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--   BEGIN;
--   DROP INDEX IF EXISTS idx_email_messages_category;
--   ALTER TABLE email_messages DROP COLUMN IF EXISTS category;
--   DROP TYPE IF EXISTS email_category_t;
--   COMMIT;
-- ---------------------------------------------------------------------------
