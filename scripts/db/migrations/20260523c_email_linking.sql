-- ============================================================================
-- 20260523c_email_linking.sql
--
-- Adds incoming-email ingestion and linkage to assets / findings / CVEs.
-- The story: when a vendor sends a security disclosure ("Mega Main Menu
-- 2.2.2 patches CVE-2023-1575"), or a customer asks "are you affected
-- by CVE-2024-2473?", or an auditor follows up on M-04 — those emails
-- are first-class evidence about findings and assets. Right now they
-- live in Outlook, disconnected. This schema is the data layer for
-- bringing them into the portal alongside the things they describe.
--
-- Four tables:
--
--   1. email_messages         — one row per incoming email
--   2. email_attachments      — one row per attachment (stored in Supabase storage)
--   3. email_links            — many-to-many email ↔ asset/finding/CVE/org
--   4. email_threads          — group related emails via RFC In-Reply-To
--
-- Critical design notes:
--
--   - email_links has a confidence column. NOTHING below HIGH gets
--     auto-displayed on /findings/[id] or /assets/[id]. Lower-confidence
--     candidates land in /inbox admin triage where an admin confirms
--     or rejects. Reason: a wrong link (showing a random vendor disclosure
--     on a CRITICAL finding) is worse than missing one. Trust-by-default
--     was right for synth; for email linking the failure mode is worse.
--
--   - email_messages.raw_message_storage_url points to the full .eml
--     blob in Supabase Storage. Audit-grade — we never lose the original.
--
--   - All tables RLS-locked to admin only. Vendor disclosures often
--     contain pre-disclosure CVE detail; treat sensitivity as equal
--     to findings.
--
--   - The 'from_address' / 'to_addresses' are stored as plain text. No
--     PII obfuscation. Emails ARE the system of record.
--
-- Idempotent. Safe to re-run.
-- ============================================================================

BEGIN;

-- ───────────────────────────────────────────────────────────────────────
-- Enums
-- ───────────────────────────────────────────────────────────────────────

DO $$ BEGIN
  CREATE TYPE email_source_t AS ENUM (
    'inbound_webhook',     -- Resend (or other) inbound webhook
    'manual_upload',       -- admin drag-dropped a .eml file
    'forwarded',           -- forwarded from another inbox (less reliable)
    'backfill'             -- bulk historical import
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE email_link_type_t AS ENUM (
    'asset',
    'finding',
    'cve',
    'organization'         -- for emails that are about a Command org generally,
                           -- not a specific asset (e.g. quarterly auditor check-in)
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE email_link_confidence_t AS ENUM ('high', 'medium', 'low');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE email_match_method_t AS ENUM (
    'domain_in_body',
    'domain_in_subject',
    'cve_reference',
    'component_reference',
    'sender_domain',
    'subject_pattern',
    'manual',              -- admin-asserted via /inbox triage
    'thread_inheritance'   -- inherited from another confirmed link in the same thread
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ───────────────────────────────────────────────────────────────────────
-- email_threads — groups via RFC In-Reply-To / References chain
-- ───────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_threads (
  thread_id           text          PRIMARY KEY,
  -- Subject with Re:/Fwd:/etc. stripped — used to merge messy threads
  -- where the In-Reply-To header is missing
  subject_normalized  text,
  first_email_at      timestamptz,
  last_email_at       timestamptz,
  message_count       integer       NOT NULL DEFAULT 0,
  -- Denormalized linked-asset list for quick filter / display
  linked_asset_ids    text[]        NOT NULL DEFAULT '{}',
  created_at          timestamptz   NOT NULL DEFAULT now(),
  updated_at          timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_threads_last_email
  ON email_threads(last_email_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_email_threads_linked_assets_gin
  ON email_threads USING gin(linked_asset_ids);

COMMENT ON TABLE email_threads IS
  'Groups related email_messages via RFC In-Reply-To / References chain. Falls back to subject_normalized when headers are missing or stripped.';

-- ───────────────────────────────────────────────────────────────────────
-- email_messages — the main table
-- ───────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_messages (
  -- We use the RFC 5322 Message-ID as the natural PK. It's globally
  -- unique by design. If a message arrives with no Message-ID (rare,
  -- usually malformed), the ingester synthesizes one.
  message_id          text          PRIMARY KEY,

  -- Sender
  from_address        text          NOT NULL,
  from_name           text,
  from_domain         text          NOT NULL,            -- pre-extracted for fast filter ("show me all wordfence emails")

  -- Recipients (the to/cc lists can be large; arrays not subqueries)
  to_addresses        text[]        NOT NULL DEFAULT '{}',
  cc_addresses        text[]        NOT NULL DEFAULT '{}',
  bcc_addresses       text[]        NOT NULL DEFAULT '{}',

  -- Content
  subject             text,
  subject_normalized  text,                              -- Re:/Fwd: stripped
  body_text           text,                              -- plain text fallback
  body_html           text,                              -- rendered in portal (sanitized at render time)

  -- Timing
  received_at         timestamptz   NOT NULL,            -- from Date: header
  ingested_at         timestamptz   NOT NULL DEFAULT now(),

  -- Provenance
  source              email_source_t NOT NULL,
  ingested_by         uuid REFERENCES auth.users(id) ON DELETE SET NULL,  -- NULL for webhook ingest

  -- Threading
  thread_id           text REFERENCES email_threads(thread_id) ON DELETE SET NULL,
  in_reply_to         text,                              -- the Message-ID this is a reply to
  references_chain    text[]        NOT NULL DEFAULT '{}', -- full References: header parsed

  -- Audit / forensic
  raw_message_storage_url text,                          -- pointer to the full .eml blob in Supabase Storage
  raw_message_sha256      text,                          -- integrity check
  size_bytes              bigint,

  created_at          timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_messages_received_at
  ON email_messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_messages_from_domain
  ON email_messages(from_domain);
CREATE INDEX IF NOT EXISTS idx_email_messages_thread_id
  ON email_messages(thread_id);
-- (Trigram index on subject was here originally for inbox search; removed
--  because pg_trgm isn't enabled on this Supabase project by default. If
--  inbox search becomes painful with the plain b-tree, run:
--    CREATE EXTENSION IF NOT EXISTS pg_trgm;
--    CREATE INDEX idx_email_messages_subject_trgm
--      ON email_messages USING gin(subject gin_trgm_ops);
-- )

COMMENT ON TABLE email_messages IS
  'Incoming emails ingested via inbound webhook, manual upload, or backfill. Audit-grade: full raw .eml preserved in Supabase Storage at raw_message_storage_url.';

-- ───────────────────────────────────────────────────────────────────────
-- email_attachments — one row per attachment
-- ───────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_attachments (
  attachment_id       bigserial     PRIMARY KEY,
  message_id          text          NOT NULL REFERENCES email_messages(message_id) ON DELETE CASCADE,
  filename            text          NOT NULL,
  content_type        text,
  byte_size           bigint,
  sha256              text,
  storage_url         text,                              -- Supabase Storage URL
  storage_bucket      text          DEFAULT 'email-attachments',
  -- Tag flag for attachments that are themselves disclosure docs (PDF
  -- advisory, .eml inline, screenshot of an exploit, etc.) — populated
  -- by the matcher or admin
  is_evidence         boolean       NOT NULL DEFAULT false,
  created_at          timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_attachments_message_id
  ON email_attachments(message_id);

-- ───────────────────────────────────────────────────────────────────────
-- email_links — many-to-many, with confidence + provenance + admin-confirm gate
-- ───────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_links (
  link_id             bigserial               PRIMARY KEY,
  message_id          text                    NOT NULL REFERENCES email_messages(message_id) ON DELETE CASCADE,

  -- What this email is about
  link_type           email_link_type_t       NOT NULL,
  -- Polymorphic target: depending on link_type, this is the asset_id,
  -- finding_id, CVE string ('CVE-2024-2473'), or organization name
  link_target_id      text                    NOT NULL,

  -- How sure are we
  confidence          email_link_confidence_t NOT NULL,
  matched_via         email_match_method_t    NOT NULL,
  matched_excerpt     text,                                            -- the snippet of email body that triggered the match (for admin context)

  -- Admin-confirmation gate. Until confirmed_by is set, this link does
  -- NOT appear on /findings/[id] or /assets/[id] — only in /inbox triage.
  confirmed_by        uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  confirmed_at        timestamptz,
  rejected_by         uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  rejected_at         timestamptz,
  rejection_reason    text,

  created_at          timestamptz             NOT NULL DEFAULT now(),

  -- Prevent duplicate suggestions for the same (message, link_type, target)
  UNIQUE (message_id, link_type, link_target_id)
);

CREATE INDEX IF NOT EXISTS idx_email_links_message
  ON email_links(message_id);
CREATE INDEX IF NOT EXISTS idx_email_links_target
  ON email_links(link_type, link_target_id);
-- Critical index: the "what emails are linked to this finding" query
-- on /findings/[id] is gated on confirmed_at IS NOT NULL.
CREATE INDEX IF NOT EXISTS idx_email_links_confirmed_target
  ON email_links(link_type, link_target_id, confirmed_at)
  WHERE confirmed_at IS NOT NULL;
-- The /inbox queue query: unresolved (neither confirmed nor rejected) links
CREATE INDEX IF NOT EXISTS idx_email_links_inbox_queue
  ON email_links(message_id)
  WHERE confirmed_at IS NULL AND rejected_at IS NULL;

COMMENT ON COLUMN email_links.confidence IS
  'How sure the matcher is. HIGH = auto-confirm safe (sender domain + CVE in subject, e.g.). MEDIUM = needs admin review. LOW = surface in inbox but hint that it might be noise.';

COMMENT ON COLUMN email_links.confirmed_by IS
  'Until set, link does NOT display on /findings/[id] or /assets/[id] — only in /inbox triage. Trust-by-default was right for synth; here a wrong link is worse than a missing one.';

-- ───────────────────────────────────────────────────────────────────────
-- View — emails awaiting triage (drives /inbox)
-- ───────────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_email_inbox_queue AS
SELECT
  m.message_id,
  m.from_address,
  m.from_domain,
  m.subject,
  m.received_at,
  m.thread_id,
  COUNT(l.link_id) FILTER (WHERE l.confirmed_at IS NULL AND l.rejected_at IS NULL) AS pending_link_count,
  MAX(l.confidence::text) FILTER (WHERE l.confirmed_at IS NULL AND l.rejected_at IS NULL) AS top_confidence,
  array_agg(DISTINCT l.link_type::text) FILTER (WHERE l.confirmed_at IS NULL AND l.rejected_at IS NULL) AS pending_link_types
FROM email_messages m
LEFT JOIN email_links l ON l.message_id = m.message_id
WHERE EXISTS (
  SELECT 1 FROM email_links lx
  WHERE lx.message_id = m.message_id
    AND lx.confirmed_at IS NULL
    AND lx.rejected_at IS NULL
)
GROUP BY m.message_id, m.from_address, m.from_domain, m.subject, m.received_at, m.thread_id
ORDER BY m.received_at DESC;

COMMENT ON VIEW v_email_inbox_queue IS
  'Emails with at least one unresolved (suggested-but-unconfirmed) link. Drives the /inbox admin triage page.';

-- ───────────────────────────────────────────────────────────────────────
-- RLS — admin-only. Vendor disclosures often contain pre-disclosure CVE
-- detail; treat sensitivity as equal to findings.
-- ───────────────────────────────────────────────────────────────────────

ALTER TABLE email_messages    ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_links       ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_threads     ENABLE ROW LEVEL SECURITY;

-- Admin-only policies. Lean on the existing is_admin() helper used
-- elsewhere in the portal RLS (defined in scripts/db/rls.sql).
DO $$ BEGIN
  CREATE POLICY admin_read_email_messages    ON email_messages    FOR SELECT  USING (is_admin());
  CREATE POLICY admin_write_email_messages   ON email_messages    FOR ALL     USING (is_admin())   WITH CHECK (is_admin());
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY admin_read_email_attachments  ON email_attachments FOR SELECT USING (is_admin());
  CREATE POLICY admin_write_email_attachments ON email_attachments FOR ALL    USING (is_admin())   WITH CHECK (is_admin());
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY admin_read_email_links   ON email_links FOR SELECT USING (is_admin());
  CREATE POLICY admin_write_email_links  ON email_links FOR ALL    USING (is_admin())   WITH CHECK (is_admin());
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY admin_read_email_threads  ON email_threads FOR SELECT USING (is_admin());
  CREATE POLICY admin_write_email_threads ON email_threads FOR ALL    USING (is_admin())   WITH CHECK (is_admin());
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMIT;

-- ---------------------------------------------------------------------------
-- Rollback (manual):
--   BEGIN;
--   DROP VIEW IF EXISTS v_email_inbox_queue;
--   DROP TABLE IF EXISTS email_links;
--   DROP TABLE IF EXISTS email_attachments;
--   DROP TABLE IF EXISTS email_messages;
--   DROP TABLE IF EXISTS email_threads;
--   DROP TYPE  IF EXISTS email_match_method_t;
--   DROP TYPE  IF EXISTS email_link_confidence_t;
--   DROP TYPE  IF EXISTS email_link_type_t;
--   DROP TYPE  IF EXISTS email_source_t;
--   COMMIT;
-- ---------------------------------------------------------------------------
