-- 20261026c_digest_approval.sql
--
-- KB 12 job 3l (2026-10-26). THE DIGEST COMES TO HOWIE FIRST; HE SENDS IT ON FROM THE EMAIL.
--
-- Howie, 2026-10-26 14:00: "I want the mail to come only to me, and then I have the ability to
-- approve it for further distribution." 14:05: "Why can't it be just in the email itself?"
-- 14:17: "This should be a simple process. I don't want to have to go into a GitHub web page
-- every morning to simply approve it." 14:19: "Go."
--
-- What this does:
--   1. NEW table digest_pending: one row per scheduled digest built. It holds exactly the email
--      the others will receive (subject, HTML, text), who they are, its fingerprint, and the
--      sha256 of the one-time token behind the approval copy's "Send to the others" button.
--      The token itself is never stored. RLS on, no policies: only the database owner (the
--      digest jobs) reads or writes it.
--   2. NEW function digest_approval_preview(token): what the portal's /digest/approve page
--      shows before Howie presses Send (which email, to whom, and whether it can still go).
--   3. NEW function digest_approve(token): the Send button. Marks that one email approved if it
--      is still waiting and not expired; returns 'approved', or why not ('already approved',
--      'sent', 'superseded', 'expired', 'failed', 'unknown'). digest-send.yml then sends it.
--   Both functions are SECURITY DEFINER with an empty search_path and are the ONLY way in for
--   the portal (anon and authenticated may execute them; nothing else on the table). Knowing a
--   token lets you send that one email to the people it was already going to; nothing more.
-- No data changes. Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 300
-- notes: Job 3l (Howie 2026-10-26 14:00-14:19): the digest goes to the approver first and to the others only after he approves it from the email. New table public.digest_pending (RLS on, no policies, anon/authenticated revoked). New SECURITY DEFINER functions digest_approval_preview(text) and digest_approve(text), search_path empty, EXECUTE for anon and authenticated only. No data changes. No dollar-quoting. Byte-identical in both repos.
-- END-META

-- ── 1. the stored emails ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.digest_pending (
  id            bigserial   PRIMARY KEY,
  kind          text        NOT NULL CHECK (kind IN ('daily', 'weekly')),
  alerter_name  text        NOT NULL,
  built_at      timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  window_start  timestamptz,
  window_end    timestamptz NOT NULL,
  subject       text        NOT NULL,
  html          text        NOT NULL,
  text_body     text        NOT NULL,
  recipients    text[]      NOT NULL,
  fingerprint   text        NOT NULL,
  token_hash    text        NOT NULL UNIQUE,
  finalize      jsonb       NOT NULL DEFAULT '{}'::jsonb,
  status        text        NOT NULL DEFAULT 'awaiting'
                CHECK (status IN ('awaiting', 'approved', 'sending', 'sent', 'superseded', 'failed')),
  approved_at   timestamptz,
  sent_at       timestamptz,
  attempts      integer     NOT NULL DEFAULT 0,
  error         text
);

CREATE INDEX IF NOT EXISTS digest_pending_status_built_idx ON public.digest_pending (status, built_at);

ALTER TABLE public.digest_pending ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.digest_pending FROM anon, authenticated;
REVOKE ALL ON SEQUENCE public.digest_pending_id_seq FROM anon, authenticated;

-- ── 2. what the approval page shows ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.digest_approval_preview(p_token text)
RETURNS TABLE (kind text, subject text, recipients text[], built_at timestamptz,
               expires_at timestamptz, state text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path TO ''
AS '
  SELECT d.kind, d.subject, d.recipients, d.built_at, d.expires_at,
         CASE WHEN d.status = ''awaiting'' AND d.expires_at <= now() THEN ''expired''
              ELSE d.status END
    FROM public.digest_pending d
   WHERE d.token_hash = encode(sha256(convert_to(coalesce(p_token, ''''), ''UTF8'')), ''hex'')
';

-- ── 3. the Send button ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.digest_approve(p_token text)
RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path TO ''
AS '
  WITH t AS (
    SELECT encode(sha256(convert_to(coalesce(p_token, ''''), ''UTF8'')), ''hex'') AS h
  ), upd AS (
    UPDATE public.digest_pending d
       SET status = ''approved'', approved_at = now()
      FROM t
     WHERE d.token_hash = t.h
       AND d.status = ''awaiting''
       AND d.expires_at > now()
    RETURNING d.id
  )
  SELECT CASE
           WHEN EXISTS (SELECT 1 FROM upd) THEN ''approved''
           ELSE coalesce((SELECT CASE WHEN d.status = ''awaiting'' THEN ''expired''
                                      WHEN d.status = ''approved'' THEN ''already approved''
                                      WHEN d.status = ''sending'' THEN ''already approved''
                                      ELSE d.status END
                            FROM public.digest_pending d, t
                           WHERE d.token_hash = t.h), ''unknown'')
         END
';

REVOKE ALL ON FUNCTION public.digest_approval_preview(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.digest_approve(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.digest_approval_preview(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.digest_approve(text) TO anon, authenticated;
