-- 20261027a_digest_slack.sql
--
-- KB 12 job 3l round 5 (2026-10-27). THE DAILY'S SECOND CHANNEL: the Slack post to
-- #on-call, with its own record and its own one-time button.
--
-- Howie, 2026-10-27 08:44: "Channel number two is Slack ... the on-call Slack channel ...
-- They're developers. What do developers need to know? They need to know if there's
-- something new that's happening: a site went down, a site came up, or a new
-- vulnerability was found." 08:46: "a button that says 'Send to Slack,' and I get to
-- decide on a daily basis" / "Obviously, also a button that says 'Approve for email'".
-- 08:47: "when I approve for Slack, it needs to be different. It's a stripped-down,
-- different form of communication for a different audience."
--
-- Three things, all additive:
--   1. public.slack_told: what the channel was told, per finding, so a nudge comes back
--      every 30 days and never two days running (the email's record, digest_told, keeps
--      one row per finding for the email's own timer; the two never share rows).
--   2. digest_pending grows the Slack half of each daily: the stored post, its own
--      one-time token, its own status. Approving the email never touches the Slack half
--      and the other way round.
--   3. digest_slack_preview(token) / digest_slack_approve(token): the "Post to Slack"
--      button, the same shape and grants as the email pair (20261026c). The post itself
--      is sent by the scanner repo's digest-send job through a webhook held only on
--      GitHub; the portal never holds it.
--
-- Lands in BOTH databases (the repos ship byte-identical). On Command nothing writes
-- these: the table stays empty and the columns stay at their defaults until Howie
-- turns the channel on there.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 800
-- notes: Job 3l round 5 (Howie 2026-10-27 08:44-08:47): the daily's Slack post to #on-call. New table public.slack_told (RLS on, no policies, anon/authenticated revoked); digest_pending gains nullable slack_* columns (payload, status with CHECK, token hash UNIQUE, approved/posted times, attempts, error, finalize); new SECURITY DEFINER functions digest_slack_preview(text) and digest_slack_approve(text), search_path empty, EXECUTE for anon and authenticated only. No data changes. No dollar-quoting. Byte-identical in both repos.
-- END-META

CREATE TABLE IF NOT EXISTS public.slack_told (
  finding_id     text        PRIMARY KEY,
  first_told_at  timestamptz NOT NULL DEFAULT now(),
  last_full_at   timestamptz NOT NULL DEFAULT now(),
  reminders      integer     NOT NULL DEFAULT 0,
  closed_seen_at timestamptz NULL,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.slack_told IS
  'Job 3l round 5 (2026-10-27): what the #on-call Slack post told, per finding, so a nudge '
  'comes back on a timer and never two days running. Written by run_alerter.py after a post '
  'that worked.';

ALTER TABLE public.slack_told ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.slack_told FROM anon, authenticated;

ALTER TABLE public.digest_pending
  ADD COLUMN IF NOT EXISTS slack_payload     jsonb       NULL,
  ADD COLUMN IF NOT EXISTS slack_status      text        NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS slack_token_hash  text        NULL,
  ADD COLUMN IF NOT EXISTS slack_approved_at timestamptz NULL,
  ADD COLUMN IF NOT EXISTS slack_posted_at   timestamptz NULL,
  ADD COLUMN IF NOT EXISTS slack_attempts    integer     NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS slack_error       text        NULL,
  ADD COLUMN IF NOT EXISTS slack_finalize    jsonb       NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.digest_pending DROP CONSTRAINT IF EXISTS digest_pending_slack_status_check;

ALTER TABLE public.digest_pending
  ADD CONSTRAINT digest_pending_slack_status_check
  CHECK (slack_status IN ('none', 'awaiting', 'approved', 'posting', 'posted', 'superseded', 'failed'));

CREATE UNIQUE INDEX IF NOT EXISTS digest_pending_slack_token_hash_idx
  ON public.digest_pending (slack_token_hash);

CREATE OR REPLACE FUNCTION public.digest_slack_preview(p_token text)
RETURNS TABLE (kind text, subject text, summary text, built_at timestamptz,
               expires_at timestamptz, state text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path TO ''
AS '
  SELECT d.kind, d.subject, coalesce(d.slack_payload->>''text'', ''''), d.built_at, d.expires_at,
         CASE WHEN d.slack_status = ''awaiting'' AND d.expires_at <= now() THEN ''expired''
              ELSE d.slack_status END
    FROM public.digest_pending d
   WHERE d.slack_token_hash = encode(sha256(convert_to(coalesce(p_token, ''''), ''UTF8'')), ''hex'')
';

CREATE OR REPLACE FUNCTION public.digest_slack_approve(p_token text)
RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path TO ''
AS '
  WITH t AS (
    SELECT encode(sha256(convert_to(coalesce(p_token, ''''), ''UTF8'')), ''hex'') AS h
  ), upd AS (
    UPDATE public.digest_pending d
       SET slack_status = ''approved'', slack_approved_at = now()
      FROM t
     WHERE d.slack_token_hash = t.h
       AND d.slack_status = ''awaiting''
       AND d.expires_at > now()
    RETURNING d.id
  )
  SELECT CASE
           WHEN EXISTS (SELECT 1 FROM upd) THEN ''approved''
           ELSE coalesce((SELECT CASE WHEN d.slack_status = ''awaiting'' THEN ''expired''
                                      WHEN d.slack_status = ''approved'' THEN ''already approved''
                                      WHEN d.slack_status = ''posting'' THEN ''already approved''
                                      ELSE d.slack_status END
                            FROM public.digest_pending d, t
                           WHERE d.slack_token_hash = t.h), ''unknown'')
         END
';

REVOKE ALL ON FUNCTION public.digest_slack_preview(text) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.digest_slack_approve(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.digest_slack_preview(text) TO anon, authenticated;

GRANT EXECUTE ON FUNCTION public.digest_slack_approve(text) TO anon, authenticated;
