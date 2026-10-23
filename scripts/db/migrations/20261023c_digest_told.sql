-- 20261023c_digest_told.sql
--
-- KB 12 job 3s (2026-10-23). SAY IT ONCE, THEN REMIND ON A TIMER — the record of what the
-- digests told.
--
-- Howie, 2026-10-22 19:59-20:02: "us constantly reminding Sean or Kianu or the people over at
-- Unimac or Command might get sick of hearing it" ... "We leave them alone, and after a certain
-- amount of time, we remind them again." Ruled: a full card when a problem is NEW, WORSE or
-- CAME BACK; after that one quiet line in the weekly, and a full reminder on a timer.
--
-- Nothing recorded what the daily or the weekly had told, so the weekly repeated the same
-- cards every Monday. This table is that record, one row per finding behind a full card that
-- was actually sent: when it was first told, when it was last told in full and at what
-- severity, and when a digest last saw it closed (so a return is told again). Written only by
-- scripts/alerter/run_alerter.py after a send succeeds (never by a test send or a dry run);
-- read by the same. The code tolerates the table's absence (everything reads as "new", today's
-- behaviour), so this file goes in first.
--
-- RLS enabled with no policy: anon and authenticated read and write nothing; the alerter
-- connects as the database owner (SUPABASE_DSN), as it does for meta_alerter_runs.
-- Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 500
-- notes: Job 3s (Howie 2026-10-22 20:02 "Agreed": say it once, then remind on a timer). New table public.digest_told (finding_id PK, first_told_at, last_full_at, last_full_severity, last_full_in, reminders, closed_seen_at, updated_at), RLS enabled with no policies, anon/authenticated revoked. No other schema; no data. Byte-identical in both repos.
-- END-META

CREATE TABLE IF NOT EXISTS public.digest_told (
  finding_id          text        PRIMARY KEY,
  first_told_at       timestamptz NOT NULL DEFAULT now(),
  last_full_at        timestamptz NOT NULL DEFAULT now(),
  last_full_severity  text        NOT NULL,
  last_full_in        text        NOT NULL CHECK (last_full_in IN ('daily', 'weekly')),
  reminders           integer     NOT NULL DEFAULT 0,
  closed_seen_at      timestamptz NULL,
  updated_at          timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.digest_told IS
  'Job 3s (2026-10-23): what the daily and weekly digests told, per finding, so a problem is '
  'told once and then reminded on a timer. Written by run_alerter.py after a real send only.';

ALTER TABLE public.digest_told ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.digest_told FROM anon, authenticated;
