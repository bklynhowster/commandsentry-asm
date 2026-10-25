-- 20261025a_site_members.sql
--
-- KB 12 job 4 (2026-10-25). ONE SITE, NOT TWO — the evidence table (migration A of two).
--
-- Howie, 2026-10-24 21:44: "it's the same damn box it's the same site. It's the same everything
-- this has to be fixed as well." Ruled 2026-10-25 08:46 (D1, "Yes"): a www name and its plain name
-- are one site only on evidence seen on both names, never because of what the names look like.
--
-- One row per in-scope pair www.X / X, written by scripts/db/site_members.py from the discovery
-- job every 6 hours: the stored verdict ('same_site' / 'separate', NULL until a first definite
-- reading), the last run's result (which may be 'unknown': a failed check never changes the
-- verdict), how many runs in a row have disagreed with it (two flip it), and the evidence (both
-- names' addresses, certificate fingerprints, HTTP answers and page signatures, the zone's
-- wildcard test, the readings behind the verdict, and every flip with both runs' readings).
--
-- NOTHING READS THIS TABLE YET (plan v3, Design step 0; checker's M1). Migration B (v_site_of and
-- v_fleet_open_reps re-pointed) and push B come only after the rows are read back. Until then
-- every reader keeps today's rules, so no site un-merges.
--
-- Permissions (checker's M2), the scan_run pattern: RLS on; authenticated users with a role read
-- (the portal will read it in push B); anon gets nothing; nobody but the database owner writes
-- (the scanner connects as the owner, SUPABASE_DSN, as for digest_told).
-- Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 500
-- notes: Job 4 migration A (Howie 2026-10-25 08:46, D1 "Yes"). New table public.site_members (member_asset_id PK, site_asset_id, verdict, last_result, contrary_runs, evidence, checked_at, since), RLS enabled, one SELECT policy for authenticated users with a role (as scan_run_select), everything revoked from anon and authenticated, then SELECT granted to authenticated. Nothing reads it yet. No other schema; no data. Byte-identical in both repos.
-- END-META

CREATE TABLE IF NOT EXISTS public.site_members (
  member_asset_id  text        PRIMARY KEY,
  site_asset_id    text        NOT NULL,
  verdict          text        NULL CHECK (verdict IN ('same_site', 'separate')),
  last_result      text        NOT NULL CHECK (last_result IN ('same_site', 'separate', 'unknown')),
  contrary_runs    integer     NOT NULL DEFAULT 0 CHECK (contrary_runs >= 0),
  evidence         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  checked_at       timestamptz NOT NULL DEFAULT now(),
  since            timestamptz NULL,
  CONSTRAINT site_members_www_of_site CHECK (member_asset_id = 'www.' || site_asset_id)
);

COMMENT ON TABLE public.site_members IS
  'Job 4 (2026-10-25): whether www.X and X are one site, from evidence seen on both names every '
  'discovery run. Written only by scripts/db/site_members.py. Read by nothing until migration B.';

ALTER TABLE public.site_members ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS site_members_select ON public.site_members;

CREATE POLICY site_members_select ON public.site_members
  FOR SELECT
  TO authenticated
  USING (public.has_role('admin') OR public.has_role('asset_owner') OR public.has_role('viewer'));

REVOKE ALL ON public.site_members FROM anon, authenticated;

GRANT SELECT ON public.site_members TO authenticated;
