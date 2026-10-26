-- 20261026b_reachability_fast_reads.sql
--
-- KB 12 job 3t (2026-10-26), hotfix to 20261026a. THE PORTAL'S DASHBOARD READ OF
-- v_asset_reachability TIMED OUT, so the dashboards showed no "Not responding" row or chip.
--
-- Found on the live check after push-345 (2026-10-26, about 16:30 UTC). Netlify's function log, on
-- dashboard loads on both portals, live and preview: "v_asset_reachability read failed: canceling
-- statement due to statement timeout". The host page (one asset) read fine. Portal users
-- (authenticated) run with an 8 s statement_timeout; the page failed soft, as built.
--
-- Why (EXPLAIN as a portal user, read-only, Command, 2026-10-26):
--   * 20261026a's verdict policy, USING (public.is_viewer_or_higher()), runs that function once
--     for every verdict row. It is SECURITY DEFINER with its own search_path, so PostgreSQL cannot
--     fold it into the query.
--   * with the policy on assets in the plan, the planner guesses ONE owned host, picks nested
--     loops, and reads the ~20,000 checks again for every host: millions of policy calls in one
--     dashboard read.
--   The database owner (the writer, the daily email, the SQL editor) bypasses RLS, so none of them
--   saw it, and neither did the PostgreSQL 16 proof, which modelled the function as a cheap one.
--
-- What this does (only 3t's own objects; the same rule, the same rows, the same columns):
--   1. The verdict policy asks its question once per query, not once per row:
--      USING ((select public.is_viewer_or_higher())), Supabase's documented form (an InitPlan).
--      The same users see the same rows; anon and a signed-in user without a role still see none.
--   2. The view's three CTEs are AS MATERIALIZED, so each is computed once per read whatever the
--      planner guesses. Every other byte of the view, its grants and its revokes is 20261026a's.
--      (CREATE OR REPLACE restates security_invoker, which it would otherwise reset.)
--
-- Proven on PostgreSQL 16 at production's shape (production's own is_viewer_or_higher() and
-- auth.uid(), 20,000 checks over 500 hosts, 20261026a then this): the dashboard read as a viewer
-- went from 52.9 s to 29 ms; every column of every row is the same as under 20261026a, for the
-- owner and for a viewer; a user without a role sees nothing. Re-applying changes nothing.
-- Byte-identical in both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 300
-- notes: Job 3t hotfix to 20261026a (the portal's dashboard read of v_asset_reachability hit the 8 s statement timeout). The asset_liveness_verdict SELECT policy for authenticated now reads USING ((select public.is_viewer_or_higher())), evaluated once per query (same rule). The view's three CTEs are AS MATERIALIZED; every other byte of the view, its grants and revokes is 20261026a's, security_invoker restated. No data changes. No dollar-quoting. Byte-identical in both repos.
-- END-META

-- ── 1. the verdict policy: one check per query, not one per row ───────────────
DROP POLICY IF EXISTS asset_liveness_verdict_role_select ON public.asset_liveness_verdict;
CREATE POLICY asset_liveness_verdict_role_select ON public.asset_liveness_verdict
  FOR SELECT TO authenticated
  USING ((select public.is_viewer_or_higher()));

-- ── 2. the view: each CTE computed once per read (otherwise 20261026a's, byte for byte) ──
CREATE OR REPLACE VIEW public.v_asset_reachability
WITH (security_invoker = true) AS
WITH answered AS MATERIALIZED (
  SELECT v.asset_id,
         max(v.probed_at) FILTER (WHERE v.any_port_responded) AS last_answer_at,
         max(v.probed_at)                                     AS last_check_at
    FROM public.asset_liveness_verdict v
   GROUP BY v.asset_id
), newest AS MATERIALIZED (
  SELECT DISTINCT ON (v.asset_id) v.asset_id, v.per_port_results
    FROM public.asset_liveness_verdict v
   ORDER BY v.asset_id, v.probed_at DESC
), fleet AS MATERIALIZED (
  SELECT max(v.probed_at) AS newest_check
    FROM public.asset_liveness_verdict v
)
SELECT a.asset_id,
       a.discovery_status,
       an.last_answer_at,
       an.last_check_at,
       coalesce(f.newest_check > now() - interval '12 hours', false) AS checks_fresh,
       a.dark_hold_reason AS held_reason,
       coalesce(a.discovery_status = 'confirmed_live'
                AND a.dark_hold_reason IS NULL
                AND f.newest_check > now() - interval '12 hours'
                AND an.last_check_at IS NOT NULL
                AND (an.last_answer_at IS NULL OR an.last_answer_at < now() - interval '24 hours'),
                false) AS not_responding,
       CASE WHEN nw.per_port_results ->> '_dns' = 'nxdomain' THEN 'name_gone'
            WHEN an.last_answer_at IS NULL THEN 'never_answered'
            ELSE 'no_answer'
       END AS reason,
       a.fade_detected_at AS notice_since,
       CASE WHEN a.fade_detected_at IS NULL THEN NULL
            ELSE greatest(a.fade_detected_at, coalesce(an.last_answer_at, a.fade_detected_at))
                 + make_interval(days => greatest(coalesce(a.dark_patience_override_days, 7), 7))
       END AS leaves_on,
       a.went_dark_at AS left_on,
       a.dark_reason  AS left_reason
  FROM public.assets a
  LEFT JOIN answered an ON an.asset_id = a.asset_id
  LEFT JOIN newest   nw ON nw.asset_id = a.asset_id
 CROSS JOIN fleet f
 WHERE coalesce(a.ownership, 'unknown') = 'owned';

GRANT SELECT ON public.v_asset_reachability TO authenticated;
REVOKE ALL ON public.v_asset_reachability FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_asset_reachability FROM authenticated;
