-- 20261026a_reachability.sql
--
-- KB 12 job 3t (2026-10-26). "NOT RESPONDING", THEN IT LEAVES THE PORTAL — the one source.
--
-- Howie, 2026-10-26 07:00: "initially we let people know that it's not responding and then after a
-- certain amount of time we say that it's going off-line and out of the portal". Ruled 07:16
-- (D1-D7) and 08:39 (D8-D10); plan v1.2, reviewed by Qwen3.8 Max (MF1-MF10, all taken).
--
-- What this does:
--   1. NEW view v_asset_reachability: one row per OWNED asset, read by the portal (banner, chip,
--      "Left the portal"), the daily email and the went-dark writer. Its clock is the newest
--      liveness answer from any route (asset_liveness_verdict.any_port_responded) — NOT
--      assets.last_alive_at, which is the scan/import clock and goes stale on a host that answers
--      every check but has not been scanned lately (plan claim 4; Qwen MF1).
--        not_responding = confirmed_live, not held, the instance's checks are fresh (newest verdict
--                         under 12 h old), the host has been checked, and no answer for 24 h (D1).
--        reason         = name_gone (newest check: the name does not resolve) | never_answered |
--                         no_answer. A refused connection is an answer (Howie 2026-10-25 10:00: "a
--                         host with any port that answers is UP"), so "refused" never shows here.
--        notice_since   = assets.fade_detected_at, the moment the notice started (stamped by the
--                         writer from push S1; NULL until then).
--        leaves_on      = greatest(notice_since, last answer) + 7 days (D2), NULL while
--                         unstamped. A per-host dark_patience_override_days can only LENGTHEN
--                         the 7, never shorten it: D2 is "never sooner than 7 days after the
--                         notice" (Qwen code review MF1).
--        left_on / left_reason = went_dark_at / dark_reason, for a host that has left.
--   2. A read policy on asset_liveness_verdict for signed-in portal users with a role (the same
--      rule as assets). RLS was on with NO policy, so the portal could read none of it (Qwen MF6).
--   3. assets.dark_hold_reason: a host on hold is kept off the banner, the chip, the daily line and
--      the writer. Set here for pm.unimacgraphics.com (D7, Howie 07:16 "Yes, I agree"); job 4c
--      clears it. One home, read by every reader (Qwen's D7 minor).
--   4. Retires unreachable-detector-test.invalid, the July test host (D6, Howie 07:16: "I don't
--      know what that is. Get rid of it."). It exists on Command only; a no-op on Prodex.
--   5. Drops asset_dark_debounce_state(): nothing calls it (Qwen claim 3) and its clock was wrong.
-- Each data change writes one admin_audit_log row, once.
--
-- The view runs as the caller (security_invoker), so the verdict and assets RLS apply: the alerter
-- and the writer (database owner) see every row; a portal user with a role sees every owned asset;
-- anon sees nothing. Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 800
-- notes: Job 3t (Howie 2026-10-26 07:16 D1-D7, 08:39 D8-D10). New view public.v_asset_reachability (owned assets; clock = newest liveness answer; not_responding after 24 h; reason; notice_since; leaves_on never sooner than notice + 7 days; left_on), security_invoker, SELECT to authenticated only. SELECT policy on asset_liveness_verdict for authenticated USING is_viewer_or_higher(). New column assets.dark_hold_reason, set for pm.unimacgraphics.com (D7). Retires unreachable-detector-test.invalid (D6). Drops the uncalled asset_dark_debounce_state(text). Two audited data changes, each once. No dollar-quoting. Byte-identical in both repos.
-- END-META

-- ── 1. the hold column (before the view, which reads it) ──────────────────────
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS dark_hold_reason text;

-- ── 2. the view: one source for the portal, the daily and the writer ──────────
CREATE OR REPLACE VIEW public.v_asset_reachability
WITH (security_invoker = true) AS
WITH answered AS (
  SELECT v.asset_id,
         max(v.probed_at) FILTER (WHERE v.any_port_responded) AS last_answer_at,
         max(v.probed_at)                                     AS last_check_at
    FROM public.asset_liveness_verdict v
   GROUP BY v.asset_id
), newest AS (
  SELECT DISTINCT ON (v.asset_id) v.asset_id, v.per_port_results
    FROM public.asset_liveness_verdict v
   ORDER BY v.asset_id, v.probed_at DESC
), fleet AS (
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

-- ── 3. portal users with a role may read the liveness checks (same rule as assets) ──
DROP POLICY IF EXISTS asset_liveness_verdict_role_select ON public.asset_liveness_verdict;
CREATE POLICY asset_liveness_verdict_role_select ON public.asset_liveness_verdict
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

-- ── 4. D7: pm.unimacgraphics.com on hold until job 4c explains it ─────────────
UPDATE public.assets
   SET dark_hold_reason = 'Held by Howie (2026-10-26, job 3t D7): Sentry''s checks get no answer while Howie''s 2026-10-25 08:56 reading did; job 4c explains the difference, then clears this.'
 WHERE asset_id = 'pm.unimacgraphics.com'
   AND dark_hold_reason IS NULL;

INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'dark_rule_hold',
       jsonb_build_object('dark_hold_reason', NULL),
       jsonb_build_object('dark_hold_reason', a.dark_hold_reason),
       jsonb_build_object('asset_id', a.asset_id, 'migration', '20261026a', 'ruling', 'Howie 2026-10-26 07:16, D7')
  FROM public.assets a
 WHERE a.asset_id = 'pm.unimacgraphics.com'
   AND a.dark_hold_reason IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'dark_rule_hold' AND l.details ->> 'asset_id' = a.asset_id);

-- ── 5. D6: retire the July test host (audit first, so before_state is the real one) ──
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'retire_test_host',
       jsonb_build_object('discovery_status', a.discovery_status),
       jsonb_build_object('discovery_status', 'retired'),
       jsonb_build_object('asset_id', a.asset_id, 'migration', '20261026a', 'ruling', 'Howie 2026-10-26 07:16, D6')
  FROM public.assets a
 WHERE a.asset_id = 'unreachable-detector-test.invalid'
   AND a.discovery_status IS DISTINCT FROM 'retired';

UPDATE public.assets
   SET discovery_status = 'retired', last_transition_at = now()
 WHERE asset_id = 'unreachable-detector-test.invalid'
   AND discovery_status IS DISTINCT FROM 'retired';

-- ── 6. the July countdown function: no caller, wrong clock ────────────────────
DROP FUNCTION IF EXISTS public.asset_dark_debounce_state(text);
