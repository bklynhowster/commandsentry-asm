-- 20261030b_release_test_box_hold.sql
--
-- KB 12 job 3u (2026-10-30). THE TEST BOX'S HOLD COMES OFF: IT IS NOT SERVING; SENTRY MARKS IT DOWN.
--
-- Howie, 2026-10-30 15:18: "Remove the hold. At this point, again, we are an outside entity that
-- knows no special information from our perspective ... The box is no longer serving content. We
-- mark it as down. Take the hold off."
--
-- Why the hold (20261029a) was wrong: it rested on ports 80/443/8080 answering through ExpressVPN.
-- Checked by hand on 2026-10-30 from the office: the name now points at 52.119.65.6, not the
-- 24.38.70.8 where Sentry saw the site serving through 2026-10-26 23:40 UTC; both addresses are
-- silent to the office; through ExpressVPN both take the connection and serve nothing (an empty
-- reply on 80, the TLS hello dropped on 443), while an address where nothing exists stays silent.
-- The "open" ports were something in front answering, not the site. Sentry's "not responding" was
-- right.
--
-- What this does: clears assets.dark_hold_reason on test.commandcommcentral.com and 52.119.65.6,
-- only where it is the 2026-10-29 job 3u hold (pm.unimacgraphics.com's job 3t hold is not this
-- one and is untouched). One admin_audit_log row per host first, once, holding the reason it
-- removes. From then on the reachability view counts both as not responding again and the went-
-- dark writer treats them like any other host. Neither host exists on Prodex: there it changes
-- nothing. Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 50
-- notes: Job 3u (Howie 2026-10-30 15:18). Data only: assets.dark_hold_reason cleared on test.commandcommcentral.com and 52.119.65.6 where it is the 2026-10-29 job 3u hold (set by 20261029a); the box is not serving, so Sentry marks it down. Audited once per host first (admin_audit_log 'dark_rule_hold_released', migration 20261030b). No schema change. No dollar-quoting. A no-op on Prodex. Byte-identical in both repos.
-- END-META

INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'dark_rule_hold_released',
       jsonb_build_object('dark_hold_reason', a.dark_hold_reason),
       jsonb_build_object('dark_hold_reason', NULL),
       jsonb_build_object('asset_id', a.asset_id, 'migration', '20261030b', 'ruling', 'Howie 2026-10-30 15:18')
  FROM public.assets a
 WHERE a.asset_id IN ('test.commandcommcentral.com', '52.119.65.6')
   AND a.dark_hold_reason LIKE 'Held by Howie (2026-10-29, job 3u):%'
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'dark_rule_hold_released'
                      AND l.details ->> 'asset_id' = a.asset_id
                      AND l.details ->> 'migration' = '20261030b');

UPDATE public.assets
   SET dark_hold_reason = NULL
 WHERE asset_id IN ('test.commandcommcentral.com', '52.119.65.6')
   AND dark_hold_reason LIKE 'Held by Howie (2026-10-29, job 3u):%';
