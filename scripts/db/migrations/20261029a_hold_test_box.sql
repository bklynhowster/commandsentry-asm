-- 20261029a_hold_test_box.sql
--
-- KB 12 job 3u (2026-10-29). THE TEST BOX ON HOLD: IT BLOCKS SENTRY; IT IS NOT DOWN.
--
-- Howie, 2026-10-29 15:14: "you can definitely mark it as blocked by our scanner". 15:31: "before
-- we send any communications to Command, we'll verify it from the office tomorrow."
--
-- test.commandcommcentral.com and its address 52.119.65.6 have answered no Sentry check since
-- 2026-10-27 13:13 UTC: not the six-hourly check from GitHub's address (9 silent since), not the
-- scanner's Mullvad exit (12 silent), not 8 more Mullvad exits in 8 cities (push-372, run
-- 40937026885, 2026-10-29). Howie reached ports 80/443/8080 by hand the same day, so the box is up
-- and drops Sentry's addresses. Both rows read "not responding" and are due to leave the portal on
-- 2026-11-04.
--
-- What this does: sets assets.dark_hold_reason (job 3t's hold, column from 20261026a) on those two
-- rows. A held host is kept off the not-responding banner, the chip and the daily line, and the
-- went-dark writer never demotes it. Nothing is said to Command (Howie 15:31). Cleared when Command
-- lets Sentry through, or by job 3u. One admin_audit_log row per host, once. Neither host exists
-- on Prodex: there it changes nothing. Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 50
-- notes: Job 3u (Howie 2026-10-29 15:14, 15:31). Data only: assets.dark_hold_reason set on test.commandcommcentral.com and 52.119.65.6 where it is NULL (they block Sentry's addresses since 2026-10-27; not down). Audited once per host (admin_audit_log 'dark_rule_hold', migration 20261029a). No schema change. No dollar-quoting. A no-op on Prodex. Byte-identical in both repos.
-- END-META

UPDATE public.assets
   SET dark_hold_reason = 'Held by Howie (2026-10-29, job 3u): blocks Sentry, not down. No Sentry check has had an answer since 2026-10-27 13:13 UTC (GitHub''s address, the scanner''s Mullvad exit, 8 more Mullvad exits on 10-29), while Howie reached 80/443/8080 by hand on 10-29. Cleared when Command lets Sentry through, or by job 3u.'
 WHERE asset_id IN ('test.commandcommcentral.com', '52.119.65.6')
   AND dark_hold_reason IS NULL;

INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'dark_rule_hold',
       jsonb_build_object('dark_hold_reason', NULL),
       jsonb_build_object('dark_hold_reason', a.dark_hold_reason),
       jsonb_build_object('asset_id', a.asset_id, 'migration', '20261029a', 'ruling', 'Howie 2026-10-29 15:14')
  FROM public.assets a
 WHERE a.asset_id IN ('test.commandcommcentral.com', '52.119.65.6')
   AND a.dark_hold_reason LIKE 'Held by Howie (2026-10-29, job 3u):%'
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'dark_rule_hold'
                      AND l.details ->> 'asset_id' = a.asset_id
                      AND l.details ->> 'migration' = '20261029a');
