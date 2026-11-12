-- 20261112a_pulse_uat_attack_test_on.sql
--
-- KB 12 (2026-11-12): THE ATTACK TEST IS SWITCHED ON FOR pulse.uat.prodexlabs.com.
--
-- Howie, 2026-11-12 11:31, on that site's page saying the test was "not approved": "Why in the
-- world are there any circumstances where there's an asset that we see on the site, yet it's
-- not authorized to scan?" The two per-site switches (assets.active_probe_authorized, read by the
-- deep scan's firewall test; assets.enforcement_probe_authorized, read by the light scan's
-- single test attack and by the portal's wording) default to false, and nobody had been asked
-- about this site since it was added on 2026-11-11.
-- The switch is the one place a person confirms the server behind a name is ours (D-064:
-- link.prodexlabs.com points at SMTP2GO, and the importer marks every name "owned"). So Howie
-- asked for a look first: 11:50 "do some deep digging in terms of NS lookups and digs to find
-- out where those sites are". What it found ([[2026-11-12 1151 - reading - where three untested
-- Prodex names point]]): pulse.uat.prodexlabs.com is a plain A record in ProDex's own zone to
-- 136.69.87.98, the SAME address as uat.prodexlabs.com, which has both switches on, has been
-- tested, and is on ProDex's CISA address list (20261110b). Howie, 11:55, to switching it on:
-- "Yes".
-- NOT in this file, on purpose: ph-test.prodexlabs.com (Azure Government; whether the servers
-- are ProDex's or Project Hosts' is not something a lookup can say) and demo-tour.prodexlabs.com
-- (the name no longer exists).
--
-- WHAT THIS DOES. One statement. On the row pulse.uat.prodexlabs.com, both switches become
-- true, and one admin_audit_log row ('change_asset_probe_authorization') records the old and
-- new values, the reason, the evidence and the approval. It happens only while ALL of these
-- hold at apply time; otherwise nothing changes and no audit row is written:
--   - the asset exists, is owned and confirmed_live, and at least one switch is still off;
--   - uat.prodexlabs.com is an owned asset with BOTH switches on (the site this one shares an
--     address with; if that site were ever switched off, this one must not go on by itself).
-- PRODEX ONLY by its own conditions: Command has neither asset, so nothing matches there.
-- Nothing is sent to any site by this file. The site's next deep scan runs the firewall test
-- (three requests that look like attacks, plus an ordinary one) and its next light scan the
-- single test attack, exactly as they already run on uat.prodexlabs.com.
--
-- GUARD (a plain SELECT that divides by zero, 20261013b's pattern; a violated guard aborts the
-- transaction and the ledger row is not written): the audit rows of this action for this asset
-- that carry this file's batch are none or one. Two would mean the change was recorded twice.
--
-- No schema change, no view, no function, nothing deleted. Byte-identical in both repos.
-- Idempotent: a second apply finds both switches on and matches nothing.
-- Reversal: UPDATE public.assets SET active_probe_authorized = false,
-- enforcement_probe_authorized = false WHERE asset_id = 'pulse.uat.prodexlabs.com';
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 200
-- notes: KB 12 2026-11-12 (Howie 11:31, 11:50, go 11:55 "Yes"). Data only, one asset. On Prodex, pulse.uat.prodexlabs.com gets active_probe_authorized and enforcement_probe_authorized = true, only while it is owned and confirmed_live and uat.prodexlabs.com (same address) is owned with both on; one admin_audit_log row. Command: nothing matches. No schema change. Idempotent. Reversal in the header.
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on.
BEGIN;

WITH changed AS (
  UPDATE public.assets a
     SET active_probe_authorized = true,
         enforcement_probe_authorized = true
    FROM public.assets old
   WHERE a.asset_id = 'pulse.uat.prodexlabs.com'
     AND old.asset_id = a.asset_id
     AND a.ownership = 'owned'
     AND a.discovery_status = 'confirmed_live'
     AND NOT (a.active_probe_authorized AND a.enforcement_probe_authorized)
     AND EXISTS (SELECT 1 FROM public.assets u
                  WHERE u.asset_id = 'uat.prodexlabs.com'
                    AND u.ownership = 'owned'
                    AND u.active_probe_authorized
                    AND u.enforcement_probe_authorized)
  RETURNING a.asset_id,
            old.active_probe_authorized AS old_active,
            old.enforcement_probe_authorized AS old_enforcement
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'change_asset_probe_authorization',
       jsonb_build_object('active_probe_authorized', c.old_active,
                          'enforcement_probe_authorized', c.old_enforcement),
       jsonb_build_object('active_probe_authorized', true,
                          'enforcement_probe_authorized', true),
       jsonb_build_object(
         'asset_id',    c.asset_id,
         'batch',       '20261112a-pulse-uat-attack-test-on',
         'reason',      'The attack test is switched on for this site. It was off only because new sites start that way and nobody had been asked.',
         'evidence',    'Public DNS, read 2026-11-12: a plain A record in the prodexlabs.com zone to 136.69.87.98, the same address as uat.prodexlabs.com, which has both switches on and is on the CISA address list.',
         'approved_by', 'howie@prodexlabs.com (chat approval 2026-11-12 11:55 ET)',
         'changed_by',  'migration 20261112a (built by Claude)',
         'undo',        'Set active_probe_authorized and enforcement_probe_authorized back to false on this asset.')
  FROM changed c;

-- ── GUARD · the change is recorded at most once.
SELECT 1 / (CASE WHEN count(*) <= 1 THEN 1 ELSE 0 END) AS guard_recorded_at_most_once
  FROM public.admin_audit_log
 WHERE action = 'change_asset_probe_authorization'
   AND details ->> 'batch' = '20261112a-pulse-uat-attack-test-on';

COMMIT;
