-- 20261109a_site_name_and_ghosts_retired.sql
--
-- KB 12 job 4 step 5, plan v4.1 part B (built 2026-11-09). THE OTHER NAME'S OLD DEEP-SCAN ROWS,
-- PRODEX'S FALSE www DNS ROWS, AND THE THREE WILDCARD GHOSTS.
--
-- Howie, 2026-11-08 07:44: "when I click on the www domain, I want to see the www domain ... I
-- don't want to be thrown over to the Apex." Plan v4.1 (reviewed four rounds, Kimi K3.1 Pro) puts
-- it in three pushes, this the last: push-423 (scanner: a retired name is never scanned, and
-- discovery never makes a wildcard-only www name live) and push-422 (portal: every name opens its
-- own page) landed first. Part B of the plan is this one file, both databases:
--
--   B1  20261104b's rule (a), EXACTLY as reviewed on 2026-11-04 (that file was approved but never
--       shipped; its rows are this file's rows): on the name that is NOT its site's face (verdict
--       'same_site', face set), the rows only a deep scan of that name writes (commandsentry_heavy,
--       commandsentry_medium, httpx; never testssl, manual_named, sslyze or the quick scan's own),
--       last seen before the face was set, once the face has a COMPLETE deep scan and the other
--       name a COMPLETE quick scan, both after the face was set.
--   B2  20261104b's rule (b), exactly as reviewed: "DNS missing SPF record" / "DNS missing DMARC
--       record" on a same_site www name whose apex_domain 20261104a filled (www.prodexlabs.com),
--       last seen before the fix, once a complete quick scan of that name ran after it.
--   B1 and B2 close as closed_reclassified, tagged 'job4-name-retired': push-404's reopen rule
--   (run_light.py and run_medium.py UPSERT_FINDING_SQL; heavy reuses the latter) reopens exactly
--   these rows as 'detected' when a scan finds them again. 20261104b's own reasons, audit action
--   and kind names are kept; only its migration and batch names are this file's.
--   B3  The three names only the unimacgraphics.com zone's wildcard DNS answers:
--       www.firewall., www.portal. and www.zoetislabs.unimacgraphics.com. They came in from
--       discovery on 2026-10-23 as live because *.unimacgraphics.com answers any name, on
--       Pressable's shared host (199.16.172.68, 199.16.173.113), the same host that serves
--       unimacgraphics.com; their plain names live elsewhere. They are not websites. Each is
--       retired (discovery_status 'retired', 20261026a's mechanism: audit first, then the
--       update) ONLY while site_members' last reading of it still shows exactly that (the zone
--       answers a made-up name, and the www name's addresses are exactly the made-up name's), and
--       its open rows close as closed_reclassified tagged 'job4-ghost-retired' (the host they
--       describe is unimacgraphics.com's own). Nothing reopens them: a retired name is never
--       scanned (push-423's gate), and discovery never lifts a retired row (its upsert only
--       promotes ct_ghost, unverified and dns_only). The portal's scope.ts drops a retired name.
--       On Prodex there are no such names: B3 matches nothing there.
--
-- AT BUILD TIME (2026-11-09 07:30 ET, SELECT only):
--   Command  B1: 39 rows, INFO and LOW (www.commandcompanies.com 13, www.commandmarketing-
--            innovations.com 10, www.unimacgraphics.com 11, commandcommcentral.com 5); the 11 on
--            www.unimacgraphics.com wait for unimacgraphics.com's first deep scan after the face
--            was set (its last: 2026-10-25). B2: none. B3: 3 names, 45 rows (15 each: INFO, LOW,
--            one MODERATE each), none HIGH.
--   Prodex   B1: 21 rows on prodexlabs.com, INFO. B2: 2 rows on www.prodexlabs.com, MODERATE.
--            B3: none.
--
-- GUARDS (plain SELECTs that divide by zero, 20261013b's pattern; a violated guard aborts the
-- transaction, the ledger row is not written):
--   1  B1 + B2 bounded: no more than 50 rows match (Command 39, Prodex 23 at build time).
--   2  B3 bounded: no more than 50 rows match (Command 45, Prodex 0).
--   3  nothing serious is closed: no matching row in B1, B2 or B3 is CRITICAL, HIGH or
--      MODERATE-HIGH.
--   4  each tag is this file's alone: no row carries 'job4-name-retired' or 'job4-ghost-retired'
--      except rows this file closed (with their audit row).
--   No guard on the timing (20261104b's reasoning, code review C2, 2026-11-04): a guard that stops
--   the apply would leave the file on main unapplied, and the ledger gate
--   (check_migrations_applied.py) pauses every scan in that repo until it applies, while the deep
--   scan it would wait for is one of those scans. The shipping script pins the timing instead: it
--   refuses to run until Claude's read-back has written its PASS marker (every pair's wait met on
--   both databases), and until both scanner mains carry push-404's reopen rule and push-423's
--   gate. Applied early, B1 simply matches fewer rows, and the rows it missed would stay open.
--
-- Reversible: UPDATE public.findings SET current_status = 'detected', tags = array_remove(tags,
-- <the tag>) WHERE finding_id IN (the audit rows' details ->> 'finding_id' where details ->> 'batch'
-- is '20261109a-site-name-retired' or '20261109a-ghost-retired'), and UPDATE public.assets SET
-- discovery_status = (the audit row's before_state ->> 'discovery_status') for the three names
-- ('retire_wildcard_ghost' rows). No schema change. Byte-identical in both repos. Idempotent: a
-- second apply matches nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: KB 12 job 4 step 5 plan v4.1 part B (Howie 2026-11-08 07:44). Data only. B1 and B2 are 20261104b's rules (a) and (b) exactly as reviewed on 2026-11-04 (never shipped): the other name's old deep-scan rows (commandsentry_heavy, commandsentry_medium, httpx) once the face has a complete deep scan and the other name a complete quick scan after the face was set, and www.prodexlabs.com's false dns-missing-spf / dns-missing-dmarc rows; closed_reclassified tagged job4-name-retired (push-404 reopens them if re-found). B3 retires www.firewall., www.portal. and www.zoetislabs.unimacgraphics.com while site_members still reads them as wildcard-only, and closes their open rows as closed_reclassified tagged job4-ghost-retired. One audit row each. Guards: B1+B2 at most 50 rows, B3 at most 50, none CRITICAL/HIGH/MODERATE-HIGH, each tag carried only by rows this file closed. Timing pinned by the shipping script (a stopping guard would pause scans through the ledger gate). Splitter-safe (no dollar-quoted blocks).
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on.
BEGIN;

-- ── GUARD 1 · B1 + B2 bounded, and GUARD 3 (part) · nothing serious (one pass over the same rule).
WITH face AS (
  SELECT sm.site_asset_id, sm.member_asset_id, sm.face_asset_id,
         CASE WHEN sm.face_asset_id = sm.member_asset_id THEN sm.site_asset_id ELSE sm.member_asset_id END AS other,
         (sm.evidence -> 'face' ->> 'since')::timestamptz AS face_since
    FROM public.site_members sm
   WHERE sm.verdict = 'same_site'
     AND sm.face_asset_id IS NOT NULL
     AND (sm.evidence -> 'face' ->> 'since') IS NOT NULL
), fixed AS (
  SELECT l.details ->> 'asset_id' AS asset_id, min(l.created_at) AS fixed_at
    FROM public.admin_audit_log l
   WHERE l.action = 'site_member_apex_domain_set'
     AND l.details ->> 'migration' = '20261104a'
   GROUP BY 1
), target AS (
  SELECT f.finding_id, f.severity::text AS severity
    FROM face fc
    JOIN public.findings f ON f.asset_id = fc.other
   WHERE f.source::text IN ('commandsentry_heavy', 'commandsentry_medium', 'httpx')
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_observed_at < fc.face_since
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fc.face_asset_id AND s.intensity::text = 'heavy'
                    AND s.status::text = 'complete' AND s.completed_at > fc.face_since)
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fc.other AND s.intensity::text = 'light'
                    AND s.status::text = 'complete' AND s.completed_at > fc.face_since)
  UNION
  SELECT f.finding_id, f.severity::text
    FROM fixed fx
    JOIN public.site_members sm ON sm.member_asset_id = fx.asset_id AND sm.verdict = 'same_site'
    JOIN public.findings f ON f.asset_id = fx.asset_id
   WHERE f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')
     AND f.source::text = 'commandsentry_light'
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_observed_at < fx.fixed_at
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fx.asset_id AND s.intensity::text = 'light'
                    AND s.status::text = 'complete' AND s.completed_at > fx.fixed_at)
)
SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END) AS guard_b1_b2_bounded,
       1 / (CASE WHEN count(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')) = 0
                 THEN 1 ELSE 0 END) AS guard_b1_b2_nothing_serious
  FROM target;

-- ── GUARD 2 · B3 bounded, and GUARD 3 (part) · nothing serious.
WITH ghost AS (
  SELECT a.asset_id
    FROM public.assets a
    JOIN public.site_members sm ON sm.member_asset_id = a.asset_id
   WHERE a.asset_id IN ('www.firewall.unimacgraphics.com', 'www.portal.unimacgraphics.com',
                        'www.zoetislabs.unimacgraphics.com')
     AND a.discovery_status IS DISTINCT FROM 'retired'
     AND (sm.evidence -> 'last' -> 'readings' -> 'zone' ->> 'wildcard') = 'true'
     AND jsonb_array_length(coalesce(sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs', '[]'::jsonb)) > 0
     AND (sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') @> (sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')
     AND (sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') <@ (sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')
)
SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END) AS guard_b3_bounded,
       1 / (CASE WHEN count(*) FILTER (WHERE f.severity::text IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')) = 0
                 THEN 1 ELSE 0 END) AS guard_b3_nothing_serious
  FROM ghost g
  JOIN public.findings f ON f.asset_id = g.asset_id
 WHERE f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed');

-- ── GUARD 4 · each tag is new: no row carries it before this file runs.
SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_tags_unused
  FROM public.findings f
 WHERE ('job4-name-retired' = ANY (coalesce(f.tags, '{}'::text[]))
        AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                         WHERE l.action = 'site_name_retired_close_reclassified'
                           AND l.details ->> 'finding_id' = f.finding_id))
    OR ('job4-ghost-retired' = ANY (coalesce(f.tags, '{}'::text[]))
        AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                         WHERE l.action = 'ghost_retired_close_reclassified'
                           AND l.details ->> 'finding_id' = f.finding_id));

-- ── B1 + B2 · one statement: choose, close and tag, then audit every closed row (20261104b's).
WITH face AS (
  SELECT sm.site_asset_id, sm.member_asset_id, sm.face_asset_id,
         CASE WHEN sm.face_asset_id = sm.member_asset_id THEN sm.site_asset_id ELSE sm.member_asset_id END AS other,
         (sm.evidence -> 'face' ->> 'since')::timestamptz AS face_since
    FROM public.site_members sm
   WHERE sm.verdict = 'same_site'
     AND sm.face_asset_id IS NOT NULL
     AND (sm.evidence -> 'face' ->> 'since') IS NOT NULL
), fixed AS (
  SELECT l.details ->> 'asset_id' AS asset_id, min(l.created_at) AS fixed_at
    FROM public.admin_audit_log l
   WHERE l.action = 'site_member_apex_domain_set'
     AND l.details ->> 'migration' = '20261104a'
   GROUP BY 1
), target AS (
  SELECT f.finding_id, f.asset_id, f.source::text AS source, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at,
         'a_deep_rows_of_the_other_name'::text AS kind, fc.face_asset_id AS face, fc.face_since AS since
    FROM face fc
    JOIN public.findings f ON f.asset_id = fc.other
   WHERE f.source::text IN ('commandsentry_heavy', 'commandsentry_medium', 'httpx')
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_observed_at < fc.face_since
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fc.face_asset_id AND s.intensity::text = 'heavy'
                    AND s.status::text = 'complete' AND s.completed_at > fc.face_since)
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fc.other AND s.intensity::text = 'light'
                    AND s.status::text = 'complete' AND s.completed_at > fc.face_since)
  UNION
  SELECT f.finding_id, f.asset_id, f.source::text, f.title, f.severity::text,
         f.current_status::text, f.last_observed_at,
         'b_false_dns_rows_of_a_www_name'::text, sm.site_asset_id, fx.fixed_at
    FROM fixed fx
    JOIN public.site_members sm ON sm.member_asset_id = fx.asset_id AND sm.verdict = 'same_site'
    JOIN public.findings f ON f.asset_id = fx.asset_id
   WHERE f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')
     AND f.source::text = 'commandsentry_light'
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_observed_at < fx.fixed_at
     AND EXISTS (SELECT 1 FROM public.scan_run s
                  WHERE s.asset_id = fx.asset_id AND s.intensity::text = 'light'
                    AND s.status::text = 'complete' AND s.completed_at > fx.fixed_at)
),
closed AS (
  UPDATE public.findings f
     SET current_status = 'closed_reclassified',
         tags           = array_append(coalesce(f.tags, '{}'::text[]), 'job4-name-retired'),
         updated_at     = now()
    FROM target t
   WHERE f.finding_id = t.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'site_name_retired_close_reclassified',
       jsonb_build_object('current_status', t.old_status, 'severity', t.severity,
                          'last_observed_at', t.last_observed_at),
       jsonb_build_object('current_status', 'closed_reclassified', 'tag', 'job4-name-retired'),
       jsonb_build_object(
         'finding_id', t.finding_id,
         'asset_id',   t.asset_id,
         'source',     t.source,
         'title',      t.title,
         'kind',       t.kind,
         'site',       t.face,
         'since',      t.since,
         'reason',     CASE t.kind
                         WHEN 'a_deep_rows_of_the_other_name' THEN 'This name is no longer deep-scanned: its site is shown and deep-scanned under ' || t.face || ' (the name the browser lands on). A later scan that finds this again reopens it.'
                         ELSE 'Read as an apex because its apex_domain was NULL (fixed by 20261104a); a fixed quick scan has not found it since. The domain''s email records are checked on ' || t.face || '.'
                       END,
         'migration',  '20261109a',
         'batch',      '20261109a-site-name-retired',
         'ruling',     'Howie 2026-11-04 D6 and 2026-11-08 07:44; KB 12 job 4 step 5 plan v4.1 B1/B2 (20261104b rules a and b as reviewed)')
  FROM target t
  JOIN closed c ON c.finding_id = t.finding_id;

-- ── B3 (1 of 3) · audit each ghost before it changes, so before_state is the real one (20261026a).
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'retire_wildcard_ghost',
       jsonb_build_object('discovery_status', a.discovery_status),
       jsonb_build_object('discovery_status', 'retired'),
       jsonb_build_object(
         'asset_id',  a.asset_id,
         'reading',   sm.evidence -> 'last' -> 'readings',
         'reason',    'Only the zone''s wildcard DNS answers this name: a made-up name next to it resolves to exactly its addresses (unimacgraphics.com''s own shared host), and its plain name lives elsewhere. It is not a website. Retired: Sentry no longer scans it.',
         'migration', '20261109a',
         'batch',     '20261109a-ghost-retired',
         'ruling',    'Howie 2026-11-08 07:44; KB 12 job 4 step 5 plan v4.1 B3')
  FROM public.assets a
  JOIN public.site_members sm ON sm.member_asset_id = a.asset_id
 WHERE a.asset_id IN ('www.firewall.unimacgraphics.com', 'www.portal.unimacgraphics.com',
                      'www.zoetislabs.unimacgraphics.com')
   AND a.discovery_status IS DISTINCT FROM 'retired'
   AND (sm.evidence -> 'last' -> 'readings' -> 'zone' ->> 'wildcard') = 'true'
   AND jsonb_array_length(coalesce(sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs', '[]'::jsonb)) > 0
   AND (sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') @> (sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs')
   AND (sm.evidence -> 'last' -> 'readings' -> 'www' -> 'addrs') <@ (sm.evidence -> 'last' -> 'readings' -> 'zone' -> 'addrs');

-- ── B3 (2 of 3) · retire exactly the names just audited by this file.
UPDATE public.assets a
   SET discovery_status = 'retired', last_transition_at = now()
 WHERE a.discovery_status IS DISTINCT FROM 'retired'
   AND EXISTS (SELECT 1 FROM public.admin_audit_log l
                WHERE l.action = 'retire_wildcard_ghost'
                  AND l.details ->> 'batch' = '20261109a-ghost-retired'
                  AND l.details ->> 'asset_id' = a.asset_id);

-- ── B3 (3 of 3) · close the retired ghosts' open rows, tag and audit each.
WITH target AS (
  SELECT f.finding_id, f.asset_id, f.source::text AS source, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at
    FROM public.findings f
    JOIN public.assets a ON a.asset_id = f.asset_id AND a.discovery_status = 'retired'
   WHERE f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND EXISTS (SELECT 1 FROM public.admin_audit_log l
                  WHERE l.action = 'retire_wildcard_ghost'
                    AND l.details ->> 'batch' = '20261109a-ghost-retired'
                    AND l.details ->> 'asset_id' = f.asset_id)
),
closed AS (
  UPDATE public.findings f
     SET current_status = 'closed_reclassified',
         tags           = array_append(coalesce(f.tags, '{}'::text[]), 'job4-ghost-retired'),
         updated_at     = now()
    FROM target t
   WHERE f.finding_id = t.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'ghost_retired_close_reclassified',
       jsonb_build_object('current_status', t.old_status, 'severity', t.severity,
                          'last_observed_at', t.last_observed_at),
       jsonb_build_object('current_status', 'closed_reclassified', 'tag', 'job4-ghost-retired'),
       jsonb_build_object(
         'finding_id', t.finding_id,
         'asset_id',   t.asset_id,
         'source',     t.source,
         'title',      t.title,
         'reason',     'This name answers only through the zone''s wildcard DNS and is retired. The host this row describes is unimacgraphics.com''s own, where Sentry keeps checking it.',
         'migration',  '20261109a',
         'batch',      '20261109a-ghost-retired',
         'ruling',     'Howie 2026-11-08 07:44; KB 12 job 4 step 5 plan v4.1 B3')
  FROM target t
  JOIN closed c ON c.finding_id = t.finding_id;

COMMIT;
