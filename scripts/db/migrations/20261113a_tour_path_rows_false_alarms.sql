-- 20261113a_tour_path_rows_false_alarms.sql
--
-- KB 12 (2026-11-13): THE 96 PATH ROWS ONE MISJUDGED SCAN WROTE ON tour.prodexlabs.com ARE
-- CLOSED AS FALSE ALARMS.
--
-- WHY. The deep scan 626f9631 of 2026-11-12 wrote 96 findings on tour.prodexlabs.com that say
-- nothing true about the site: 84 "Accessible path: /x (HTTP 200)" rows, /actuator and /swagger
-- among them and rated MODERATE (the team channel announced both on 2026-11-13 07:08 New York),
-- and 12 "Forbidden endpoint: /x (HTTP 403)" rows. That site answers every address with the
-- same 3,080-byte page. Before the path check (ffuf) runs, the scanner asks for two made-up
-- paths to learn what a site does with a page that is not there. In that scan the two answers
-- differed, because the site's front door was refusing about half of what the scanner's exit
-- sent (straight after a 570-second nikto run from it; the health check one second later got a
-- 403; 12 of the first chunk's 25 answers were refusals and none after the exit changed), and
-- run_medium.detect_ffuf_catchall read a disagreement as "this host tells real pages from fake
-- ones". Every answer was then written as a finding. push-438 fixed that reading: such a scan
-- now skips the path check. It did not touch the rows already written, and nothing else closes
-- them: the open -> remediated close of findings that are not seen again is off (D-056).
--
-- WHY false_positive. The rows claim that /actuator, /swagger and the rest are pages of that
-- site, or pages it protects. Neither was ever true: 84 of them are the one page the site gives
-- to everything, 12 are refusals that followed the scanner's exit, not the address. The same
-- thing was done for the 98 path rows of atlantis-gcp.prodexlabs.com on 2026-09-16. The fact
-- that IS true stays reported by its own open row, "Host returns HTTP 200 to 97 paths
-- uniformly" (tour.prodexlabs.com:medium:ffuf-catchall-status-200), and this file does nothing
-- unless that row is open. Howie, 2026-11-13 11:18 New York, to marking these rows false
-- alarms: "yes...approved".
-- KNOWN COST, stated to Howie: a false_positive row is not reopened by a later scan (the
-- findings upserts keep that status). If one of these 96 addresses ever becomes a real page
-- on that site, the path check will not raise it again under this id.
--
-- WHICH ROWS. A finding of tour.prodexlabs.com, id 'tour.prodexlabs.com:medium:ffuf-found-<word>',
-- FIRST written by scan 626f9631-78bd-4a4c-891b-030caee35f2f, still open (detected, confirmed,
-- open, regressed), and matching what that scan's own ffuf records (scan_run_artifacts) hold
-- for its word:
--   (a) title "Accessible path: /<word> (HTTP 200)" and an answer with status 200 and exactly
--       3080 bytes, the one page; or
--   (b) title "Forbidden endpoint: /<word> (HTTP 403)" and an answer with status 403.
-- And only while BOTH of these hold at apply time (otherwise nothing changes and no audit row
-- is written):
--   - that scan's ffuf records hold at least 80 answers with status 200 and exactly 3080
--     bytes (the scan's own proof that it is one page; 85 at build time);
--   - the summary row named above is open.
-- NOT touched: /health (a real path with its own 8-byte answer, first found in July), the
-- /assets redirect row, the summary row, every row a person already closed, every other
-- finding of that site, every other site. PRODEX ONLY by its own conditions: Command has no
-- such asset and no such scan, so nothing matches there.
--
-- WHAT THIS DOES. One statement: the matching rows get current_status = false_positive and
-- updated_at = now(), and one admin_audit_log row each ('path_rows_close_false_positive') with
-- the old status, the severity, which kind of answer it was, the scan, the reason, the
-- evidence, the approval and the undo. remediated_at stays NULL (nothing was fixed).
-- trg_findings_sync_current_risk recomputes the site's current_risk.
--
-- GUARD (a plain SELECT that divides by zero, 20261013b's pattern; a violated guard aborts the
-- transaction and the ledger row is not written): this file's audit rows are at most 96 and
-- no finding is recorded twice.
--
-- No schema change, no view, no function, nothing deleted. Byte-identical in both repos.
-- Idempotent: a second apply finds no such row open and matches nothing.
-- Reversal: UPDATE public.findings SET current_status = 'detected' WHERE finding_id IN
-- (SELECT details ->> 'finding_id' FROM public.admin_audit_log WHERE action =
-- 'path_rows_close_false_positive' AND details ->> 'batch' = '20261113a-tour-path-rows-false-alarms');
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: KB 12 2026-11-13 (Howie 11:18 "yes...approved"). Data only, one site on Prodex. The 96 open path rows first written by deep scan 626f9631 on tour.prodexlabs.com (84 "Accessible path" rows for the one page the site gives every address, 2 of them MODERATE; 12 "Forbidden endpoint" rows for refusals that followed the scanner's exit) become false_positive, one admin_audit_log row each; only while that scan's own ffuf records show the one page at least 80 times and the site's open summary row is there. Command: nothing matches. No schema change. Idempotent. Reversal in the header.
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on.
BEGIN;

WITH answers AS (
  -- what that scan's path check recorded: one row per answer (a word asked twice appears twice)
  SELECT r.res -> 'input' ->> 'FUZZ' AS word,
         r.res ->> 'status'          AS status,
         r.res ->> 'length'          AS bytes
    FROM public.scan_run_artifacts a
   CROSS JOIN LATERAL jsonb_array_elements(
           CASE WHEN jsonb_typeof(a.content_jsonb -> 'results') = 'array'
                THEN a.content_jsonb -> 'results' ELSE '[]'::jsonb END) AS r(res)
   WHERE a.scan_run_id = '626f9631-78bd-4a4c-891b-030caee35f2f'
     AND a.tool_name = 'ffuf'
),
target AS (
  SELECT f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at,
         CASE WHEN f.title LIKE 'Accessible path: /% (HTTP 200)'
              THEN 'the one page the site gives every address (HTTP 200, 3080 bytes)'
              ELSE 'a refusal that followed the scanner''s exit (HTTP 403)' END AS answer
    FROM public.findings f
   WHERE f.asset_id = 'tour.prodexlabs.com'
     AND f.finding_id LIKE 'tour.prodexlabs.com:medium:ffuf-found-%'
     AND f.first_detected_scan = '626f9631-78bd-4a4c-891b-030caee35f2f'
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND (   (f.title LIKE 'Accessible path: /% (HTTP 200)'
              AND EXISTS (SELECT 1 FROM answers w
                           WHERE 'tour.prodexlabs.com:medium:ffuf-found-' || w.word = f.finding_id
                             AND w.status = '200' AND w.bytes = '3080'))
          OR (f.title LIKE 'Forbidden endpoint: /% (HTTP 403)'
              AND EXISTS (SELECT 1 FROM answers w
                           WHERE 'tour.prodexlabs.com:medium:ffuf-found-' || w.word = f.finding_id
                             AND w.status = '403')))
     AND (SELECT count(*) FROM answers w WHERE w.status = '200' AND w.bytes = '3080') >= 80
     AND EXISTS (SELECT 1 FROM public.findings s
                  WHERE s.finding_id = 'tour.prodexlabs.com:medium:ffuf-catchall-status-200'
                    AND s.current_status::text IN ('detected', 'confirmed', 'open', 'regressed'))
),
closed AS (
  UPDATE public.findings f
     SET current_status = 'false_positive',
         updated_at     = now()
    FROM target t
   WHERE f.finding_id = t.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'path_rows_close_false_positive',
       jsonb_build_object('current_status', t.old_status, 'severity', t.severity,
                          'last_observed_at', t.last_observed_at),
       jsonb_build_object('current_status', 'false_positive'),
       jsonb_build_object(
         'finding_id',  t.finding_id,
         'asset_id',    t.asset_id,
         'title',       t.title,
         'answer',      t.answer,
         'scan_run_id', '626f9631-78bd-4a4c-891b-030caee35f2f',
         'batch',       '20261113a-tour-path-rows-false-alarms',
         'reason',      'Written by a path check that should not have run: its two made-up paths got different answers and that was read as a site that tells real pages from fake ones (fixed by push-438).',
         'evidence',    'That scan''s own ffuf records: 85 answers are the same 3,080-byte page, /actuator and /swagger among them; the 12 refusals are all in the first chunk, 2 or 3 in every burst of 5, and none after the exit changed. The scan of 2026-11-08 wrote one summary row for the same site.',
         'approved_by', 'howie@prodexlabs.com (chat approval 2026-11-13 11:18 ET)',
         'changed_by',  'migration 20261113a (built by Claude)',
         'undo',        'Set current_status back to detected on this finding.')
  FROM target t
  JOIN closed c ON c.finding_id = t.finding_id;

-- ── GUARD · at most 96 rows recorded, and no finding recorded twice.
SELECT 1 / (CASE WHEN count(*) <= 96 AND count(*) = count(DISTINCT details ->> 'finding_id')
                 THEN 1 ELSE 0 END) AS guard_each_row_recorded_once
  FROM public.admin_audit_log
 WHERE action = 'path_rows_close_false_positive'
   AND details ->> 'batch' = '20261113a-tour-path-rows-false-alarms';

COMMIT;
