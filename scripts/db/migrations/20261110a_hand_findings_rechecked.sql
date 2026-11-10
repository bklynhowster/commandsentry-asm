-- 20261110a_hand_findings_rechecked.sql
--
-- KB 12 (Proposed, RULED 2026-11-08 07:39): THE 118 HAND-ENTERED COMMAND FINDINGS, RE-CHECKED.
--
-- Howie, 2026-11-08 07:39: "Recheck." The 118 open hand-entered findings (source manual_named,
-- status open), entered March 25 to May 14 and never re-checked by a scan, are re-checked, not
-- retired. Plan: [[2026-11-10 1015 - plan - re-check the 118 hand-entered Command findings]];
-- Howie 2026-11-10 10:10 "Go, you have my approval", 10:15 "Yes, full approval. Go for it."
-- Each of the 118 was read against Sentry's own current evidence (its scanners' open rows and the
-- raw tool output each scan keeps in scan_run_artifacts). Nothing new was sent to any host.
--
-- WHICH ROWS (48 of the 118, each named below by finding_id; the other 70 are not touched):
--   superseded   21  still there, and Sentry's own scan files the same problem on the same name
--                    at the SAME OR A HIGHER grade, seen after the hand row. The hand row closes
--                    (closed_reclassified); Sentry's row carries the problem with a live date.
--                    Where Sentry's grade is LOWER than the hand row's (12 rows), the hand row is
--                    NOT closed: Howie's 2026-11-09 ruling "Once, higher wins" keeps the higher.
--   remediated    4  fixed, read from the asset's NEWEST record of the named tool that holds a
--                    reading of that fact (a newer reading that says otherwise keeps the row open;
--                    a scan that never reached the check is no reading either way): ftp.sciimage.com
--                    F-01 (testssl: the certificate chain passes), ftp.sciimage.com F-04 (the page's
--                    Content-Security-Policy has no unsafe-inline or unsafe-eval), insite.sciimage.com
--                    F-05 (plain http:// is sent to https), api.commandcommcentral.com A-05 (port
--                    8080 is not among the open ports). remediated_at is THAT scan's time, so the
--                    daily's "fixed" list (which reads remediated_at in its window) does not report
--                    old fixes as today's news.
--   reclassified  2  test.commandcommcentral.com L-05 (no SPF/DMARC on a name that sends no mail:
--                    the domain's own SPF row AND its DMARC row are both open and carry it, Sentry's
--                    dns_posture says the domain owns the gap, Howie
--                    2026-11-04: duplicates) and vpn2.sciimage.com S-05 (a note about the hand
--                    tester's tool timing out, not a fact about the host).
--   ghost        21  test3.commandcommcentral.com, 15 rows: the name does not exist (ct_ghost, never
--                    reached by a scan; NXDOMAIN in the 3y name check, 2026-11-01). The asset is
--                    left as it is (a ghost discovery would promote if it ever resolved).
--                    ip-range:cablenet-nodns, 6 rows: a placeholder from before 24.157.51.84, .86
--                    and .88 got their own pages; all three are live and scanned.
--   Every one closes only while its own condition still holds at apply time; a row whose
--   condition no longer holds is left open. Nothing reopens these rows: no scanner writes a
--   manual_named row.
--
-- AT BUILD TIME (2026-11-10, SELECT only): Command 48 rows match (21, 4, 2, 21). Prodex has no
-- hand-entered rows: nothing matches there. One HIGH among them, ftp.sciimage.com F-01, so
-- ftp.sciimage.com's rating falls from HIGH to MODERATE; no other live site's rating moves (the
-- two ghost entries' do: the placeholder has no open row left, test3 keeps 11 old imported
-- rows). Dashboard and email counts (v_fleet_open_reps; test3, a ghost, is not in them, the
-- ip-range placeholder is): High 1 to 0, Moderate 145 to 138, Low 427 to 412, Info 728 to 720.
--
-- GUARDS (plain SELECTs that divide by zero, 20261013b's pattern; a violated guard aborts the
-- transaction, the ledger row is not written):
--   1  bounded: no more than 60 rows chosen (48 at build time).
--   2  nothing serious closes: no CRITICAL or MODERATE-HIGH row is chosen, and the only HIGH
--      that may be is ftp.sciimage.com:manual:F-01 (remediated, on its evidence).
--   3  the tag is this file's alone: no row carries 'recheck-20261110a' without this file's audit row.
--
-- WHAT THIS DOES. One statement: the chosen rows get their new status (remediated with
-- remediated_at for the four fixed, closed_reclassified for the rest), the tag 'recheck-20261110a' and
-- updated_at = now(); one admin_audit_log row each ('hand_recheck_close') with the old status,
-- severity and last-seen time, the kind, the evidence read, Sentry's own rows that carry it (for
-- the superseded), the time of the scan read, a plain-words reason, the ruling and the batch.
-- trg_findings_sync_current_risk recomputes each touched asset's rating. No schema change, no
-- view, no function. Byte-identical in both repos. Idempotent: a second apply matches nothing
-- (the rows are no longer open). Reversible: UPDATE public.findings SET current_status = 'open',
-- remediated_at = NULL, tags = array_remove(tags, 'recheck-20261110a') WHERE finding_id IN (the audit rows'
-- details ->> 'finding_id' where details ->> 'batch' = '20261110a-hand-recheck'); updated_at keeps this apply's
-- time.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: KB 12 Proposed RULED 2026-11-08 07:39 (Howie "Recheck."), plan approved 2026-11-10 10:10 and 10:15. Data only. 48 named hand-entered (manual_named, open) Command rows close, each only while its own evidence holds: 21 superseded by Sentry's own open row for the same problem at the same or a higher grade (closed_reclassified), 4 fixed on the asset's newest testssl / headers_check / plain_http / naabu record that reads the fact (remediated, remediated_at = that scan), 2 reclassified (a second copy of the domain's own SPF and DMARC rows, both open; a note about the tester's tool), 21 on a name that does not exist or a placeholder split into its live addresses (closed_reclassified). Tagged recheck-20261110a, one hand_recheck_close audit row each. Guards: at most 60 rows, no CRITICAL or MODERATE-HIGH, the only HIGH ftp.sciimage.com:manual:F-01, the tag unused before. Nothing on Prodex. Splitter-safe (no dollar-quoted blocks).
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on.
BEGIN;

-- ── GUARDS 1 and 2 · bounded, and nothing serious (one pass over the same rule as the change).
WITH list (finding_id, kind, evidence, twin_source, twin_key, twin_title) AS (
  VALUES
    ('api.commandcommcentral.com:manual:A-01', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('api.commandcommcentral.com:manual:A-04', 'superseded', NULL, 'testssl', NULL, '^HSTS max-age too short'),
    ('commandcommcentral.com:manual:L-01', 'superseded', NULL, 'testssl', NULL, '^TLS 1\.3 not offered'),
    ('commandcommcentral.com:manual:L-02', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('commandcommcentral.com:manual:L-05', 'superseded', NULL, 'commandsentry_light', 'dns-missing-%', NULL),
    ('commandcommcentral.com:manual:I-04', 'superseded', NULL, 'testssl', NULL, '^Certificate list ordering issue'),
    ('commandmarketinginnovations.com:manual:F-02', 'superseded', NULL, 'commandsentry_light', 'dns-missing-%', NULL),
    ('insite.sciimage.com:manual:F-11', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('test.commandcommcentral.com:manual:L-02', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('test.commandcommcentral.com:manual:I-02', 'superseded', NULL, 'testssl', 'cve-2013-0169', NULL),
    ('testapi.commandcommcentral.com:manual:A-03', 'superseded', NULL, 'testssl', NULL, '^HSTS max-age too short'),
    ('unimacgraphics.com:manual:F-01', 'superseded', NULL, 'commandsentry_light', 'wpplugin-mega_main_menu', NULL),
    ('unimacgraphics.com:manual:F-07', 'superseded', NULL, 'testssl', 'cve-2013-3587', NULL),
    ('vpn.sciimage.com:manual:A-04', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('vpn.sciimage.com:manual:A-06', 'superseded', NULL, 'testssl', NULL, '^Wildcard certificate in use'),
    ('vpn.sciimage.com:manual:A-07', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('vpn.sciimage.com:manual:S-04', 'superseded', NULL, 'testssl', 'tls-ocsp-stapling-missing', NULL),
    ('vpn2.sciimage.com:manual:A-04', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('vpn2.sciimage.com:manual:A-06', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('vpn2.sciimage.com:manual:A-07', 'superseded', NULL, 'testssl', NULL, '^Wildcard certificate in use'),
    ('vpn2.sciimage.com:manual:S-04', 'superseded', NULL, 'testssl', 'tls-ocsp-stapling-missing', NULL),
    ('ftp.sciimage.com:manual:F-01', 'remediated', 'testssl_chain_passed', NULL, NULL, NULL),
    ('ftp.sciimage.com:manual:F-04', 'remediated', 'csp_no_unsafe', NULL, NULL, NULL),
    ('insite.sciimage.com:manual:F-05', 'remediated', 'plain_http_to_https', NULL, NULL, NULL),
    ('api.commandcommcentral.com:manual:A-05', 'remediated', 'naabu_no_8080', NULL, NULL, NULL),
    ('test.commandcommcentral.com:manual:L-05', 'reclassified', 'apex_owns_the_gap', NULL, NULL, NULL),
    ('vpn2.sciimage.com:manual:S-05', 'reclassified', 'tool_note', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-01', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-02', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-03', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-04', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-05', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-06', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-07', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-08', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-09', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-10', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-01', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-02', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-03', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-04', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-05', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-01', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-07', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-08', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-09', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-10', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-11', 'ghost', 'placeholder_split', NULL, NULL, NULL)
), hand AS (
  SELECT f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at,
         l.kind, l.evidence, l.twin_source, l.twin_key, l.twin_title,
         CASE f.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3
              WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END AS sev_rank
    FROM list l
    JOIN public.findings f ON f.finding_id = l.finding_id
   WHERE f.source::text = 'manual_named'
     AND f.current_status::text = 'open'
), twin AS (
  SELECT h.finding_id, array_agg(t.finding_id ORDER BY t.finding_id) AS twins, max(t.last_observed_at) AS seen
    FROM hand h
    JOIN public.findings t ON t.asset_id = h.asset_id
   WHERE h.kind = 'superseded'
     AND t.source::text = h.twin_source
     AND t.current_status::text IN ('detected', 'confirmed', 'regressed')
     AND (h.twin_key IS NULL
          OR t.normalized_key = h.twin_key
          OR (right(h.twin_key, 1) = '%'
              AND left(t.normalized_key, length(h.twin_key) - 1) = left(h.twin_key, length(h.twin_key) - 1)))
     AND (h.twin_title IS NULL OR t.title ~ h.twin_title)
     AND t.last_observed_at > h.last_observed_at
     AND (CASE t.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3
              WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END) <= h.sev_rank
   GROUP BY h.finding_id
), reading AS (
  SELECT h.finding_id, x.at, x.c
    FROM hand h
    CROSS JOIN LATERAL (
      SELECT coalesce(s.completed_at, s.started_at) AS at, r.content_jsonb AS c
        FROM public.scan_run s
        JOIN public.scan_run_artifacts r ON r.scan_run_id = s.scan_run_id
       WHERE s.asset_id = h.asset_id
         AND r.tool_name = CASE h.evidence
                             WHEN 'testssl_chain_passed' THEN 'testssl.sh'
                             WHEN 'csp_no_unsafe'        THEN 'headers_check'
                             WHEN 'plain_http_to_https'  THEN 'plain_http'
                             WHEN 'naabu_no_8080'        THEN 'naabu'
                             WHEN 'apex_owns_the_gap'    THEN 'dns_posture'
                           END
         AND (CASE h.evidence
                WHEN 'testssl_chain_passed' THEN EXISTS (
                       SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.content_jsonb) = 'array' THEN r.content_jsonb ELSE '[]'::jsonb END) e
                        WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443')
                WHEN 'csp_no_unsafe'        THEN jsonb_typeof(r.content_jsonb -> 'header') = 'object'
                WHEN 'plain_http_to_https'  THEN (r.content_jsonb -> 'outcome') IS NOT NULL
                WHEN 'naabu_no_8080'        THEN coalesce(r.content_jsonb ->> 'raw', '') ~ 'open ports: \['
                WHEN 'apex_owns_the_gap'    THEN (r.content_jsonb -> 'dmarc') IS NOT NULL
              END)
       ORDER BY s.started_at DESC NULLS LAST
       LIMIT 1) x
   WHERE h.evidence IN ('testssl_chain_passed', 'csp_no_unsafe', 'plain_http_to_https', 'naabu_no_8080', 'apex_owns_the_gap')
), chosen AS (
  SELECT h.finding_id, h.asset_id, h.title, h.severity, h.old_status, h.last_observed_at, h.kind, h.evidence,
         tw.twins, coalesce(tw.seen, rd.at) AS seen, rd.at AS reading_at
    FROM hand h
    LEFT JOIN twin tw ON tw.finding_id = h.finding_id
    LEFT JOIN reading rd ON rd.finding_id = h.finding_id
   WHERE (h.kind = 'superseded' AND tw.finding_id IS NOT NULL)
      OR (h.kind = 'remediated' AND rd.at > h.last_observed_at AND (
            (h.evidence = 'testssl_chain_passed'
               AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rd.c) = 'array' THEN rd.c ELSE '[]'::jsonb END) e
                            WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443')
               AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rd.c) = 'array' THEN rd.c ELSE '[]'::jsonb END) e
                                WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443'
                                  AND coalesce(e ->> 'finding', '') NOT LIKE 'passed%'))
         OR (h.evidence = 'csp_no_unsafe'
               AND (rd.c -> 'header' ->> 'content_security_policy') IS NOT NULL
               AND (rd.c -> 'header' ->> 'content_security_policy') !~* 'unsafe-inline|unsafe-eval')
         OR (h.evidence = 'plain_http_to_https' AND rd.c ->> 'outcome' = 'sent_to_https')
         OR (h.evidence = 'naabu_no_8080'
               AND (rd.c ->> 'raw') ~ 'open ports: \[[0-9, ]+\]'
               AND substring(rd.c ->> 'raw' FROM 'open ports: \[([0-9, ]+)\]') !~ '(^|[^0-9])8080([^0-9]|$)')))
      OR (h.kind = 'reclassified' AND (
            h.evidence = 'tool_note'
         OR (h.evidence = 'apex_owns_the_gap'
               AND rd.c ->> 'dmarc_suppressed' = 'apex_owns_the_gap'
               AND (SELECT count(DISTINCT p.normalized_key)
                      FROM public.assets a
                      JOIN public.findings p ON p.asset_id = a.apex_domain
                     WHERE a.asset_id = h.asset_id
                       AND a.apex_domain IS DISTINCT FROM a.asset_id
                       AND p.source::text = 'commandsentry_light'
                       AND p.normalized_key IN ('dns-missing-dmarc', 'dns-missing-spf')
                       AND p.current_status::text IN ('detected', 'confirmed', 'regressed')) = 2)))
      OR (h.kind = 'ghost' AND (
            (h.evidence = 'name_does_not_exist'
               AND EXISTS (SELECT 1 FROM public.assets a WHERE a.asset_id = h.asset_id AND a.discovery_status = 'ct_ghost')
               AND NOT EXISTS (SELECT 1 FROM public.scan_run s WHERE s.asset_id = h.asset_id AND s.status::text = 'complete'))
         OR (h.evidence = 'placeholder_split'
               AND EXISTS (SELECT 1 FROM public.assets a WHERE a.asset_id = h.asset_id AND a.discovery_status = 'unverified')
               AND NOT EXISTS (SELECT 1 FROM public.scan_run s WHERE s.asset_id = h.asset_id AND s.status::text = 'complete')
               AND (SELECT count(*) FROM public.assets a
                     WHERE a.asset_id IN ('24.157.51.84', '24.157.51.86', '24.157.51.88')
                       AND a.discovery_status = 'confirmed_live'
                       AND EXISTS (SELECT 1 FROM public.scan_run s
                                    WHERE s.asset_id = a.asset_id AND s.status::text = 'complete'
                                      AND s.started_at > '2026-10-01'::timestamptz)) = 3)))
)
SELECT 1 / (CASE WHEN count(*) <= 60 THEN 1 ELSE 0 END) AS guard_bounded,
       1 / (CASE WHEN count(*) FILTER (WHERE severity IN ('CRITICAL', 'MODERATE-HIGH')) = 0
                  AND count(*) FILTER (WHERE severity = 'HIGH' AND finding_id <> 'ftp.sciimage.com:manual:F-01') = 0
                 THEN 1 ELSE 0 END) AS guard_nothing_serious
  FROM chosen;

-- ── GUARD 3 · the tag is new: no row carries it without this file's audit row.
SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_tag_unused
  FROM public.findings f
 WHERE 'recheck-20261110a' = ANY (coalesce(f.tags, '{}'::text[]))
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'hand_recheck_close'
                      AND l.details ->> 'finding_id' = f.finding_id);

-- ── THE CHANGE · one statement: choose, close and tag, then audit every closed row.
WITH list (finding_id, kind, evidence, twin_source, twin_key, twin_title) AS (
  VALUES
    ('api.commandcommcentral.com:manual:A-01', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('api.commandcommcentral.com:manual:A-04', 'superseded', NULL, 'testssl', NULL, '^HSTS max-age too short'),
    ('commandcommcentral.com:manual:L-01', 'superseded', NULL, 'testssl', NULL, '^TLS 1\.3 not offered'),
    ('commandcommcentral.com:manual:L-02', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('commandcommcentral.com:manual:L-05', 'superseded', NULL, 'commandsentry_light', 'dns-missing-%', NULL),
    ('commandcommcentral.com:manual:I-04', 'superseded', NULL, 'testssl', NULL, '^Certificate list ordering issue'),
    ('commandmarketinginnovations.com:manual:F-02', 'superseded', NULL, 'commandsentry_light', 'dns-missing-%', NULL),
    ('insite.sciimage.com:manual:F-11', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('test.commandcommcentral.com:manual:L-02', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('test.commandcommcentral.com:manual:I-02', 'superseded', NULL, 'testssl', 'cve-2013-0169', NULL),
    ('testapi.commandcommcentral.com:manual:A-03', 'superseded', NULL, 'testssl', NULL, '^HSTS max-age too short'),
    ('unimacgraphics.com:manual:F-01', 'superseded', NULL, 'commandsentry_light', 'wpplugin-mega_main_menu', NULL),
    ('unimacgraphics.com:manual:F-07', 'superseded', NULL, 'testssl', 'cve-2013-3587', NULL),
    ('vpn.sciimage.com:manual:A-04', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('vpn.sciimage.com:manual:A-06', 'superseded', NULL, 'testssl', NULL, '^Wildcard certificate in use'),
    ('vpn.sciimage.com:manual:A-07', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('vpn.sciimage.com:manual:S-04', 'superseded', NULL, 'testssl', 'tls-ocsp-stapling-missing', NULL),
    ('vpn2.sciimage.com:manual:A-04', 'superseded', NULL, 'commandsentry_light', 'csp-scripts-not-limited', NULL),
    ('vpn2.sciimage.com:manual:A-06', 'superseded', NULL, 'commandsentry_light', 'missing-header-%', NULL),
    ('vpn2.sciimage.com:manual:A-07', 'superseded', NULL, 'testssl', NULL, '^Wildcard certificate in use'),
    ('vpn2.sciimage.com:manual:S-04', 'superseded', NULL, 'testssl', 'tls-ocsp-stapling-missing', NULL),
    ('ftp.sciimage.com:manual:F-01', 'remediated', 'testssl_chain_passed', NULL, NULL, NULL),
    ('ftp.sciimage.com:manual:F-04', 'remediated', 'csp_no_unsafe', NULL, NULL, NULL),
    ('insite.sciimage.com:manual:F-05', 'remediated', 'plain_http_to_https', NULL, NULL, NULL),
    ('api.commandcommcentral.com:manual:A-05', 'remediated', 'naabu_no_8080', NULL, NULL, NULL),
    ('test.commandcommcentral.com:manual:L-05', 'reclassified', 'apex_owns_the_gap', NULL, NULL, NULL),
    ('vpn2.sciimage.com:manual:S-05', 'reclassified', 'tool_note', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-01', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-02', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-03', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-04', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-05', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-06', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-07', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-08', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-09', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:A-10', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-01', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-02', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-03', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-04', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('test3.commandcommcentral.com:manual:W-05', 'ghost', 'name_does_not_exist', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-01', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-07', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-08', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-09', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-10', 'ghost', 'placeholder_split', NULL, NULL, NULL),
    ('ip-range:cablenet-nodns:manual:I-11', 'ghost', 'placeholder_split', NULL, NULL, NULL)
), hand AS (
  SELECT f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at,
         l.kind, l.evidence, l.twin_source, l.twin_key, l.twin_title,
         CASE f.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3
              WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END AS sev_rank
    FROM list l
    JOIN public.findings f ON f.finding_id = l.finding_id
   WHERE f.source::text = 'manual_named'
     AND f.current_status::text = 'open'
), twin AS (
  SELECT h.finding_id, array_agg(t.finding_id ORDER BY t.finding_id) AS twins, max(t.last_observed_at) AS seen
    FROM hand h
    JOIN public.findings t ON t.asset_id = h.asset_id
   WHERE h.kind = 'superseded'
     AND t.source::text = h.twin_source
     AND t.current_status::text IN ('detected', 'confirmed', 'regressed')
     AND (h.twin_key IS NULL
          OR t.normalized_key = h.twin_key
          OR (right(h.twin_key, 1) = '%'
              AND left(t.normalized_key, length(h.twin_key) - 1) = left(h.twin_key, length(h.twin_key) - 1)))
     AND (h.twin_title IS NULL OR t.title ~ h.twin_title)
     AND t.last_observed_at > h.last_observed_at
     AND (CASE t.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MODERATE-HIGH' THEN 3
              WHEN 'MODERATE' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END) <= h.sev_rank
   GROUP BY h.finding_id
), reading AS (
  SELECT h.finding_id, x.at, x.c
    FROM hand h
    CROSS JOIN LATERAL (
      SELECT coalesce(s.completed_at, s.started_at) AS at, r.content_jsonb AS c
        FROM public.scan_run s
        JOIN public.scan_run_artifacts r ON r.scan_run_id = s.scan_run_id
       WHERE s.asset_id = h.asset_id
         AND r.tool_name = CASE h.evidence
                             WHEN 'testssl_chain_passed' THEN 'testssl.sh'
                             WHEN 'csp_no_unsafe'        THEN 'headers_check'
                             WHEN 'plain_http_to_https'  THEN 'plain_http'
                             WHEN 'naabu_no_8080'        THEN 'naabu'
                             WHEN 'apex_owns_the_gap'    THEN 'dns_posture'
                           END
         AND (CASE h.evidence
                WHEN 'testssl_chain_passed' THEN EXISTS (
                       SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.content_jsonb) = 'array' THEN r.content_jsonb ELSE '[]'::jsonb END) e
                        WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443')
                WHEN 'csp_no_unsafe'        THEN jsonb_typeof(r.content_jsonb -> 'header') = 'object'
                WHEN 'plain_http_to_https'  THEN (r.content_jsonb -> 'outcome') IS NOT NULL
                WHEN 'naabu_no_8080'        THEN coalesce(r.content_jsonb ->> 'raw', '') ~ 'open ports: \['
                WHEN 'apex_owns_the_gap'    THEN (r.content_jsonb -> 'dmarc') IS NOT NULL
              END)
       ORDER BY s.started_at DESC NULLS LAST
       LIMIT 1) x
   WHERE h.evidence IN ('testssl_chain_passed', 'csp_no_unsafe', 'plain_http_to_https', 'naabu_no_8080', 'apex_owns_the_gap')
), chosen AS (
  SELECT h.finding_id, h.asset_id, h.title, h.severity, h.old_status, h.last_observed_at, h.kind, h.evidence,
         tw.twins, coalesce(tw.seen, rd.at) AS seen, rd.at AS reading_at
    FROM hand h
    LEFT JOIN twin tw ON tw.finding_id = h.finding_id
    LEFT JOIN reading rd ON rd.finding_id = h.finding_id
   WHERE (h.kind = 'superseded' AND tw.finding_id IS NOT NULL)
      OR (h.kind = 'remediated' AND rd.at > h.last_observed_at AND (
            (h.evidence = 'testssl_chain_passed'
               AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rd.c) = 'array' THEN rd.c ELSE '[]'::jsonb END) e
                            WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443')
               AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(rd.c) = 'array' THEN rd.c ELSE '[]'::jsonb END) e
                                WHERE e ->> 'id' = 'cert_chain_of_trust' AND e ->> 'port' = '443'
                                  AND coalesce(e ->> 'finding', '') NOT LIKE 'passed%'))
         OR (h.evidence = 'csp_no_unsafe'
               AND (rd.c -> 'header' ->> 'content_security_policy') IS NOT NULL
               AND (rd.c -> 'header' ->> 'content_security_policy') !~* 'unsafe-inline|unsafe-eval')
         OR (h.evidence = 'plain_http_to_https' AND rd.c ->> 'outcome' = 'sent_to_https')
         OR (h.evidence = 'naabu_no_8080'
               AND (rd.c ->> 'raw') ~ 'open ports: \[[0-9, ]+\]'
               AND substring(rd.c ->> 'raw' FROM 'open ports: \[([0-9, ]+)\]') !~ '(^|[^0-9])8080([^0-9]|$)')))
      OR (h.kind = 'reclassified' AND (
            h.evidence = 'tool_note'
         OR (h.evidence = 'apex_owns_the_gap'
               AND rd.c ->> 'dmarc_suppressed' = 'apex_owns_the_gap'
               AND (SELECT count(DISTINCT p.normalized_key)
                      FROM public.assets a
                      JOIN public.findings p ON p.asset_id = a.apex_domain
                     WHERE a.asset_id = h.asset_id
                       AND a.apex_domain IS DISTINCT FROM a.asset_id
                       AND p.source::text = 'commandsentry_light'
                       AND p.normalized_key IN ('dns-missing-dmarc', 'dns-missing-spf')
                       AND p.current_status::text IN ('detected', 'confirmed', 'regressed')) = 2)))
      OR (h.kind = 'ghost' AND (
            (h.evidence = 'name_does_not_exist'
               AND EXISTS (SELECT 1 FROM public.assets a WHERE a.asset_id = h.asset_id AND a.discovery_status = 'ct_ghost')
               AND NOT EXISTS (SELECT 1 FROM public.scan_run s WHERE s.asset_id = h.asset_id AND s.status::text = 'complete'))
         OR (h.evidence = 'placeholder_split'
               AND EXISTS (SELECT 1 FROM public.assets a WHERE a.asset_id = h.asset_id AND a.discovery_status = 'unverified')
               AND NOT EXISTS (SELECT 1 FROM public.scan_run s WHERE s.asset_id = h.asset_id AND s.status::text = 'complete')
               AND (SELECT count(*) FROM public.assets a
                     WHERE a.asset_id IN ('24.157.51.84', '24.157.51.86', '24.157.51.88')
                       AND a.discovery_status = 'confirmed_live'
                       AND EXISTS (SELECT 1 FROM public.scan_run s
                                    WHERE s.asset_id = a.asset_id AND s.status::text = 'complete'
                                      AND s.started_at > '2026-10-01'::timestamptz)) = 3)))
),
closed AS (
  UPDATE public.findings f
     SET current_status = (CASE WHEN c.kind = 'remediated' THEN 'remediated' ELSE 'closed_reclassified' END)::public.finding_status_t,
         remediated_at  = CASE WHEN c.kind = 'remediated' THEN c.reading_at ELSE f.remediated_at END,
         tags           = array_append(coalesce(f.tags, '{}'::text[]), 'recheck-20261110a'),
         updated_at     = now()
    FROM chosen c
   WHERE f.finding_id = c.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'hand_recheck_close',
       jsonb_build_object('current_status', c.old_status, 'severity', c.severity,
                          'last_observed_at', c.last_observed_at),
       jsonb_build_object('current_status', CASE WHEN c.kind = 'remediated' THEN 'remediated' ELSE 'closed_reclassified' END,
                          'tag', 'recheck-20261110a',
                          'remediated_at', CASE WHEN c.kind = 'remediated' THEN c.reading_at END),
       jsonb_build_object(
         'finding_id', c.finding_id,
         'asset_id',   c.asset_id,
         'title',      c.title,
         'kind',       c.kind,
         'evidence',   c.evidence,
         'twins',      to_jsonb(c.twins),
         'seen',       c.seen,
         'reason',     CASE
                         WHEN c.kind = 'superseded' THEN 'Re-checked: still there. Sentry''s own scan files the same problem on this name at the same or a higher grade, last seen ' || to_char(c.seen AT TIME ZONE 'America/New_York', 'FMMonth FMDD, YYYY') || ' (' || array_to_string(c.twins, ', ') || '). That row carries it from now on; this hand-entered copy never refreshes.'
                         WHEN c.evidence = 'testssl_chain_passed' THEN 'Re-checked: fixed. Sentry''s deep scan of ' || to_char(c.seen AT TIME ZONE 'America/New_York', 'FMMonth FMDD, YYYY') || ' reads the certificate chain as complete (testssl: cert_chain_of_trust passed).'
                         WHEN c.evidence = 'csp_no_unsafe' THEN 'Re-checked: fixed. Sentry''s scan of ' || to_char(c.seen AT TIME ZONE 'America/New_York', 'FMMonth FMDD, YYYY') || ' reads a Content-Security-Policy on the page with neither unsafe-inline nor unsafe-eval.'
                         WHEN c.evidence = 'plain_http_to_https' THEN 'Re-checked: fixed. Sentry''s scan of ' || to_char(c.seen AT TIME ZONE 'America/New_York', 'FMMonth FMDD, YYYY') || ' sees the plain http:// address send visitors to https.'
                         WHEN c.evidence = 'naabu_no_8080' THEN 'Re-checked: fixed. Sentry''s port check of ' || to_char(c.seen AT TIME ZONE 'America/New_York', 'FMMonth FMDD, YYYY') || ' (the 100 most common ports) finds port 8080 closed.'
                         WHEN c.evidence = 'apex_owns_the_gap' THEN 'Re-checked: a second copy. This name sends no mail; its domain''s missing SPF and DMARC records are reported on the domain itself, where they stay open (Howie 2026-11-04: such rows are duplicates).'
                         WHEN c.evidence = 'tool_note' THEN 'A note about the hand tester''s own tool (its service detection timed out), not a fact about this host.'
                         WHEN c.evidence = 'name_does_not_exist' THEN 'This name does not exist: it does not resolve (Sentry''s name check, November 1, 2026: no such name) and no Sentry scan has ever reached it. There is nothing here to re-check.'
                         ELSE 'This placeholder stood for the Cablenet addresses before each got its own page. 24.157.51.84, .86 and .88 are now scanned on their own pages, which carry the current readings.'
                       END,
         'migration',  '20261110a',
         'batch',      '20261110a-hand-recheck',
         'ruling',     'Howie 2026-11-08 07:39 "Recheck."; plan approved 2026-11-10 10:10 and 10:15')
  FROM chosen c
  JOIN closed x ON x.finding_id = c.finding_id;

COMMIT;
