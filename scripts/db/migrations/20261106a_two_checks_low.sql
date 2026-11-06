-- 20261106a_two_checks_low.sql
--
-- KB 12 job 4v (2026-11-06). TWO CHECKS ARE LOW: A SCRIPT RULE THAT DOES NOT LIMIT SCRIPTS, AND
-- COMPRESSED PAGES (testssl's BREACH check, when compression is all it saw).
--
-- Howie, 2026-11-04 15:33, on the compressed-pages check: "Change it to a low. I agree with you."
-- (15:32: "It's a misnomer. It's going to freak people out"). 2026-11-06 07:38, on the script-rule
-- check leading the dailies day after day: "its too unimportant and repetitive"; 08:03: "yes" (rate
-- it Low, with the compressed-pages check, one job). The push that goes with this file
-- (csp_policy.py, cs_parsers/testssl.py) writes LOW from now on. A row is rewritten only when a scan
-- sees it again, and the deep scan that runs testssl reaches some sites rarely (never on its own
-- for the FortiWeb sites), so this lowers the open rows once.
--
-- Read 2026-11-06, by 08:13 ET (read only): open and MODERATE, Command 6 script-rule rows
-- (24.157.51.70, 24.157.51.84, insite.sciimage.com, pay.commandmi.com, vpn.sciimage.com,
-- vpn2.sciimage.com) and 6 compressed-pages rows; Prodex 18 and 24. Every compressed-pages row
-- reads "potentially VULNERABLE, <gzip | gzip deflate | br gzip> HTTP compression detected  -
-- only supplied '/' tested  (CWE-310)", which the pattern below matches.
-- Command's 4 remediated compressed-pages rows are closed and left as they are.
--
-- 1. Each open MODERATE row of the two checks -> LOW, audited row by row (its old severity
--    logged):
--      the quick scan's script-rule finding (source commandsentry_light, finding_id ending
--      ':light:csp-scripts-not-limited');
--      testssl's BREACH finding whose text is testssl's compression-only line and nothing more
--      (source testssl, ':testssl:BREACH:' in the finding_id, and the description, which holds
--      testssl's own text plus '  (CWE-310)', matching the same pattern the scanner uses:
--      breach_is_compression_only in cs_parsers/testssl.py; the test holds the two equal). A
--      text that says compression AND something more keeps its rating (code review 2026-11-06,
--      must-fix 1).
--    Left as they are: every other severity (only MODERATE is lowered), closed rows, a person's
--    hand-test entry (manual_named: Sentry never rewrites a person's rating; ftp.sciimage.com F-04
--    and unimacgraphics.com F-07 keep theirs), Nikto's compression note (already INFO), and the
--    script rule's eval() finding (already LOW). So this lowers exactly the rows the scanner now
--    writes LOW, never more. The upsert keeps the less severe value, so a lowered row stays LOW.
-- 2. Every asset's rating recomputed once (refresh_all_asset_posture), as 20261029b did.
--
-- Shape: 20261029b's (a bounded guard, then the audited batch; the old severity is read in a CTE
-- because RETURNING sees only the new one). Byte-identical in both repos. Re-applying changes
-- nothing: step 1 selects only rows still MODERATE. Reversible: UPDATE public.findings SET
-- severity = 'MODERATE' WHERE finding_id IN (the audit rows' details ->> 'finding_id' where
-- action = 'job4v_rated_low'), with the push reverted first.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 15000
-- notes: Job 4v (Howie 2026-11-04 15:33 "Change it to a low."; 2026-11-06 08:03 "yes"). Open MODERATE rows of two checks -> LOW, audited per row ('job4v_rated_low', old severity kept): the quick scan's csp-scripts-not-limited, and testssl's BREACH when its text is the compression-only line. refresh_all_asset_posture once. Command 12 rows, Prodex 42 (2026-11-06). No schema change. No dollar-quoting. Byte-identical in both repos.
-- END-META

-- Guard: 2026-11-06 Command 12, Prodex 42. More than 100 is not this batch: abort, write nothing.
SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_job4v_rated_low
  FROM public.findings f
 WHERE f.severity::text = 'MODERATE'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND ((f.source::text = 'commandsentry_light' AND f.finding_id LIKE '%:light:csp-scripts-not-limited')
     OR (f.source::text = 'testssl' AND f.finding_id LIKE '%:testssl:BREACH:%'
         AND f.description ~ '^potentially VULNERABLE, (gzip|deflate|compress|br|zstd)( (gzip|deflate|compress|br|zstd))* HTTP compression detected +- only supplied (''[^'']*''|"[^"]*") tested(  \(CWE-[0-9]+\))?$'));

-- 1. The two checks -> LOW, audited ---------------------------------------------------------
WITH target AS (
  SELECT f.finding_id, f.severity::text AS old_severity
    FROM public.findings f
 WHERE f.severity::text = 'MODERATE'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND ((f.source::text = 'commandsentry_light' AND f.finding_id LIKE '%:light:csp-scripts-not-limited')
     OR (f.source::text = 'testssl' AND f.finding_id LIKE '%:testssl:BREACH:%'
         AND f.description ~ '^potentially VULNERABLE, (gzip|deflate|compress|br|zstd)( (gzip|deflate|compress|br|zstd))* HTTP compression detected +- only supplied (''[^'']*''|"[^"]*") tested(  \(CWE-[0-9]+\))?$'))
), changed AS (
  UPDATE public.findings f
     SET severity = 'LOW'::severity_t, updated_at = now()
    FROM target t
   WHERE f.finding_id = t.finding_id
     AND f.severity::text = 'MODERATE'
  RETURNING f.finding_id, f.asset_id, f.source::text AS source, f.title, f.last_observed_at,
            t.old_severity
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'job4v_rated_low', NULL, NULL,
       jsonb_build_object('severity', c.old_severity),
       jsonb_build_object('severity', 'LOW'),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'source', c.source,
                          'title', c.title, 'last_observed_at', c.last_observed_at,
                          'check', CASE WHEN c.source = 'testssl' THEN 'BREACH'
                                        ELSE 'csp-scripts-not-limited' END,
                          'reason', CASE WHEN c.source = 'testssl'
                                         THEN 'compression is all the check saw, not the attack it is '
                                              'named after (Howie 2026-11-04 15:33, job 4v)'
                                         ELSE 'a script rule that does not limit scripts lets nothing '
                                              'in by itself (Howie 2026-11-06 08:03, job 4v)' END,
                          'tool', '20261106a_two_checks_low.sql', 'rule', 'job 4v')
  FROM changed c;

-- 2. Once: every asset, the one rule ------------------------------------------------------
SELECT public.refresh_all_asset_posture();
