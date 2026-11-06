-- 20261106b_csp_header_findings_low.sql
--
-- KB 12 job 5c (2026-11-06). A MISSING CONTENT-SECURITY-POLICY AND A STATIC CSP NONCE ARE LOW.
--
-- Howie, 2026-11-06 11:40, on the quick scan's "Missing security header: Content-Security-Policy":
-- "Yes, recategorize them as low for the emails, please." By 11:44, on the two static-nonce checks:
-- "Yes, include them". The same reasoning as job 4v (20261106a): a policy that is missing, or whose
-- nonce never changes, stops nothing; by itself it lets nothing in. The push that goes with this file
-- (run_light.py) writes LOW from now on; this lowers the open rows once.
--
-- Read 2026-11-06, by 11:45 ET (read only): open and MODERATE, Command 36 missing-policy rows and 9
-- static-nonce rows (csp-static-nonce 2, csp-static-nonce-script_src 1, csp-static-nonce-style_src 6);
-- Prodex 6 missing-policy rows and none of the other.
--
-- 1. Each open MODERATE row of those checks -> LOW, audited row by row (its old severity logged):
--      source commandsentry_light, and a finding_id ending ':light:missing-header-content-security-policy',
--      or ':light:csp-static-nonce', or ':light:csp-static-nonce-' plus a directive of at least one
--      character (LIKE '_' is one character: a bare trailing hyphen, which the scanner never writes,
--      is not lowered; code review 2026-11-06, must-fix 1).
--    Left as they are: every other severity (only MODERATE is lowered), closed rows, every other
--    source (Nikto's and nuclei's missing-header notes are INFO already; testssl's "Security headers
--    missing or weak" is its own check), every hand-entered finding (CCC M-02 static nonces,
--    test3.commandcommcentral.com A-02 missing policy: Sentry never rewrites a person's rating), the
--    other missing headers (Strict-Transport-Security stays MODERATE). So this lowers exactly the rows
--    the scanner now writes LOW, never more. The upsert keeps the less severe value, so a lowered row
--    stays LOW.
-- 2. Every asset's rating recomputed once (refresh_all_asset_posture), as 20261106a did.
--
-- Shape: 20261106a's. Byte-identical in both repos. Re-applying changes nothing: step 1 selects only
-- rows still MODERATE. Reversible: UPDATE public.findings SET severity = 'MODERATE' WHERE finding_id IN
-- (the audit rows' details ->> 'finding_id' where action = 'job5c_rated_low'), with the push reverted.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 15000
-- notes: Job 5c (Howie 2026-11-06 11:40 "Yes, recategorize them as low for the emails, please."; by 11:44 "Yes, include them"). Open MODERATE rows of the quick scan's missing-header-content-security-policy and csp-static-nonce checks -> LOW, audited per row ('job5c_rated_low', old severity kept). refresh_all_asset_posture once. Command 45 rows, Prodex 6 (2026-11-06). No schema change. No dollar-quoting. Byte-identical in both repos.
-- END-META

-- Guard: 2026-11-06 Command 45, Prodex 6. More than 100 is not this batch: abort, write nothing.
SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_job5c_rated_low
  FROM public.findings f
 WHERE f.severity::text = 'MODERATE'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.source::text = 'commandsentry_light'
   AND (f.finding_id LIKE '%:light:missing-header-content-security-policy'
     OR f.finding_id LIKE '%:light:csp-static-nonce'
     OR f.finding_id LIKE '%:light:csp-static-nonce-_%');

-- 1. The checks -> LOW, audited ---------------------------------------------------------------
WITH target AS (
  SELECT f.finding_id, f.severity::text AS old_severity
    FROM public.findings f
 WHERE f.severity::text = 'MODERATE'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.source::text = 'commandsentry_light'
   AND (f.finding_id LIKE '%:light:missing-header-content-security-policy'
     OR f.finding_id LIKE '%:light:csp-static-nonce'
     OR f.finding_id LIKE '%:light:csp-static-nonce-_%')
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
SELECT NULL, 'job5c_rated_low', NULL, NULL,
       jsonb_build_object('severity', c.old_severity),
       jsonb_build_object('severity', 'LOW'),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'source', c.source,
                          'title', c.title, 'last_observed_at', c.last_observed_at,
                          'check', regexp_replace(c.finding_id, '^.*:light:', ''),
                          'reason', 'a missing or static-nonce Content-Security-Policy stops nothing, '
                                    'and lets nothing in by itself (Howie 2026-11-06, job 5c)',
                          'tool', '20261106b_csp_header_findings_low.sql', 'rule', 'job 5c')
  FROM changed c;

-- 2. Once: every asset, the one rule ------------------------------------------------------
SELECT public.refresh_all_asset_posture();
