-- 20261023a_known_not_guessed.sql
--
-- KB 12 job 3r (2026-10-23). PROVEN, OUT OF DATE, GUESS — the one-time cleanup.
--
-- Howie, 2026-10-22 15:58: "we don't know. We have no inside information on anything."
-- 20:34: "There are risks and there are things that are known, that's all."
-- 2026-10-23 07:21-07:25, on the hand assessment's Mega Main Menu row: "I think we can
-- drop it ... drop it to moderate, and then some kind of indication that there is still
-- some action required here."
--
-- The code (push-337) makes every writer follow the ladder from now on. This file does,
-- once, what the code cannot do to rows already written. It is the "explicit, audited
-- batch run by a human" that migration 20260902b requires for detector_retired, and
-- the 3r plan review's must-fix 1: the advisory watch never retires anything itself.
--
-- Shape: the house pattern for a one-time batch (20261013b): a bounded-batch guard
-- (division by zero aborts the whole file when a step would touch more than it should),
-- then one statement per step, `WITH changed AS (UPDATE ... RETURNING ...) INSERT INTO
-- admin_audit_log ... FROM changed` - so the log holds exactly the rows that changed. Step 1
-- uses retire_detector_findings.py's action and rule strings, like 20261013b.
--
-- WHAT THIS DOES:
--   1. GUESSES RETIRED. Every open advisory-watch row on the pre-3r identity
--      ('<asset>:advisory_watch:advisory:<product>:<hash>'). Every such row ever written
--      is a "Runs X, version not shown" guess (both DBs, 2026-10-23: Command 9 open +
--      1 closed, Prodex none). -> detector_retired + detector_retired_at. 20260902b's
--      criteria hold: the detector that wrote them (the version-not-shown branch) is
--      removed, and nothing writes that identity any more (out-of-date rows have their
--      own, 'out-of-date:<product>' - 3r plan review must-fix 2).
--   2. ADVISORIES THAT NEVER APPLIED, CLOSED AS FALSE POSITIVES. Slider Revolution
--      CVE-2026-6692 ("in versions 7.0.0 to 7.0.10"), CVE-2026-7542 ("7.0 to 7.0.10"),
--      CVE-2026-9048 ("7.0.0 - 7.0.14") and CVE-2026-57678 ("from 7.0.0 through
--      7.0.16") cover only 7.0.x. Every row that records a version below 7.0 (all of
--      Command's record 6.7.54-6.7.58) was a false match: the scanner read only the
--      upper bound. -> false_positive. A later 7.0.x install is re-found by the fixed
--      scanner like any closed light finding.
--   3. OUT OF DATE RE-RATED. Every other open version-based row - WordPress advisories
--      (light identity 'wpvuln-', any writer), JavaScript library advisories ('libflaw-'),
--      the WPScan-import rows - goes to MODERATE, or MODERATE-HIGH when findings.kev_listed
--      (cve-scoring.yml keeps it). Only rows whose severity differs are touched.
--   4. HOWIE'S RULING on unimacgraphics.com:manual:F-01 ("Abandoned Plugin - Mega Main
--      Menu 2.2.1"): HIGH -> MODERATE, his words in the audit row. Sentry never changes a
--      person's row on its own: this is Howie's act, by this file.
-- Every rating follows by itself (trg_findings_sync_current_risk, the one rule, 20261022a).
--
-- Byte-identical in both repos. Prodex has no row any step matches (measured 2026-10-23):
-- every statement there changes nothing. Re-applying changes nothing: each step selects
-- only rows not yet in their target state.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: Job 3r (Howie 2026-10-22 "There are risks and there are things that are known, that's all." / 2026-10-23 "drop it to moderate"). One-time cleanup, audited row by row: guess rows (pre-3r advisory_watch identity) -> detector_retired; Slider Revolution 7.0.x-only advisories on 6.x rows -> false_positive; other open version-based rows -> MODERATE / MODERATE-HIGH by kev_listed; manual F-01 HIGH -> MODERATE. Command only in practice (Prodex 0 rows). Touches no schema. Byte-identical in both repos.
-- END-META

-- Guards: on Command 2026-10-23 they count 9 / 24 / 15 (the third runs before step 2 closes
-- the false matches; the steps then change 9 / 24 / 5 / 1 rows). More than 50 in any step is
-- not this batch: abort, write nothing.
SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END) AS guard_guesses
  FROM public.findings f
 WHERE f.source::text = 'advisory_watch'
   AND f.finding_id LIKE '%:advisory_watch:advisory:%'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed');

SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END) AS guard_false_matches
  FROM public.findings f
 WHERE (f.finding_id ~ ':light:wpvuln-cve-2026-(6692|7542|9048|57678)$'
        OR f.finding_id ~ ':wpvuln:revslider:CVE-2026-(6692|7542|9048|57678):')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND string_to_array(COALESCE(substring(f.description from 'at version ([0-9]+(\.[0-9]+)*)'),
                                substring(f.title from '^revslider ([0-9]+(\.[0-9]+)*) ')), '.')::int[]
       < ARRAY[7, 0];

SELECT 1 / (CASE WHEN count(*) <= 50 THEN 1 ELSE 0 END) AS guard_out_of_date
  FROM public.findings f
 WHERE (f.finding_id LIKE '%:light:wpvuln-%' OR f.finding_id LIKE '%:light:libflaw-%'
        OR (f.source::text = 'wpscan' AND f.finding_id LIKE '%:wpvulnerability:wpvuln:%'))
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.severity::text IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE')
   AND f.severity::text <> CASE WHEN f.kev_listed THEN 'MODERATE-HIGH' ELSE 'MODERATE' END;

-- 1. Guesses retired -------------------------------------------------------------------
WITH changed AS (
  UPDATE public.findings f
     SET current_status = 'detector_retired', detector_retired_at = now(), updated_at = now()
   WHERE f.source::text = 'advisory_watch'
   AND f.finding_id LIKE '%:advisory_watch:advisory:%'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
  RETURNING f.finding_id, f.asset_id, f.title, f.severity::text AS severity, f.detector_retired_at
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'detector_retired_finding', NULL, NULL,
       jsonb_build_object('current_status', 'open_family', 'source', 'advisory_watch', 'severity', c.severity),
       jsonb_build_object('current_status', 'detector_retired', 'detector_retired_at', c.detector_retired_at),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'title', c.title,
                          'retired_class', 'advisory_watch/version-not-shown',
                          'reason', 'a version we did not see is a guess, not a finding (Howie 2026-10-22 20:34); '
                                    'the advisory watch no longer writes this identity (job 3r)',
                          'tool', '20261023a_known_not_guessed.sql',
                          'rule', '4.7_ruling_57_detector_retired_manual_transition',
                          'batch_rule', 'job_3r_guesses')
  FROM changed c;

-- 2. Advisories that never applied -> false_positive -----------------------------------
WITH changed AS (
  UPDATE public.findings f
     SET current_status = 'false_positive', updated_at = now()
   WHERE (f.finding_id ~ ':light:wpvuln-cve-2026-(6692|7542|9048|57678)$'
        OR f.finding_id ~ ':wpvuln:revslider:CVE-2026-(6692|7542|9048|57678):')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND string_to_array(COALESCE(substring(f.description from 'at version ([0-9]+(\.[0-9]+)*)'),
                                substring(f.title from '^revslider ([0-9]+(\.[0-9]+)*) ')), '.')::int[]
       < ARRAY[7, 0]
  RETURNING f.finding_id, f.asset_id, f.title, f.severity::text AS severity
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'job_3r_false_match', NULL, NULL,
       jsonb_build_object('current_status', 'open_family', 'severity', c.severity),
       jsonb_build_object('current_status', 'false_positive'),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'title', c.title,
                          'reason', 'the advisory''s own text covers only 7.0.x and the row records an older version',
                          'tool', '20261023a_known_not_guessed.sql', 'rule', 'job_3r')
  FROM changed c;

-- 3. Out of date re-rated --------------------------------------------------------------
WITH was AS (
  SELECT f.finding_id, f.severity::text AS severity
    FROM public.findings f
   WHERE (f.finding_id LIKE '%:light:wpvuln-%' OR f.finding_id LIKE '%:light:libflaw-%'
        OR (f.source::text = 'wpscan' AND f.finding_id LIKE '%:wpvulnerability:wpvuln:%'))
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.severity::text IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE')
   AND f.severity::text <> CASE WHEN f.kev_listed THEN 'MODERATE-HIGH' ELSE 'MODERATE' END
), changed AS (
  UPDATE public.findings f
     SET severity = (CASE WHEN f.kev_listed THEN 'MODERATE-HIGH' ELSE 'MODERATE' END)::severity_t,
         updated_at = now()
    FROM was w
   WHERE f.finding_id = w.finding_id
  RETURNING f.finding_id, f.asset_id, f.title, w.severity AS severity_was, f.severity::text AS severity_now
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'job_3r_out_of_date', NULL, NULL,
       jsonb_build_object('severity', c.severity_was),
       jsonb_build_object('severity', c.severity_now),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'title', c.title,
                          'reason', 'a version we saw, older than the fix: out of date, not proven',
                          'tool', '20261023a_known_not_guessed.sql', 'rule', 'job_3r')
  FROM changed c;

-- 4. Howie's ruling on the hand assessment's Mega Main Menu row ------------------------
WITH changed AS (
  UPDATE public.findings f
     SET severity = 'MODERATE'::severity_t, updated_at = now()
   WHERE f.finding_id = 'unimacgraphics.com:manual:F-01'
   AND f.severity::text = 'HIGH'
  RETURNING f.finding_id, f.asset_id, f.title
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'job_3r_howie_ruling', NULL, NULL,
       jsonb_build_object('severity', 'HIGH'),
       jsonb_build_object('severity', 'MODERATE'),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'title', c.title,
                          'ruled_by', 'Howie',
                          'words', 'I think we can drop it ... drop it to moderate, and then some kind of '
                                   'indication that there is still some action required here. (2026-10-23 07:21-07:25)',
                          'tool', '20261023a_known_not_guessed.sql', 'rule', 'job_3r')
  FROM changed c;
