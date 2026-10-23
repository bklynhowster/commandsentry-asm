-- 20261023b_open_members_rate_a_group.sql
--
-- KB 12 job 3r-b (2026-10-23). TWO RATINGS THAT STAYED WRONG AFTER 3r.
--
-- 1. A GROUP IS RATED BY ITS OPEN MEMBERS. v_open_findings_dedup groups findings by
--    (asset_id, normalized_key) and took the group's severity, title and CVE list from ALL
--    members, closed ones included. After migration 20261023a closed the 24 Slider Revolution
--    advisories that never applied (false_positive), five Command sites kept a HIGH rating
--    with no open HIGH finding: the closed CVE-2026-6692 rows still carry HIGH, and the open
--    group took it (commandcompanies.com, www.commandcompanies.com,
--    commandmarketinginnovations.com, www.commandmarketinginnovations.com,
--    www.unimacgraphics.com - read 2026-10-23 11:40). The rating rule (20261022a) is "an
--    asset's rating is its single worst OPEN finding"; this view broke it for any group that
--    mixes open and closed members. Now: while a group has an open member, its severity,
--    title and CVE list come from its open members only; a group whose members are all
--    closed keeps the old reading (history unchanged). Same columns, same types, same order,
--    same security_invoker - v_asset_posture_counts (the portal's counts) and
--    v_fleet_open_reps (the weekly) read it unchanged and follow.
--
-- 2. "NO ENFORCING WAF" ROWS WRITTEN BEFORE push-329 -> MODERATE. Howie, 2026-10-21 (job 3b):
--    a proven absence on its own is MODERATE. push-329 applied that at write time only, so
--    the rows last written before it kept HIGH (2026-10-23: Command 5, Prodex 7), and an
--    offline host is never rewritten (valorep.prodexlabs.com). Howie, 2026-10-23 11:41: "We
--    are still showing a high with regard to the lack of a WAF. I thought we agreed on
--    cutting that back down to a medium." -> each such open row to MODERATE, audited row by
--    row (old severity logged). The next heavy scan writes the same value.
--
-- 3. Every asset's rating recomputed once with the one rule (refresh_all_asset_posture, as
--    20261022a did) - so the view change reaches assets with no new finding.
--
-- Shape: the house pattern (20261013a for the view; 20261013b / 20261023a for the audited
-- batch: a bounded guard, then WITH changed AS (UPDATE ... RETURNING) INSERT INTO
-- admin_audit_log ... FROM changed). Byte-identical in both repos. Re-applying changes
-- nothing: the view is replaced by itself, step 2 selects only rows still HIGH, and the
-- recompute is the trigger's own rule.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 15000
-- notes: Job 3r-b (Howie 2026-10-23 11:41 "I thought we agreed on cutting that back down to a medium."). v_open_findings_dedup rates a group by its open members while it has any (severity, title, cve), same columns; open waf-absent-differential rows still HIGH -> MODERATE (job 3b ruling), audited; refresh_all_asset_posture once. Touches no schema beyond the view. Byte-identical in both repos.
-- END-META

-- Guard: 2026-10-23 Command 5, Prodex 7. More than 20 is not this batch: abort, write nothing.
SELECT 1 / (CASE WHEN count(*) <= 20 THEN 1 ELSE 0 END) AS guard_waf_absence_high
  FROM public.findings f
 WHERE f.finding_id LIKE '%:commandsentry_heavy:waf-absent-differential:%'
   AND f.severity::text = 'HIGH'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed');

-- 1. v_open_findings_dedup: a group is rated by its open members -------------------------
-- (20261013a's definition; only the severity, title and cve expressions change.)
CREATE OR REPLACE VIEW public.v_open_findings_dedup
WITH (security_invoker = true) AS
WITH grouped AS (
  SELECT findings.asset_id,
         findings.normalized_key AS dedup_id,
         (array_agg(findings.severity ORDER BY
            (findings.current_status = ANY (ARRAY[
               'remediated'::finding_status_t,
               'validated_remediated'::finding_status_t,
               'false_positive'::finding_status_t,
               'wont_fix'::finding_status_t,
               'accepted_risk'::finding_status_t,
               'closed_reclassified'::finding_status_t,
               'detector_retired'::finding_status_t])),
            (CASE findings.severity
              WHEN 'CRITICAL'::severity_t      THEN 1
              WHEN 'HIGH'::severity_t          THEN 2
              WHEN 'MODERATE-HIGH'::severity_t THEN 3
              WHEN 'MODERATE'::severity_t      THEN 4
              WHEN 'LOW'::severity_t           THEN 5
              WHEN 'INFO'::severity_t          THEN 6
              ELSE 9
            END)))[1] AS severity,
         CASE
           WHEN bool_or(findings.current_status <> ALL (ARRAY[
                  'remediated'::finding_status_t,
                  'validated_remediated'::finding_status_t,
                  'false_positive'::finding_status_t,
                  'wont_fix'::finding_status_t,
                  'accepted_risk'::finding_status_t,
                  'closed_reclassified'::finding_status_t,
                  'detector_retired'::finding_status_t]))
             THEN 'detected'::finding_status_t
           ELSE (array_agg(findings.current_status))[1]
         END AS current_status,
         (array_agg(findings.title ORDER BY
            (findings.current_status = ANY (ARRAY[
               'remediated'::finding_status_t,
               'validated_remediated'::finding_status_t,
               'false_positive'::finding_status_t,
               'wont_fix'::finding_status_t,
               'accepted_risk'::finding_status_t,
               'closed_reclassified'::finding_status_t,
               'detector_retired'::finding_status_t])),
            (length(findings.title)) DESC NULLS LAST))[1] AS title,
         array_agg(DISTINCT findings.source ORDER BY findings.source) AS sources,
         count(*) AS source_count,
         min(findings.first_detected_at) AS first_detected_at,
         max(findings.last_observed_at) AS last_observed_at,
         CASE
           WHEN bool_or(findings.current_status <> ALL (ARRAY[
                  'remediated'::finding_status_t,
                  'validated_remediated'::finding_status_t,
                  'false_positive'::finding_status_t,
                  'wont_fix'::finding_status_t,
                  'accepted_risk'::finding_status_t,
                  'closed_reclassified'::finding_status_t,
                  'detector_retired'::finding_status_t]))
             THEN ( SELECT array_agg(DISTINCT c.c ORDER BY c.c) AS array_agg
                      FROM unnest(array_remove(array_cat_agg(findings.cve) FILTER (WHERE
                             findings.current_status <> ALL (ARRAY[
                               'remediated'::finding_status_t,
                               'validated_remediated'::finding_status_t,
                               'false_positive'::finding_status_t,
                               'wont_fix'::finding_status_t,
                               'accepted_risk'::finding_status_t,
                               'closed_reclassified'::finding_status_t,
                               'detector_retired'::finding_status_t])), NULL::text)) c(c)
                     WHERE c.c IS NOT NULL)
           ELSE ( SELECT array_agg(DISTINCT c.c ORDER BY c.c) AS array_agg
                    FROM unnest(array_remove(array_cat_agg(findings.cve), NULL::text)) c(c)
                   WHERE c.c IS NOT NULL)
         END AS cve,
         array_agg(findings.finding_id ORDER BY findings.first_detected_at) AS member_finding_ids
    FROM findings
   WHERE findings.normalized_key IS NOT NULL
   GROUP BY findings.asset_id, findings.normalized_key
), ungrouped AS (
  SELECT findings.asset_id,
         findings.finding_id AS dedup_id,
         findings.severity,
         findings.current_status,
         findings.title,
         ARRAY[findings.source] AS sources,
         1 AS source_count,
         findings.first_detected_at,
         findings.last_observed_at,
         findings.cve,
         ARRAY[findings.finding_id] AS member_finding_ids
    FROM findings
   WHERE findings.normalized_key IS NULL
)
SELECT grouped.asset_id, grouped.dedup_id, grouped.severity, grouped.current_status,
       grouped.title, grouped.sources, grouped.source_count, grouped.first_detected_at,
       grouped.last_observed_at, grouped.cve, grouped.member_finding_ids
  FROM grouped
UNION ALL
SELECT ungrouped.asset_id, ungrouped.dedup_id, ungrouped.severity, ungrouped.current_status,
       ungrouped.title, ungrouped.sources, ungrouped.source_count, ungrouped.first_detected_at,
       ungrouped.last_observed_at, ungrouped.cve, ungrouped.member_finding_ids
  FROM ungrouped;

-- 2. "No enforcing WAF" rows written before push-329 -> MODERATE ---------------------------
WITH changed AS (
  UPDATE public.findings f
     SET severity = 'MODERATE'::severity_t, updated_at = now()
   WHERE f.finding_id LIKE '%:commandsentry_heavy:waf-absent-differential:%'
   AND f.severity::text = 'HIGH'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
  RETURNING f.finding_id, f.asset_id, f.title, f.last_observed_at
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL, 'job_3r_waf_absence_moderate', NULL, NULL,
       jsonb_build_object('severity', 'HIGH'),
       jsonb_build_object('severity', 'MODERATE'),
       jsonb_build_object('finding_id', c.finding_id, 'asset_id', c.asset_id, 'title', c.title,
                          'last_observed_at', c.last_observed_at,
                          'reason', 'a proven absence of an enforcing WAF on its own is MODERATE '
                                    '(Howie 2026-10-21, job 3b); this row was last written before '
                                    'push-329 applied it (Howie 2026-10-23 11:41)',
                          'tool', '20261023b_open_members_rate_a_group.sql', 'rule', 'job_3b')
  FROM changed c;

-- 3. Once: every asset, the one rule ------------------------------------------------------
SELECT public.refresh_all_asset_posture();
