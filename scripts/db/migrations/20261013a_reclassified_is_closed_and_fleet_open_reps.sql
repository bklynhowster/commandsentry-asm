-- ============================================================================
-- 20261013a — "reclassified" and "detector retired" count as CLOSED, and one
--             SQL definition of the fleet's open problems (v_fleet_open_reps)
-- ============================================================================
--
-- WHAT WAS WRONG (found 2026-10-11, note 307).
--   v_open_findings_dedup groups findings by (asset_id, normalized_key) and
--   calls a group open ('detected') when ANY member's status is outside its
--   closed list. That list was written in June (20260601a) and never learned
--   the two statuses added later:
--       closed_reclassified  (20260827a: "the observation moved elsewhere")
--       detector_retired     (20260902b: the detector no longer exists)
--   20260827a itself said "closed_reclassified should be filtered from active
--   views". It never was. On Command, 34 DMARC/SPF groups whose every member
--   was closed_reclassified on 2026-08-28 still counted as open: the dashboard
--   headline said 1,356 open while /findings (which reads the rows directly)
--   said 1,322, and four nameservers (ns01/ns02 .sciimage.com and
--   .commandcommcentral.com) carried risk MODERATE for findings that were
--   closed six weeks earlier. Prodex has no such rows today, but runs the
--   same view.
--
-- WHAT THIS CHANGES.
--   1. v_open_findings_dedup: the closed list gains closed_reclassified and
--      detector_retired. Nothing else in the view moves (same columns, same
--      types, same order, same security_invoker setting). v_asset_posture_counts
--      reads this view and needs no change of its own; it is re-created only
--      because CREATE OR REPLACE VIEW on a view another view depends on is
--      fine, but re-stating it keeps the two definitions reviewable together.
--   2. assets.current_risk is recomputed for every asset that has at least one
--      group now closed by rule 1, through the existing
--      recompute_asset_current_risk_for() (the same function the findings
--      trigger calls). On Command that is 18 assets; 14 keep their risk (other
--      findings remain) and the 4 nameservers go to UNKNOWN with the reason
--      "All N previously-detected findings are resolved." — which is the truth.
--   3. NEW view v_fleet_open_reps: the dashboard headline's counting rule, in
--      SQL, one row per open PROBLEM:
--        - in scope = the portal's isInScopeAsset (src/lib/scope.ts): owned;
--          not ct_ghost / went_dark / retired; 'unverified' only for IP and
--          range markers; a missing ownership reads as 'unknown' and a missing
--          discovery_status as 'unverified', as the portal does;
--        - an apex that is a bare two-label domain and has its www. host in
--          scope is ONE site (src/lib/posture.ts findApexWwwPairs); inside it,
--          findings collapse by the portal's dedupKey: normalized_key, else
--          CRITICAL/HIGH/MODERATE-HIGH are row-unique, else severity + source +
--          a slug of the title;
--        - every other in-scope asset contributes its v_open_findings_dedup
--          rows as they are.
--      The daily digest reads its "currently open" numbers from this view from
--      push-307c on, so the email and the dashboard count the same things.
--      The portal keeps its own TypeScript implementation for now; this view
--      is the reference the two are checked against.
--
-- WHAT IT DOES NOT CHANGE. No table, column or row in findings. No status is
-- rewritten. The scanner, the alerter's other queries, the ledger gate and
-- migrate.yml are unaffected.
--
-- SANITY QUERIES — after this applies.
--   1) The dashboard headline and /findings agree (Command: both 1,322 on
--      2026-10-13 data; the 34 reclassified groups are gone):
--        SELECT count(*) FROM public.v_open_findings_dedup
--         WHERE current_status IN ('detected','confirmed','open','regressed');
--   2) v_fleet_open_reps counts by severity equal the dashboard's chips:
--        SELECT severity, count(*) FROM public.v_fleet_open_reps GROUP BY 1;
--   3) The four nameservers read UNKNOWN with the "resolved" reason:
--        SELECT asset_id, current_risk, current_risk_reason FROM public.assets
--         WHERE asset_id LIKE 'ns0%';
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 1500
-- notes: CREATE OR REPLACE on two existing views (same columns, security_invoker kept), one new view, and one SELECT that calls recompute_asset_current_risk_for() for the affected assets (idempotent — recomputing twice gives the same answer). Splitter-safe (no dollar-quoted blocks). Byte-identical in both repos. Verified on PostgreSQL 16 with production's own table, view, function and trigger definitions (Command and Prodex shapes), with the repo's runner.
-- END-META

-- ── 1. v_open_findings_dedup: the closed list, complete ─────────────────────
CREATE OR REPLACE VIEW public.v_open_findings_dedup
WITH (security_invoker = true) AS
WITH grouped AS (
  SELECT findings.asset_id,
         findings.normalized_key AS dedup_id,
         (array_agg(findings.severity ORDER BY (
            CASE findings.severity
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
         (array_agg(findings.title ORDER BY (length(findings.title)) DESC NULLS LAST))[1] AS title,
         array_agg(DISTINCT findings.source ORDER BY findings.source) AS sources,
         count(*) AS source_count,
         min(findings.first_detected_at) AS first_detected_at,
         max(findings.last_observed_at) AS last_observed_at,
         ( SELECT array_agg(DISTINCT c.c ORDER BY c.c) AS array_agg
             FROM unnest(array_remove(array_cat_agg(findings.cve), NULL::text)) c(c)
            WHERE c.c IS NOT NULL) AS cve,
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

-- ── 2. v_asset_posture_counts: unchanged definition, re-stated ─────────────
CREATE OR REPLACE VIEW public.v_asset_posture_counts
WITH (security_invoker = true) AS
SELECT a.asset_id,
       a.name,
       a.organization,
       a.current_risk,
       count(f.dedup_id) FILTER (WHERE f.severity = 'CRITICAL'::severity_t)      AS critical_open,
       count(f.dedup_id) FILTER (WHERE f.severity = 'HIGH'::severity_t)          AS high_open,
       count(f.dedup_id) FILTER (WHERE f.severity = 'MODERATE-HIGH'::severity_t) AS mod_high_open,
       count(f.dedup_id) FILTER (WHERE f.severity = 'MODERATE'::severity_t)      AS moderate_open,
       count(f.dedup_id) FILTER (WHERE f.severity = 'LOW'::severity_t)           AS low_open,
       count(f.dedup_id) FILTER (WHERE f.severity = 'INFO'::severity_t)          AS info_open,
       count(f.dedup_id) AS total_open
  FROM assets a
  LEFT JOIN v_open_findings_dedup f
         ON f.asset_id = a.asset_id
        AND (f.current_status = ANY (ARRAY['detected'::finding_status_t, 'confirmed'::finding_status_t,
                                           'open'::finding_status_t, 'regressed'::finding_status_t]))
 GROUP BY a.asset_id, a.name, a.organization, a.current_risk;

-- ── 3. v_fleet_open_reps: one row per open problem, the dashboard's rule ───
CREATE OR REPLACE VIEW public.v_fleet_open_reps
WITH (security_invoker = true) AS
WITH scope AS (
  -- src/lib/scope.ts isInScopeAsset, over the same rows the dashboard reads
  -- (every asset; v_asset_posture_counts is a LEFT JOIN from assets).
  SELECT a.asset_id
    FROM public.assets a
   WHERE coalesce(a.ownership, 'unknown') = 'owned'
     AND coalesce(a.discovery_status, 'unverified') <> ALL (ARRAY['ct_ghost', 'went_dark', 'retired'])
     AND (coalesce(a.discovery_status, 'unverified') <> 'unverified'
          OR a.asset_id LIKE 'range:%'
          OR a.asset_id LIKE 'ip-range:%'
          OR a.asset_id LIKE 'ip:%'
          OR a.asset_id ~ '^[0-9.]+$')
), pairs AS (
  -- src/lib/posture.ts findApexWwwPairs + isBareApex
  SELECT s.asset_id AS apex
    FROM scope s
   WHERE s.asset_id NOT LIKE 'www.%'
     AND s.asset_id !~ '^[0-9.]+$'
     AND s.asset_id NOT LIKE 'range:%'
     AND s.asset_id NOT LIKE 'ip-range:%'
     AND s.asset_id NOT LIKE 'ip:%'
     AND array_length(string_to_array(s.asset_id, '.'), 1) = 2
     AND EXISTS (SELECT 1 FROM scope w WHERE w.asset_id = 'www.' || s.asset_id)
), members AS (
  SELECT p.apex, p.apex AS member FROM pairs p
  UNION ALL
  SELECT p.apex, 'www.' || p.apex FROM pairs p
), cluster_findings AS (
  -- src/lib/posture.ts dedupKey, over OPEN findings of both members
  SELECT m.apex,
         f.finding_id,
         f.asset_id,
         f.severity,
         f.title,
         f.first_detected_at,
         f.last_observed_at,
         CASE
           WHEN f.normalized_key IS NOT NULL THEN 'nk:' || f.normalized_key
           WHEN f.severity = ANY (ARRAY['CRITICAL'::severity_t, 'HIGH'::severity_t, 'MODERATE-HIGH'::severity_t])
             THEN 'high-no-fallback:' || f.finding_id
           ELSE 'tk:' || f.severity::text || ':' || coalesce(f.source::text, '') || ':'
                || trim(BOTH '-' FROM left(regexp_replace(lower(coalesce(f.title, '')), '[^a-z0-9]+', '-', 'g'), 120))
         END AS dedup_key,
         CASE f.severity
           WHEN 'CRITICAL'::severity_t THEN 1 WHEN 'HIGH'::severity_t THEN 2
           WHEN 'MODERATE-HIGH'::severity_t THEN 3 WHEN 'MODERATE'::severity_t THEN 4
           WHEN 'LOW'::severity_t THEN 5 WHEN 'INFO'::severity_t THEN 6 ELSE 9
         END AS sev_rank
    FROM members m
    JOIN public.findings f ON f.asset_id = m.member
   WHERE f.current_status = ANY (ARRAY['detected'::finding_status_t, 'confirmed'::finding_status_t,
                                       'open'::finding_status_t, 'regressed'::finding_status_t])
), cluster_reps AS (
  SELECT 'cluster'::text AS rep_kind,
         cf.apex AS scope_id,
         cf.dedup_key,
         (array_agg(cf.severity ORDER BY cf.sev_rank, cf.finding_id))[1] AS severity,
         (array_agg(cf.title ORDER BY cf.sev_rank, length(cf.title) DESC NULLS LAST, cf.finding_id))[1] AS title,
         min(cf.first_detected_at) AS first_detected_at,
         max(cf.last_observed_at) AS last_observed_at,
         count(*)::integer AS member_count,
         array_agg(cf.finding_id ORDER BY cf.sev_rank, cf.finding_id) AS member_finding_ids,
         array_agg(DISTINCT cf.asset_id) AS asset_ids
    FROM cluster_findings cf
   GROUP BY cf.apex, cf.dedup_key
), asset_reps AS (
  SELECT 'asset'::text AS rep_kind,
         v.asset_id AS scope_id,
         'view:' || v.dedup_id AS dedup_key,
         v.severity,
         v.title,
         v.first_detected_at,
         v.last_observed_at,
         v.source_count::integer AS member_count,
         v.member_finding_ids,
         ARRAY[v.asset_id] AS asset_ids
    FROM public.v_open_findings_dedup v
   WHERE v.current_status = ANY (ARRAY['detected'::finding_status_t, 'confirmed'::finding_status_t,
                                       'open'::finding_status_t, 'regressed'::finding_status_t])
     AND v.asset_id IN (SELECT asset_id FROM scope)
     AND v.asset_id NOT IN (SELECT member FROM members)
)
SELECT rep_kind, scope_id, dedup_key, severity, title, first_detected_at, last_observed_at,
       member_count, member_finding_ids, asset_ids
  FROM cluster_reps
UNION ALL
SELECT rep_kind, scope_id, dedup_key, severity, title, first_detected_at, last_observed_at,
       member_count, member_finding_ids, asset_ids
  FROM asset_reps;

-- Readable by signed-in portal users (RLS on the base tables applies, since
-- the view runs as the caller); the anon key gets nothing, as 20261009a set.
GRANT SELECT ON public.v_fleet_open_reps TO authenticated;
REVOKE ALL ON public.v_fleet_open_reps FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_fleet_open_reps FROM authenticated;

-- ── 4. Recompute current_risk where rule 1 closed a group ──────────────────
-- Every asset that has a normalized_key group whose members are ALL in the
-- closed list and at least one of them is closed_reclassified or
-- detector_retired: those groups counted as open until now.
SELECT public.recompute_asset_current_risk_for(g.asset_id)
  FROM (
    SELECT DISTINCT f.asset_id
      FROM public.findings f
     WHERE f.normalized_key IS NOT NULL
     GROUP BY f.asset_id, f.normalized_key
    HAVING bool_or(f.current_status = ANY (ARRAY['closed_reclassified'::finding_status_t,
                                                 'detector_retired'::finding_status_t]))
       AND NOT bool_or(f.current_status <> ALL (ARRAY[
             'remediated'::finding_status_t, 'validated_remediated'::finding_status_t,
             'false_positive'::finding_status_t, 'wont_fix'::finding_status_t,
             'accepted_risk'::finding_status_t, 'closed_reclassified'::finding_status_t,
             'detector_retired'::finding_status_t]))
  ) g;
