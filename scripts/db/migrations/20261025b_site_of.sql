-- 20261025b_site_of.sql
--
-- KB 12 job 4 (2026-10-25). ONE SITE, NOT TWO — readers ask the evidence (migration B of two).
--
-- Howie, 2026-10-24 21:44: "it's the same damn box it's the same site. It's the same everything
-- this has to be fixed as well." Ruled 2026-10-25 08:46 (D1, "Yes"): a www name and its plain name
-- are one site only on evidence seen on both names, never because of what the names look like.
--
-- Migration A (20261025a) made public.site_members; discovery has filled it since push-340. This
-- migration makes the readers use it:
--   1. NEW view v_site_of(asset_id, site_asset_id): every asset maps to itself, except a www name
--      whose site_members row says verdict = 'same_site', which maps to its plain name. A pair
--      still waiting for its first definite reading (verdict NULL), or read 'separate', stays two.
--   2. v_fleet_open_reps (last defined in 20261013a, unchanged since) replaced in place: its
--      pairs come from v_site_of instead of "a two-label name whose www twin exists". Everything
--      else in the view (scope, dedup key, columns, order, grants) is 20261013a's, byte for byte.
--      Today's evidence merges the same five pairs the name rule did; the three Unimac
--      www.<sub> names were never in the name rule's pairs (three labels), so nothing changes
--      count here — the digest's own name rule (push B) is where those three stop folding.
--
-- Both views run as the caller (security_invoker), so site_members' RLS applies: the alerter
-- (database owner) and portal users with a role see the pairs; anyone else sees every asset as
-- its own site, which un-merges nothing they could see anyway.
-- Byte-identical in both repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 500
-- notes: Job 4 migration B (Howie 2026-10-25 08:46, D1 "Yes"; after the site_members read-back). New view public.v_site_of (asset -> its site, from site_members verdict 'same_site'); v_fleet_open_reps replaced in place with its pairs read from v_site_of (columns, scope rule, dedup key and grants unchanged from 20261013a). Both security_invoker. No table, no data, no function. Byte-identical in both repos.
-- END-META

-- ── 1. v_site_of: which site each asset belongs to, from evidence ─────────────
CREATE OR REPLACE VIEW public.v_site_of
WITH (security_invoker = true) AS
SELECT a.asset_id,
       coalesce(sm.site_asset_id, a.asset_id) AS site_asset_id
  FROM public.assets a
  LEFT JOIN public.site_members sm
         ON sm.member_asset_id = a.asset_id
        AND sm.verdict = 'same_site';

GRANT SELECT ON public.v_site_of TO authenticated;
REVOKE ALL ON public.v_site_of FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_site_of FROM authenticated;

-- ── 2. v_fleet_open_reps: pairs from the evidence, everything else as 20261013a ──
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
), site_pairs AS (
  -- Job 4 (migration B): src/lib/posture.ts findApexWwwPairs with the site_members pairs.
  -- A pair counts only when both names are in scope, as before.
  SELECT so.site_asset_id AS apex, so.asset_id AS member
    FROM public.v_site_of so
   WHERE so.asset_id <> so.site_asset_id
     AND so.asset_id IN (SELECT asset_id FROM scope)
     AND so.site_asset_id IN (SELECT asset_id FROM scope)
), members AS (
  SELECT DISTINCT p.apex, p.apex AS member FROM site_pairs p
  UNION ALL
  SELECT p.apex, p.member FROM site_pairs p
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
