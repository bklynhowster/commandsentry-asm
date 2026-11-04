-- 20261104a_site_face.sql
--
-- KB 12 job 4, plan v1.3, step 1 (2026-11-04). EACH SITE IS THE NAME THE BROWSER LANDS ON: THE
-- COLUMN THAT WILL HOLD IT, THE VIEW THAT WILL READ IT, AND ONE WRONG apex_domain.
--
-- Howie, 2026-11-04 (D6, multiple choice): "Where the browser lands (Recommended)": each site is
-- the name a visitor's browser ends up on (commandcompanies.com, commandmarketinginnovations.com,
-- unimacgraphics.com, www.prodexlabs.com, www.commandcommcentral.com); Sentry deep-scans and shows
-- that name; the other name keeps its quick scan. site_members.py already measures it on every
-- discovery run (one GET per name, no redirect followed): www 301 -> plain on the three Command
-- sites, plain 301 -> www on prodexlabs.com, both 200 with the same page on commandcommcentral.com.
--
-- What this does:
--   1. site_members.face_asset_id: which of the pair's two names is the site's face. NULL until
--      the discovery push (plan step 3) writes it; it can only be one of the row's two names.
--   2. v_site_of: both names of a 'same_site' pair map to the face; with no face, to the plain
--      name exactly as 20261025b did (the www name moves to it, the plain name stays itself).
--      Every reader (both digests, the alerter's site map, v_fleet_open_reps) is unchanged and
--      sees today's answer until a face is written. Same columns, same grants, caller's rights.
--   3. A 'same_site' www name whose apex_domain is NULL gets its plain name. Only Prodex has one:
--      www.prodexlabs.com, read as an apex by the quick scan's email check (run_light.py
--      check_dns_posture: a NULL apex_domain means "this row is the apex"), so it carries
--      "DNS missing SPF record" and "DNS missing DMARC record" although it sends no mail (no
--      MX, no SPF, no CNAME) and prodexlabs.com publishes both. Prodex's 115 other subdomain
--      rows already carry 'prodexlabs.com'; the importer never rewrites apex_domain on an
--      existing row. On Command every same_site www row already carries its plain name: there
--      it changes no row. One admin_audit_log row per changed asset, once, written before the
--      change so it records the NULL.
--
-- No finding changes here (plan step 4 is a later, separate migration). Byte-identical in both
-- repos. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 200
-- notes: Job 4 plan v1.3 step 1 (Howie 2026-11-04 D6 "Where the browser lands"). site_members gains face_asset_id (NULL until the discovery push writes it, CHECK: one of the row's two names); v_site_of maps both names of a same_site pair to coalesce(face, plain), identical to 20261025b while faces are NULL; a same_site www row with a NULL apex_domain gets its plain name (Prodex www.prodexlabs.com only; none on Command), audited once per asset before the change. No finding touched. No dollar-quoting. Byte-identical in both repos.
-- END-META

ALTER TABLE public.site_members ADD COLUMN IF NOT EXISTS face_asset_id text;

ALTER TABLE public.site_members DROP CONSTRAINT IF EXISTS site_members_face_is_one_of_the_pair;

ALTER TABLE public.site_members ADD CONSTRAINT site_members_face_is_one_of_the_pair
  CHECK (face_asset_id IS NULL OR face_asset_id = member_asset_id OR face_asset_id = site_asset_id);

COMMENT ON COLUMN public.site_members.face_asset_id IS
  'KB 12 job 4 (2026-11-04, Howie D6): the name the site is shown and deep-scanned under, the one a visitor''s browser lands on. Written by site_members.py from its own no-follow reading (a redirect pair: the name that answered 2xx; a same_page pair: the www name), set or changed only after two definite runs agree. NULL = not yet known: readers use the plain name (site_asset_id), as before.';

CREATE OR REPLACE VIEW public.v_site_of
WITH (security_invoker = true) AS
SELECT a.asset_id,
       coalesce(sw.face_asset_id, sw.site_asset_id, sp.face_asset_id, a.asset_id) AS site_asset_id
  FROM public.assets a
  LEFT JOIN public.site_members sw
         ON sw.member_asset_id = a.asset_id
        AND sw.verdict = 'same_site'
  LEFT JOIN public.site_members sp
         ON sp.site_asset_id = a.asset_id
        AND sp.verdict = 'same_site';

GRANT SELECT ON public.v_site_of TO authenticated;
REVOKE ALL ON public.v_site_of FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_site_of FROM authenticated;

INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'site_member_apex_domain_set',
       jsonb_build_object('apex_domain', NULL),
       jsonb_build_object('apex_domain', sm.site_asset_id),
       jsonb_build_object('asset_id', a.asset_id, 'migration', '20261104a', 'ruling', 'Howie 2026-11-04 D6; KB 12 job 4 plan v1.3 step 1')
  FROM public.assets a
  JOIN public.site_members sm
    ON sm.member_asset_id = a.asset_id
   AND sm.verdict = 'same_site'
 WHERE a.apex_domain IS NULL
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'site_member_apex_domain_set'
                      AND l.details ->> 'asset_id' = a.asset_id
                      AND l.details ->> 'migration' = '20261104a');

UPDATE public.assets a
   SET apex_domain = sm.site_asset_id
  FROM public.site_members sm
 WHERE sm.member_asset_id = a.asset_id
   AND sm.verdict = 'same_site'
   AND a.apex_domain IS NULL;
