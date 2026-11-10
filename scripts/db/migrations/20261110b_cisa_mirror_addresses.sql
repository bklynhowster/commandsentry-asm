-- 20261110b_cisa_mirror_addresses.sql
--
-- PRODEX PLAN 2026-11-10: A SEPARATE ADDRESS AREA, SCANNED THE WAY CISA DOES.
-- Howie, 10:48: "we could have a section that just does the names as we do now, and then
-- we could have another section that does the IP addresses." 10:49: "forget about Command.
-- This is a Prodex-only thing, so I don't want to add anything to Command." Plan written
-- 11:05 ([[2026-11-10 1100 - plan - Prodex address area, scanned the way CISA does]]),
-- go 12:27 ("Yes.").
--
-- ONE THING: public.cisa_mirror_addresses, the addresses on ProDex's CISA Cyber Hygiene
-- authorization that Sentry scans the way CISA scans them. Each row carries:
--   - names: the names that should point at the address. The scanner's safety rail
--     (poll_queue.cisa_mirror_block): a scan of the address goes ahead only while at
--     least one of them resolves to it; otherwise the claim is aborted, nothing scanned.
--   - priority / next_scan_at / last_counted_scan_run: CISA's rescan state (cyhy-core
--     scheduler.py: new addresses start at priority 0; cisa_mirror.next_priority moves it
--     one scan at a time). Written by the scheduler job, not by this migration.
--
-- PRODEX ONLY. The ten rows go in only where the Prodex apex is an owned asset
-- (public.assets 'prodexlabs.com'); on Command, which has no such asset (read 2026-11-10
-- 12:4x), the table is created and stays empty, and nothing reads it there.
--
-- Adds no asset and starts no scan. The addresses become assets when they are added to
-- Prodex's data/targets.yml (a later push); until then no row here matches an asset.
-- Names as resolved from the workspace 2026-11-10 12:4x ET, equal to the CISA sheet
-- "CISA scan list - ProDex public IPs for verification (2026-11-10)". Left out on purpose:
-- the ten outbound-only Cloud NAT addresses, and anything not on the sheet.
--
-- Reversal: DROP TABLE public.cisa_mirror_addresses; (nothing else depends on it in this
-- migration). Lands in BOTH databases; the repos ship byte-identical.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 500
-- notes: Prodex plan 2026-11-10 (Howie 10:48-10:49, go 12:27). New table public.cisa_mirror_addresses (address PK, an IPv4 address only; names text[] non-empty; what; reserved; priority int default 0; next_scan_at; last_counted_scan_run; added_at; added_by). RLS on, no policies, anon/authenticated revoked. Ten rows, the inbound addresses on ProDex's CISA Cyber Hygiene list, inserted only where public.assets holds the owned Prodex apex prodexlabs.com (none on Command). Guard: after the insert the table holds 0 or exactly 10 rows. No asset, finding or view touched. Splitter-safe (no dollar-quoted blocks).
-- END-META

BEGIN;

CREATE TABLE IF NOT EXISTS public.cisa_mirror_addresses (
  address               text        PRIMARY KEY
                                    CHECK (address ~ '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'),
  names                 text[]      NOT NULL CHECK (cardinality(names) > 0),
  what                  text        NOT NULL,
  reserved              boolean     NOT NULL,
  priority              integer     NOT NULL DEFAULT 0,
  next_scan_at          timestamptz NULL,
  last_counted_scan_run text        NULL,
  added_at              timestamptz NOT NULL DEFAULT now(),
  added_by              text        NOT NULL DEFAULT 'migration 20261110b (Prodex plan 2026-11-10)'
);

COMMENT ON TABLE public.cisa_mirror_addresses IS
  'Prodex plan 2026-11-10: the addresses on ProDex''s CISA Cyber Hygiene authorization that '
  'Sentry scans the way CISA does (every TCP port, CISA''s ping, CISA''s risky services, CISA''s '
  'rescan schedule). A scan of an address goes ahead only while one of its names resolves to '
  'it (poll_queue.cisa_mirror_block). Empty on Command.';

ALTER TABLE public.cisa_mirror_addresses ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.cisa_mirror_addresses FROM anon, authenticated;

INSERT INTO public.cisa_mirror_addresses (address, names, what, reserved)
SELECT v.address, v.names, v.what, v.reserved
  FROM (VALUES
    ('136.81.173.196', ARRAY['prod.prodexlabs.com', 'bitec.prodexlabs.com', 'dass.prodexlabs.com',
                             'demo.prodexlabs.com', 'highcom.prodexlabs.com', 'l3h-ivs.prodexlabs.com',
                             'l3h-nh.prodexlabs.com', 'l3h-ss.prodexlabs.com', 'littleleaffarms.prodexlabs.com',
                             'panthalassa.prodexlabs.com', 'time.prodexlabs.com', 'trial.prodexlabs.com'],
     'production front door (prodex-production)', true),
    ('136.81.178.35',  ARRAY['staging.prodexlabs.com'], 'staging front door (prodex-staging)', true),
    ('136.69.87.98',   ARRAY['uat.prodexlabs.com'], 'UAT front door (prodex-uat)', true),
    ('34.54.236.210',  ARRAY['preview.prodexlabs.com'], 'preview front door (prodex-preview)', true),
    ('136.81.198.25',  ARRAY['sandbox.prodexlabs.com', 'oidc-test.prodexlabs.com'], 'sandbox front door (prodex-sandbox)', true),
    ('34.67.20.186',   ARRAY['atlantis-gcp.prodexlabs.com'], 'atlantis-gcp, a Kubernetes load balancer (prodex-sandbox); not reserved, can change', false),
    ('34.36.153.196',  ARRAY['tour.prodexlabs.com'], 'tour (prodex-demo-501115)', true),
    ('8.232.147.166',  ARRAY['prodexlabs.com', 'www.prodexlabs.com', 'cooked.prodexlabs.com'], 'the website (prodex-website-8f8e)', true),
    ('136.81.194.166', ARRAY['prosalud.prodexlabs.com'], 'ProSalud front door (ttd-may-11)', true),
    ('136.81.196.61',  ARRAY['prosalud-staging.prodexlabs.com'], 'ProSalud staging front door (ttd-may-11)', true)
  ) AS v (address, names, what, reserved)
 WHERE EXISTS (SELECT 1 FROM public.assets a
                WHERE a.asset_id = 'prodexlabs.com' AND a.ownership = 'owned')
ON CONFLICT (address) DO NOTHING;

-- Guard: none (Command) or exactly the ten (Prodex). Anything else stops the migration.
SELECT 1 / (CASE WHEN (SELECT count(*) FROM public.cisa_mirror_addresses) IN (0, 10) THEN 1 ELSE 0 END) AS guard_none_or_ten;

COMMIT;
