-- ============================================================================
-- 20261009a — close the public-key path to findings, assets and scan data
-- ============================================================================
--
-- WHAT WAS WRONG (found 2026-10-09, both instances, identical).
-- The portal hands every browser the project's publishable ("anon") key. That
-- is by design: row-level security (RLS) is what keeps that key from reading
-- anything until someone logs in. Two gaps went around it:
--
--   1. Ten views ran with their OWNER's rights (the Postgres default,
--      security_invoker off). The owner, postgres, bypasses RLS, so the anon
--      key could read every row behind them. v_open_findings alone is every
--      open finding (1,494 on Command on 2026-10-09). Two of them are simple
--      enough to be updatable (v_open_findings, v_alerter_high_risk_assets),
--      so the same key could also UPDATE or DELETE findings and assets through
--      them.
--   2. Eleven tables (ten on Prodex) had RLS switched off while the anon role
--      holds Supabase's default SELECT/INSERT/UPDATE/DELETE grants on them.
--
-- Supabase's own security advisor reports both (security_definer_view and
-- rls_disabled_in_public, level ERROR). The edge logs from 2026-09-28 on
-- (Command) and 2026-09-30 on (Prodex) show every read of these objects coming
-- from the portal's own server, none from anywhere else.
--
-- WHAT THIS CHANGES.
--   1. Every one of the ten views runs as the CALLER (security_invoker), so
--      the base tables' existing policies apply: a logged-in admin, asset
--      owner or viewer sees exactly what they saw before (each base table
--      already has an is_viewer_or_higher() or is_admin() select policy);
--      the anon key sees nothing.
--   2. RLS on for the eleven tables. The three the portal reads
--      (asset_tech_history, asset_template_cursor, device_class_dryrun) get the
--      same select rule the findings table uses. The other eight get no
--      policy: only the scanner, alerter and migrations read or write them,
--      and those connect as postgres, which bypasses RLS.
--   3. No writes through the views from the two API roles (belt and braces;
--      the portal never writes through a view).
--
-- WHAT IT DOES NOT CHANGE. No table, column or row. No view definition. The
-- scanner, alerter, migrate.yml and the scan gate connect as postgres
-- (SUPABASE_DSN) and are unaffected. recompute_asset_current_risk_for is
-- SECURITY DEFINER (owner postgres), so its read of v_open_findings_dedup
-- still sees every row. The portal's admin pages use the service-role key,
-- which bypasses RLS.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 300
-- notes: Permissions only. ALTER VIEW SET (security_invoker) on 10 views,
--   ENABLE ROW LEVEL SECURITY on 11 tables (IF EXISTS: p2_demotion_dryrun),
--   3 select policies (drop-if-exists then create), REVOKE writes on the 10
--   views from anon and authenticated. Every statement is idempotent.
--   Splitter-safe (no dollar-quoted blocks), byte-identical in both repos.
--   Verified on PostgreSQL 16 with production's own view, function, policy
--   and table definitions, with the repo's runner and scan gate. Production is
--   PostgreSQL 17.6; security_invoker exists since 15.
-- END-META
-- ============================================================================

begin;

-- 1. Views run as the caller, so base-table RLS applies.
alter view if exists public.v_open_findings            set (security_invoker = true);
alter view if exists public.v_open_findings_dedup      set (security_invoker = true);
alter view if exists public.v_asset_posture_counts     set (security_invoker = true);
alter view if exists public.v_dashboard_30d_metrics    set (security_invoker = true);
alter view if exists public.v_alerter_changes          set (security_invoker = true);
alter view if exists public.v_alerter_high_risk_assets set (security_invoker = true);
alter view if exists public.v_latest_scan_per_asset    set (security_invoker = true);
alter view if exists public.v_email_inbox_queue        set (security_invoker = true);
alter view if exists public.v_scan_queue_drift         set (security_invoker = true);
alter view if exists public.asset_tech_recent_changes  set (security_invoker = true);

-- 2. RLS on for every public table that had it off.
alter table if exists public.asset_tech_history     enable row level security;
alter table if exists public.asset_template_cursor  enable row level security;
alter table if exists public.device_class_dryrun    enable row level security;
alter table if exists public.active_probe_audit     enable row level security;
alter table if exists public.asset_fronting         enable row level security;
alter table if exists public.asset_liveness_verdict enable row level security;
alter table if exists public.cve_enrichments        enable row level security;
alter table if exists public.exploit_attempts       enable row level security;
alter table if exists public.schema_migrations      enable row level security;
alter table if exists public.vpn_slots              enable row level security;
alter table if exists public.p2_demotion_dryrun     enable row level security;

-- 3. The three tables the portal reads: the findings table's rule.
drop policy if exists asset_tech_history_role_select on public.asset_tech_history;
create policy asset_tech_history_role_select on public.asset_tech_history
    for select to authenticated using (public.is_viewer_or_higher());

drop policy if exists asset_template_cursor_role_select on public.asset_template_cursor;
create policy asset_template_cursor_role_select on public.asset_template_cursor
    for select to authenticated using (public.is_viewer_or_higher());

drop policy if exists device_class_dryrun_role_select on public.device_class_dryrun;
create policy device_class_dryrun_role_select on public.device_class_dryrun
    for select to authenticated using (public.is_viewer_or_higher());

-- 4. No writes through the views from the API roles.
revoke insert, update, delete, truncate on
    public.v_open_findings, public.v_open_findings_dedup,
    public.v_asset_posture_counts, public.v_dashboard_30d_metrics,
    public.v_alerter_changes, public.v_alerter_high_risk_assets,
    public.v_latest_scan_per_asset, public.v_email_inbox_queue,
    public.v_scan_queue_drift, public.asset_tech_recent_changes
  from anon, authenticated;

commit;
