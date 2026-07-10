-- 20260701 — grant the dashboard Recent-changes panel read access.
--
-- The dashboard Recent-changes panel (2026-07-01) reads public.v_alerter_changes
-- as the authenticated portal role to mirror the daily posture digest. That view
-- was created for the alerter (scripts/db/alerter.sql), which connects as
-- service_role and bypasses grants/RLS — so it was never granted to authenticated.
-- Without this grant the panel's PostgREST SELECT returns permission-denied, the
-- page's non-fatal changeErr branch swallows it, and the panel silently renders
-- nothing.
--
-- Mirrors the explicit per-view grants already in place for
-- v_asset_posture_counts (20260601c) and v_dashboard_30d_metrics (maintenance.sql).
--
-- Safe: SELECT-only, on a view whose base tables (findings, finding_history)
-- already carry authenticated_read RLS policies (scripts/db/rls.sql).

grant select on public.v_alerter_changes to authenticated;
