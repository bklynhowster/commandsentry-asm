-- ============================================================================
-- MIGRATION — 2026-05-21 — User Roles + Admin Audit Log (MVP)
--
-- Adds the role-based access control layer for the COMMANDsentry portal.
-- Scope is intentionally minimal for MVP: two roles (admin, viewer),
-- one user_roles join table, one admin_audit_log table.
--
-- Auth is already wired (Supabase email+password via @supabase/ssr in the
-- portal middleware). This migration adds the AUTHORIZATION layer on top —
-- who, with a valid session, can do what.
--
-- Design decisions (confirmed 2026-05-21):
--   - Invite flow: magic-link passwordless first-login (Supabase Auth handles)
--   - Default role: viewer (must be explicitly elevated to admin)
--   - Soft-delete only — never DELETE from user_roles or admin_audit_log
--   - Existing SELECT policies on assets/findings/scans stay as-is — they
--     already scope to `authenticated`, which any role-holder satisfies
--   - admin_audit_log is append-only by RLS (no UPDATE/DELETE policies)
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260521_user_roles_and_admin_audit.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. app_role enum — the canonical role list
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
    CREATE TYPE app_role AS ENUM ('admin', 'viewer');
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- 2. user_roles table — single role per user (one-to-one with auth.users)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_roles (
  user_id      uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  role         app_role NOT NULL DEFAULT 'viewer',
  granted_by   uuid REFERENCES auth.users(id),
  granted_at   timestamptz NOT NULL DEFAULT now(),
  -- Soft-deactivation: set is_active=false instead of deleting the row.
  is_active    boolean NOT NULL DEFAULT true,
  deactivated_by uuid REFERENCES auth.users(id),
  deactivated_at timestamptz,
  notes        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS user_roles_role_idx ON public.user_roles(role) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS user_roles_is_active_idx ON public.user_roles(is_active);

COMMENT ON TABLE public.user_roles IS
  'Per-user role assignment for the COMMANDsentry portal. One row per user. Soft-delete only — set is_active=false rather than deleting.';
COMMENT ON COLUMN public.user_roles.is_active IS
  'When false, the user is deactivated and should be treated as having no role at all (no SELECT, no anything).';

-- ---------------------------------------------------------------------------
-- 3. admin_audit_log — append-only record of admin actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.admin_audit_log (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id  uuid REFERENCES auth.users(id),
  action         text NOT NULL,           -- e.g., 'invite_user', 'change_role', 'deactivate_user'
  target_user_id uuid REFERENCES auth.users(id),
  target_email   text,                    -- captured at action time (durable if target user is later deleted)
  before_state   jsonb,
  after_state    jsonb,
  details        jsonb,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_audit_log_actor_idx ON public.admin_audit_log(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_log_target_idx ON public.admin_audit_log(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_log_action_idx ON public.admin_audit_log(action, created_at DESC);

COMMENT ON TABLE public.admin_audit_log IS
  'Append-only log of administrative actions. RLS denies UPDATE/DELETE — once a row is written it stays. Supports compliance audit requirements.';

-- ---------------------------------------------------------------------------
-- 4. Helper functions for RLS — public.is_admin(), public.has_role()
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.has_role(required_role app_role)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.user_roles ur
     WHERE ur.user_id = (SELECT auth.uid())
       AND ur.is_active = true
       AND ur.role = required_role
  );
$$;

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
  SELECT public.has_role('admin'::public.app_role);
$$;

CREATE OR REPLACE FUNCTION public.is_viewer_or_higher()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.user_roles ur
     WHERE ur.user_id = (SELECT auth.uid())
       AND ur.is_active = true
       AND ur.role IN ('admin'::public.app_role, 'viewer'::public.app_role)
  );
$$;

-- Grant execute to the authenticated role so the portal can call these.
GRANT EXECUTE ON FUNCTION public.has_role(app_role) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_viewer_or_higher() TO authenticated;

COMMENT ON FUNCTION public.is_admin() IS
  'Returns true iff the calling user has an active admin role assignment. Used in RLS policies for admin-only operations.';
COMMENT ON FUNCTION public.is_viewer_or_higher() IS
  'Returns true iff the calling user has any active role (viewer or admin). Use this for "any authenticated user with assigned access" gating — distinct from just "authenticated" which includes users who have no role yet.';

-- ---------------------------------------------------------------------------
-- 5. RLS — enable + policies on the new tables
-- ---------------------------------------------------------------------------

-- user_roles: only admins can read or modify.
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_roles_admin_select ON public.user_roles;
CREATE POLICY user_roles_admin_select ON public.user_roles
  FOR SELECT TO authenticated
  USING (public.is_admin());

DROP POLICY IF EXISTS user_roles_admin_insert ON public.user_roles;
CREATE POLICY user_roles_admin_insert ON public.user_roles
  FOR INSERT TO authenticated
  WITH CHECK (public.is_admin());

DROP POLICY IF EXISTS user_roles_admin_update ON public.user_roles;
CREATE POLICY user_roles_admin_update ON public.user_roles
  FOR UPDATE TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Intentionally NO delete policy. Soft-delete via is_active=false only.

-- Each user can SELECT their own role row (so the portal UI can show
-- "you are signed in as viewer" without needing admin privileges).
DROP POLICY IF EXISTS user_roles_self_select ON public.user_roles;
CREATE POLICY user_roles_self_select ON public.user_roles
  FOR SELECT TO authenticated
  USING (user_id = (SELECT auth.uid()));

-- admin_audit_log: admins can SELECT and INSERT. Nobody can UPDATE or DELETE.
ALTER TABLE public.admin_audit_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_log_admin_select ON public.admin_audit_log;
CREATE POLICY audit_log_admin_select ON public.admin_audit_log
  FOR SELECT TO authenticated
  USING (public.is_admin());

DROP POLICY IF EXISTS audit_log_admin_insert ON public.admin_audit_log;
CREATE POLICY audit_log_admin_insert ON public.admin_audit_log
  FOR INSERT TO authenticated
  WITH CHECK (public.is_admin() AND actor_user_id = (SELECT auth.uid()));

-- ---------------------------------------------------------------------------
-- 6. Tighten existing SELECT policies on assets/findings/scans/etc.
-- ---------------------------------------------------------------------------
-- Current policies allow any 'authenticated' user. We want any authenticated
-- user WITH AN ACTIVE ROLE assignment (admin or viewer). A user with a valid
-- session but no role row should NOT see data.
--
-- This protects against the case where someone signs up but hasn't been
-- granted a role yet — they shouldn't see the portal contents.

DROP POLICY IF EXISTS authenticated_read_assets ON public.assets;
CREATE POLICY assets_role_select ON public.assets
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

DROP POLICY IF EXISTS authenticated_read_findings ON public.findings;
CREATE POLICY findings_role_select ON public.findings
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

DROP POLICY IF EXISTS authenticated_read_scans ON public.scans;
CREATE POLICY scans_role_select ON public.scans
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

DROP POLICY IF EXISTS authenticated_read_finding_history ON public.finding_history;
CREATE POLICY finding_history_role_select ON public.finding_history
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

DROP POLICY IF EXISTS authenticated_read_evidence_artifacts ON public.evidence_artifacts;
CREATE POLICY evidence_artifacts_role_select ON public.evidence_artifacts
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

-- meta_alerter_runs: admin-only (it's operational metadata, not findings)
DROP POLICY IF EXISTS authenticated_read_meta_alerter_runs ON public.meta_alerter_runs;
CREATE POLICY meta_alerter_runs_admin_select ON public.meta_alerter_runs
  FOR SELECT TO authenticated
  USING (public.is_admin());

-- NOTE: ingestion (scripts/db/import_jsonl.py) connects with the service_role
-- key, which bypasses RLS by default. No INSERT/UPDATE policy changes needed
-- for the ingestion path — it continues to work as before.

-- ---------------------------------------------------------------------------
-- 7. Trigger: keep user_roles.updated_at fresh
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.touch_user_roles_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS user_roles_updated_at_trg ON public.user_roles;
CREATE TRIGGER user_roles_updated_at_trg
  BEFORE UPDATE ON public.user_roles
  FOR EACH ROW
  EXECUTE FUNCTION public.touch_user_roles_updated_at();

-- ---------------------------------------------------------------------------
-- 8. Seed Howie as admin (the existing single auth.users row)
-- ---------------------------------------------------------------------------
INSERT INTO public.user_roles (user_id, role, granted_by, notes)
SELECT u.id, 'admin'::app_role, u.id,
       'Bootstrap admin — seeded by migration 20260521_user_roles_and_admin_audit'
  FROM auth.users u
 WHERE u.email = 'hschneider@commandcompanies.com'
ON CONFLICT (user_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 9. Verification queries
-- ---------------------------------------------------------------------------
SELECT 'app_role enum values:' AS info;
SELECT unnest(enum_range(NULL::app_role)) AS app_role_values;

SELECT 'user_roles seeded rows:' AS info;
SELECT ur.user_id, u.email, ur.role, ur.is_active, ur.granted_at::date
  FROM public.user_roles ur
  JOIN auth.users u ON u.id = ur.user_id
 ORDER BY ur.granted_at;

SELECT 'Helper functions:' AS info;
SELECT proname, pronargs
  FROM pg_proc
 WHERE proname IN ('is_admin','has_role','is_viewer_or_higher')
   AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public');

SELECT 'Updated RLS policies on public schema:' AS info;
SELECT tablename, policyname, cmd
  FROM pg_policies
 WHERE schemaname='public'
 ORDER BY tablename, policyname;

COMMIT;

-- Manual smoke tests after applying:
--   1. As an anon user (no session): SELECT * FROM assets — should return 0 rows
--   2. As Howie (admin): SELECT * FROM assets — should return all rows
--   3. As Howie: SELECT * FROM user_roles — should return Howie's row
--   4. As Howie: SELECT * FROM admin_audit_log — should return 0 rows (none yet)
--   5. Create a test viewer user via the portal, assign role 'viewer',
--      sign in as them, confirm they can read assets but NOT user_roles.
