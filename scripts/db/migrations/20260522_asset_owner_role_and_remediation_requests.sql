-- ============================================================================
-- MIGRATION — 2026-05-22 — Asset Owner role + remediation request workflow
--
-- Adds the third app_role and the workflow table behind the "request retest"
-- feature. Builds on 20260521_user_roles_and_admin_audit.sql.
--
-- Design (confirmed 2026-05-22):
--   - Three-role model: admin, asset_owner, viewer
--   - asset_owner can read everything and flip a finding from open → remediated
--     (= "I think I fixed it, please verify"). Cannot change severity, manage
--     users, run scans, or mark validated_remediated.
--   - Permissions are FLAT in v1 — any asset_owner can act on any finding.
--     Per-org scoping (Anil → Unimac etc.) is deferred to v2.
--   - Separation of duties baked into the finding_status_t enum already
--     (remediated → validated_remediated requires admin). NIST AC-5 /
--     ISO 27001 A.9.2.3.
--   - remediation_requests is append-only. Each retest cycle is its own row.
--   - Email notifications fire from server actions, not from DB triggers
--     (cleaner failure handling + branded templates live in app code).
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260522_asset_owner_role_and_remediation_requests.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Extend app_role enum with 'asset_owner'
--    Postgres requires ALTER TYPE ... ADD VALUE outside a transaction in
--    older versions, but PG13+ allows it inside if not used same-tx. We
--    add the value first, then COMMIT, then create the helpers in a
--    second transaction so the new enum value is visible.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_enum
     WHERE enumlabel = 'asset_owner'
       AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'app_role')
  ) THEN
    ALTER TYPE app_role ADD VALUE 'asset_owner';
  END IF;
END$$;

COMMIT;

-- ---------------------------------------------------------------------------
-- Second transaction — helpers + remediation_requests table + RLS
-- ---------------------------------------------------------------------------
BEGIN;

-- ---------------------------------------------------------------------------
-- 2. Helper functions for the new role
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.is_asset_owner()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
  SELECT public.has_role('asset_owner'::public.app_role);
$$;

CREATE OR REPLACE FUNCTION public.can_remediate()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
STABLE
AS $$
  -- Admin or asset_owner can submit remediation requests.
  SELECT EXISTS (
    SELECT 1
      FROM public.user_roles ur
     WHERE ur.user_id = (SELECT auth.uid())
       AND ur.is_active = true
       AND ur.role IN ('admin'::public.app_role, 'asset_owner'::public.app_role)
  );
$$;

-- Update is_viewer_or_higher to include the new role. Any active role
-- counts as "viewer or higher" for purposes of reading the portal.
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
       AND ur.role IN (
         'admin'::public.app_role,
         'asset_owner'::public.app_role,
         'viewer'::public.app_role
       )
  );
$$;

GRANT EXECUTE ON FUNCTION public.is_asset_owner() TO authenticated;
GRANT EXECUTE ON FUNCTION public.can_remediate() TO authenticated;

COMMENT ON FUNCTION public.is_asset_owner() IS
  'Returns true iff the calling user has an active asset_owner role assignment.';
COMMENT ON FUNCTION public.can_remediate() IS
  'Returns true iff the calling user can submit/edit remediation requests (admin or asset_owner).';

-- ---------------------------------------------------------------------------
-- 3. remediation_requests table
--    Append-only workflow record. One row per retest submission. Admin
--    review fills in the verification fields on the same row (no separate
--    table) — keeps the request → outcome lineage in one place.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.remediation_requests (
  id                      bigserial   PRIMARY KEY,
  finding_id              text        NOT NULL REFERENCES public.findings(finding_id) ON DELETE CASCADE,

  -- Who submitted (asset_owner or admin)
  submitted_by            uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  submitted_by_email      text        NOT NULL,   -- durable snapshot
  submitted_at            timestamptz NOT NULL DEFAULT now(),
  submitter_notes         text        NOT NULL,
  finding_status_at_submission public.finding_status_t NOT NULL,

  -- Admin review fields (NULL until reviewed)
  reviewed_by             uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  reviewed_by_email       text,
  reviewed_at             timestamptz,
  review_outcome          text        CHECK (review_outcome IN (
                                              'validated_remediated',
                                              'regressed',
                                              'still_open',
                                              'false_positive'
                                            )),
  reviewer_notes          text,

  -- Lifecycle status of the request itself
  request_status          text        NOT NULL DEFAULT 'pending'
                                       CHECK (request_status IN ('pending', 'reviewed', 'cancelled')),

  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rr_finding_id_idx ON public.remediation_requests(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rr_status_idx     ON public.remediation_requests(request_status) WHERE request_status = 'pending';
CREATE INDEX IF NOT EXISTS rr_submitter_idx  ON public.remediation_requests(submitted_by, created_at DESC);

COMMENT ON TABLE public.remediation_requests IS
  'Asset-owner retest submissions + admin verification outcomes. Append-only — each retest cycle is a new row. Email notifications fire from server actions.';

-- Touch updated_at on review.
CREATE OR REPLACE FUNCTION public.touch_remediation_request_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS remediation_requests_updated_at_trg ON public.remediation_requests;
CREATE TRIGGER remediation_requests_updated_at_trg
  BEFORE UPDATE ON public.remediation_requests
  FOR EACH ROW
  EXECUTE FUNCTION public.touch_remediation_request_updated_at();

-- ---------------------------------------------------------------------------
-- 4. RLS on remediation_requests
-- ---------------------------------------------------------------------------
ALTER TABLE public.remediation_requests ENABLE ROW LEVEL SECURITY;

-- Admin can SELECT all rows (for the review queue)
DROP POLICY IF EXISTS rr_admin_select ON public.remediation_requests;
CREATE POLICY rr_admin_select ON public.remediation_requests
  FOR SELECT TO authenticated
  USING (public.is_admin());

-- Asset owners and viewers can SELECT rows for findings they can already
-- see — RLS on findings already gates which findings each user can read.
-- We expose remediation_requests parallel to that: any user who can see
-- the finding can see its request history.
DROP POLICY IF EXISTS rr_viewer_select ON public.remediation_requests;
CREATE POLICY rr_viewer_select ON public.remediation_requests
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher());

-- INSERT: admin or asset_owner. submitted_by must match the caller's uid.
DROP POLICY IF EXISTS rr_remediator_insert ON public.remediation_requests;
CREATE POLICY rr_remediator_insert ON public.remediation_requests
  FOR INSERT TO authenticated
  WITH CHECK (
    public.can_remediate()
    AND submitted_by = (SELECT auth.uid())
  );

-- UPDATE: admin only (filling in review fields). No one else can edit
-- a request once submitted — append-only for asset owners.
DROP POLICY IF EXISTS rr_admin_update ON public.remediation_requests;
CREATE POLICY rr_admin_update ON public.remediation_requests
  FOR UPDATE TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- DELETE: nobody via RLS. Soft-state-change via request_status='cancelled' only.

-- ---------------------------------------------------------------------------
-- 5. Verification queries
-- ---------------------------------------------------------------------------
SELECT 'app_role values (should include asset_owner):' AS info;
SELECT unnest(enum_range(NULL::app_role)) AS app_role_values;

SELECT 'Helper functions for new role:' AS info;
SELECT proname
  FROM pg_proc
 WHERE proname IN ('is_asset_owner','can_remediate','is_viewer_or_higher','is_admin','has_role')
   AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')
 ORDER BY proname;

SELECT 'remediation_requests RLS policies:' AS info;
SELECT policyname, cmd
  FROM pg_policies
 WHERE schemaname='public' AND tablename='remediation_requests'
 ORDER BY policyname;

COMMIT;
