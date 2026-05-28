-- ============================================================================
-- MIGRATION — 2026-05-22 (c) — Finding feedback (any-user feedback channel)
--
-- Lets ALL signed-in users (viewer, asset_owner, admin) submit tagged
-- feedback about any finding without altering finding state. Distinct
-- from remediation_requests, which only admin + asset_owner can submit
-- and which DO change finding state.
--
-- Use cases:
--   - Viewer (Anil reading a CCC finding):
--       "This looks like the same as M-04 — possible duplicate"
--       "I don't understand step 3 of the remediation"
--       "We saw exploit attempts against this in our logs today"
--   - Asset owner:
--       Same as viewer; plus collaborative comments alongside their claims
--   - Admin:
--       Internal notes for the next admin who looks at this finding
--
-- Persistence: append-only by user-side actions. No DELETE policy. Admin
-- can change `status` (open → addressed / dismissed) but the row stays
-- forever for audit. Every status change is logged in admin_audit_log.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260522c_finding_feedback.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. finding_feedback table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.finding_feedback (
  id                  bigserial   PRIMARY KEY,
  finding_id          text        NOT NULL REFERENCES public.findings(finding_id) ON DELETE CASCADE,

  -- Submitter
  submitted_by        uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  submitted_by_email  text        NOT NULL,             -- durable snapshot
  submitter_role      text        NOT NULL,             -- 'admin' | 'asset_owner' | 'viewer'
  submitted_at        timestamptz NOT NULL DEFAULT now(),

  -- Content
  feedback_tag        text        NOT NULL,             -- see CHECK below
  notes               text        NOT NULL CHECK (length(notes) >= 10),

  -- Admin triage
  status              text        NOT NULL DEFAULT 'open',
  addressed_by        uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  addressed_by_email  text,
  addressed_at        timestamptz,
  addressed_notes     text,                              -- admin's response (optional)

  -- Soft hide — if admin marks abusive/spam, don't show on finding page
  -- but keep the row for audit. Distinct from dismissed (which is the
  -- normal "we looked at it, no action needed" close).
  hidden              boolean     NOT NULL DEFAULT false,

  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Allowed tags
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'finding_feedback_tag_check'
       AND conrelid = 'public.finding_feedback'::regclass
  ) THEN
    ALTER TABLE public.finding_feedback
      ADD CONSTRAINT finding_feedback_tag_check
      CHECK (feedback_tag IN (
        'suspicious_urgent',
        'possible_duplicate',
        'remediation_question',
        'data_quality',
        'other'
      ));
  END IF;
END$$;

-- Allowed statuses
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'finding_feedback_status_check'
       AND conrelid = 'public.finding_feedback'::regclass
  ) THEN
    ALTER TABLE public.finding_feedback
      ADD CONSTRAINT finding_feedback_status_check
      CHECK (status IN ('open', 'addressed', 'dismissed'));
  END IF;
END$$;

-- Allowed submitter roles (mirror of app_role enum, but stored as text snapshot)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'finding_feedback_submitter_role_check'
       AND conrelid = 'public.finding_feedback'::regclass
  ) THEN
    ALTER TABLE public.finding_feedback
      ADD CONSTRAINT finding_feedback_submitter_role_check
      CHECK (submitter_role IN ('admin', 'asset_owner', 'viewer'));
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_finding_feedback_finding
  ON public.finding_feedback(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_feedback_status
  ON public.finding_feedback(status) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_finding_feedback_submitter
  ON public.finding_feedback(submitted_by, created_at DESC);

COMMENT ON TABLE public.finding_feedback IS
  'User-submitted feedback about findings — questions, duplicate flags, urgent escalations, data-quality concerns. Distinct from remediation_requests (which mutate finding state). Append-only by user; admin triages via status field. Persists forever for audit.';

-- Touch updated_at on any update.
CREATE OR REPLACE FUNCTION public.touch_finding_feedback_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS finding_feedback_updated_at_trg ON public.finding_feedback;
CREATE TRIGGER finding_feedback_updated_at_trg
  BEFORE UPDATE ON public.finding_feedback
  FOR EACH ROW
  EXECUTE FUNCTION public.touch_finding_feedback_updated_at();

-- ---------------------------------------------------------------------------
-- 2. RLS
-- ---------------------------------------------------------------------------
ALTER TABLE public.finding_feedback ENABLE ROW LEVEL SECURITY;

-- SELECT: any user with any active role can read feedback. Hidden rows
-- are still visible to admins; viewers/asset_owners only see non-hidden.
DROP POLICY IF EXISTS feedback_admin_select ON public.finding_feedback;
CREATE POLICY feedback_admin_select ON public.finding_feedback
  FOR SELECT TO authenticated
  USING (public.is_admin());

DROP POLICY IF EXISTS feedback_role_select ON public.finding_feedback;
CREATE POLICY feedback_role_select ON public.finding_feedback
  FOR SELECT TO authenticated
  USING (public.is_viewer_or_higher() AND hidden = false);

-- INSERT: any user with an active role can submit. submitted_by must
-- match the caller's uid (no impersonation).
DROP POLICY IF EXISTS feedback_role_insert ON public.finding_feedback;
CREATE POLICY feedback_role_insert ON public.finding_feedback
  FOR INSERT TO authenticated
  WITH CHECK (
    public.is_viewer_or_higher()
    AND submitted_by = (SELECT auth.uid())
  );

-- UPDATE: admin only (status changes, hide flag, response notes).
DROP POLICY IF EXISTS feedback_admin_update ON public.finding_feedback;
CREATE POLICY feedback_admin_update ON public.finding_feedback
  FOR UPDATE TO authenticated
  USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- DELETE: nobody via RLS. Soft-state-change only.

-- ---------------------------------------------------------------------------
-- 3. Verification
-- ---------------------------------------------------------------------------
SELECT 'finding_feedback table created:' AS info;
SELECT column_name, data_type, column_default
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND table_name = 'finding_feedback'
 ORDER BY ordinal_position;

SELECT 'finding_feedback check constraints:' AS info;
SELECT conname, pg_get_constraintdef(oid) AS definition
  FROM pg_constraint
 WHERE conrelid = 'public.finding_feedback'::regclass
   AND contype = 'c'
 ORDER BY conname;

SELECT 'finding_feedback RLS policies:' AS info;
SELECT policyname, cmd
  FROM pg_policies
 WHERE schemaname='public' AND tablename='finding_feedback'
 ORDER BY policyname;

COMMIT;
