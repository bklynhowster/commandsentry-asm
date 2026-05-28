-- ============================================================================
-- MIGRATION — 2026-05-21 (b) — Fix admin_audit_log FK on-delete behavior
--
-- Bug found: deleting an auth.users row fails with "Database error deleting
-- user" when the user has any rows in admin_audit_log (either as actor or
-- target). The original migration declared the FKs without an ON DELETE
-- clause, so Postgres defaults to NO ACTION (rejects the delete).
--
-- That breaks the test-user cleanup flow we need today: invite a throwaway
-- email, verify the email looks right, delete the auth user, re-invite, etc.
--
-- Audit-log integrity is preserved by switching to ON DELETE SET NULL —
-- the row stays, but the dangling user_id pointer is nulled. The durable
-- evidence (target_email, action, before/after_state, details, created_at)
-- is captured at the time of action and is independent of the auth row.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260521b_audit_log_fk_set_null.sql
--
-- Idempotent.
-- ============================================================================

BEGIN;

-- Drop and recreate actor_user_id FK with ON DELETE SET NULL
ALTER TABLE public.admin_audit_log
  DROP CONSTRAINT IF EXISTS admin_audit_log_actor_user_id_fkey;

ALTER TABLE public.admin_audit_log
  ADD CONSTRAINT admin_audit_log_actor_user_id_fkey
  FOREIGN KEY (actor_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

-- Drop and recreate target_user_id FK with ON DELETE SET NULL
ALTER TABLE public.admin_audit_log
  DROP CONSTRAINT IF EXISTS admin_audit_log_target_user_id_fkey;

ALTER TABLE public.admin_audit_log
  ADD CONSTRAINT admin_audit_log_target_user_id_fkey
  FOREIGN KEY (target_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

-- Also fix the granted_by / deactivated_by FKs on user_roles for the same
-- reason. The user_id PK already has ON DELETE CASCADE so this doesn't
-- block the actual subject delete — but if Howie ever needs to be removed
-- in the future, the granted_by / deactivated_by columns on other users'
-- rows would block it. SET NULL is the right call here too.
ALTER TABLE public.user_roles
  DROP CONSTRAINT IF EXISTS user_roles_granted_by_fkey;

ALTER TABLE public.user_roles
  ADD CONSTRAINT user_roles_granted_by_fkey
  FOREIGN KEY (granted_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.user_roles
  DROP CONSTRAINT IF EXISTS user_roles_deactivated_by_fkey;

ALTER TABLE public.user_roles
  ADD CONSTRAINT user_roles_deactivated_by_fkey
  FOREIGN KEY (deactivated_by) REFERENCES auth.users(id) ON DELETE SET NULL;

-- Verification
SELECT 'admin_audit_log FKs (should both say SET NULL):' AS info;
SELECT conname, confdeltype  -- 'n' = SET NULL, 'a' = NO ACTION, 'c' = CASCADE
  FROM pg_constraint
 WHERE conrelid = 'public.admin_audit_log'::regclass
   AND contype = 'f';

SELECT 'user_roles FKs (user_id should be CASCADE, others SET NULL):' AS info;
SELECT conname, confdeltype
  FROM pg_constraint
 WHERE conrelid = 'public.user_roles'::regclass
   AND contype = 'f';

COMMIT;
