-- 20261030c_claims_feedback_server_only_writes.sql
--
-- PORTAL SECURITY AUDIT #4 (2026-10-30, medium). A FORGED CLAIM CAN NO LONGER MAKE "REJECT" CLOSE A FINDING.
--
-- Howie, 2026-10-30 19:22: "Let's do number 4".
-- The audit found, and Claude's live read the same day confirmed on both projects (read only):
-- remediation_requests (an Operator's claim on a finding) and finding_feedback (anyone's note on
-- a finding) each had one INSERT rule, "the row's submitted_by is the caller", and the signed-in
-- role held table-wide INSERT, UPDATE, DELETE and TRUNCATE. So an Operator (Command has 3) could
-- skip the portal, call the database API with their own session and the public key, and write a
-- claim whose finding_status_at_submission is already closed (false_positive, accepted_risk,
-- validated_remediated); an admin's Reject then wrote that status to the finding. The same path
-- let a claim be planted already 'reviewed' under an admin's name, and let anyone signed in set
-- any submitter email or role on feedback.
-- Every portal write to these two tables already runs as the service role (submitFindingClaim
-- and submitForRetest, reviewClaim, submitFeedback, and addressFeedback / dismissFeedback /
-- hideFeedback), read from the portal's code at main 18c18c8 on 2026-10-30.
-- Live, 2026-10-30, both projects: no claim or feedback row shows a planted value (pending
-- claims' status snapshot matches the finding; every submitter email matches its account;
-- every reviewed claim has its review_claim audit row). Command: 3 claims, 0 feedback.
-- Prodex: none.
--
-- What this does (both projects, byte-identical): drops the two INSERT rules and takes INSERT,
-- UPDATE, DELETE and TRUNCATE on both tables away from anon and the signed-in role. Reading
-- through the existing SELECT rules is untouched, so the finding page and the queues still show
-- claims and feedback. The admin UPDATE rules stay; with no UPDATE grant they do nothing, and the
-- portal's admin actions run as the service role anyway. The service role and the database owner
-- keep everything. No data changes. Re-applying changes nothing.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 100
-- notes: Audit #4 (Howie 2026-10-30 19:22). remediation_requests and finding_feedback: drop rr_remediator_insert and feedback_role_insert; revoke INSERT, UPDATE, DELETE, TRUNCATE from anon and authenticated. SELECT and the service role untouched. No data change. No dollar-quoting. Byte-identical in both repos.
-- END-META

DROP POLICY IF EXISTS rr_remediator_insert ON public.remediation_requests;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.remediation_requests FROM anon, authenticated;

DROP POLICY IF EXISTS feedback_role_insert ON public.finding_feedback;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.finding_feedback FROM anon, authenticated;
