-- 20260902c_autoclose_wpvuln_and_retired_detector_exclusion.sql
--
-- 4.7 rulings (58) invariant + (59c) exclusion + (61) wpvulnerability.
-- PART 2 OF 2 — REQUIRES 20260902b APPLIED AND COMMITTED FIRST.
--
-- 🔴 ORDERING IS NOT OPTIONAL. This file references the enum value
-- 'detector_retired'. PostgreSQL rejects using a newly-added enum value in the
-- transaction that added it. If b and c run together you get
-- "unsafe use of new value of enum type finding_status_t". Apply b, commit,
-- verify, then apply c.
--
-- ============================================================================
-- (61) wpvulnerability joins the commandsentry_light producer list
-- ============================================================================
-- `wpvulnerability` is a registered LIGHT phase (phase_registry.py L66,
-- verified 2026-09-02), has run in 544 scans, and emits findings — but was
-- ABSENT from commandsentry_light's producer pattern list. So a WordPress
-- plugin CVE attributed to commandsentry_light never required the WordPress
-- detector to have run: tls_check + headers_check + friends satisfied
-- all-match, and none of them look at plugins.
--
-- ⚠ WHY THIS IS APPROVED WHERE THE ANALOGOUS commandsentry_heavy WIDENING WAS
-- DECLINED (Obsidian 208 §5). They look identical from a distance — both add a
-- tool to a producer list, both tighten all-match. The difference is empirical:
-- heavy had ZERO live findings in the affected class (all 176 were naabu/
-- fingerprintx Service-inventory rows), so widening was speculation. Here there
-- IS a live affected class. Discipline: producer-list additions require
-- observed emission, never "this tool seems related."
--
-- Currently INERT — wpvulnerability ran ok:true in the covering scan for the
-- three live Mega Main Menu candidates, so this changes no outcome today. It
-- closes a latent hole, which is the same standard applied elsewhere.
--
-- Companion audit (2026-09-02): commandsentry_medium's list
-- ['nuclei%','ffuf','nikto','wafw00f'] exactly matches all four MEDIUM phases.
-- wpvulnerability in light was the ONLY gap across the registry.
--
-- Everything else in this function is unchanged from 20260626a. Restated in
-- full because CREATE OR REPLACE has no partial form.

CREATE OR REPLACE FUNCTION public.asm_autoclose_producer_patterns(p_source text)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE p_source
    WHEN 'nuclei'               THEN ARRAY['nuclei%']
    WHEN 'nikto'                THEN ARRAY['nikto']
    WHEN 'testssl'              THEN ARRAY['testssl.sh','testssl']
    WHEN 'commandsentry_light'  THEN ARRAY['tls_check','headers_check','csp_nonce_check','dns_posture','methods_check','common_paths','httpx_tech','behavioral_probes','wpvulnerability']
    WHEN 'commandsentry_medium' THEN ARRAY['nuclei%','ffuf','nikto','wafw00f']
    WHEN 'commandsentry_heavy'  THEN ARRAY['naabu','fingerprintx']
    ELSE NULL
  END;
$$;

COMMENT ON FUNCTION public.asm_autoclose_producer_patterns(text) IS
  'note 127 + 4.7 (61): source -> LIKE patterns identifying that source''s '
  'producer tool(s). NULL = source not eligible for auto-close. Additions '
  'require OBSERVED emission by that tool for that source — not topical '
  'similarity (see 20260902c header re: the declined commandsentry_heavy case).';

-- ============================================================================
-- (58) The invariant. Separate from note 126, which is untouched.
-- ============================================================================
-- note 126 (unchanged): status in {remediated, validated_remediated}
--                       iff remediated_at IS NOT NULL
-- new (here):           status = 'detector_retired'
--                       iff detector_retired_at IS NOT NULL
--
-- Two invariants, two timestamps, each meaning exactly one thing. Satisfied by
-- every existing row (all have detector_retired_at NULL and a status other than
-- detector_retired), so this validates without a backfill.
ALTER TABLE public.findings
  DROP CONSTRAINT IF EXISTS chk_detector_retired_at;
ALTER TABLE public.findings
  ADD CONSTRAINT chk_detector_retired_at
  CHECK ((current_status = 'detector_retired') = (detector_retired_at IS NOT NULL));

-- ============================================================================
-- (59c) Exclude the ONE retired-detector class from autoclose eligibility
-- ============================================================================
-- Only the eligibility CTE changes. Everything else is 20260902a verbatim —
-- all-match predicate, ⑳ runtime guard, audit shape.

CREATE OR REPLACE FUNCTION public.asm_autoclose_stale_findings(
  p_dry_run boolean DEFAULT true
)
RETURNS TABLE (
  finding_id        text,
  asset_id          text,
  severity          text,
  source            text,
  title             text,
  last_observed_at  timestamptz,
  scan_run_id       uuid,
  scan_completed_at timestamptz,
  matched_tool      text,
  acted             boolean
)
LANGUAGE plpgsql
AS $$
DECLARE
  v_batch_id uuid := gen_random_uuid();
  v_now      timestamptz := now();
BEGIN
  -- ⑳ RUNTIME GUARD (20260902a) — unchanged. Fail closed before reading a row.
  IF NOT p_dry_run THEN
    RAISE EXCEPTION
      'asm_autoclose_stale_findings: LIVE RUN BLOCKED by migration 20260902a (4.7 ruling 20).'
      USING DETAIL =
        'Dry-run is unaffected: call asm_autoclose_stale_findings() or (true). '
        'This function has no automatic caller; a live run can only be invoked by hand.',
      HINT =
        'Removing this guard requires a NEW MIGRATION and an explicit decision, not an edit. '
        'All four gates must pass first: '
        '(1) all-match empirically validated as sufficient, or precise-match ready; '
        '(2) the Command dry-run candidates reviewed for calibration; '
        '(3) a live-monitoring plan in place; '
        '(4) an explicit decision that the autocloser should run live. '
        'See scripts/db/AUTOCLOSE_BLOCKER.md.';
  END IF;

  RETURN QUERY
  WITH eligible AS (
    SELECT f.finding_id,
           f.asset_id,
           f.severity::text          AS severity,
           f.source::text            AS source,
           f.title,
           f.current_status::text    AS current_status,
           f.last_observed_at
      FROM public.findings f
     WHERE f.current_status IN ('detected','open','regressed')
       AND f.severity::text NOT IN ('CRITICAL','HIGH','MODERATE-HIGH')
       AND public.asm_autoclose_producer_patterns(f.source::text) IS NOT NULL
       AND f.last_observed_at IS NOT NULL
       -- ── 4.7 (59c) RETIRED-DETECTOR EXCLUSION ──────────────────────────
       -- The scanner runs NO info-severity nuclei templates on ANY tier.
       -- run_medium.py L2407-2426 is the complete chunk plan:
       --   BASE    critical,high · medium:cve
       --   STACK   wordpress/wp · iis/.net · php · drupal · joomla
       --   CLOSER  medium:exposure,config · medium:tech
       -- Every chunk is critical,high or medium:*.
       --
       -- So for a nuclei INFO finding: no future scan can re-detect it,
       -- last_observed_at can never advance, it is a candidate FOREVER — and
       -- all-match is ALWAYS satisfied, because the producer pattern for
       -- source 'nuclei' is ARRAY['nuclei%'], which matches the critical/medium
       -- chunks that DO run clean. It would be closed on evidence that
       -- structurally cannot exist.
       --
       -- ⑰'s all-match cannot fix this: the pattern says which tools RAN, never
       -- whether they COVER the finding. That is precise-match, deferred.
       --
       -- Scope is exactly this one class — audit 2026-09-02 (Obsidian 212 §6)
       -- checked every autoclose-eligible source × severity: 8 of 10 classes
       -- (805 findings) were observed that same day; nikto LOW looked stale but
       -- is a 3-asset SCAN-COVERAGE gap (nikto_runs_since = 0), not a
       -- retirement, and was never a candidate.
       --
       -- Deliberately a single explicit clause, not a registry. A capability
       -- registry (option b) was declined: its primary failure mode is drifting
       -- out of sync with the chunk plan, which is precisely the bug being
       -- fixed here. One retirement does not justify that. If retirements
       -- become frequent, revisit — the accumulation of clauses IS the signal.
       AND NOT (f.source::text = 'nuclei' AND f.severity::text = 'INFO')
  ),
  candidates AS (
    SELECT e.finding_id,
           e.asset_id,
           e.severity,
           e.source,
           e.title,
           e.current_status,
           e.last_observed_at,
           cov.scan_run_id,
           cov.completed_at  AS scan_completed_at,
           cov.tools_run,
           cov.matched_tool
      FROM eligible e
      JOIN LATERAL (
        SELECT sr.scan_run_id,
               sr.completed_at,
               sr.tools_run,
               (SELECT string_agg(t2.tool, ',' ORDER BY t2.tool)
                  FROM unnest(sr.tools_run) AS t2(tool)
                 WHERE EXISTS (
                   SELECT 1
                     FROM unnest(public.asm_autoclose_producer_patterns(e.source)) AS p2(pattern)
                    WHERE t2.tool LIKE p2.pattern)
               ) AS matched_tool
          FROM public.scan_run sr
         WHERE sr.asset_id     = e.asset_id
           AND sr.status::text = 'complete'
           AND sr.completed_at > e.last_observed_at
           -- ⑰ (a) PRESENCE
           AND EXISTS (
             SELECT 1
               FROM unnest(sr.tools_run) AS t(tool),
                    unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
              WHERE t.tool LIKE p.pattern
           )
           -- ⑰ (b) ALL-MATCH
           AND NOT EXISTS (
             SELECT 1
               FROM unnest(sr.tools_run) AS t(tool)
              WHERE EXISTS (
                    SELECT 1
                      FROM unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
                     WHERE t.tool LIKE p.pattern)
                AND coalesce(sr.tool_status -> t.tool ->> 'ok', '') <> 'true'
           )
         ORDER BY sr.completed_at ASC
         LIMIT 1
      ) cov ON true
  ),
  upd AS (
    UPDATE public.findings f
       SET current_status = 'remediated',
           remediated_at  = v_now,
           updated_at     = v_now
      FROM candidates c
     WHERE f.finding_id = c.finding_id
       AND NOT p_dry_run
    RETURNING f.finding_id
  ),
  aud AS (
    INSERT INTO public.admin_audit_log (
      actor_user_id, action, target_user_id, target_email,
      before_state, after_state, details
    )
    SELECT
      NULL,
      'autoclose_stale_finding',
      NULL,
      NULL,
      jsonb_build_object(
        'current_status',    c.current_status,
        'source',            c.source,
        'severity',          c.severity,
        'last_observed_at',  c.last_observed_at
      ),
      jsonb_build_object(
        'current_status', 'remediated',
        'remediated_at',  v_now
      ),
      jsonb_build_object(
        'finding_id',         c.finding_id,
        'asset_id',           c.asset_id,
        'title',              c.title,
        'scan_run_id',        c.scan_run_id,
        'scan_completed_at',  c.scan_completed_at,
        'tools_run',          to_jsonb(c.tools_run),
        'matched_tool',       c.matched_tool,
        'batch_id',           v_batch_id,
        'rule',               'note_127_coverage_allmatch_autoclose_v3_retired_detector_excluded'
      )
    FROM candidates c
    WHERE NOT p_dry_run
    RETURNING id
  )
  SELECT c.finding_id,
         c.asset_id,
         c.severity,
         c.source,
         c.title,
         c.last_observed_at,
         c.scan_run_id,
         c.scan_completed_at,
         c.matched_tool,
         (NOT p_dry_run) AS acted
    FROM candidates c
   ORDER BY c.scan_completed_at DESC, c.finding_id;
END $$;

COMMENT ON FUNCTION public.asm_autoclose_stale_findings(boolean) IS
  '20260902c: all-match coverage predicate (20260902a) PLUS exclusion of '
  'retired-detector classes — currently nuclei INFO, which no chunk in the scan '
  'plan can ever re-detect. LIVE RUNS REMAIN BLOCKED at runtime per 4.7 ruling '
  '20; removing that block requires a new migration.';

-- ============================================================================
-- VERIFY AFTER APPLYING (run all five)
-- ============================================================================
-- 1) wpvulnerability is in the light list (expect true):
--      SELECT 'wpvulnerability' = ANY(
--               public.asm_autoclose_producer_patterns('commandsentry_light'));
--
-- 2) Exclusion is live — ZERO nuclei INFO candidates (expect 0):
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(true)
--       WHERE source = 'nuclei' AND severity = 'INFO';
--
-- 3) Dry-run count SHRANK by the 28 excluded (expect Command 202 -> 174):
--      SELECT count(*) FROM public.asm_autoclose_stale_findings(true);
--    A LARGER number means the predicate got looser — roll back.
--
-- 4) ⑳ guard still fires (expect ERROR, not rows):
--      SELECT * FROM public.asm_autoclose_stale_findings(false);
--
-- 5) Invariant holds and nothing was transitioned (expect 0 and 0):
--      SELECT count(*) FROM public.findings WHERE detector_retired_at IS NOT NULL;
--      SELECT count(*) FROM public.findings WHERE current_status::text = 'detector_retired';
--
-- ROLLBACK: re-apply 20260902a verbatim (restores the pre-exclusion predicate
-- and the pre-(61) producer list), then
--   ALTER TABLE public.findings DROP CONSTRAINT chk_detector_retired_at;
-- The enum value from 20260902b cannot be dropped — harmless if unused.
--
-- ============================================================================
-- RECORD THE LEDGER ROW (run after the SQL above, before pushing)
-- ============================================================================
--   INSERT INTO public.schema_migrations
--     (filename, applied_by, content_sha256, git_commit_sha, notes)
--   VALUES ('20260902c_autoclose_wpvuln_and_retired_detector_exclusion.sql', 'manual',
--           '<SHA256_OF_THIS_FILE>', NULL,
--           'Manual apply, AFTER 20260902b commits. 4.7 rulings 58/59c/61.')
--   ON CONFLICT (filename) DO NOTHING;
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: false
-- requires_backup: false
-- estimated_duration_ms: 150
-- risk: medium
-- notes: PART 2 OF 2 — REQUIRES 20260902b COMMITTED FIRST (references enum value detector_retired). Adds wpvulnerability to the commandsentry_light producer list (4.7 61, empirically justified where the analogous heavy widening was declined), adds the chk_detector_retired_at invariant leaving note 126 untouched, and excludes nuclei INFO from autoclose eligibility because no chunk in the scan plan can ever re-detect it. Strictly more conservative than 20260902a: closure can only shrink (Command 202 -> 174 expected). Transitions NO rows — detector_retired transitions are a separate, deliberate, human-run batch. MANUAL APPLY on BOTH instances, ledger row, THEN push.
-- END-META
