-- ============================================================================
-- MIGRATION — 2026-06-29b — note 129 round 7
--                          finding_history.scan_id: drop FK to legacy
--                          scans table (Part A of the write-dead fix)
--
-- WHY (FINDING_HISTORY_FIX_SPEC.md):
--   finding_history.scan_id is NOT NULL + FK→public.scans(scan_id). The
--   live scanners (run_medium / run_heavy), the note-127 auto-closer,
--   and the round-6 regress fn are all scan_run-driven and have no
--   scans-table counterpart — so none of them can satisfy the FK
--   and none of them write finding_history. The per-finding timeline
--   is frozen at the last offline import. Verified live: the
--   ftp.sciimage.com cert finding (re-scanned 3× heavy today) has 1
--   finding_history row (May 25 offline-import), despite a full
--   detected → remediated → regressed → detected churn — none of
--   which made it into history.
--
-- WHAT (Part A — schema):
--   Drop the FK. scan_id stays NOT NULL text — it's already
--   heterogeneous free text in practice (import scan_ids look like
--   `ftp-sciimage__intensive-scan-2026-05-25_010411`, scan_run_ids
--   are UUIDs cast to text). The unique constraint on
--   (finding_id, scan_id) stays — write idempotency depends on it.
--
--   Rejected alternative: insert a sentinel scans row per scan_run
--   to keep referential integrity. Heavier + doesn't reflect the
--   actual semantic (scan_id is a "which scan observed this"
--   pointer, not an FK-target). Per 4.8 spec.
--
--   Existing import rows untouched. Their scan_id values still
--   "happen to" match an existing scans row, but nothing enforces
--   that anymore.
--
-- WHAT NOT TO TOUCH:
--   - finding_history.finding_id FK → findings.finding_id (ON DELETE
--     CASCADE): keep. A deleted finding correctly takes its history
--     with it.
--   - UNIQUE (finding_id, scan_id): keep. Part B's writer relies
--     on this for ON CONFLICT DO NOTHING idempotency.
--   - Indexes idx_fh_finding_id / idx_fh_scan_id / idx_fh_observed_at:
--     keep. Same query patterns post-relax.
--
-- WHY OK to drop the cascade-delete-on-scans:
--   The cascade was: delete scans row → cascade delete its
--   finding_history rows. That was meaningful in the offline-import
--   era when scans was the source of truth. Now scan_run is the
--   source of truth, and we never delete scan_run rows (retained
--   forever for audit per scan_run table comment). The cascade was
--   dormant in practice for the live path.
-- ============================================================================

-- Constraint name follows the Postgres default for inline FK on
-- the column: <table>_<col>_fkey. IF EXISTS guards against an
-- alternate naming if the original schema was created differently.
ALTER TABLE public.finding_history
  DROP CONSTRAINT IF EXISTS finding_history_scan_id_fkey;

COMMENT ON COLUMN public.finding_history.scan_id IS
  'Free-text pointer to the observation source. Historically '
  '(pre-2026-06-29 round 7) FK to scans.scan_id; FK dropped because '
  'live scan_run-driven flows (run_medium / run_heavy / auto-closer / '
  'regress fn) have no scans-table row to satisfy it, and the column '
  'is already heterogeneous (import dirnames + scan_run UUIDs). '
  'Unique constraint with finding_id is retained for write '
  'idempotency.';

-- ============================================================================
-- SANITY QUERIES — run after migration applies, before wiring the
-- code-side writer.
-- ============================================================================
--
-- 1) Confirm the FK is gone (should return zero rows):
--      SELECT constraint_name
--        FROM information_schema.table_constraints
--       WHERE table_schema = 'public'
--         AND table_name   = 'finding_history'
--         AND constraint_type = 'FOREIGN KEY'
--         AND constraint_name LIKE '%scan_id%';
--
-- 2) Confirm NOT NULL + unique constraint still in place:
--      SELECT column_name, is_nullable
--        FROM information_schema.columns
--       WHERE table_schema = 'public'
--         AND table_name = 'finding_history'
--         AND column_name = 'scan_id';
--      -- expect: is_nullable = NO
--
--      SELECT indexname, indexdef
--        FROM pg_indexes
--       WHERE schemaname = 'public'
--         AND tablename  = 'finding_history';
--      -- expect: a unique index over (finding_id, scan_id).
--
-- 3) Existing rows untouched — row count + sample stay constant:
--      SELECT count(*) FROM public.finding_history;
--      SELECT scan_id, count(*)
--        FROM public.finding_history
--       GROUP BY scan_id
--       ORDER BY count(*) DESC LIMIT 5;
--
-- 4) Can now insert a scan_run-driven row (no FK violation):
--      INSERT INTO public.finding_history
--        (finding_id, scan_id, observed_at, status)
--      SELECT finding_id, gen_random_uuid()::text, now(), 'detected'
--        FROM public.findings
--       LIMIT 1
--       ON CONFLICT (finding_id, scan_id) DO NOTHING;
--      -- expect: 1 row inserted (or 0 on collision). pre-Part A this
--      -- would have raised foreign_key_violation.
