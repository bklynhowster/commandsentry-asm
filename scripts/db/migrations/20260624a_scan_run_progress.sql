-- ============================================================================
-- MIGRATION — 2026-06-24a — scan_run progress columns (live scan progress)
--
-- Backs the portal's live ScanProgress component (handoff note 103).
-- The scanner accumulates ctx.tool_status / ctx.tools_run in memory and
-- today only writes them to scan_run at close_out — so a mid-run scan
-- shows tools_run=0 from the portal's perspective. After this migration
-- + the scanner-side flush_progress wiring, the portal can poll
-- scan_run every ~4s and see step completion as it happens.
--
-- TWO ADDITIVE COLUMNS:
--
--   planned_steps  jsonb         — the expected phase list, written ONCE
--                                  after Phase 1 completes (when ctx.tech_
--                                  stack + ctx.auth_gated are known and
--                                  build_chunk_plan can be called). Drives
--                                  the portal's denominator ("N/M steps").
--                                  Honest about auth_gated skips: ffuf +
--                                  nikto + non-tech nuclei chunks are
--                                  EXCLUDED when auth_gated, so the count
--                                  reflects what'll really run (not a
--                                  hardcoded 12).
--
--   updated_at     timestamptz   — bumped by flush_progress on every
--                                  incremental write. Lets the portal
--                                  detect "scan still alive" vs stuck.
--                                  NOT NULL DEFAULT now() backfills
--                                  existing rows with the migration
--                                  timestamp — cheap, no separate
--                                  backfill cycle.
--
-- ----------------------------------------------------------------------------
-- INVARIANT (per note 103 §Part 1, advisor lean):
--   Progress writes are ADDITIVE. close_out still does the authoritative
--   final write (tools_run + tool_status + status + completed_at + etc).
--   flush_progress only touches tool_status + tools_run + updated_at,
--   never status / completed_at / findings_added. A failed flush is
--   best-effort (try/except + continue) — scan continues regardless.
-- ============================================================================

BEGIN;

ALTER TABLE public.scan_run
  ADD COLUMN IF NOT EXISTS planned_steps jsonb;

COMMENT ON COLUMN public.scan_run.planned_steps IS
  'Live scan progress (note 103): expected phase/tool list for this run, '
  'written once after Phase 1 detect_waf+detect_tech_stack complete '
  '(by then build_chunk_plan can produce the nuclei chunk names and '
  'auth_gated is known so ffuf/nikto inclusion is honest). Drives the '
  'portal denominator. NULL on pre-migration rows + rows where the '
  'planned-steps write failed (best-effort).';

ALTER TABLE public.scan_run
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN public.scan_run.updated_at IS
  'Live scan progress (note 103): bumped on every flush_progress write '
  'during the scan. Lets the portal detect liveness (scan_run.updated_at '
  'stale + status=running = stuck) and the portal polling component skip '
  'redundant fetches. NOT NULL DEFAULT now() — existing rows backfilled '
  'with the migration timestamp.';

COMMIT;

-- ============================================================================
-- Rollback recipe (if needed before the scanner-side wiring ships):
--
--   ALTER TABLE public.scan_run DROP COLUMN IF EXISTS planned_steps;
--   ALTER TABLE public.scan_run DROP COLUMN IF EXISTS updated_at;
--
-- Safe because both are additive — no consumer queries them yet pre-
-- portal-Part-2. After Part 2 ships, dropping these breaks the portal
-- progress component but scan execution still works (close_out path is
-- the authoritative final write and unaffected).
-- ============================================================================
