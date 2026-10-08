-- ============================================================================
-- 20261007a — asset_template_cursor.last_cut_fraction (270 Change 2)
-- ============================================================================
--
-- WHAT IT IS FOR. A nuclei chunk that hits the 400 s wall is CUT, and the
-- cursor HOLDS: the same window is re-dispatched next run. Until now that
-- window shrank by a blind 15% per hold. At the ~7 req/s Prodex sites answer,
-- that takes 4-5 wasted heavy scans to fit. Read from the Prodex DB on
-- 2026-10-08: uat.prodexlabs.com nuclei[critical,high] at consecutive_holds 4,
-- pass_count 0, and none of the 29 Prodex assets has ever completed a pass of
-- nuclei[critical,high].
--
-- A cut already says how far it got: requests/total from nuclei -stats. This
-- column keeps that fraction, so the next slice is sized from it ONCE:
-- floor(slice x fraction x 0.85), never larger than the blind 15% step.
--
-- ⭐ THE CODE IS ALREADY ON MAIN, AND IS SAFE WITHOUT THIS COLUMN.
-- commandsentry-asm 705eb45b and prodexsentry-asm 42e51092 (PR #47 in each,
-- merged 2026-10-08) read and write this column. While it is missing, both
-- statements fall back, after a ROLLBACK, to the old row shape, and sizing
-- uses the blind backoff exactly as before. The measured sizing switches on
-- the moment this column exists. Code first, column second, per the
-- never-a-.sql-in-a-code-push rule.
--
-- SEMANTICS. Written by fold_dispatch on a HOLD when the fraction is usable
-- (0 < f < 1); a hold with no usable fraction leaves the old value alone.
-- Cleared to NULL on a completed ADVANCE. NULL = no measurement = blind
-- backoff, so existing rows behave exactly as today. No default.
--
-- WHY NO CHECK CONSTRAINT. The reader, usable_cut_fraction(), already ignores
-- anything outside 0 < f < 1 (and NaN). A constraint would add nothing the
-- reader does not enforce, and would turn one odd value into a failed write
-- of the whole cursor row, losing the hold count with it.
--
-- WHY NUMERIC. Stated in the 270 plan and verified against PostgreSQL 16 with
-- the live table definition on 2026-10-08, before and after this exact ALTER.
-- psycopg returns it as Decimal; the reader converts with float().
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 100
-- notes: Single additive nullable column on asset_template_cursor, no default,
--   so no table rewrite. The table holds one row per (asset, chunk), about 110
--   per instance. No existing column altered, no row rewritten, no routing
--   change. Splitter-safe (no dollar-quoted blocks), idempotent (add column if
--   not exists), byte-identical in both repos. The table and 20260924a are
--   applied on BOTH instances, read from each project on 2026-10-08.
-- END-META
-- ============================================================================

begin;

alter table asset_template_cursor
    add column if not exists last_cut_fraction numeric;

comment on column asset_template_cursor.last_cut_fraction is
    '270 Change 2 - how far the last CUT nuclei slice got (requests/total from '
    'nuclei -stats). Written on a hold when 0 < f < 1, cleared to NULL on a '
    'completed advance. The next slice is sized floor(slice x f x 0.85), never '
    'larger than the blind 0.85 backoff step. NULL = no measurement = blind '
    'backoff. Measured case: uat.prodexlabs.com nuclei[critical,high] at '
    'consecutive_holds 4, pass_count 0 on 2026-10-08.';

commit;
