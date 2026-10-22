-- 20261022a_one_rating_rule.sql
--
-- KB 12 job 3m (2026-10-22). ONE RATING RULE: an asset's rating is its single
-- worst open finding.
--
-- Howie, 2026-10-22 08:59, on "an asset's rating is its worst single finding …
-- four missing-header warnings shouldn't add up to an alarm": "Absolutely."
-- Decision 1 (handoff 004, 12:36): "Go with A." — the one-time recompute rides
-- inside this migration.
--
-- WHY: two database rules disagreed. The trigger function
-- recompute_asset_current_risk_for() (fires on every finding change; counts
-- from v_open_findings_dedup) rates an asset by its worst open finding.
-- refresh_asset_posture() (called by import_jsonl.py, backfills, and one
-- unknown per-asset caller) counted RAW findings and rated 4+ MODERATE as
-- MODERATE-HIGH, and called a never-scanned name INFO. Whichever ran last
-- won: on 2026-10-22 ten Command assets went MODERATE -> MODERATE-HIGH with no
-- new finding and the daily digest reported "10 asset risk shift(s)".
--
-- WHAT THIS DOES:
--   1. refresh_asset_posture(text) now hands every call to
--      recompute_asset_current_risk_for(text). Same name, same signature,
--      same result type: every caller keeps working and gets the one rule
--      (and its de-duplicated counting and reason text).
--      refresh_all_asset_posture() is unchanged (it loops over the above).
--   2. Once: recompute every asset with the one rule (Command 492 assets,
--      Prodex 91; measured 2026-10-22: Command 451 change — 11 MODERATE-HIGH
--      -> MODERATE, 440 INFO -> UNKNOWN; Prodex 0; none goes up).
--   3. Once: clear the old rule's "no open findings above INFO" text left on
--      assets the one rule rates UNKNOWN (the trigger's no-history branch
--      sets the rating only, so that text would otherwise sit under UNKNOWN).
--
-- Touches no finding. Scans are paused between merge and apply (ledger gate),
-- so the one-time pass cannot race a scan's finding writes. Re-applying is
-- harmless: the function is replaced with itself and the recompute is the
-- trigger's own rule, so a second pass changes nothing. Undo: re-create the
-- old body from scripts/db/maintenance.sql at the parent commit and run
-- refresh_all_asset_posture().
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 15000
-- notes: Job 3m (Howie 2026-10-22 "Absolutely." / Decision 1 "Go with A."). refresh_asset_posture delegates to recompute_asset_current_risk_for (one rule - worst open finding); one-time recompute of every asset (Command 451 rows change, Prodex 0) and clears the old rule's reason text under UNKNOWN. Touches no finding. Byte-identical in both repos.
-- END-META

-- LANGUAGE sql with a single-quoted body: the migration runner (apply_pending_migrations
-- ._split) splits on every semicolon outside single quotes and knows no dollar quoting, so a
-- plpgsql body would be cut apart. This body has no ';' and is one quoted string.
CREATE OR REPLACE FUNCTION public.refresh_asset_posture(p_asset_id text)
RETURNS void
LANGUAGE sql
AS 'SELECT public.recompute_asset_current_risk_for(p_asset_id)';

COMMENT ON FUNCTION public.refresh_asset_posture(text) IS
  'Job 3m (2026-10-22): delegates to recompute_asset_current_risk_for - one rating rule, '
  'the worst open finding (v_open_findings_dedup). Kept for import_jsonl.py and backfills.';

-- One-time pass (Decision 1 "Go with A."): every asset, the one rule. Returns the count.
SELECT public.refresh_all_asset_posture();

-- One-time: the trigger's no-history branch sets the rating only, so clear the old
-- rule's INFO text it would leave under UNKNOWN (never-scanned names).
UPDATE public.assets
   SET current_risk_reason = NULL
 WHERE current_risk = 'UNKNOWN'
   AND current_risk_reason = 'no open findings above INFO';
