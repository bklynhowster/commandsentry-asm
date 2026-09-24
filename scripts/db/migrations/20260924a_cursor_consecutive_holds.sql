-- ============================================================================
-- 20260924a — asset_template_cursor.consecutive_holds (262 ruling B)
-- ============================================================================
--
-- ⛔ WHAT THIS EXISTS TO MAKE VISIBLE. A chunk that has NEVER completed a slice
-- is already legible: last_dispatched IS NULL, and the portal banner calls it
-- STALLED. A chunk that advanced ONCE and then FROZE is not legible at all —
-- it carries a non-null last_dispatched, so every consumer counts it among the
-- phases that are "advancing", while it re-dispatches the same window forever.
--
-- ⭐ MEASURED, NOT HYPOTHETICAL (uat.prodexlabs.com, 2026-09-24). Across two
-- consecutive heavies — run 36016017275 (1951s) and run 36024094012 —
-- nuclei[critical,high] held byte-identical cursor state:
--
--     chunk                           last_dispatched                    pass
--     nuclei[critical,high]           http/cves/2024/CVE-2024-27718.yaml    0
--     nuclei[medium:exposure,config]  network/misconfig/open-socks-...      2
--     nuclei[medium:tech]             http/exposed-panels/compalex-...      2
--
-- The two small chunks wrapped twice. critical,high — the LARGEST corpus at
-- 4318 templates — was cut at the 400s wall both runs (2677 requests), so the
-- cursor correctly HELD each time. Correct behaviour, zero forward progress,
-- and the banner still counted it among "3 sweep phases advancing".
--
-- ⚠ PROVENANCE: that it made no progress in the SECOND run is observed (same
-- value read 11:14 and 12:36 EDT). Whether it advanced earlier inside the first
-- run was never read. Do not restate this as "it has never advanced".
--
-- ⭐ 262's own line is the argument for this column: "A mechanism that is
-- correct and makes no progress is not a solution." The cursor is behaving to
-- spec; the outcome is useless coverage on the chunk that matters most. You
-- cannot fix what you cannot see, and per-chunk sizing (the next increment)
-- needs this counter to prove it worked.
--
-- WHY A COUNTER AND NOT A DERIVATION. 4.7 considered reconstructing hold streaks
-- from history and ruled it more fragile than one integer: scan_run rows are
-- per-run and immutable, so a derivation has to join across runs and re-derive
-- the same fact every read. fold_dispatch owns this field — increment on a
-- hold, RESET TO 0 on a completed advance.
--
-- ⛔ NO CODE READS OR WRITES THIS YET. Additive column, defaulted, inert. This
-- migration changes NO scan behaviour, moves NO wall, fires NOTHING. The writer
-- (fold_dispatch) and the reader (the banner's advancing/stalled split) are the
-- next increment and ship separately, per the never-a-.sql-in-a-code-push rule.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 100
-- notes: Single additive column on asset_template_cursor, NOT NULL DEFAULT 0 —
--   catalog-stored default on PG11+, so no table rewrite; the table holds one
--   row per (asset, chunk), single digits to low hundreds. No existing column
--   altered, no row rewritten, no routing change, nothing reads it yet.
--   Splitter-safe (no dollar-quoted blocks), idempotent, byte-identical both
--   repos. The table itself (20260923a) is applied on BOTH instances —
--   verified 2026-09-24 via to_regclass on each project — so this needs no
--   instance-first divergence entry.
-- END-META
-- ============================================================================

begin;

alter table asset_template_cursor
    add column if not exists consecutive_holds integer not null default 0;

comment on column asset_template_cursor.consecutive_holds is
    '262 ruling B — consecutive runs this chunk HELD (was cut, so the cursor did '
    'not advance). Incremented on a hold, RESET TO 0 on a completed advance. '
    'Exists because last_dispatched IS NULL only catches a chunk that never '
    'completed a slice; a chunk that advanced once and then froze is otherwise '
    'indistinguishable from one that is advancing. Measured case: '
    'nuclei[critical,high] on uat.prodexlabs.com, cut at the 400s wall on '
    'consecutive heavies 2026-09-24 with identical cursor state.';

commit;
