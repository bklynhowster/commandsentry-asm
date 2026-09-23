-- ============================================================================
-- 20260923a — asset_template_cursor (relay 450 spec, 454 ruling)
-- ============================================================================
--
-- ⛔ WHAT WAS WRONG. run_medium's nuclei argv has no -shuffle, no -offset, no
-- -exclude-id and no slice: it is -severity + -tags in nuclei's own fixed
-- internal order, cut by NUCLEI_CHUNK_WALL_S=400 and MAX_REQUESTS_TOTAL=8000.
-- Fixed order + fixed cut = THE SAME SUBSET EVERY RUN. Measured the same day on
-- both instances: critical,high covered 2,428/8,716 on uat.prodexlabs.com and
-- 2,427/8,716 on www.commandcompanies.com — two targets, two egress regions,
-- two repos, within ONE request of each other. That reproducibility is the
-- proof: ~6,289 critical/high templates had never executed against these hosts
-- and never would. The portal reported it as "51% coverage", which implies
-- sampling. It was not sampling; it was a permanent blind spot.
--
-- ⭐ WHAT THIS TABLE HOLDS, AND WHAT IT DELIBERATELY DOES NOT. One row per
-- (asset, nuclei chunk) carrying a RESUME POSITION. 4.7 ruled fork C COARSE:
-- no per-(asset x template) rows. At Command's 78 live assets a per-template
-- ledger is ~1,030,000 rows; this is ~78 x the chunk count, and coverage % is
-- DERIVED (position in the ordered corpus / corpus size) rather than stored.
--
-- ⭐ last_dispatched IS A TEMPLATE PATH, NOT AN INTEGER OFFSET — and that is
-- the correctness decision in this migration. 4.7's ruling flagged the trap:
-- "when dir_sha256/templates_version changes, the cursor's OFFSETS no longer
-- map to the same templates — reconcile (reset to 0, or diff-and-append)."
-- Exactly right about offsets. Templates inserted anywhere in a sorted list
-- shift every subsequent index, so an integer cursor is invalidated by ANY
-- corpus bump and forces either a reset (discarding accrued coverage) or a diff
-- (requiring the whole old list to be persisted). A PATH has no such
-- dependency: additions before the position are picked up on the next wrap,
-- additions after it are covered by the next slice, and a deleted cursor
-- template still resolves because the resume is a bisect for the first
-- survivor greater than it. The trap is dissolved rather than handled, the
-- reconciliation branch never has to exist, and the state stays one string.
--
-- ⚠ corpus_identity IS STILL RECORDED. Not to drive a reset, but to SCOPE the
-- claim: "100% of v10.4.9" means something different from "100%" after a
-- corpus bump. That is a labelling concern, and labelling it wrong is how a
-- coverage number becomes a lie.
--
-- ⛔ NO CODE READS THIS YET. Additive table only. The writer is a later
-- increment; this migration alone changes NO scan behaviour, moves NO wall, and
-- fires NOTHING. NUCLEI_CHUNK_WALL_S and MAX_REQUESTS_TOTAL are untouched by
-- design — 4.7 ruled KEEP THE WALL, because raising it hides the loss (you
-- clear the wall, hit the request ceiling, and report `complete` while dropping
-- ~40% of the corpus with no cut-reason). With a cursor, "the wall cuts here,
-- the next run resumes there" becomes the design instead of the bug.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 200
-- notes: Additive table + one index. No existing table altered, no row
--   rewritten, no routing change, no code reads it yet. Prodex-first per 4.7
--   fork D; Command follows after the cursor is observed advancing, wrapping
--   and surviving a corpus bump on the canary. Splitter-safe (no dollar-quoted
--   blocks), idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

begin;

create table if not exists asset_template_cursor (
    asset_id          text        not null,
    chunk_label       text        not null,   -- nuclei_chunk_label(), e.g. 'critical,high'
    -- The last template path we DISPATCHED and that the chunk COMPLETED.
    -- NULL = never run. See the header: a path, never an offset.
    last_dispatched   text,
    -- Full passes finished. Coverage is a cycle, not a one-shot, because both
    -- the corpus and the target keep changing.
    pass_count        integer     not null default 0,
    -- templates_version + dir_sha256 prefix, from the corpus_prewarm stamp the
    -- scanner already writes. Scopes the claim; does NOT trigger a reset.
    corpus_identity   text,
    -- Size of the ordered corpus when we last advanced, so coverage % is
    -- derivable without re-listing 13k templates on a portal read.
    corpus_size       integer,
    updated_at        timestamptz not null default now(),
    primary key (asset_id, chunk_label)
);

-- Portal reads "which assets are furthest behind" across the fleet.
create index if not exists idx_atc_asset
    on asset_template_cursor (asset_id);

comment on table asset_template_cursor is
    'relay 454 — cross-run nuclei template coverage. One row per (asset, chunk). '
    'last_dispatched is a template PATH, never an integer offset, so a corpus '
    'bump needs no reset and no diff. Coverage %% is DERIVED from the position, '
    'never stored per-template (4.7 fork C: ~78 rows, not ~1M).';

comment on column asset_template_cursor.last_dispatched is
    'Last template path dispatched AND completed. A CUT chunk must not advance '
    'this — nuclei emits matches, not attempts, so a cut cannot say where it '
    'stopped, and advancing anyway would mark unexecuted templates as covered.';

commit;
