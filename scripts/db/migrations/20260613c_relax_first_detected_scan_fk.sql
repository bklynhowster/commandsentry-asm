-- ============================================================================
-- MIGRATION — 2026-06-13c — Drop obsolete findings.first_detected_scan FK
--
-- CONDITIONAL GATE for the trust-layer fix PR. Apply ONLY IF the verify
-- queries below confirm an enforced FK on findings.first_detected_scan
-- pointing at the OLD `scans` table. Drop-only — no column type change,
-- no replacement FK. Bug D's writes go through as UUID-shaped strings
-- in a text column, matching how the ce47fc27 backfill already exercised
-- the column structurally.
--
-- WHY DROP-ONLY (advisor-approved scope, 2026-06-13)
--   • The trust-layer fix PR is about the validation_status invariant,
--     not schema hygiene on a forensic pointer column.
--   • A proper text→uuid conversion + replacement FK to scan_run takes
--     a brief ACCESS EXCLUSIVE lock and shouldn't run mid-scan-window
--     as a side effect of a different fix. Defer to a dedicated schema
--     hygiene pass with its own change-management window.
--   • Bug D writes UUID-shaped strings into a text column — same shape
--     the ce47fc27 backfill UPDATE already used. Zero runtime risk for
--     the immediate trust-fix landing.
--   • The only thing dropped here is FK integrity on a forensic pointer.
--     Re-addable any time as a focused follow-up (see "Future cleanup"
--     below).
--
-- BACKGROUND
--   schema.sql declares:
--     first_detected_scan text REFERENCES scans(scan_id) ON DELETE SET NULL
--   Phase 4a (2026-05-28) introduced scan_run + scan_run_id (uuid per
--   that file, but VERIFY against live state — that's the whole point
--   of this gate) but never migrated either the FK target OR the
--   column type. Until Bug D's fix, the column was always NULL — NULL
--   is FK-exempt, so both mismatches were silently latent. The Bug D
--   write will be the first non-NULL value the column has ever seen
--   from the runner. If the old FK is enforced, that write crashes the
--   write phase.
--
-- ADVISOR-GATED APPLY ORDER (2026-06-13)
--
--   STEP 1. Run BOTH verify queries against the LIVE database:
--
--     -- Q1: FK constraints on findings
--     SELECT conname,
--            confrelid::regclass AS ref_table,
--            convalidated,
--            pg_get_constraintdef(oid) AS def
--       FROM pg_constraint
--      WHERE conrelid = 'public.findings'::regclass
--        AND contype  = 'f';
--
--     -- Q2: column types — INTEL ONLY for the future-cleanup task,
--     -- does NOT gate this drop-only migration (no type conversion here)
--     SELECT table_name, column_name, data_type
--       FROM information_schema.columns
--      WHERE (table_name = 'findings'
--             AND column_name = 'first_detected_scan')
--         OR (table_name = 'scan_run'
--             AND column_name = 'scan_run_id');
--
--   STEP 2. Decision tree — Q1 ref_table is the sole gate:
--
--     CASE A — Q1 returns no FK row for first_detected_scan:
--       → schema.sql is stale; Bug D writes the UUID as text, no FK to
--         trip. SKIP this migration. No file needs applying.
--
--     CASE B — Q1 has row with ref_table='scans' (regardless of
--              convalidated value — see ⚠️  below):
--       → FK enforced for new INSERTs; Bug D's write would crash.
--         APPLY this migration BEFORE merging the trust-layer code.
--         After this drops the FK, Bug D writes succeed against the
--         text column (UUID-as-string shape, identical to the ce47fc27
--         backfill pattern).
--
--       ⚠️  DO NOT condition on convalidated=true. A NOT VALID FK
--           still enforces every new INSERT — `convalidated=false`
--           only means historical rows were not back-checked, NOT
--           that the constraint is dormant. Bug D's write IS a new
--           INSERT and would crash either way. Caught 2026-06-13.
--
--     CASE C — Q1 has row with ref_table='scan_run':
--       → Already migrated by some prior path. SKIP this migration
--         (the DO block introspects and no-ops anyway, but skip means
--         skip).
--
--   STEP 3. (Only if Case B) Apply this migration:
--     psql "$SUPABASE_DSN" -f scripts/db/migrations/20260613c_relax_first_detected_scan_fk.sql
--
--   STEP 4. Merge trust-layer PR + deploy.
--
--   STEP 5. Observe next validate run (no owned-asset fire) — confirm
--           findings.first_detected_scan populates without error.
--
--   STEP 6. Manually apply 20260613b sweep + acceptance gate queries.
--
-- FUTURE CLEANUP (deliberate, not part of this PR)
--   Proper schema hygiene for this column:
--     1. Verify scan_run.scan_run_id is uuid (live query, not assumption).
--     2. Pre-check: no non-NULL, non-UUID-shaped values in
--        findings.first_detected_scan.
--     3. Schedule a change window (brief ACCESS EXCLUSIVE lock on
--        findings).
--     4. ALTER COLUMN TYPE uuid USING ...::uuid + add FK to scan_run.
--   File this as a follow-up task. Don't bolt it onto the trust-fix.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260613c_relax_first_detected_scan_fk.sql
--
-- Idempotent. The DO block introspects pg_constraint and only acts
-- when an FK to `scans` is present.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Drop the old FK (only if it exists pointing at `scans`)
--    Constraint name not assumed — look it up by column + reference.
-- ---------------------------------------------------------------------------
do $$
declare
  v_conname text;
begin
  select c.conname
    into v_conname
    from pg_constraint c
    join pg_attribute  a on a.attrelid = c.conrelid
                        and a.attnum   = ANY(c.conkey)
    join pg_class      rel on rel.oid = c.confrelid
   where c.conrelid = 'public.findings'::regclass
     and c.contype  = 'f'
     and a.attname  = 'first_detected_scan'
     and rel.relname = 'scans'
   limit 1;

  if v_conname is not null then
    execute format('alter table public.findings drop constraint %I', v_conname);
    raise notice 'Dropped FK % on public.findings(first_detected_scan) -> scans', v_conname;
  else
    raise notice 'No FK on public.findings(first_detected_scan) -> scans — nothing to drop (CASE A or C — skip applying this file)';
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 2. Verification — confirm the drop took (or wasn't needed)
-- ---------------------------------------------------------------------------
select conname,
       confrelid::regclass as ref_table,
       convalidated,
       pg_get_constraintdef(oid) as def
  from pg_constraint
 where conrelid = 'public.findings'::regclass
   and contype  = 'f'
 order by conname;

select 'findings.first_detected_scan column state (informational — not changed by this migration)' as info,
       data_type
  from information_schema.columns
 where table_schema = 'public'
   and table_name   = 'findings'
   and column_name  = 'first_detected_scan';

select 'findings.first_detected_scan NULL count (Bug-D pre-fix baseline)' as info,
       count(*) filter (where first_detected_scan is null)     as null_rows,
       count(*) filter (where first_detected_scan is not null) as nonnull_rows,
       count(*)                                                  as total_rows
  from public.findings;

commit;

-- ============================================================================
-- Post-apply expectations:
--
--   • The previously-present `scans` FK on first_detected_scan is gone
--     (Q1 returns no row with ref_table='scans').
--   • data_type still 'text' (unchanged by this migration — that's the
--     point; type cleanup is a future hygiene pass).
--   • null_rows ≈ total_rows (Bug D still in effect until the PR
--     deploys; non-null values begin appearing on the next medium
--     scan_run write post-deploy).
--
-- After deploy:
--   • Bug D writes scan_run UUIDs as text into the text column.
--   • Runtime safe — same shape ce47fc27's backfill already used.
--   • FK integrity on the forensic pointer is gone temporarily;
--     re-add in a dedicated cleanup pass per "FUTURE CLEANUP" above.
--
-- Roll-back recipe (only if dropping the FK breaks something downstream
-- that depended on the constraint — unlikely, since the column has been
-- effectively all-NULL):
--
--   alter table public.findings
--     add constraint findings_first_detected_scan_fkey
--     foreign key (first_detected_scan)
--     references public.scans(scan_id)
--     on delete set null;
--
--   -- Only restore if the `scans` table still exists and contains the
--   -- rows the column is supposed to reference.
-- ============================================================================
