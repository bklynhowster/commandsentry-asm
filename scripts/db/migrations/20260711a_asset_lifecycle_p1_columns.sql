-- 20260711a_asset_lifecycle_p1_columns.sql
-- ASM Asset Lifecycle — P1 (non-destructive foundation). Spec: ASSET_LIFECYCLE_SPEC.md v2
-- (4.7-verified 2026-07-11). Adds lifecycle columns, backfills last_alive_at, and a
-- forward-enforcing CHECK on discovery_status. NO demotion logic here — the went_dark
-- writer is P2 and only ships after a 14-day soak of real last_alive_at data.
-- Byte-identical on commandsentry-asm and prodexsentry-asm.
--
-- last_alive_at = last sweep that observed a live service; it powers the R2 dwell (D).
-- Backfilled for confirmed_live ONLY — dns_only never had a service, so it can't
-- "go dark" and gets no last_alive_at. Backfill to last_observed (truthful, recent for
-- live assets) so nothing inherits a stale clock. A currently-live asset re-stamps
-- last_alive_at=now() on its next sweep, so the backfill value is only a floor. The
-- mass-tombstone-on-day-15 trap (4.7 Q10) is avoided because every existing asset gets
-- a non-null recent clock here AND no demotion writer exists until P2.
--
-- CHECK is added NOT VALID: it enforces on ALL NEW writes immediately (stops
-- discovery_status typo-drift the moment P1 lands) without failing on any pre-existing
-- drift. Command's discovery_status was audited clean (2026-07-11). Prodex must run
--   SELECT DISTINCT discovery_status FROM public.assets;
-- and clean any drift, then a follow-up `ALTER TABLE public.assets VALIDATE CONSTRAINT
-- chk_discovery_status;` promotes it to fully validated on both DBs.
--
-- No dollar-quoted (do ...) block on purpose: the applier's _split is single-quote
-- aware but NOT dollar-quote aware, so a do-block's inner semicolons get shredded.
-- Idempotent CHECK is done with drop-if-exists + add instead. No BEGIN/COMMIT — the
-- applier wraps its own transaction.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 250
-- notes: Additive columns (IF NOT EXISTS) + idempotent backfill (WHERE last_alive_at IS NULL, confirmed_live only) + drop-then-add NOT VALID CHECK. No do-block (splitter is not dollar-quote aware). assets is small. No demotion logic. Byte-identical on both scanner repos.
-- END-META

alter table public.assets add column if not exists last_alive_at      timestamptz;
alter table public.assets add column if not exists went_dark_at       timestamptz;
alter table public.assets add column if not exists last_transition_at timestamptz;
alter table public.assets add column if not exists resurrection_count integer not null default 0;

update public.assets
   set last_alive_at = coalesce(last_alive_at, last_observed, first_observed, now())
 where discovery_status = 'confirmed_live'
   and last_alive_at is null;

alter table public.assets drop constraint if exists chk_discovery_status;

alter table public.assets add constraint chk_discovery_status
  check (discovery_status in (
    'confirmed_live','ct_ghost','unverified','dns_only',
    'confirmed_dark','went_dark','retired'
  )) not valid;
