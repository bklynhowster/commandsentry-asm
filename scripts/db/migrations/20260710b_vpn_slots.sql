-- 20260710b_vpn_slots.sql
-- VPN concurrency-guard slot pool — the enforcement point that keeps concurrent
-- VPN'd scans (medium/heavy) under the Mullvad device cap. Claimed at VPN
-- bring-up, released at teardown. See PORTAL_HEAVY_PROMOTION_SPEC.md §8 and the
-- 4.7 ruling (Q2). Command + Prodex share ONE Mullvad account (5-device cap), so
-- the ACTIVE pool size per instance is set by env VPN_SLOTS_N in scanner.yml
-- (Command=1, Prodex=2 → sum 3, 2 slots of slack). Rebalancing = an env flip, not
-- a migration, so this file stays byte-identical on both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 150
-- notes: Additive — new table + partial unique index + seed of 5 slot rows (the
--   physical Mullvad device cap). No existing-object changes. Active pool per
--   instance is capped at claim time by env VPN_SLOTS_N (default 1 if unset —
--   safe-low), NOT by this row count. Identical on commandsentry-asm and
--   prodexsentry-asm; no .migration-divergence.yaml entry needed.
-- END-META

create table if not exists public.vpn_slots (
  slot_id      int primary key,
  scan_run_id  uuid null references public.scan_run(scan_run_id) on delete set null,
  claimed_at   timestamptz,
  heartbeat_at timestamptz
);

-- A scan may hold at most one slot (defense against a double-claim bug).
create unique index if not exists vpn_slots_scan_run_uniq
  on public.vpn_slots (scan_run_id) where scan_run_id is not null;

-- Seed the physical device-cap worth of slots (5). Active usage per instance is
-- bounded by env VPN_SLOTS_N at claim time, not by the number of rows here — so a
-- future move to separate Mullvad accounts is just a VPN_SLOTS_N bump, no migration.
insert into public.vpn_slots (slot_id)
select generate_series(1, 5)
on conflict (slot_id) do nothing;
