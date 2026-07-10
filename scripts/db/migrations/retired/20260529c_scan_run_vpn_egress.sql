-- ============================================================================
-- 20260529c — Add vpn_egress column to scan_run for forensic tracking
-- ============================================================================
--
-- Phase 4a M7 foundation. Medium and Heavy tier scans will route through
-- ExpressVPN to dodge FortiGate / Cloudflare WAF bans on cloud-runner IPs.
-- We need to record which region + IP each scan actually used so that:
--
--   1. Debugging "why did this Medium scan get blocked" later is possible.
--      If FortiGate banned a specific exit IP, we need to know which one.
--
--   2. Region rotation logic can avoid recently-used exit IPs in case
--      Smart Connect lands us on a recently-blocked one.
--
--   3. Forensic reproducibility — a Medium scan run today should be
--      replayable from the same egress later by reading vpn_egress.
--
-- Format: "REGION | IP" (e.g. "USA - New York | 168.151.20.42") so the
-- column carries both human-readable region + machine-checkable IP in a
-- single field. NULL for Light tier (no VPN) and pre-M7 scans.
-- ============================================================================

alter table public.scan_run
  add column if not exists vpn_egress text;

comment on column public.scan_run.vpn_egress is
  'ExpressVPN egress used for this scan, formatted "REGION | IP" '
  '(e.g. "USA - New York | 168.151.20.42"). NULL for Light tier scans '
  '(no VPN) and pre-M7 scans. Used for forensic debugging when a '
  'Medium/Heavy scan gets blocked and we need to identify which exit '
  'IP was banned.';
