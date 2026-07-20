-- ============================================================================
-- 20260720a — assets.vendor_product_confidence (R5 two-bar split, Obsidian 146)
-- ============================================================================
--
-- P1 of the multi-signal security-stack ID engine. P0.5 split the classifier's
-- single confidence into TWO bars (derive_device_class.classify, 4.7 R5):
--   * device_class_confidence  — "is a device of this TYPE present" (all signals;
--     presence_only can confirm "a WAF is present"). Already columned (20260713a).
--   * vendor_product_confidence — "do we know the actual VENDOR" (vendor_identifying
--     signals ONLY; presence-only never earns a brand). This column lands it.
--
-- WHY it must exist before P2: CVE exposure is brand-specific — there is no such
-- thing as a generic-WAF CVE. P2 (CVE -> KEV enrichment) gates every attribution
-- on vendor_product_confidence = 'confirmed', so a presence-only-confirmed asset
-- (wafw00f positive, vendor null) can NEVER fire a "vendor unknown" CVE finding
-- (146 biggest-risk ruling). This migration is that gate's storage.
--
-- Additive, idempotent, splitter-safe (no do-blocks, no ';' inside strings, no
-- '--' inside string literals), CLASSIFY-ONLY (changes no routing — routing still
-- gates on device_class_confidence). Byte-identical both repos. Default 'unknown'
-- so every existing row is correct until device_class_runner re-stamps it.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 120
-- notes: Additive vendor_product_confidence text+CHECK on public.assets AND public.device_class_dryrun (audit parity), default 'unknown'. R5 two-bar split storage; P2 CVE enrichment gates on this. Changes no routing. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================

-- ----------------------------------------------------------------------------
-- assets — the vendor-naming confidence bar (orthogonal to device_class_confidence)
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists vendor_product_confidence text not null default 'unknown'
    check (vendor_product_confidence in ('confirmed','suspected','unknown'));

comment on column public.assets.vendor_product_confidence is
  'R5 two-bar split (Obsidian 146): confidence that vendor_product NAMES the '
  'vendor, scored over vendor_identifying signals ONLY. Orthogonal to '
  'device_class_confidence (which can be confirmed on presence_only signals '
  'alone). unknown until a vendor-identifying signal fires. P2 CVE enrichment '
  'requires this = confirmed before attributing any brand-specific CVE.';

-- ----------------------------------------------------------------------------
-- device_class_dryrun — same column on the soak audit trail (4.7 E3 parity)
-- ----------------------------------------------------------------------------
-- Every audit row already records confidence (== device_class_confidence) and
-- vendor_product; record the vendor bar too, so post-hoc soak review can answer
-- "did we ever NAME a vendor on asset X, and how sure" from the trail alone.
alter table public.device_class_dryrun
  add column if not exists vendor_product_confidence text not null default 'unknown'
    check (vendor_product_confidence in ('confirmed','suspected','unknown'));

comment on column public.device_class_dryrun.vendor_product_confidence is
  'R5 vendor-naming confidence at the moment of this audit event (Obsidian 146). '
  'Mirrors assets.vendor_product_confidence; vendor_identifying signals only.';
