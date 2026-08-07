-- ============================================================================
-- 20260806a — device_class 'unreadable' + evidence-collection event types
-- ============================================================================
--
-- Phase 1 of 3 (4.7 Q3, Obsidian 170). TAXONOMY ONLY. No code lands with this
-- migration; it rides alone (4.7 Q5). The classifier changes that USE these
-- values are phase 2, and the portal/consumer changes are phase 3.
--
-- THE DEFECT (Obsidian 169). The classifier cannot distinguish "evidence was
-- gathered and nothing matched" from "evidence collection failed". Both produce
-- device_class 'unknown' with empty evidence, and the write path in
-- device_class_runner.py stamps that over a confirmed classification with no
-- guard. Across the 2026-07-24 to 2026-08-06 soak window, 30 assets would have
-- been overwritten had write mode been enabled (Command 4, Prodex 26). All four
-- Command events were nameservers, in a single pass, identical to the
-- microsecond -- the signature of one transient input failure, not a
-- reclassification.
--
-- THE FIX. Give the classifier a word for the second case.
--   unknown     = evidence gathered, nothing matched. Empirically unclassifiable.
--   unreadable  = evidence collection failed. We could not determine.
--
-- Once those are distinct, the guard becomes a property of the vocabulary
-- rather than ad-hoc write-path logic: never overwrite a positive
-- classification with unreadable. That rule lands in phase 2, not here.
--
-- Same shape as the VPN egress fail-open closed on 2026-07-29, where the fix
-- was splitting a placeholder into distinct exit codes for unreadable versus
-- no-baseline. 4.7 G1: a transient input failure must never produce a verdict.
--
-- WHY drop-and-add rather than add-column-if-not-exists. device_class is
-- text plus CHECK, not an enum. 20260713a made that choice deliberately,
-- because an idempotent enum requires a do-block the migration splitter cannot
-- parse. Widening a CHECK therefore means replacing it. The pair
-- "drop constraint if exists" followed by "add constraint" with an explicit
-- name is idempotent AS A PAIR and needs no do-block. Same idiom as 20260711a.
--
-- WHY no "not valid". Each new value list is a strict SUPERSET of the list it
-- replaces, so every existing row already satisfies it and validation cannot
-- fail. 20260711a used "not valid" because it was rewriting a list where
-- existing rows might not pass. Validating here is nearly free and leaves the
-- constraints in a fully-valid state.
--
-- CONSTRAINT NAMES were read from pg_constraint on both live instances on
-- 2026-08-06 rather than assumed. They are Postgres auto-generated names from
-- the inline column CHECKs in 20260713a and 20260713b. Note there are THREE,
-- not one: device_class_confidence is separately constrained and also needs
-- unreadable, and the dryrun event_type list needs the two new event types.
-- device_class_dryrun.device_class and .confidence are unconstrained text and
-- need no change.
--
-- Additive, idempotent, splitter-safe (no do-blocks, no semicolons inside
-- string literals, no double-dash inside string literals). Stamps nothing,
-- writes no rows, changes no routing. Byte-identical both repos.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 90
-- notes: Taxonomy only. Widens assets_device_class_check and assets_device_class_confidence_check to accept unreadable, and device_class_dryrun_event_type_check to accept EVIDENCE_COLLECTION_FAILED and EVIDENCE_RECOVERED. Constraint names verified against pg_constraint on both instances. No code, no data change, no routing change. Phase 1 of 3 and rides alone. Splitter-safe, idempotent, byte-identical both repos.
-- END-META
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1. assets.device_class — add 'unreadable'
-- ----------------------------------------------------------------------------
alter table public.assets drop constraint if exists assets_device_class_check;

alter table public.assets add constraint assets_device_class_check
  check (device_class in (
    'origin_host','edge_firewall','waf','adc_lb','cdn','cloud_endpoint',
    'unknown','unreadable'
  ));

comment on column public.assets.device_class is
  'Fronting-device classification. unknown means evidence was gathered and '
  'nothing matched, so the asset is empirically unclassifiable. unreadable '
  'means evidence collection FAILED and we could not determine anything. It is '
  'a transient input failure, not a verdict. The two are distinct so that '
  'unreadable can never overwrite a positive classification (4.7 G1, '
  'Obsidian 169/170). Anything reading this column must treat unreadable as '
  'no-information, NOT as a classification.';


-- ----------------------------------------------------------------------------
-- 2. assets.device_class_confidence — add 'unreadable'
-- ----------------------------------------------------------------------------
-- Confidence is only meaningful for a positive classification. unreadable is a
-- state rather than a graded verdict, so it carries a matching sentinel here to
-- keep the column non-null (4.7 Q1). Phase 2 ranks it BELOW unknown, so it can
-- never win a comparison against a real classification.
alter table public.assets
  drop constraint if exists assets_device_class_confidence_check;

alter table public.assets add constraint assets_device_class_confidence_check
  check (device_class_confidence in (
    'confirmed','suspected','unknown','unreadable'
  ));

comment on column public.assets.device_class_confidence is
  'Confidence in device_class. Ranks confirmed > suspected > unknown > '
  'unreadable. unreadable is the sentinel for a failed evidence collection and '
  'ranks lowest by design, so it can never displace a real classification.';


-- ----------------------------------------------------------------------------
-- 3. device_class_dryrun.event_type — add the evidence-collection events
-- ----------------------------------------------------------------------------
-- 4.7 Q2 ruled these ship WITH the taxonomy rather than later: without them an
-- evidence-collection failure fires silently and only a manual query can find
-- it. With them, persistent-failure alerting is a trivial query over the trail,
-- and the soak exit criterion in 4.7 Q6 becomes measurable -- it requires
-- observing at least five EVIDENCE_COLLECTION_FAILED events, each one verified
-- to have preserved the prior classification, plus at least one recovery.
alter table public.device_class_dryrun
  drop constraint if exists device_class_dryrun_event_type_check;

alter table public.device_class_dryrun add constraint device_class_dryrun_event_type_check
  check (event_type in (
    'STAMP','CHANGE','TRANSITION_UPGRADE','TRANSITION_DOWNGRADE',
    'EVIDENCE_COLLECTION_FAILED','EVIDENCE_RECOVERED'
  ));

comment on column public.device_class_dryrun.event_type is
  'Soak audit event taxonomy (4.7 E3). TRANSITION_DOWNGRADE remains the red '
  'flag that resets the soak clock. EVIDENCE_COLLECTION_FAILED records an '
  'evaluation that returned unreadable, where the prior classification was '
  'PRESERVED rather than overwritten. EVIDENCE_RECOVERED records the return '
  'from unreadable to a determinate classification.';
