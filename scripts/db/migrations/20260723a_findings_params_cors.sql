-- 20260723a_findings_params_cors.sql
-- Param-carrying finding pipeline FOUNDATION, part 1/2 (Obsidian 160 / #2.05.CORS, 4.7 2026-07-23).
--
-- Additive findings.params jsonb — per-class target context for the safe-exploit pipeline (4.7 Q3):
--   cors                      -> {endpoint, acao_observed, acac_observed, source}
--   redirect/ssrf/lfi (ph.2)  -> {endpoint, param_name, param_example, discovery_source}
-- DEFAULT '{}' -> zero backfill, zero behavior change on existing rows.
--
-- Companion: 20260723b adds the 'cors' finding_category_t label (isolated per the 55P04 rule).
-- BOTH are prerequisites to the passive CORS-finding emitter, which ships in a LATER push AFTER
-- these apply to both DBs (enum-before-code discipline — writing category='cors' before the label
-- exists dies at persist, like the 2026-07-10 httpx-source incident).
--
-- Splitter-safe (plain DDL, no dollar-quoted blocks), idempotent (IF NOT EXISTS), byte-identical.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 80
-- notes: Additive findings.params jsonb (default '{}'), no backfill (DEFAULT covers existing rows).
--   Byte-identical on commandsentry-asm and prodexsentry-asm. Prereq to the #2.05.CORS emitter.
-- END-META

alter table public.findings
  add column if not exists params jsonb not null default '{}'::jsonb;

comment on column public.findings.params is
  'Obsidian 160 / #2.05. Per-class target context for the safe-exploit pipeline (jsonb, default '
  '{}). cors: {endpoint, acao_observed, acac_observed, source}. redirect/ssrf/lfi (phase 2): '
  '{endpoint, param_name, param_example, discovery_source}. See PARAMS_SCHEMAS in safe_exploit.py.';
