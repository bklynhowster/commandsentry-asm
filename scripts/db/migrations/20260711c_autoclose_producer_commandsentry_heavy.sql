-- 20260711c_autoclose_producer_commandsentry_heavy.sql
-- Heavy Phase 1 (net depth) — Q7 step 1. Spec: HEAVY_PHASE1_NETDEPTH_SPEC.md (4.7 v2).
-- Adds the 'commandsentry_heavy' branch to asm_autoclose_producer_patterns so
-- net-depth findings (naabu/fingerprintx, source='commandsentry_heavy') become
-- eligible for the note-127 autocloser. INERT until the naabu/fingerprintx phase
-- functions land + emit findings — landed FIRST (4.7 Q7) so those findings are
-- autoclose-eligible from their very first scan.
--
-- 4.7 Q3 CORRECTION (grounded in the real function, not the summary): the
-- producer-map patterns are TOOL-NAME LIKE patterns matched against
-- scan_run.tools_run (asm_autoclose_stale: `t.tool LIKE p.pattern`), NOT
-- check_name prefixes. The net-depth tools appear in tools_run as 'naabu' and
-- 'fingerprintx' (run_heavy's net-tool loop), so the pattern set is exactly those
-- two. NO 'testssl' here — testssl findings carry source='testssl' and already
-- have their own branch; commandsentry_heavy covers naabu + fingerprintx only.
--
-- Splitter-safe: LANGUAGE sql, single SELECT-CASE body, NO trailing ';' inside the
-- $$ body (the ledger applier's _split is not dollar-quote aware; a ';' before the
-- closing $$ would shred it — same discipline as 20260711b). CREATE OR REPLACE is
-- idempotent; the existing COMMENT ON FUNCTION persists.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 30
-- notes: Additive CASE branch commandsentry_heavy -> {naabu, fingerprintx} in asm_autoclose_producer_patterns. Inert until net-depth phase functions emit findings. LANGUAGE sql, no internal semicolon (splitter-safe). Byte-identical both repos.
-- END-META

CREATE OR REPLACE FUNCTION public.asm_autoclose_producer_patterns(p_source text)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE p_source
    WHEN 'nuclei'               THEN ARRAY['nuclei%']
    WHEN 'nikto'                THEN ARRAY['nikto']
    WHEN 'testssl'              THEN ARRAY['testssl.sh','testssl']
    WHEN 'commandsentry_light'  THEN ARRAY['tls_check','headers_check','csp_nonce_check','dns_posture','methods_check','common_paths','httpx_tech','behavioral_probes']
    WHEN 'commandsentry_medium' THEN ARRAY['nuclei%','ffuf','nikto','wafw00f']
    WHEN 'commandsentry_heavy'  THEN ARRAY['naabu','fingerprintx']
    ELSE NULL
  END
$$;
