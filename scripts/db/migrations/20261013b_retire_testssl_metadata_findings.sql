-- 20261013b_retire_testssl_metadata_findings.sql
--
-- Retire the open testssl findings whose CHECK the parser stopped emitting on
-- 2026-07-25. Note 308 (proposal item 1). Howie 2026-10-13: "let's do number one."
--
-- ============================================================================
-- WHY
-- ============================================================================
-- On 2026-07-25, reviewing littleleaffarms, Howie ruled that a set of testssl
-- ids are TLS INVENTORY, NOT FINDINGS ("somewhat redundant and crazy ... doesn't
-- really help a security analyst"). scripts/normalize/cs_parsers/testssl.py
-- METADATA_IDS drops them at parse time, so no scan has produced one since.
-- The rows that already existed were never retired: on Command 60 open rows
-- (FS_KEMs 31, FS_TLS12_sig_algs 27, cert_subjectAltName 2 — the last two at
-- HIGH), on Prodex 19 (FS_KEMs 6, FS_TLS12_sig_algs 5, TLS_session_ticket 5,
-- cert_notAfter 3). Every one has last_observed_at <= 2026-07-25. They sit in
-- the dashboard's open count, in v_fleet_open_reps, and in the daily email's
-- "not seen by any scan in 30+ days" line — as problems nobody can act on and
-- no scan can ever re-observe.
--
-- `detector_retired` (20260902b, 4.7 ruling 57) names exactly this: the
-- detector that watched the finding stopped watching. Both criteria hold:
--   (1) a specific detector was removed from the plan — the parser drops the
--       id, deliberately, on the record (the METADATA_IDS comment);
--   (2) no remaining detector can re-observe it — the id is dropped for every
--       tier and every asset, so a future testssl run cannot bring it back.
-- NOT remediated: nobody established a fix. NOT false_positive: the facts were
-- true. NOT closed_reclassified: nothing moved. Retired is the honest word.
--
-- ============================================================================
-- WHY A MIGRATION AND NOT scripts/db/retire_detector_findings.py
-- ============================================================================
-- That tool is the designed channel for this status, but its class is
-- (source, severity) — testssl/LOW would also match LUCKY13, OCSP_stapling and
-- other LIVE checks, and its criterion-(2) guard would (rightly) refuse the
-- batch because those are observed weekly. It needs a check-id filter, and it
-- has no runner: nothing on Howie's Mac holds the database connection; every
-- database write in this project goes through GitHub (migrate.yml, approved
-- per instance). The migration pipeline is therefore the human-run, approved,
-- ledgered channel. This file carries the tool's guardrails:
--   SOURCE-TAG      one admin_audit_log row per retired finding, with the
--                   reason, the rule, the parser decision date and a batch id;
--   THRESHOLD-ABORT fails the apply (nothing written) above 200 rows;
--   CRITERION (2)   fails the apply (nothing written) if ANY row with one of
--                   these ids was observed after the parser change — evidence
--                   that something still emits it;
--   NAME THE TARGET migrate.yml runs per repo against its own instance;
--   EXPLICIT REASON in every audit row.
-- The two guards are plain SELECTs that divide by zero when violated
-- (apply_pending_migrations.py's splitter is not dollar-quote aware, so no
-- DO block). A violated guard aborts the transaction (the runner's, or the
-- BEGIN/COMMIT below on a hand run); the ledger row is not written; the scan
-- gate stays closed until a human looks.
--
-- ============================================================================
-- WHAT THIS DOES — AND DOES NOT
-- ============================================================================
-- One UPDATE ... RETURNING feeding one INSERT (a single data-modifying CTE
-- statement, atomic). Rows touched: source = testssl, an open-family status
-- (detected / confirmed / open / regressed), check id in the parser's
-- METADATA_IDS. Sets current_status = detector_retired and
-- detector_retired_at = now() (chk_detector_retired_at requires both).
-- remediated_at stays NULL (not a remediation; note 126's invariant holds).
-- trg_findings_sync_current_risk recomputes each touched asset's current_risk
-- by itself; nothing else changes. No view, no function, no table shape.
--
-- The id list below is pinned to METADATA_IDS by scripts/db/test_migration_
-- 20261013b.py, and scripts/db/test_retired_parser_ids_have_migrations.py
-- fails whenever an id is added to METADATA_IDS without a retirement
-- migration listing it — so the next parser decision retires its rows in the
-- same change instead of three months later.
--
-- NOT in this file, deliberately:
--   - DNS_CAArecord (Command 31 open, nothing observed since 2026-08-25). Not
--     a parser decision; the check went quiet for a reason not yet found. A
--     retirement needs a known removal (criterion 1). Chased separately.
--   - cert_trust_wildcard (demoted to INFO by T2): still observed daily under
--     its existing rows. Not retired; a severity question for another day.
--   - Anything merely stale (testssl ran later and did not re-report it, or
--     the asset was not deep-scanned). Those are proposal items 2 and 3.
--
-- Idempotent: a second apply matches zero rows and writes nothing; the guards
-- pass on an empty set. Reversible: UPDATE findings SET current_status =
-- 'detected', detector_retired_at = NULL WHERE finding_id IN (the audit rows
-- with details->>'batch_rule' = 'note_308_item1_testssl_metadata_ids').
--
-- ============================================================================
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: Data-only. One UPDATE+INSERT statement retiring open testssl rows whose check id the parser dropped on 2026-07-25 (METADATA_IDS), with an audit row each; two guard SELECTs that abort the apply (division by zero) if any such id was observed after the parser change or more than 200 rows match. current_risk recomputed by the existing trigger. Byte-identical in both repos; Command 60 rows, Prodex 19 at build time. Splitter-safe (no dollar-quoted blocks).
-- END-META
-- ============================================================================

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction; they are here
-- so a HAND run (psql -f) also stops at a failed guard instead of printing the
-- error and carrying on to the UPDATE.
BEGIN;

-- ── GUARD 1 · criterion (2): nothing with one of these ids may have been
--    observed after the parser stopped emitting them. If this divides by zero,
--    something still emits the id and this is NOT a retired detector.
SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_nothing_observed_since_parser_change
  FROM public.findings f
 WHERE f.source::text = 'testssl'
   AND f.last_observed_at > TIMESTAMPTZ '2026-07-26 00:00:00+00'
   AND f.finding_id LIKE f.asset_id || ':testssl:%'
   AND regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') IN (
     -- BEGIN RETIRED CHECK IDS (= testssl.py METADATA_IDS, 2026-07-25)
     'cert_notAfter', 'cert_notBefore', 'cert_keySize', 'cert_signatureAlgorithm',
     'cert_commonName', 'cert_subjectAltName', 'cert_serialNumber',
     'cert_fingerprintSHA1', 'cert_fingerprintSHA256', 'cert_caIssuers',
     'cert_crlDistributionPoints', 'cert_ocspURL', 'cert_mustStapleExtension',
     'cert_eTS_wildcard', 'intermediate_cert_notAfter', 'intermediate_cert_notBefore',
     'intermediate_cert_keySize', 'intermediate_cert_signatureAlgorithm',
     'FS_TLS12_sig_algs', 'FS_ECDHE_curves', 'FS_TLS13_sig_algs', 'FS_KEMs',
     'TLS_session_ticket', 'TLS_timestamp', 'TLS_extensions', 'SSL_sessionID_support',
     'sessionresumption_ticket', 'sessionresumption_ID', 'clientsimulation'
     -- END RETIRED CHECK IDS
   );

-- ── GUARD 2 · threshold: a known retirement is a bounded class. More than 200
--    matching rows means the predicate is wrong, not that the class is big.
SELECT 1 / (CASE WHEN count(*) <= 200 THEN 1 ELSE 0 END) AS guard_bounded_batch
  FROM public.findings f
 WHERE f.source::text = 'testssl'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.finding_id LIKE f.asset_id || ':testssl:%'
   AND regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') IN (
     'cert_notAfter', 'cert_notBefore', 'cert_keySize', 'cert_signatureAlgorithm',
     'cert_commonName', 'cert_subjectAltName', 'cert_serialNumber',
     'cert_fingerprintSHA1', 'cert_fingerprintSHA256', 'cert_caIssuers',
     'cert_crlDistributionPoints', 'cert_ocspURL', 'cert_mustStapleExtension',
     'cert_eTS_wildcard', 'intermediate_cert_notAfter', 'intermediate_cert_notBefore',
     'intermediate_cert_keySize', 'intermediate_cert_signatureAlgorithm',
     'FS_TLS12_sig_algs', 'FS_ECDHE_curves', 'FS_TLS13_sig_algs', 'FS_KEMs',
     'TLS_session_ticket', 'TLS_timestamp', 'TLS_extensions', 'SSL_sessionID_support',
     'sessionresumption_ticket', 'sessionresumption_ID', 'clientsimulation'
   );

-- ── THE TRANSITION · one statement: retire, then audit every retired row.
WITH retired AS (
  UPDATE public.findings f
     SET current_status      = 'detector_retired',
         detector_retired_at = now(),
         updated_at          = now()
   WHERE f.source::text = 'testssl'
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.finding_id LIKE f.asset_id || ':testssl:%'
     AND regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') IN (
       'cert_notAfter', 'cert_notBefore', 'cert_keySize', 'cert_signatureAlgorithm',
       'cert_commonName', 'cert_subjectAltName', 'cert_serialNumber',
       'cert_fingerprintSHA1', 'cert_fingerprintSHA256', 'cert_caIssuers',
       'cert_crlDistributionPoints', 'cert_ocspURL', 'cert_mustStapleExtension',
       'cert_eTS_wildcard', 'intermediate_cert_notAfter', 'intermediate_cert_notBefore',
       'intermediate_cert_keySize', 'intermediate_cert_signatureAlgorithm',
       'FS_TLS12_sig_algs', 'FS_ECDHE_curves', 'FS_TLS13_sig_algs', 'FS_KEMs',
       'TLS_session_ticket', 'TLS_timestamp', 'TLS_extensions', 'SSL_sessionID_support',
       'sessionresumption_ticket', 'sessionresumption_ID', 'clientsimulation'
     )
  RETURNING f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
            f.last_observed_at, f.detector_retired_at,
            regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') AS check_id
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL,
       'detector_retired_finding',
       NULL,
       NULL,
       jsonb_build_object('current_status', 'open_family', 'source', 'testssl',
                          'severity', r.severity, 'last_observed_at', r.last_observed_at),
       jsonb_build_object('current_status', 'detector_retired',
                          'detector_retired_at', r.detector_retired_at),
       jsonb_build_object(
         'finding_id',   r.finding_id,
         'asset_id',     r.asset_id,
         'title',        r.title,
         'check_id',     r.check_id,
         'retired_class', 'testssl/' || r.check_id,
         'reason',       'testssl id dropped from the parser as TLS inventory on 2026-07-25 (testssl.py METADATA_IDS, Howie reviewing littleleaffarms), no scan can re-observe it',
         'tool',         '20261013b_retire_testssl_metadata_findings.sql',
         'rule',         '4.7_ruling_57_detector_retired_manual_transition',
         'batch_rule',   'note_308_item1_testssl_metadata_ids',
         'parser_change_date', '2026-07-25'
       )
  FROM retired r;

COMMIT;
