-- 20261013c_autoclose_testssl_not_reobserved_once.sql
--
-- ONE-TIME, REVIEWED batch: close the TLS (testssl) findings that a later clean
-- deep scan looked for properly and did not find. Note 308 item 2. Howie
-- 2026-10-13: "Go with your recommendation. I totally agree."
--
-- ============================================================================
-- WHY
-- ============================================================================
-- The deep (heavy) tier was designed to rely on asm_autoclose_stale_findings
-- as its remediation engine (close_out_heavy deliberately does not call
-- delta_close_for_scan_run; medium does). That engine has been BLOCKED live
-- since 20260902a (4.7 ruling 20, four gates). So on the deep tier nothing has
-- ever closed a finding a later scan failed to re-observe: on Command today 67
-- LOW/MODERATE testssl rows on 25 assets have not been seen for 30+ days while
-- testssl ran successfully on the same host afterwards AND re-reported the
-- host's other, previously known TLS findings — the same subset every week.
-- They sit in the dashboard's open count and in the daily email's "not seen
-- by any scan in 30+ days" line, and only a human could close them.
--
-- ============================================================================
-- WHY NOT JUST LIFT THE BLOCK
-- ============================================================================
-- The ruling was right. The engine's evidence is "a producer tool ran with
-- tool_status ok=true after the last observation and did not re-report". On
-- 2026-09-06 testssl on ftp.sciimage.com reported ok=true, emitted two trivial
-- lines (TLS1_2, TLS1_3) and none of the host's nine known issues: the tool
-- "succeeded" without reading the host. The engine would close those nine for
-- the wrong reason. Six such rows exist today, all on that host.
--
-- THE STRICTER RULE here (per 4.7 gate 1, "all-match empirically validated as
-- sufficient, or precise-match ready" — this is a precise-match for the TLS
-- surface): a finding closes only when a later complete scan
--   (a) ran testssl.sh with tool_status ok = true, AND
--   (b) RE-OBSERVED, in THAT scan (a finding_history row for the witness
--       with scan_id = that scan_run_id — finding_history is written per scan
--       on the clean path only), at least one OTHER testssl finding on the
--       same host and the same port (same hash7 segment) that already existed
--       before that scan (first_detected_at more than a day before it) —
--       proof the tool read the host and the parser read the tool — AND
--   (c) did NOT re-observe this finding in that scan (no finding_history row
--       for it), and this finding has now been unseen 30+ days;
--   (d) the witness is a check that needs a COMPLETED HANDSHAKE — never a
--       "protocol not offered" line (SSLv2/SSLv3/TLS1/TLS1_1/TLS1_2/TLS1_3)
--       and never DNS_CAArecord. Found in review: since 2026-09-06 testssl
--       on ftp.unimacgraphics.com and ftp.sciimage.com gets no handshake at
--       all and reports only "TLS 1.2/1.3 not offered"; those two lines
--       would otherwise have passed as witnesses for 13 real findings;
--   (e) the finding's CHECK is still alive somewhere in the fleet (some
--       testssl row with the same check id observed in the last 30 days).
--       Found in review: DNS_CAArecord has been silent fleet-wide since
--       2026-08-25 (cause unknown); 24 rows passed (a)-(c) and would have
--       closed as 24 same-week fixes. A check nobody sees anywhere is a
--       broken or retired detector, not a fix.
-- Severity LOW or MODERATE only (the engine's cap: never HIGH or above; INFO
-- is inventory and is not in scope here). Source testssl only. The EARLIEST
-- qualifying scan is recorded as the evidence, with the witness finding (the
-- witness may itself be closed or retired — it proves the tool read the host,
-- nothing more). Binding the witness to the scan through finding_history
-- (review item, 2026-10-13) is what stops a blind "ok" scan being credited
-- with a sibling a LATER scan saw, and stops a degraded scan's observation
-- from counting (degraded runs write no finding_history).
-- Measured 2026-10-13 (read-only): Command 31 rows / 12 assets (all port
-- 443), Prodex 10 rows / 8 assets. Without (d) and (e) Command would have
-- been 67.
--
-- KNOWN GAP IN THE MONITORING (review item): a DEGRADED later scan that
-- re-emits a closed row updates last_observed_at and last_seen_scan_run but
-- the status stays 'remediated' (the UPSERT's downgrade guard), and
-- regress_observed_for_scan_run runs on the clean path only. Such a row is
-- caught by the next CLEAN scan. Until then it reads "remediated, observed
-- after remediated_at" — a digest line for that shape is a follow-up.
--
-- ============================================================================
-- THE FOUR GATES, AS MET FOR THIS BATCH
-- ============================================================================
--   1. precise-match ready for the TLS surface: rule (b) above.
--   2. candidates reviewed: the dry-run list (note 308) was read by 4.8 and
--      summarised for Howie before this ran.
--   3. live monitoring: the deep tier already calls
--      regress_observed_for_scan_run(scan_run_id, 'testssl') on its clean
--      path (20260629a): a closed finding the next clean scan re-emits flips
--      to 'regressed' with an audit row, and the daily digest counts
--      regressed items in its headline and subject. Two quiet weeks before
--      any recurring run is decided.
--   4. explicit decision: Howie, 2026-10-13, quoted above.
-- The block on asm_autoclose_stale_findings(false) is NOT lifted. Nothing
-- recurring is created. A second run is a new decision.
--
-- ============================================================================
-- WHAT THIS DOES — AND DOES NOT
-- ============================================================================
-- One guard SELECT (threshold: more than 100 rows means the predicate is
-- wrong; divide by zero aborts the transaction, nothing written, no ledger
-- row, scan gate stays closed). Then ONE statement: UPDATE ... RETURNING
-- feeding INSERT into admin_audit_log — one row per closed finding carrying
-- the covering scan, its completion time, the witness finding, the rule and
-- a batch id. Sets current_status = remediated, remediated_at = now()
-- (note 126's invariant: remediated_at iff remediated/validated_remediated),
-- so tomorrow's digest lists them under "Marked fixed in this window", where
-- the audit row says who marked them and why. trg_findings_sync_current_risk
-- recomputes each touched asset's risk by itself. Nothing else changes.
-- Idempotent: a second apply finds the rows remediated and matches nothing.
-- Reversible: the audit rows (details->>'batch_rule') name every finding.
-- BEGIN/COMMIT so a hand psql run also stops at the guard.
--
-- ============================================================================
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 4000
-- notes: Data-only, one-time reviewed batch. Closes (remediated + remediated_at) testssl LOW/MODERATE findings unseen 30+ days where a later complete scan ran testssl.sh ok AND, per finding_history, observed in that scan another pre-existing handshake-level testssl finding on the same asset and port while not observing this one, and the check is still observed somewhere in the fleet; audit row per finding with the covering scan and witness; threshold guard (>100 rows aborts via division by zero). Does not touch asm_autoclose_stale_findings or its block. current_risk recomputed by the existing trigger. Byte-identical in both repos; Command 31 rows / Prodex 10 at build. Splitter-safe.
-- END-META
-- ============================================================================

BEGIN;

-- ── GUARD · a known batch is bounded. Command measured 31; more than 100
--    matching rows means the predicate is wrong, not that the batch is big.
SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_bounded_batch
  FROM public.findings f
 WHERE f.source::text = 'testssl'
   AND f.severity::text IN ('LOW', 'MODERATE')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.last_observed_at < now() - interval '30 days'
   AND f.finding_id LIKE f.asset_id || ':testssl:%'
   AND EXISTS (
     SELECT 1
       FROM public.scan_run sr
      WHERE sr.asset_id = f.asset_id
        AND sr.status::text = 'complete'
        AND sr.completed_at > f.last_observed_at
        AND 'testssl.sh' = ANY (sr.tools_run)
        AND sr.tool_status -> 'testssl.sh' ->> 'ok' = 'true'
        -- (c) this finding was NOT observed in that scan
        AND NOT EXISTS (
          SELECT 1 FROM public.finding_history fx
           WHERE fx.finding_id = f.finding_id AND fx.scan_id = sr.scan_run_id::text
        )
        -- (b) a pre-existing handshake-level sibling on the same port WAS observed in that scan
        AND EXISTS (
          SELECT 1
            FROM public.findings g
            JOIN public.finding_history fh
              ON fh.finding_id = g.finding_id AND fh.scan_id = sr.scan_run_id::text
           WHERE g.asset_id = f.asset_id
             AND g.source::text = 'testssl'
             AND g.finding_id <> f.finding_id
             AND g.first_detected_at < sr.completed_at - interval '1 day'
             AND substring(g.finding_id from ':[^:]*$') = substring(f.finding_id from ':[^:]*$')
             AND g.finding_id !~ ':testssl:(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3|DNS_CAArecord):'
        )
   )
   -- (e) the check is alive somewhere in the fleet (exact id compare; no LIKE wildcards)
   AND EXISTS (
     SELECT 1
       FROM public.findings h
      WHERE h.source::text = 'testssl'
        AND h.finding_id LIKE h.asset_id || ':testssl:%'
        AND regexp_replace(substr(h.finding_id, length(h.asset_id) + 10), ':[^:]*$', '')
          = regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '')
        AND h.last_observed_at > now() - interval '30 days'
   );

-- ── THE BATCH · close, then audit every closed row with its evidence.
WITH batch AS (
  SELECT gen_random_uuid() AS id, now() AS at
),
candidates AS (
  SELECT f.finding_id,
         f.asset_id,
         f.title,
         f.severity::text       AS severity,
         f.current_status::text AS old_status,
         f.last_observed_at,
         ev.scan_run_id,
         ev.completed_at        AS scan_completed_at,
         ev.witness_finding_id,
         ev.witness_last_observed_at
    FROM public.findings f
    JOIN LATERAL (
      -- the EARLIEST clean testssl scan after the last observation that
      -- re-observed a pre-existing sibling (the witness) and not this row
      SELECT sr.scan_run_id, sr.completed_at, w.finding_id AS witness_finding_id,
             w.last_observed_at AS witness_last_observed_at
        FROM public.scan_run sr
        JOIN LATERAL (
          SELECT g.finding_id, g.last_observed_at
            FROM public.findings g
            JOIN public.finding_history fh
              ON fh.finding_id = g.finding_id AND fh.scan_id = sr.scan_run_id::text
           WHERE g.asset_id = f.asset_id
             AND g.source::text = 'testssl'
             AND g.finding_id <> f.finding_id
             AND g.first_detected_at < sr.completed_at - interval '1 day'
             AND substring(g.finding_id from ':[^:]*$') = substring(f.finding_id from ':[^:]*$')
             AND g.finding_id !~ ':testssl:(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3|DNS_CAArecord):'
           ORDER BY g.first_detected_at, g.finding_id
           LIMIT 1
        ) w ON true
       WHERE sr.asset_id = f.asset_id
         AND sr.status::text = 'complete'
         AND sr.completed_at > f.last_observed_at
         AND 'testssl.sh' = ANY (sr.tools_run)
         AND sr.tool_status -> 'testssl.sh' ->> 'ok' = 'true'
         AND NOT EXISTS (
           SELECT 1 FROM public.finding_history fx
            WHERE fx.finding_id = f.finding_id AND fx.scan_id = sr.scan_run_id::text
         )
       ORDER BY sr.completed_at ASC
       LIMIT 1
    ) ev ON true
   WHERE f.source::text = 'testssl'
     AND f.severity::text IN ('LOW', 'MODERATE')
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND f.last_observed_at < now() - interval '30 days'
     AND f.finding_id LIKE f.asset_id || ':testssl:%'
     AND EXISTS (
       SELECT 1
         FROM public.findings h
        WHERE h.source::text = 'testssl'
          AND h.finding_id LIKE h.asset_id || ':testssl:%'
          AND regexp_replace(substr(h.finding_id, length(h.asset_id) + 10), ':[^:]*$', '')
            = regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '')
          AND h.last_observed_at > now() - interval '30 days'
     )
),
closed AS (
  UPDATE public.findings f
     SET current_status = 'remediated',
         remediated_at  = b.at,
         updated_at     = b.at
    FROM candidates c, batch b
   WHERE f.finding_id = c.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
SELECT NULL,
       'autoclose_stale_finding',
       NULL,
       NULL,
       jsonb_build_object('current_status', c.old_status, 'source', 'testssl',
                          'severity', c.severity, 'last_observed_at', c.last_observed_at),
       jsonb_build_object('current_status', 'remediated', 'remediated_at', b.at),
       jsonb_build_object(
         'finding_id',          c.finding_id,
         'asset_id',            c.asset_id,
         'title',               c.title,
         'scan_run_id',         c.scan_run_id,
         'scan_completed_at',   c.scan_completed_at,
         'witness_finding_id',  c.witness_finding_id,
         'witness_last_observed_at', c.witness_last_observed_at,
         'batch_id',            b.id,
         'rule',                'note_308_item2_testssl_strict_sibling_v3',
         'batch_rule',          'note_308_item2_testssl_not_reobserved_once',
         'reason',              'unseen 30+ days, a later complete scan ran testssl.sh ok and (per finding_history) observed a pre-existing handshake-level testssl finding on this host and port but not this one, and the check is still observed elsewhere in the fleet',
         'tool',                '20261013c_autoclose_testssl_not_reobserved_once.sql',
         'monitoring',          'regress_observed_for_scan_run(testssl) flips it to regressed if a later clean scan re-emits it'
       )
  FROM candidates c
  JOIN closed x ON x.finding_id = c.finding_id
  CROSS JOIN batch b;

COMMIT;
