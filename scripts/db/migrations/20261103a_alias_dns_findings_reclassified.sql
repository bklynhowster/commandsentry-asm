-- 20261103a_alias_dns_findings_reclassified.sql
--
-- KB 12 job 4r (2026-11-03). AN ALIAS IS NOT A MAIL SERVER: THE SPF / DMARC ROWS THE MISREAD MADE
-- CLOSE AS RECLASSIFIED (the gap they point at is already reported on the parent domain).
--
-- WHY. check_dns_posture (scripts/scanner/run_light.py) read `dig +short MX <name>` and counted
-- every line as a mail server. For a name that is an alias, dig prints the alias chain first, so
-- every aliased name became a "sending host" (confidence high) and got "DNS missing SPF record"
-- and "DNS missing DMARC record" at MODERATE. On Command at build time: 12 names, 24 rows
-- (pay.commandmi.com, email.commandcompanies.com, nine Unimac sites on Azure,
-- www.commandmarketinginnovations.com). push-396 fixes the read (split_mx_answer: only
-- "<preference> <exchange>" lines are mail servers; the chain is kept as alias_chain). A fixed
-- scan stops re-observing these rows, but nothing closes them: the quick scan's close-out never
-- closes, the deep tier's auto-closer is blocked (20260902a), medium's delta-close is off
-- (D-056) and is scoped to its own source. Left alone they sit open and age into the
-- "not seen in 30+ days" line.
--
-- WHY closed_reclassified (Howie 2026-11-03 09:42, A-D2: "Yes, I agree. Reclassification").
-- Each parent domain already carries its own open finding for the real gap, and this file
-- refuses to close a row whose parent does not (guard 2): commandmi.com and
-- commandcompanies.com "DMARC policy set to p=none" (LOW), unimacgraphics.com and
-- commandmarketinginnovations.com "DNS missing DMARC record" (MODERATE). That is exactly what
-- 20260827a defined: "closed because we changed WHERE this fact is modelled, not because it was
-- fixed and not because it was never true". Command closed 34 such DNS groups the same way on
-- 2026-08-28 (admin_audit_log 'ship_a1_close_reclassified'). NOT remediated: nobody fixed
-- anything, and the daily's "fixed" list reads only remediated / validated_remediated.
-- Re-detection never reopens a closed_reclassified row (the status-downgrade guard in the
-- light and medium findings upserts), so the order against push-396 does not matter.
--
-- WHICH ROWS. An open dns-missing-spf / dns-missing-dmarc row whose asset's NEWEST dns_posture
-- record (scan_run_artifacts, its scan's tool_status.dns_posture.ok = true) says the name is not
-- the plain domain (is_apex false), has no SPF of its own and no mail-server name, AND either
--   (a) was read by the code before push-396: it counted mail servers, and every one of them is
--       a bare alias name (letters, digits, dots, hyphens, at least one letter: no "<number>
--       <host>" line among them, no bare number, nothing else), or
--   (b) was read by push-396's code: the alias chain is recorded apart (alias_chain non-empty),
--       no real mail server is left (mx empty), and the record carries the explicit suppression
--       reasons (spf_suppressed, dmarc_suppressed), as 20260827a's batch required.
-- Names that send by their own records, names whose alias leads to real mail servers
-- (www.commandcompanies.com, www.unimacgraphics.com) and the plain-domain cases are not touched.
--
-- GUARDS (plain SELECTs that divide by zero, 20261013b's pattern; a violated guard aborts the
-- transaction, the ledger row is not written):
--   1  bounded batch: no more than 40 rows match (24 at build time on Command, 0 on Prodex).
--   2  nothing is lost: every matching row's parent domain (assets.apex_domain) has an open
--      dns-missing-dmarc or dns-dmarc-policy-none finding of its own.
--
-- WHAT THIS DOES. One statement: the matching rows get current_status = closed_reclassified and
-- updated_at = now(), and one admin_audit_log row each ('alias_dns_close_reclassified') with
-- the old status, the reading form ((a) or (b)), the alias chain read, the parent domain and its
-- own finding, the ruling and the batch. remediated_at stays NULL. trg_findings_sync_current_risk
-- recomputes each touched asset's current_risk. No schema change, no view, no function.
-- Byte-identical in both repos. Idempotent: a second apply matches nothing. Reversible:
-- UPDATE public.findings SET current_status = 'detected' WHERE finding_id IN (the audit rows'
-- details ->> 'finding_id' where details ->> 'batch' = '20261103a-alias-dns').
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 3000
-- notes: Job 4r (Howie 2026-11-03 09:36 A-D1, 09:42 A-D2, 09:47 A-D3). Data only: open dns-missing-spf / dns-missing-dmarc rows that exist only because check_dns_posture counted an alias chain as mail servers become closed_reclassified (the parent domain already carries the gap), with an audit row each. Two guard SELECTs abort the apply (division by zero) above 40 rows or if any row's parent domain lacks its own open DMARC finding. current_risk recomputed by the existing trigger. Command 24 rows, Prodex 0 at build time. Byte-identical in both repos. Splitter-safe (no dollar-quoted blocks).
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on to the UPDATE.
BEGIN;

-- ── GUARD 1 · bounded batch.
SELECT 1 / (CASE WHEN count(*) <= 40 THEN 1 ELSE 0 END) AS guard_bounded_batch
  FROM public.findings f
  JOIN LATERAL (
        SELECT a.content_jsonb AS rec
          FROM public.scan_run_artifacts a
          JOIN public.scan_run s ON s.scan_run_id = a.scan_run_id
         WHERE s.asset_id = f.asset_id
           AND a.tool_name = 'dns_posture'
           AND (s.tool_status -> 'dns_posture' ->> 'ok') = 'true'
         ORDER BY s.started_at DESC, a.created_at DESC
         LIMIT 1) l ON true
 WHERE f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND (l.rec ->> 'is_apex') = 'false'
   AND (l.rec -> 'sending_host' -> 'signals' ->> 'own_spf') = 'false'
   AND (l.rec -> 'sending_host' -> 'signals' ->> 'naming_pattern') = 'false'
   AND jsonb_typeof(l.rec -> 'mx') = 'array'
   AND (
        (NOT ((l.rec -> 'alias_chain') IS NOT NULL)
         AND jsonb_array_length(l.rec -> 'mx') > 0
         AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(l.rec -> 'mx') m
                          WHERE m !~ '^[A-Za-z0-9_.-]+$' OR m !~ '[A-Za-z]'))
     OR (((l.rec -> 'alias_chain') IS NOT NULL)
         AND jsonb_typeof(l.rec -> 'alias_chain') = 'array'
         AND jsonb_array_length(l.rec -> 'alias_chain') > 0
         AND jsonb_array_length(l.rec -> 'mx') = 0
         AND ((l.rec -> 'spf_suppressed') IS NOT NULL) AND ((l.rec -> 'dmarc_suppressed') IS NOT NULL))
   );

-- ── GUARD 2 · nothing is lost: each matching row's parent domain reports the gap itself.
SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_parent_owns_the_gap
  FROM public.findings f
  JOIN public.assets ast ON ast.asset_id = f.asset_id
  JOIN LATERAL (
        SELECT a.content_jsonb AS rec
          FROM public.scan_run_artifacts a
          JOIN public.scan_run s ON s.scan_run_id = a.scan_run_id
         WHERE s.asset_id = f.asset_id
           AND a.tool_name = 'dns_posture'
           AND (s.tool_status -> 'dns_posture' ->> 'ok') = 'true'
         ORDER BY s.started_at DESC, a.created_at DESC
         LIMIT 1) l ON true
 WHERE f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND (l.rec ->> 'is_apex') = 'false'
   AND (l.rec -> 'sending_host' -> 'signals' ->> 'own_spf') = 'false'
   AND (l.rec -> 'sending_host' -> 'signals' ->> 'naming_pattern') = 'false'
   AND jsonb_typeof(l.rec -> 'mx') = 'array'
   AND (
        (NOT ((l.rec -> 'alias_chain') IS NOT NULL)
         AND jsonb_array_length(l.rec -> 'mx') > 0
         AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(l.rec -> 'mx') m
                          WHERE m !~ '^[A-Za-z0-9_.-]+$' OR m !~ '[A-Za-z]'))
     OR (((l.rec -> 'alias_chain') IS NOT NULL)
         AND jsonb_typeof(l.rec -> 'alias_chain') = 'array'
         AND jsonb_array_length(l.rec -> 'alias_chain') > 0
         AND jsonb_array_length(l.rec -> 'mx') = 0
         AND ((l.rec -> 'spf_suppressed') IS NOT NULL) AND ((l.rec -> 'dmarc_suppressed') IS NOT NULL))
   )
   AND NOT EXISTS (
        SELECT 1 FROM public.findings p
         WHERE p.asset_id = ast.apex_domain
           AND p.asset_id <> f.asset_id
           AND p.normalized_key IN ('dns-missing-dmarc', 'dns-dmarc-policy-none')
           AND p.current_status::text IN ('detected', 'confirmed', 'open', 'regressed'));

-- ── THE TRANSITION · one statement: choose, close, then audit every closed row.
WITH target AS (
  SELECT f.finding_id, f.asset_id, f.normalized_key, f.title, f.severity::text AS severity,
         f.current_status::text AS old_status, f.last_observed_at,
         ast.apex_domain AS parent,
         CASE WHEN (l.rec -> 'alias_chain') IS NOT NULL THEN 'b_read_by_4r_code' ELSE 'a_read_before_4r' END AS reading,
         CASE WHEN (l.rec -> 'alias_chain') IS NOT NULL THEN l.rec -> 'alias_chain' ELSE l.rec -> 'mx' END AS chain,
         (SELECT p.finding_id FROM public.findings p
           WHERE p.asset_id = ast.apex_domain
             AND p.asset_id <> f.asset_id
             AND p.normalized_key IN ('dns-missing-dmarc', 'dns-dmarc-policy-none')
             AND p.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
           ORDER BY p.normalized_key, p.finding_id
           LIMIT 1) AS parent_finding
    FROM public.findings f
    JOIN public.assets ast ON ast.asset_id = f.asset_id
    JOIN LATERAL (
          SELECT a.content_jsonb AS rec
            FROM public.scan_run_artifacts a
            JOIN public.scan_run s ON s.scan_run_id = a.scan_run_id
           WHERE s.asset_id = f.asset_id
             AND a.tool_name = 'dns_posture'
             AND (s.tool_status -> 'dns_posture' ->> 'ok') = 'true'
           ORDER BY s.started_at DESC, a.created_at DESC
           LIMIT 1) l ON true
   WHERE f.normalized_key IN ('dns-missing-spf', 'dns-missing-dmarc')
     AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
     AND (l.rec ->> 'is_apex') = 'false'
     AND (l.rec -> 'sending_host' -> 'signals' ->> 'own_spf') = 'false'
     AND (l.rec -> 'sending_host' -> 'signals' ->> 'naming_pattern') = 'false'
     AND jsonb_typeof(l.rec -> 'mx') = 'array'
     AND (
          (NOT ((l.rec -> 'alias_chain') IS NOT NULL)
           AND jsonb_array_length(l.rec -> 'mx') > 0
           AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(l.rec -> 'mx') m
                            WHERE m !~ '^[A-Za-z0-9_.-]+$' OR m !~ '[A-Za-z]'))
       OR (((l.rec -> 'alias_chain') IS NOT NULL)
           AND jsonb_typeof(l.rec -> 'alias_chain') = 'array'
           AND jsonb_array_length(l.rec -> 'alias_chain') > 0
           AND jsonb_array_length(l.rec -> 'mx') = 0
           AND ((l.rec -> 'spf_suppressed') IS NOT NULL) AND ((l.rec -> 'dmarc_suppressed') IS NOT NULL))
     )
),
closed AS (
  UPDATE public.findings f
     SET current_status = 'closed_reclassified',
         updated_at     = now()
    FROM target t
   WHERE f.finding_id = t.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL,
       'alias_dns_close_reclassified',
       jsonb_build_object('current_status', t.old_status, 'severity', t.severity,
                          'last_observed_at', t.last_observed_at),
       jsonb_build_object('current_status', 'closed_reclassified'),
       jsonb_build_object(
         'finding_id',      t.finding_id,
         'asset_id',        t.asset_id,
         'normalized_key',  t.normalized_key,
         'title',           t.title,
         'reading',         t.reading,
         'alias_chain',     t.chain,
         'parent_domain',   t.parent,
         'parent_finding',  t.parent_finding,
         'reason',          'check_dns_posture counted the alias chain from dig +short MX as mail servers, so this name was taken for a sender. It is not one. The gap is reported on the parent domain.',
         'migration',       '20261103a',
         'batch',           '20261103a-alias-dns',
         'ruling',          'Howie 2026-11-03 09:36 A-D1, 09:42 A-D2, 09:47 A-D3')
  FROM target t
  JOIN closed c ON c.finding_id = t.finding_id;

COMMIT;
