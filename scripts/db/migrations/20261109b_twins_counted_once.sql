-- 20261109b_twins_counted_once.sql
--
-- KB 12, five-visitor item 7 (built 2026-11-09). TWINS COUNTED ONCE, HIGHER WINS.
--
-- Howie, 2026-11-09 14:20: "Once, higher wins." Two scans filing the same problem on one name at
-- different severities are one row, at the higher severity, naming both scans, counted once.
-- v_open_findings_dedup already does that for rows that share a normalized_key; the twins never
-- shared one because the live deep scan's TLS parser wrote every testssl row with no key.
-- push-426 (both scanner repos, land it FIRST) makes the parser apply the curated same-fact list
-- (cs_parsers/common.py CROSS_SOURCE_EQUIVALENCE: June's DMARC and OCSP, plus HSTS-missing and
-- BEAST) to every row it writes. Plan v3, reviewed three rounds (Kimi K3.1 Pro: ready); Howie
-- 2026-11-09 20:01: "go". This file, both databases:
--
--   1  The open rows a rescan would key, keyed now (many wait weeks for their next deep scan;
--      some were last seen 2026-06-29), with the same patterns as common.py's list:
--        missing-header-strict-transport-security (the quick scan's own key): testssl
--          "HSTS not enabled"; a quick-scan row with that header's exact title and no key; the
--          medium scan's old nikto line "Suggested security header missing:
--          strict-transport-security" (the medium scan stopped writing these in #28 Q1);
--        tls-beast: testssl "BEAST attack vulnerability" and its cipher record "TLS ·
--          BEAST_CBC_..."; the TLS 1.0 one also gets push-426's plain words, exactly as the
--          parser now writes them ("BEAST attack possible on TLS 1.0 — " + its first 100
--          characters);
--        tls-ocsp-stapling-missing: testssl "OCSP stapling not enabled" (June's entry, which the
--          live path never applied).
--      Only a testssl row of the site's own https port shares a key (push-426's
--      testssl.shared_key_for_port, code review 2026-11-09 must-fix): its finding_id ends in
--      the port's hash, ':33ad838' (port-443) or ':c51b944' (a record with no port). Any other
--      port's row is left for its next deep scan, which writes "<key>:port-<n>". On both
--      databases tonight every testssl row is port 443 (Command 1191, Prodex 159).
--      One audit row each (action twins_keyed). Each update fires the rating trigger
--      (trg_findings_sync_current_risk) for its name with the new view below.
--   2  v_open_findings_dedup: a merged row shows the higher row's words. The title order is open
--      members first (as before), then the worst severity, then the longest title, then the
--      finding id (a fixed tie-break): v_fleet_open_reps' own rule for a site. Without it the
--      merged BEAST row would read "(likely mitigated)" at MODERATE. 20261023b's definition
--      exactly, only the title's ORDER BY changes: same columns, same security_invoker, so
--      v_asset_posture_counts and v_fleet_open_reps (built on it) follow unchanged.
--   3  Replacing a view writes no row and fires no trigger, so the names whose shown words change
--      through 2 alone (recorded before 2, one audit row each, action twins_view_words) get
--      their rating recomputed by hand: 20261013a's pattern. A rating is the worst open
--      severity (recompute_asset_current_risk_for); it does not move: the worse twin stays.
--
-- AT BUILD TIME (2026-11-09 evening, SELECT only):
--   Command  1: 50 rows: 22 HSTS (testssl), 4 BEAST (2 reworded), 23 OCSP, 1 nikto (demo.
--            testfire.net), no quick-scan row. 3: 2 names (ftp.sciimage.com "OCSP stapling not
--            enabled" -> "F-09: No OCSP Stapling"; test.commandcommcentral.com "CSP style-src
--            nonce is static across requests (10 value(s) repeated)" -> "M-02: Static /
--            Predictable CSP Nonces").
--   Prodex   1: 18 rows: 6 HSTS, 10 BEAST (5 reworded), 2 OCSP. 3: none.
--   On the name pages: Command 23 duplicate rows fewer on 20 names, Prodex 10 on 7; every one the
--   LOW (or INFO) copy. No rating moves.
--
-- GUARDS (plain SELECTs that divide by zero, 20261013b's pattern; a violated guard aborts the
-- transaction, the ledger row is not written):
--   1  bounded: no more than 100 rows chosen (Command 50, Prodex 18 at build time);
--   2  nothing serious: no chosen row is CRITICAL, HIGH or MODERATE-HIGH;
--   3  no other key overwritten: a chosen row has no key, or already this one;
--   4  no stranger in a group: every row already carrying tls-beast is a testssl BEAST row, and
--      every non-quick-scan row carrying missing-header-strict-transport-security is one of the
--      patterns above.
--   The shipping script refuses to run until both scanner mains carry push-426 and Claude's
--   read-back has written its PASS marker.
--
-- Reversible: UPDATE public.findings SET normalized_key = (before_state ->> 'normalized_key'),
-- title = (before_state ->> 'title') for the twins_keyed audit rows of batch 20261109b-twins, and
-- 20261023b's view statement again; then recompute those names. No schema change. Byte-identical
-- in both repos. Idempotent: a second apply chooses nothing, records nothing new, and the
-- recompute gives the same answer.
--
-- MIGRATION-META:
-- idempotent: true
-- transactional: true
-- safe_auto_apply: true
-- requires_backup: false
-- estimated_duration_ms: 5000
-- notes: KB 12 five-visitor item 7 (Howie 2026-11-09 14:20 "Once, higher wins."; plan v3, 20:01 "go"). Data and one view. The open testssl HSTS, BEAST and OCSP rows of the site's own https port, a keyless quick-scan HSTS row and the old nikto HSTS line get the curated same-fact keys (push-426's list: missing-header-strict-transport-security, tls-beast, tls-ocsp-stapling-missing); the TLS 1.0 BEAST cipher row gets push-426's plain words; one audit row each. v_open_findings_dedup shows the higher row's words (open first, worst severity, longest, finding id), 20261023b's definition otherwise. The names whose words change through the view alone are recorded first and recomputed by hand. Guards: at most 100 rows, none CRITICAL/HIGH/MODERATE-HIGH, no other key overwritten, no stranger carrying a key. Splitter-safe (no dollar-quoted blocks).
-- END-META

-- BEGIN/COMMIT: the runner strips them and wraps its own transaction. They are here so a HAND
-- run (psql -f) also stops at a failed guard instead of carrying on.
BEGIN;

-- ── GUARDS 1-3 · bounded, nothing serious, no other key overwritten (one pass over the rule).
WITH target AS (
  SELECT f.finding_id, f.asset_id, f.source::text AS source, f.title, f.severity::text AS severity,
         f.normalized_key AS old_key,
         CASE
           WHEN f.source::text = 'testssl'
                AND right(f.finding_id, 8) NOT IN (':33ad838', ':c51b944')
             THEN NULL
           WHEN f.source::text = 'testssl'
                AND f.title ~* '^hsts not enabled( — .*|  \(\d+ reports\))?$'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'commandsentry_light'
                AND f.title ~* '^missing security header: strict-transport-security$'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'commandsentry_medium'
                AND f.title ~* '^nikto: .*suggested security header missing: strict-transport-security'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'testssl'
                AND (f.title ~* '^beast attack vulnerability( — .*|  \(\d+ reports\))?$'
                     OR f.title ~* '^tls · beast_cbc_'
                     OR f.title ~* '^beast attack possible on tls 1\.0( — .*|  \(\d+ reports\))?$')
             THEN 'tls-beast'
           WHEN f.source::text = 'testssl'
                AND f.title ~* 'ocsp stapling not enabled'
             THEN 'tls-ocsp-stapling-missing'
         END AS new_key,
         CASE
           WHEN f.source::text = 'testssl' AND f.title ~ '^TLS · BEAST_CBC_TLS1: .'
             THEN 'BEAST attack possible on TLS 1.0 — '
                  || left(substr(f.title, char_length('TLS · BEAST_CBC_TLS1: ') + 1), 100)
           ELSE f.title
         END AS new_title
    FROM public.findings f
   WHERE f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
), chosen AS (
  SELECT t.*
    FROM target t
   WHERE t.new_key IS NOT NULL
     AND (t.old_key IS DISTINCT FROM t.new_key OR t.new_title IS DISTINCT FROM t.title)
)
SELECT 1 / (CASE WHEN count(*) <= 100 THEN 1 ELSE 0 END) AS guard_bounded,
       1 / (CASE WHEN count(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH')) = 0
                 THEN 1 ELSE 0 END) AS guard_nothing_serious,
       1 / (CASE WHEN count(*) FILTER (WHERE old_key IS NOT NULL AND old_key <> new_key) = 0
                 THEN 1 ELSE 0 END) AS guard_no_other_key_overwritten
  FROM chosen;

-- ── GUARD 4 · no stranger already carries either key.
SELECT 1 / (CASE WHEN count(*) = 0 THEN 1 ELSE 0 END) AS guard_no_stranger
  FROM public.findings f
 WHERE (f.normalized_key = 'tls-beast'
        AND NOT (f.source::text = 'testssl'
                 AND (f.title ~* '^beast attack vulnerability( — .*|  \(\d+ reports\))?$'
                      OR f.title ~* '^tls · beast_cbc_'
                      OR f.title ~* '^beast attack possible on tls 1\.0( — .*|  \(\d+ reports\))?$')))
    OR (f.normalized_key = 'missing-header-strict-transport-security'
        AND f.source::text <> 'commandsentry_light'
        AND NOT ((f.source::text = 'testssl'
                  AND f.title ~* '^hsts not enabled( — .*|  \(\d+ reports\))?$')
                 OR (f.source::text = 'commandsentry_medium'
                     AND f.title ~* '^nikto: .*suggested security header missing: strict-transport-security')));

-- ── 3 (1 of 2) · before the view changes: record each name whose shown words change through the
-- view alone (a group with an open member, no member keyed by this file, whose title the new
-- order picks differently). One audit row each; nothing on findings changes here.
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'twins_view_words',
       jsonb_build_object('title', g.old_title),
       jsonb_build_object('title', g.new_title),
       jsonb_build_object(
         'asset_id',  g.asset_id,
         'dedup_id',  g.dedup_id,
         'reason',    'Two rows of one problem on this name show as one; it now shows the higher row''s words (open first, worst severity, longest, finding id). Its rating summary is recomputed.',
         'migration', '20261109b',
         'batch',     '20261109b-twins',
         'ruling',    'Howie 2026-11-09 14:20 (five-visitor item 7): Once, higher wins; plan v3 (Kimi ready), Howie 20:01: go')
  FROM (
    SELECT f.asset_id, f.normalized_key AS dedup_id,
           (array_agg(f.title ORDER BY (f.current_status = ANY (ARRAY[
              'remediated'::finding_status_t, 'validated_remediated'::finding_status_t,
              'false_positive'::finding_status_t, 'wont_fix'::finding_status_t,
              'accepted_risk'::finding_status_t, 'closed_reclassified'::finding_status_t,
              'detector_retired'::finding_status_t])),
                      (length(f.title)) DESC NULLS LAST))[1] AS old_title,
           (array_agg(f.title ORDER BY (f.current_status = ANY (ARRAY[
              'remediated'::finding_status_t, 'validated_remediated'::finding_status_t,
              'false_positive'::finding_status_t, 'wont_fix'::finding_status_t,
              'accepted_risk'::finding_status_t, 'closed_reclassified'::finding_status_t,
              'detector_retired'::finding_status_t])),
                      (CASE f.severity
              WHEN 'CRITICAL'::severity_t THEN 1 WHEN 'HIGH'::severity_t THEN 2
              WHEN 'MODERATE-HIGH'::severity_t THEN 3 WHEN 'MODERATE'::severity_t THEN 4
              WHEN 'LOW'::severity_t THEN 5 WHEN 'INFO'::severity_t THEN 6 ELSE 9 END),
                      (length(f.title)) DESC NULLS LAST, f.finding_id))[1] AS new_title
      FROM public.findings f
      LEFT JOIN public.admin_audit_log k
        ON k.action = 'twins_keyed' AND k.details ->> 'batch' = '20261109b-twins'
       AND k.details ->> 'finding_id' = f.finding_id
     WHERE f.normalized_key IS NOT NULL
     GROUP BY f.asset_id, f.normalized_key
    HAVING bool_or(f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed'))
       AND NOT bool_or(k.id IS NOT NULL)
  ) g
 WHERE g.old_title IS DISTINCT FROM g.new_title
   AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l
                    WHERE l.action = 'twins_view_words'
                      AND l.details ->> 'batch' = '20261109b-twins'
                      AND l.details ->> 'asset_id' = g.asset_id
                      AND l.details ->> 'dedup_id' = g.dedup_id);

-- ── 2 · v_open_findings_dedup: a merged row shows the higher row's words.
-- (20261023b's definition; only the title's ORDER BY changes.)
CREATE OR REPLACE VIEW public.v_open_findings_dedup
WITH (security_invoker = true) AS
WITH grouped AS (
  SELECT findings.asset_id,
         findings.normalized_key AS dedup_id,
         (array_agg(findings.severity ORDER BY
            (findings.current_status = ANY (ARRAY[
               'remediated'::finding_status_t,
               'validated_remediated'::finding_status_t,
               'false_positive'::finding_status_t,
               'wont_fix'::finding_status_t,
               'accepted_risk'::finding_status_t,
               'closed_reclassified'::finding_status_t,
               'detector_retired'::finding_status_t])),
            (CASE findings.severity
              WHEN 'CRITICAL'::severity_t      THEN 1
              WHEN 'HIGH'::severity_t          THEN 2
              WHEN 'MODERATE-HIGH'::severity_t THEN 3
              WHEN 'MODERATE'::severity_t      THEN 4
              WHEN 'LOW'::severity_t           THEN 5
              WHEN 'INFO'::severity_t          THEN 6
              ELSE 9
            END)))[1] AS severity,
         CASE
           WHEN bool_or(findings.current_status <> ALL (ARRAY[
                  'remediated'::finding_status_t,
                  'validated_remediated'::finding_status_t,
                  'false_positive'::finding_status_t,
                  'wont_fix'::finding_status_t,
                  'accepted_risk'::finding_status_t,
                  'closed_reclassified'::finding_status_t,
                  'detector_retired'::finding_status_t]))
             THEN 'detected'::finding_status_t
           ELSE (array_agg(findings.current_status))[1]
         END AS current_status,
         (array_agg(findings.title ORDER BY
            (findings.current_status = ANY (ARRAY[
               'remediated'::finding_status_t,
               'validated_remediated'::finding_status_t,
               'false_positive'::finding_status_t,
               'wont_fix'::finding_status_t,
               'accepted_risk'::finding_status_t,
               'closed_reclassified'::finding_status_t,
               'detector_retired'::finding_status_t])),
            (CASE findings.severity
              WHEN 'CRITICAL'::severity_t      THEN 1
              WHEN 'HIGH'::severity_t          THEN 2
              WHEN 'MODERATE-HIGH'::severity_t THEN 3
              WHEN 'MODERATE'::severity_t      THEN 4
              WHEN 'LOW'::severity_t           THEN 5
              WHEN 'INFO'::severity_t          THEN 6
              ELSE 9
            END),
            (length(findings.title)) DESC NULLS LAST,
            findings.finding_id))[1] AS title,
         array_agg(DISTINCT findings.source ORDER BY findings.source) AS sources,
         count(*) AS source_count,
         min(findings.first_detected_at) AS first_detected_at,
         max(findings.last_observed_at) AS last_observed_at,
         CASE
           WHEN bool_or(findings.current_status <> ALL (ARRAY[
                  'remediated'::finding_status_t,
                  'validated_remediated'::finding_status_t,
                  'false_positive'::finding_status_t,
                  'wont_fix'::finding_status_t,
                  'accepted_risk'::finding_status_t,
                  'closed_reclassified'::finding_status_t,
                  'detector_retired'::finding_status_t]))
             THEN ( SELECT array_agg(DISTINCT c.c ORDER BY c.c) AS array_agg
                      FROM unnest(array_remove(array_cat_agg(findings.cve) FILTER (WHERE
                             findings.current_status <> ALL (ARRAY[
                               'remediated'::finding_status_t,
                               'validated_remediated'::finding_status_t,
                               'false_positive'::finding_status_t,
                               'wont_fix'::finding_status_t,
                               'accepted_risk'::finding_status_t,
                               'closed_reclassified'::finding_status_t,
                               'detector_retired'::finding_status_t])), NULL::text)) c(c)
                     WHERE c.c IS NOT NULL)
           ELSE ( SELECT array_agg(DISTINCT c.c ORDER BY c.c) AS array_agg
                    FROM unnest(array_remove(array_cat_agg(findings.cve), NULL::text)) c(c)
                   WHERE c.c IS NOT NULL)
         END AS cve,
         array_agg(findings.finding_id ORDER BY findings.first_detected_at) AS member_finding_ids
    FROM findings
   WHERE findings.normalized_key IS NOT NULL
   GROUP BY findings.asset_id, findings.normalized_key
), ungrouped AS (
  SELECT findings.asset_id,
         findings.finding_id AS dedup_id,
         findings.severity,
         findings.current_status,
         findings.title,
         ARRAY[findings.source] AS sources,
         1 AS source_count,
         findings.first_detected_at,
         findings.last_observed_at,
         findings.cve,
         ARRAY[findings.finding_id] AS member_finding_ids
    FROM findings
   WHERE findings.normalized_key IS NULL
)
SELECT grouped.asset_id, grouped.dedup_id, grouped.severity, grouped.current_status,
       grouped.title, grouped.sources, grouped.source_count, grouped.first_detected_at,
       grouped.last_observed_at, grouped.cve, grouped.member_finding_ids
  FROM grouped
UNION ALL
SELECT ungrouped.asset_id, ungrouped.dedup_id, ungrouped.severity, ungrouped.current_status,
       ungrouped.title, ungrouped.sources, ungrouped.source_count, ungrouped.first_detected_at,
       ungrouped.last_observed_at, ungrouped.cve, ungrouped.member_finding_ids
  FROM ungrouped;

-- ── 1 · key the twins (and reword the TLS 1.0 BEAST cipher row), audit each. Each update fires
-- the rating trigger for its name, which now reads the view above.
WITH target AS (
  SELECT f.finding_id, f.asset_id, f.source::text AS source, f.title, f.severity::text AS severity,
         f.normalized_key AS old_key,
         CASE
           WHEN f.source::text = 'testssl'
                AND right(f.finding_id, 8) NOT IN (':33ad838', ':c51b944')
             THEN NULL
           WHEN f.source::text = 'testssl'
                AND f.title ~* '^hsts not enabled( — .*|  \(\d+ reports\))?$'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'commandsentry_light'
                AND f.title ~* '^missing security header: strict-transport-security$'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'commandsentry_medium'
                AND f.title ~* '^nikto: .*suggested security header missing: strict-transport-security'
             THEN 'missing-header-strict-transport-security'
           WHEN f.source::text = 'testssl'
                AND (f.title ~* '^beast attack vulnerability( — .*|  \(\d+ reports\))?$'
                     OR f.title ~* '^tls · beast_cbc_'
                     OR f.title ~* '^beast attack possible on tls 1\.0( — .*|  \(\d+ reports\))?$')
             THEN 'tls-beast'
           WHEN f.source::text = 'testssl'
                AND f.title ~* 'ocsp stapling not enabled'
             THEN 'tls-ocsp-stapling-missing'
         END AS new_key,
         CASE
           WHEN f.source::text = 'testssl' AND f.title ~ '^TLS · BEAST_CBC_TLS1: .'
             THEN 'BEAST attack possible on TLS 1.0 — '
                  || left(substr(f.title, char_length('TLS · BEAST_CBC_TLS1: ') + 1), 100)
           ELSE f.title
         END AS new_title
    FROM public.findings f
   WHERE f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
), chosen AS (
  SELECT t.*
    FROM target t
   WHERE t.new_key IS NOT NULL
     AND (t.old_key IS DISTINCT FROM t.new_key OR t.new_title IS DISTINCT FROM t.title)
),
changed AS (
  UPDATE public.findings f
     SET normalized_key = c.new_key,
         title          = c.new_title,
         updated_at     = now()
    FROM chosen c
   WHERE f.finding_id = c.finding_id
  RETURNING f.finding_id
)
INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details)
SELECT NULL, 'twins_keyed',
       jsonb_build_object('normalized_key', c.old_key, 'title', c.title),
       jsonb_build_object('normalized_key', c.new_key, 'title', c.new_title),
       jsonb_build_object(
         'finding_id', c.finding_id,
         'asset_id',   c.asset_id,
         'source',     c.source,
         'severity',   c.severity,
         'reason',     'The same problem another scan or another line of the same test files on this name: one key, so it shows and counts once, at the higher severity, naming both scans (the curated same-fact list, cs_parsers/common.py, push-426).',
         'migration',  '20261109b',
         'batch',      '20261109b-twins',
         'ruling',     'Howie 2026-11-09 14:20 (five-visitor item 7): Once, higher wins; plan v3 (Kimi ready), Howie 20:01: go')
  FROM chosen c
  JOIN changed d ON d.finding_id = c.finding_id;

-- ── 3 (2 of 2) · recompute the names recorded above (the trigger's own rule; twice is the same).
SELECT public.recompute_asset_current_risk_for(x.asset_id)
  FROM (SELECT DISTINCT l.details ->> 'asset_id' AS asset_id
          FROM public.admin_audit_log l
         WHERE l.action = 'twins_view_words'
           AND l.details ->> 'batch' = '20261109b-twins') x;

COMMIT;
