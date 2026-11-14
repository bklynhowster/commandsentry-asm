"""close_fixed.py — a fixed security header or old-encryption finding closes by itself (D-078).

Howie, 2026-11-13 18:35 ET: "Go yes to both." (to: switch the close on for security-header and
old-encryption findings only; and old encryption closes after two clean deep scans in a row, not
one). Decisions Log D-078; plan and picture in the vault, Wrap-ups/Close fixed findings
(2026-11-13)/. An exception to D-062's close-off for these two kinds ONLY: findings of retired
attack checks must still never look fixed, so everything here closes on a reading that SAW the
fix, never on silence alone.

WHAT CLOSES, AND ON WHAT EVIDENCE
  Security headers (light:missing-header-<name>, light:csp-scripts-not-limited), one clean scan,
  quick or deep. That scan's header check ran ok, its own recorded reading of the front page
  (the headers_check artifact) answered 200 to 399, the header IS in that reading with a value
  (positive evidence: a check that stopped running proves nothing and closes nothing), and the
  scan did not see the finding. For csp-scripts-not-limited the policy in that reading must also
  be judged by the same rule the scanner uses (csp_policy) as no longer "does not limit
  scripts". csp-allows-eval and the static-nonce checks are NOT in D-078 and are never touched.
  Old encryption (testssl TLS1, TLS1_1, cipherlist_3DES_IDEA, BEAST, BEAST_CBC_TLS1, SWEET32,
  LUCKY13, cipherlist_OBSOLETED, HSTS, security_headers), two clean deep scans in a row: this
  deep scan and the asset's previous complete deep scan both ran the encryption test ok, both
  saw again another, older, handshake-level encryption finding on the same port (the witness:
  proof the test read the site, the rule of 20261013c), neither saw this one, nothing has seen
  it since before the earlier of the two started, and the check is still being seen somewhere
  else: on another row, by a scan since the earlier of the two started, and in the last 30 days
  (a check nobody sees any more is a broken detector, not a fix; "since the earlier scan", not
  just "in 30 days", because when a detector breaks every row it made stops at once, and those
  rows must not vouch for one another while they age).

  Never HIGH or worse; encryption LOW and MODERATE only. Open rows only (detected, confirmed,
  open, regressed): nothing a person closed is touched. Every close writes an audit row (the
  proving scan, the rule, the evidence, the undo) and a history row bound to the proving scan.

  A closed header finding the quick scan sees again reopens at once (regressed), with an audit
  row and a 'regressed' history row, so the daily email lists it as "Came back after being
  fixed". The deep scan's own regress step already does this for everything it re-sees
  (regress_observed_for_scan_run), encryption included.

WHY READ last_seen_scan_run, NEVER finding_history, FOR "NOT SEEN"
  The quick scan writes history only when every one of its tools ran ok, so most quick-scan
  observations leave no history row. Measured 2026-11-13: a history-based rule would have closed
  18 Command header findings that are still true. Every upsert stamps last_seen_scan_run and
  last_observed_at, so those are the record of who last saw a finding. The previous deep scan's
  evidence does use history: the deep scan writes it on every clean run, and 20261013c relies
  on that.

SAFETY
  Each step runs in its own savepoint and returns 0 on any error after logging it: this can
  never cost a scan. It sends nothing to any site: it reads what the scan already recorded.
  OFF switches: CLOSE_FIXED_HEADERS_ON / CLOSE_FIXED_TLS_ON below (one-line change).
"""
from __future__ import annotations

import json

import csp_policy

CLOSE_FIXED_HEADERS_ON = True
CLOSE_FIXED_TLS_ON = True

LIGHT_SOURCE = "commandsentry_light"
TLS_SOURCE = "testssl"
OPEN_STATUSES = ("detected", "confirmed", "open", "regressed")
CLOSED_FIXED_STATUSES = ("remediated", "validated_remediated")
HEADER_SEVERITIES = ("MODERATE", "LOW", "INFO")
TLS_SEVERITIES = ("LOW", "MODERATE")
TLS_CHECKS = ("TLS1", "TLS1_1", "cipherlist_3DES_IDEA", "BEAST", "BEAST_CBC_TLS1", "SWEET32",
              "LUCKY13", "cipherlist_OBSOLETED", "HSTS", "security_headers")
# A witness must need a completed handshake (20261013c rule d): never a "protocol not offered"
# line and never the CAA record.
WITNESS_EXCLUDED = ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "DNS_CAArecord")
CSP_CHECK = csp_policy.CHECK_NOT_LIMITED            # "csp-scripts-not-limited"
CSP_HEADER = "Content-Security-Policy"

CLOSE_ACTION = "close_fixed_finding"
REOPEN_ACTION = "auto_regress_observed"            # the same action the deep scan's reopen writes
HEADER_RULE = "d078_header_seen_fixed_v1"
TLS_RULE = "d078_tls_two_clean_deep_scans_v1"
REOPEN_RULE = "d078_header_seen_again_v1"
DECISION = "D-078 (Howie 2026-11-13 18:35 ET: Go yes to both.)"


def _noop(_msg):
    return None


def _tool_ok(tool_status, key) -> bool:
    entry = (tool_status or {}).get(key)
    return isinstance(entry, dict) and entry.get("ok") is True


def header_check_ids(header_names) -> list:
    """Every check id of the D-078 header family, in a fixed order."""
    return [f"missing-header-{name.lower()}" for name in header_names] + [CSP_CHECK]


def _has_value(v) -> bool:
    if v is None:
        return False
    if isinstance(v, (list, tuple)):
        return any(str(x).strip() for x in v)
    return bool(str(v).strip())


def reading_from_artifact(content):
    """The scan's recorded front-page reading -> (status_code, header map), or None.
    The writer stores httpx's one JSON line parsed (an object with 'header'), or {'raw': text}
    when it did not parse; the raw text's first line is what check_headers itself read."""
    rec = content
    if isinstance(rec, dict) and "header" not in rec and isinstance(rec.get("raw"), str):
        lines = rec["raw"].strip().splitlines()
        if not lines:
            return None
        try:
            rec = json.loads(lines[0])
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(rec, dict):
        return None
    headers = rec.get("header")
    status = rec.get("status_code")
    if not isinstance(headers, dict) or isinstance(status, bool) or not isinstance(status, int):
        return None
    return status, headers


def fixed_header_checks(headers: dict, header_names, header_key) -> dict:
    """Which header checks this reading shows FIXED -> {check id: evidence}. Positive evidence
    only: the header is there with a value. csp-scripts-not-limited also needs the policy judged
    by csp_policy as no longer 'does not limit scripts' (an error in the judging closes nothing)."""
    out = {}
    for name in header_names:
        key = header_key(name)
        if key in headers and _has_value(headers[key]):
            out[f"missing-header-{name.lower()}"] = {"header": name, "present": True}
    csp_key = header_key(CSP_HEADER)
    csp = headers.get(csp_key)
    if _has_value(csp):
        try:
            verdict = csp_policy.script_weakness(csp)
        except Exception:  # noqa: BLE001 — an unreadable policy is no evidence of a fix
            verdict = "error"
        if verdict is None or (isinstance(verdict, dict)
                               and verdict.get("weakness") != csp_policy.CHECK_NOT_LIMITED):
            out[CSP_CHECK] = {"header": CSP_HEADER, "present": True,
                              "csp_verdict": (verdict.get("weakness") if isinstance(verdict, dict)
                                              else "limits scripts")}
    return out


READING_SQL = """
SELECT a.content_jsonb
  FROM public.scan_run_artifacts a
 WHERE a.scan_run_id = %(scan_run_id)s::uuid
   AND a.tool_name = 'headers_check'
"""

HEADER_CANDIDATES_SQL = """
SELECT f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
       f.current_status::text AS old_status, f.last_observed_at, f.last_seen_scan_run
  FROM public.findings f
  JOIN public.scan_run s ON s.scan_run_id = %(scan_run_id)s::uuid AND s.asset_id = f.asset_id
 WHERE f.asset_id = %(asset_id)s
   AND f.finding_id = ANY(%(finding_ids)s::text[])
   AND f.source::text = 'commandsentry_light'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.severity::text IN ('MODERATE', 'LOW', 'INFO')
   AND f.last_seen_scan_run IS DISTINCT FROM %(scan_run_id)s::text
   AND f.last_observed_at < s.started_at
 ORDER BY f.finding_id
   FOR UPDATE OF f
"""

CLOSE_ONE_SQL = """
UPDATE public.findings
   SET current_status = 'remediated', remediated_at = now(), updated_at = now()
 WHERE finding_id = %(finding_id)s
   AND current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
RETURNING finding_id
"""

HISTORY_SQL = """
INSERT INTO public.finding_history (finding_id, scan_id, observed_at, status, severity_at_scan, notes)
VALUES (%(finding_id)s, %(scan_run_id)s, now(), %(status)s::history_status_t, %(severity)s::severity_t, %(notes)s)
ON CONFLICT (finding_id, scan_id) DO NOTHING
"""

AUDIT_SQL = """
INSERT INTO public.admin_audit_log (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
VALUES (NULL, %(action)s, NULL, NULL, %(before)s::jsonb, %(after)s::jsonb, %(details)s::jsonb)
"""

REOPEN_CANDIDATES_SQL = """
SELECT f.finding_id, f.asset_id, f.severity::text AS severity,
       f.current_status::text AS old_status, f.remediated_at, f.last_regressed_at
  FROM public.findings f
 WHERE f.asset_id = %(asset_id)s
   AND f.finding_id = ANY(%(finding_ids)s::text[])
   AND f.source::text = 'commandsentry_light'
   AND f.current_status::text IN ('remediated', 'validated_remediated')
   AND f.last_seen_scan_run = %(scan_run_id)s::text
 ORDER BY f.finding_id
   FOR UPDATE OF f
"""

REOPEN_ONE_SQL = """
UPDATE public.findings
   SET current_status = 'regressed', remediated_at = NULL,
       last_regressed_at = coalesce(last_regressed_at, now()), updated_at = now()
 WHERE finding_id = %(finding_id)s
   AND current_status::text IN ('remediated', 'validated_remediated')
RETURNING finding_id
"""

# The check id of a testssl finding: <asset>:testssl:<check>:<hash7>  (length(':testssl:') = 9).
_CHECK = "regexp_replace(substr({t}.finding_id, length({t}.asset_id) + 10), ':[^:]*$', '')"
_PORT = "substring({t}.finding_id from ':[^:]*$')"
_IS_TLS_ROW = "left({t}.finding_id, length({t}.asset_id) + 9) = {t}.asset_id || ':testssl:'"

TLS_CANDIDATES_SQL = f"""
WITH this_scan AS (
  SELECT sr.scan_run_id, sr.asset_id, sr.started_at
    FROM public.scan_run sr
   WHERE sr.scan_run_id = %(scan_run_id)s::uuid AND sr.asset_id = %(asset_id)s
),
prev AS (
  SELECT p.scan_run_id, p.started_at, p.tool_status
    FROM public.scan_run p
    JOIN this_scan s ON p.asset_id = s.asset_id
   WHERE p.intensity::text = 'heavy'
     AND p.status::text = 'complete'
     AND p.started_at < s.started_at
     AND p.scan_run_id <> s.scan_run_id
   ORDER BY p.started_at DESC
   LIMIT 1
)
SELECT f.finding_id, f.asset_id, f.title, f.severity::text AS severity,
       f.current_status::text AS old_status, f.last_observed_at, f.last_seen_scan_run,
       {_CHECK.format(t='f')} AS check_id,
       p.scan_run_id::text AS prev_scan_run_id, p.started_at AS prev_started_at,
       w_this.finding_id AS witness_this, w_prev.finding_id AS witness_prev
  FROM public.findings f
  JOIN this_scan s ON s.asset_id = f.asset_id
  CROSS JOIN prev p
  JOIN LATERAL (
    SELECT g.finding_id
      FROM public.findings g
     WHERE g.asset_id = f.asset_id
       AND g.source::text = 'testssl'
       AND {_IS_TLS_ROW.format(t='g')}
       AND g.finding_id <> f.finding_id
       AND g.last_seen_scan_run = s.scan_run_id::text
       AND g.first_detected_at < s.started_at - interval '1 day'
       AND {_PORT.format(t='g')} = {_PORT.format(t='f')}
       AND {_CHECK.format(t='g')} <> ALL(%(witness_excluded)s::text[])
     ORDER BY g.first_detected_at, g.finding_id
     LIMIT 1
  ) w_this ON true
  JOIN LATERAL (
    SELECT g.finding_id
      FROM public.findings g
      JOIN public.finding_history fh
        ON fh.finding_id = g.finding_id AND fh.scan_id = p.scan_run_id::text
       -- an OBSERVATION row: a close (this module's own, among others) writes 'remediated'
       -- for a finding the scan did NOT see, and 'absent' is reconciliation-only. On the deep
       -- scan's clean path a re-seen closed row is regressed before history is written, so
       -- an observation never carries these statuses.
       AND fh.status::text NOT IN ('remediated', 'validated_remediated', 'absent')
     WHERE g.asset_id = f.asset_id
       AND g.source::text = 'testssl'
       AND {_IS_TLS_ROW.format(t='g')}
       AND g.finding_id <> f.finding_id
       AND g.first_detected_at < p.started_at - interval '1 day'
       AND {_PORT.format(t='g')} = {_PORT.format(t='f')}
       AND {_CHECK.format(t='g')} <> ALL(%(witness_excluded)s::text[])
     ORDER BY g.first_detected_at, g.finding_id
     LIMIT 1
  ) w_prev ON true
 WHERE f.asset_id = %(asset_id)s
   AND f.source::text = 'testssl'
   AND {_IS_TLS_ROW.format(t='f')}
   AND {_CHECK.format(t='f')} = ANY(%(checks)s::text[])
   AND f.severity::text IN ('LOW', 'MODERATE')
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND f.last_seen_scan_run IS DISTINCT FROM s.scan_run_id::text
   AND f.last_seen_scan_run IS DISTINCT FROM p.scan_run_id::text
   AND f.last_observed_at < p.started_at
   AND p.tool_status -> 'testssl.sh' ->> 'ok' = 'true'
   AND NOT EXISTS (
     SELECT 1 FROM public.finding_history fx
      WHERE fx.finding_id = f.finding_id AND fx.scan_id = p.scan_run_id::text)
   AND EXISTS (
     SELECT 1 FROM public.findings h
      WHERE h.source::text = 'testssl'
        AND {_IS_TLS_ROW.format(t='h')}
        AND h.finding_id <> f.finding_id
        AND {_CHECK.format(t='h')} = {_CHECK.format(t='f')}
        AND h.last_observed_at > p.started_at
        AND h.last_observed_at > now() - interval '30 days')
 ORDER BY f.finding_id
   FOR UPDATE OF f
"""


def _row(r, key, idx):
    return r[key] if isinstance(r, dict) else r[idx]


def _lit(v):
    """A value as an SQL literal for an undo statement (timestamps print in a form timestamptz reads)."""
    return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"


def _close(cur, Json, scan_run_id, row, *, rule, tier, evidence, notes):
    """Close one candidate row (re-checked open by the UPDATE), then history, then audit."""
    fid = row["finding_id"]
    cur.execute(CLOSE_ONE_SQL, {"finding_id": fid})
    if not cur.fetchone():
        return False
    cur.execute(HISTORY_SQL, {"finding_id": fid, "scan_run_id": scan_run_id, "status": "remediated",
                              "severity": row["severity"], "notes": notes})
    cur.execute(AUDIT_SQL, {
        "action": CLOSE_ACTION,
        "before": Json({"finding_id": fid, "current_status": row["old_status"],
                        "severity": row["severity"],
                        "last_observed_at": str(row["last_observed_at"]),
                        "last_seen_scan_run": row["last_seen_scan_run"]}),
        "after": Json({"finding_id": fid, "current_status": "remediated"}),
        "details": Json({"rule": rule, "decision": DECISION, "tier": tier,
                         "finding_id": fid, "asset_id": row["asset_id"], "title": row["title"],
                         "scan_run_id": scan_run_id, "evidence": evidence,
                         "undo": (f"UPDATE public.findings SET current_status = {_lit(row['old_status'])}, "
                                  f"remediated_at = NULL, updated_at = now() WHERE finding_id = {_lit(fid)} "
                                  "AND current_status = 'remediated'")}),
    })
    return True


def close_fixed_headers(conn, scan_run_id, asset_id, tool_status, Json, *, header_names, header_key,
                        tier, log=_noop) -> int:
    """D-078, headers: close the open header findings this scan's own reading shows fixed.
    Call on a scan's close-out, after its findings and artifacts are written. Returns the count."""
    if not CLOSE_FIXED_HEADERS_ON or not _tool_ok(tool_status, "headers_check"):
        return 0
    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(READING_SQL, {"scan_run_id": scan_run_id})
                rows = cur.fetchall()
                if len(rows) != 1:
                    log(f"close-fixed headers: {len(rows)} header reading(s) recorded, need exactly 1 — nothing closed")
                    return 0
                reading = reading_from_artifact(_row(rows[0], "content_jsonb", 0))
                if reading is None:
                    log("close-fixed headers: the recorded reading is not readable — nothing closed")
                    return 0
                status, headers = reading
                if not 200 <= status <= 399:
                    log(f"close-fixed headers: front page answered {status} (not 200-399) — nothing closed")
                    return 0
                fixed = fixed_header_checks(headers, header_names, header_key)
                if not fixed:
                    return 0
                cur.execute(HEADER_CANDIDATES_SQL, {
                    "scan_run_id": scan_run_id, "asset_id": asset_id,
                    "finding_ids": [f"{asset_id}:light:{c}" for c in fixed]})
                cands = cur.fetchall()
                n = 0
                for row in cands:
                    check = row["finding_id"][len(f"{asset_id}:light:"):]
                    ev = dict(fixed[check], tool="headers_check", status_code=status)
                    if _close(cur, Json, scan_run_id, row, rule=HEADER_RULE, tier=tier, evidence=ev,
                              notes=(f"closed by {tier} scan_run {scan_run_id} (D-078): the front page "
                                     f"answered {status} with {ev['header']} present")):
                        n += 1
                        log(f"close-fixed headers: {row['finding_id']} closed as remediated "
                            f"({ev['header']} present, page {status})")
                return n
    except Exception as e:  # noqa: BLE001 — never costs the scan
        log(f"close-fixed headers: skipped after an error (non-fatal, nothing written): {e!r}")
        return 0


def reopen_headers_seen_again(conn, scan_run_id, asset_id, tool_status, Json, *, header_names,
                              tier, log=_noop) -> int:
    """D-078: a closed header finding this quick scan saw again reopens at once (regressed),
    with an audit row and a 'regressed' history row (the daily email's "Came back after being
    fixed"). The deep scan's regress_observed_for_scan_run already does this on its own path."""
    if not CLOSE_FIXED_HEADERS_ON or not _tool_ok(tool_status, "headers_check"):
        return 0
    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(REOPEN_CANDIDATES_SQL, {
                    "scan_run_id": scan_run_id, "asset_id": asset_id,
                    "finding_ids": [f"{asset_id}:light:{c}" for c in header_check_ids(header_names)]})
                n = 0
                for row in cur.fetchall():
                    fid = row["finding_id"]
                    cur.execute(REOPEN_ONE_SQL, {"finding_id": fid})
                    if not cur.fetchone():
                        continue
                    cur.execute(HISTORY_SQL, {
                        "finding_id": fid, "scan_run_id": scan_run_id, "status": "regressed",
                        "severity": row["severity"],
                        "notes": f"seen again by {tier} scan_run {scan_run_id} after being closed (D-078)"})
                    cur.execute(AUDIT_SQL, {
                        "action": REOPEN_ACTION,
                        "before": Json({"current_status": row["old_status"],
                                        "remediated_at": (None if row["remediated_at"] is None
                                                          else str(row["remediated_at"])),
                                        "last_regressed_at": (None if row["last_regressed_at"] is None
                                                              else str(row["last_regressed_at"]))}),
                        "after": Json({"current_status": "regressed", "remediated_at": None}),
                        "details": Json({"finding_id": fid, "asset_id": row["asset_id"],
                                         "source": LIGHT_SOURCE, "scan_run_id": scan_run_id,
                                         "rule": REOPEN_RULE, "decision": DECISION, "tier": tier,
                                         "undo": (f"UPDATE public.findings SET current_status = {_lit(row['old_status'])}, "
                                                  f"remediated_at = {_lit(row['remediated_at'])}, "
                                                  f"last_regressed_at = {_lit(row['last_regressed_at'])}, "
                                                  f"updated_at = now() WHERE finding_id = {_lit(fid)} "
                                                  "AND current_status = 'regressed'")}),
                    })
                    n += 1
                    log(f"close-fixed headers: {fid} seen again — reopened as regressed")
                return n
    except Exception as e:  # noqa: BLE001
        log(f"close-fixed headers: reopen skipped after an error (non-fatal, nothing written): {e!r}")
        return 0


def close_fixed_tls(conn, scan_run_id, asset_id, tool_status, Json, *, log=_noop) -> int:
    """D-078, old encryption: close after two clean deep scans in a row (see the module note).
    Deep scan clean path only, after the regress loop and before the history writer."""
    if not CLOSE_FIXED_TLS_ON or not _tool_ok(tool_status, "testssl.sh"):
        return 0
    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(TLS_CANDIDATES_SQL, {
                    "scan_run_id": scan_run_id, "asset_id": asset_id,
                    "checks": list(TLS_CHECKS), "witness_excluded": list(WITNESS_EXCLUDED)})
                n = 0
                for row in cur.fetchall():
                    ev = {"tool": "testssl.sh", "check": row["check_id"],
                          "scan_run_id": scan_run_id, "witness_this_scan": row["witness_this"],
                          "previous_deep_scan": row["prev_scan_run_id"],
                          "previous_started_at": str(row["prev_started_at"]),
                          "witness_previous_scan": row["witness_prev"]}
                    if _close(cur, Json, scan_run_id, row, rule=TLS_RULE, tier="heavy", evidence=ev,
                              notes=(f"closed by heavy scan_run {scan_run_id} (D-078): not seen in two "
                                     f"clean deep scans in a row ({row['prev_scan_run_id']} and this one)")):
                        n += 1
                        log(f"close-fixed encryption: {row['finding_id']} closed as remediated "
                            f"(not seen in {row['prev_scan_run_id']} or this scan)")
                return n
    except Exception as e:  # noqa: BLE001
        log(f"close-fixed encryption: skipped after an error (non-fatal, nothing written): {e!r}")
        return 0
