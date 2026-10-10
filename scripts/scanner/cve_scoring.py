#!/usr/bin/env python3
"""cve_scoring.py — automatic CVE scoring (plan 302, step 3; 2026-10-09).

Every finding that names a CVE gets three public facts, refreshed every two
hours by .github/workflows/cve-scoring.yml:

  * NVD        — the CVSS base score and vector (how bad, on paper)
  * FIRST EPSS — the probability the flaw is exploited in the next 30 days
  * CISA KEV   — whether it is on the US government's known-exploited list,
                 and CISA's fix-by date

Results are cached per CVE in cve_enrichments and rolled up onto each finding
(findings.epss_score / epss_percentile / kev_listed / kev_due_date, and
cvss_score / cvss_vector when the finding has none). The portal already marks
a KEV-listed finding loudly (red CISA KEV chip, red impact panel).

It NEVER changes a finding's severity. A severity floor for KEV findings was
built and taken out before shipping: the scan writers let a re-scan set the
scanner's own severity again, so a raise would be undone on the next scan and
flip back every two hours, and it would override a severity an operator had
lowered on purpose. Putting KEV findings at the top belongs in the writers'
severity rule or in the portal's ordering, as its own change.

It talks only to those three public services and to the database. Nothing is
sent to any scanned target.

Replaces scripts/normalize/cve_enricher.py, which only ever ran from the Mac
(last run 2026-05-25; 36 of 91 Command CVE findings scored, Prodex never).

SAFETY RULES, BUILT IN
  * A source that fails changes nothing. A failed or truncated KEV download
    never clears a KEV flag; a failed EPSS or NVD call never blanks a value.
    (The old script set kev_listed=false on everything when cisa.gov failed.)
    CISA's GitHub copy, used only when cisa.gov refuses, can add a listing but
    never clears one (it may lag behind cisa.gov).
  * One bad value cannot block the run: each CVE's cache row is written in its
    own savepoint, and NUL characters (which PostgreSQL text cannot hold) are
    removed from source text.
  * Findings are written one row at a time, only when a value actually
    changes, with lock_timeout (500 ms) below the server's deadlock_timeout
    (1 s). A scan writing the same rows always wins: this job gives way, and
    can never be the reason a scan's write fails. (Measured on PostgreSQL 16
    with the production trigger shape: without the timeout, a scan and this
    job deadlock on the asset row that trg_findings_sync_current_risk updates.)
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cves}"
KEV_FEEDS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own GitHub copy of the same file, tried only if cisa.gov refuses.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
)
USER_AGENT = "Sentry-ASM cve-scoring/1.0 (public CVE data lookups)"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

NVD_DELAY_S = 6.5         # NVD asks for at most 5 requests per 30 s without a key
NVD_FRESH_DAYS = 30       # NVD scores rarely change; re-read monthly
NVD_UNSCORED_DAYS = 1     # not in NVD yet, or not scored yet: look again daily
NVD_MAX_PER_RUN = 60      # bounds one run's NVD pacing to about 7 minutes
EPSS_BATCH = 50           # EPSS answers up to 100 CVEs per call
KEV_MIN_ENTRIES = 1000    # the real catalog has 1,400+; fewer means a bad download
RETRY_SLEEP_S = 5
LOCK_TIMEOUT_MS = 500     # and never more than half the server's deadlock_timeout

# Network-level failures. http.client.HTTPException covers a reply cut off
# mid-body (IncompleteRead) or a garbled status line, which are not OSError.
NET_ERRORS = (OSError, ValueError, http.client.HTTPException)


class SourceError(Exception):
    """A public source could not be read this run."""


def normalize_cves(values) -> list[str]:
    """Upper-case, trimmed, well-formed, unique, sorted. PURE."""
    out = set()
    for v in values or []:
        if isinstance(v, str):
            s = v.strip().upper()
            if CVE_RE.match(s):
                out.add(s)
    return sorted(out)


def _txt(v):
    """Source text as PostgreSQL can store it (no NUL), or None."""
    return v.replace("\x00", "") if isinstance(v, str) else None


# ── reading the public sources ───────────────────────────────────────────────

def http_get_json(url, timeout=30, opener=None):
    """GET JSON. None on 404. One retry on rate limits, 5xx and network errors;
    anything else raises SourceError."""
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    last = None
    for attempt in (1, 2):
        try:
            with opener(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                break
        except NET_ERRORS as e:                 # URLError, timeouts, cut-off replies, bad JSON
            last = e
        if attempt == 1:
            time.sleep(RETRY_SLEEP_S)
    raise SourceError(f"{type(last).__name__}: {str(last)[:200]}")


def _utc(ts):
    """NVD timestamps carry no zone; they are UTC."""
    if not isinstance(ts, str) or not ts:
        return None
    return ts if re.search(r"(Z|[+-]\d{2}:\d{2})$", ts) else ts + "+00:00"


def _date(s):
    return s if isinstance(s, str) and DATE_RE.match(s) else None


def parse_nvd(doc) -> dict | None:
    """One NVD 2.0 answer -> the cve_enrichments NVD columns. None = the CVE is
    not in NVD (yet). PURE."""
    vulns = (doc or {}).get("vulnerabilities") or []
    if not vulns or not isinstance(vulns[0], dict):
        return None
    cve = vulns[0].get("cve") or {}
    out = {
        "nvd_cvss_v3_vector": None, "nvd_cvss_v3_score": None, "nvd_severity": None,
        "nvd_cwe_ids": [], "nvd_description": None,
        "nvd_published_at": _utc(cve.get("published")),
        "nvd_last_modified": _utc(cve.get("lastModified")),
        "nvd_references": [],
    }
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = [m for m in (metrics.get(key) or []) if isinstance(m, dict)]
        if not entries:
            continue
        # NVD's own score ("Primary") over the reporting vendor's ("Secondary").
        chosen = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
            out["nvd_cvss_v3_score"] = float(score)
            out["nvd_cvss_v3_vector"] = _txt(data.get("vectorString")) or None
            out["nvd_severity"] = (_txt(data.get("baseSeverity")) or "").upper() or None
        break
    cwes = set()
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            m = re.match(r"^CWE-(\d+)$", str((d or {}).get("value") or "").strip(), re.I)
            if m:
                cwes.add(int(m.group(1)))
    out["nvd_cwe_ids"] = sorted(cwes)
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en":
            out["nvd_description"] = _txt(d.get("value"))
            break
    out["nvd_references"] = [_txt(r["url"]) for r in cve.get("references") or []
                             if isinstance(r, dict) and isinstance(r.get("url"), str)]
    return out


def parse_epss(doc) -> dict:
    """One EPSS answer -> {CVE: {epss_score, epss_percentile}}. PURE."""
    out = {}
    for item in (doc or {}).get("data") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cve") or "").strip().upper()
        try:
            score, pct = float(item["epss"]), float(item["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if CVE_RE.match(cve) and 0 <= score <= 1 and 0 <= pct <= 1:
            out[cve] = {"epss_score": round(score, 4), "epss_percentile": round(pct, 4)}
    return out


def parse_kev(doc) -> dict:
    """The whole KEV catalog -> {CVE: kev columns}. Raises SourceError if it
    does not look like the real catalog, so a bad download can never clear a
    KEV flag. PURE."""
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    n = len(vulns) if isinstance(vulns, list) else 0
    if n < KEV_MIN_ENTRIES:
        raise SourceError(f"KEV catalog looks wrong ({n} entries, expected {KEV_MIN_ENTRIES}+)")
    idx = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if CVE_RE.match(cve):
            idx[cve] = {
                "kev_added_date": _date(v.get("dateAdded")),
                "kev_due_date": _date(v.get("dueDate")),
                "kev_short_desc": _txt(v.get("shortDescription")),
                "kev_required_action": _txt(v.get("requiredAction")),
            }
    return idx


def fetch_kev(get=http_get_json):
    """-> (catalog, authoritative). authoritative is False when the catalog
    came from the GitHub copy: it may lag cisa.gov, so it may add a listing
    but must never clear one."""
    errors = []
    for i, url in enumerate(KEV_FEEDS):
        try:
            return parse_kev(get(url, timeout=60)), i == 0
        except SourceError as e:
            errors.append(f"{url.split('/')[2]}: {e}")
    raise SourceError("; ".join(errors))


def fetch_epss(cves, get=http_get_json):
    """-> ({CVE: scores}, [errors]). A failed batch is skipped, not fatal."""
    out, errors = {}, []
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        try:
            doc = get(EPSS_API.format(cves=",".join(batch)))
            if not isinstance(doc, dict) or "data" not in doc or doc.get("status-code", 200) != 200:
                raise SourceError("answer had no data")
        except SourceError as e:
            errors.append(f"EPSS {batch[0]}..: {e}")
            continue
        out.update({k: v for k, v in parse_epss(doc).items() if k in batch})
    return out, errors


def fetch_nvd(cves, get=http_get_json, sleep=time.sleep):
    """-> ({CVE: fields or None}, error or None). Paced; stops at the first
    refusal (NVD answers 403 when it wants us to slow down)."""
    out = {}
    for i, cve in enumerate(cves):
        if i:
            sleep(NVD_DELAY_S)
        try:
            doc = get(NVD_API.format(cve=cve))
        except SourceError as e:
            return out, f"NVD {cve}: {e}"
        out[cve] = parse_nvd(doc)
    return out, None


def nvd_due(cves, cache, now) -> list[str]:
    """CVEs whose NVD data should be (re)read, never-read first, capped at
    NVD_MAX_PER_RUN. cache: {CVE: (nvd_fetched_at, has_score)}. A CVE NVD has
    not scored yet (or does not have yet) is looked at again after a day;
    a scored one after NVD_FRESH_DAYS. PURE."""
    def due(c):
        ts, scored = cache.get(c, (None, False))
        if ts is None:
            return True
        return (now - ts) > timedelta(days=NVD_FRESH_DAYS if scored else NVD_UNSCORED_DAYS)
    out = [c for c in cves if due(c)]
    out.sort(key=lambda c: (cache.get(c, (None,))[0] is not None, cache.get(c, (None,))[0] or now, c))
    return out[:NVD_MAX_PER_RUN]


# ── what to write on each finding ────────────────────────────────────────────

def plan_finding_update(row) -> dict:
    """Columns to change on one finding, given its current values and the
    rollup across its CVEs (ROLLUP_SQL). Empty = nothing changed. PURE.

    EPSS: the worst (highest) across the finding's CVEs; never blanked.
    KEV: written only when every CVE on the finding has been checked against
         the catalog; true if any is listed, due date the soonest.
    CVSS: filled only when the finding has no score of its own.
    Severity: never touched (see the module docstring)."""
    new = {}
    if row["r_epss_score"] is not None:
        if row["epss_score"] != row["r_epss_score"]:
            new["epss_score"] = row["r_epss_score"]
        if row["epss_percentile"] != row["r_epss_percentile"]:
            new["epss_percentile"] = row["r_epss_percentile"]
    if row["r_kev_known"]:
        kev = bool(row["r_kev_listed"])
        due = row["r_kev_due_date"] if kev else None
        if bool(row["kev_listed"]) != kev:
            new["kev_listed"] = kev
        if row["kev_due_date"] != due:
            new["kev_due_date"] = due
    if row["cvss_score"] is None and row["r_cvss_score"] is not None:
        new["cvss_score"] = row["r_cvss_score"]
        if not row["cvss_vector"] and row["r_cvss_vector"]:
            new["cvss_vector"] = row["r_cvss_vector"]
    return new


# ── database ─────────────────────────────────────────────────────────────────

SELECT_FINDING_CVES_SQL = """
SELECT DISTINCT u.id AS cve FROM public.findings f, unnest(f.cve) AS u(id)
 WHERE cardinality(f.cve) > 0
"""

SELECT_CACHE_SQL = """
SELECT cve_id, nvd_fetched_at, (nvd_cvss_v3_score IS NOT NULL) AS scored
  FROM public.cve_enrichments
"""

ENSURE_ROW_SQL = """
INSERT INTO public.cve_enrichments (cve_id) VALUES (%(cve_id)s)
ON CONFLICT (cve_id) DO NOTHING
"""

UPDATE_NVD_SQL = """
UPDATE public.cve_enrichments SET
    -- an answer without a v3 score never blanks a score already held
    nvd_cvss_v3_vector = CASE WHEN %(nvd_cvss_v3_score)s::numeric IS NULL
                              THEN nvd_cvss_v3_vector ELSE %(nvd_cvss_v3_vector)s END,
    nvd_cvss_v3_score  = COALESCE(%(nvd_cvss_v3_score)s::numeric, nvd_cvss_v3_score),
    nvd_severity       = CASE WHEN %(nvd_cvss_v3_score)s::numeric IS NULL
                              THEN nvd_severity ELSE %(nvd_severity)s END,
    nvd_cwe_ids        = %(nvd_cwe_ids)s::integer[],
    nvd_description    = %(nvd_description)s,
    nvd_published_at   = %(nvd_published_at)s::timestamptz,
    nvd_last_modified  = %(nvd_last_modified)s::timestamptz,
    nvd_references     = %(nvd_references)s::text[],
    nvd_fetched_at     = now(),
    updated_at         = now()
 WHERE cve_id = %(cve_id)s
"""

# Not in NVD (yet): remember that we asked, keep anything held from before.
UPDATE_NVD_MISSING_SQL = """
UPDATE public.cve_enrichments SET nvd_fetched_at = now(), updated_at = now()
 WHERE cve_id = %(cve_id)s
"""

UPDATE_EPSS_SQL = """
UPDATE public.cve_enrichments SET
    epss_score      = %(epss_score)s,
    epss_percentile = %(epss_percentile)s,
    epss_fetched_at = now(),
    updated_at      = now()
 WHERE cve_id = %(cve_id)s
"""

UPDATE_KEV_SQL = """
UPDATE public.cve_enrichments SET
    kev_listed          = %(kev_listed)s,
    kev_added_date      = %(kev_added_date)s::date,
    kev_due_date        = %(kev_due_date)s::date,
    kev_short_desc      = %(kev_short_desc)s,
    kev_required_action = %(kev_required_action)s,
    kev_fetched_at      = now(),
    updated_at          = now()
 WHERE cve_id = %(cve_id)s
"""

# One row per finding that names at least one CVE we hold data for: its current
# values next to the rollup across its CVEs.
ROLLUP_SQL = """
SELECT f.finding_id,
       f.epss_score, f.epss_percentile, f.kev_listed, f.kev_due_date,
       f.cvss_score, f.cvss_vector,
       r.epss_score      AS r_epss_score,
       r.epss_percentile AS r_epss_percentile,
       r.kev_known       AS r_kev_known,
       r.kev_listed      AS r_kev_listed,
       r.kev_due_date    AS r_kev_due_date,
       r.cvss_score      AS r_cvss_score,
       r.cvss_vector     AS r_cvss_vector
  FROM public.findings f
  CROSS JOIN LATERAL (
    SELECT count(e.cve_id)                                               AS known,
           max(e.epss_score)                                             AS epss_score,
           (array_agg(e.epss_percentile ORDER BY e.epss_score DESC NULLS LAST, e.cve_id)
              FILTER (WHERE e.epss_score IS NOT NULL))[1]                AS epss_percentile,
           -- every CVE on the finding checked against the catalog (an
           -- unmatched CVE joins as NULL and makes this false)
           coalesce(bool_and(e.kev_fetched_at IS NOT NULL), false)       AS kev_known,
           coalesce(bool_or(e.kev_listed), false)                        AS kev_listed,
           min(e.kev_due_date) FILTER (WHERE e.kev_listed)               AS kev_due_date,
           (array_agg(e.nvd_cvss_v3_score ORDER BY e.nvd_cvss_v3_score DESC NULLS LAST, e.cve_id)
              FILTER (WHERE e.nvd_cvss_v3_score IS NOT NULL))[1]         AS cvss_score,
           (array_agg(e.nvd_cvss_v3_vector ORDER BY e.nvd_cvss_v3_score DESC NULLS LAST, e.cve_id)
              FILTER (WHERE e.nvd_cvss_v3_score IS NOT NULL))[1]         AS cvss_vector
      FROM unnest(f.cve) AS c(id)
      LEFT JOIN public.cve_enrichments e ON e.cve_id = upper(btrim(c.id))
     WHERE upper(btrim(c.id)) ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
  ) r
 WHERE cardinality(f.cve) > 0
   AND r.known > 0
 ORDER BY f.finding_id
"""

FINDING_COLUMNS = ("epss_score", "epss_percentile", "kev_listed", "kev_due_date",
                   "cvss_score", "cvss_vector")


def update_finding_sql(cols) -> str:
    """One-row UPDATE for exactly these columns (names from FINDING_COLUMNS
    only — severity, status and everything else are refused)."""
    bad = [c for c in cols if c not in FINDING_COLUMNS]
    if bad or not cols:
        raise ValueError(f"not scoring columns: {bad or cols!r}")
    sets = [f"{c} = %({c})s" for c in cols] + ["cve_enriched_at = now()"]
    return ("UPDATE public.findings SET " + ", ".join(sets)
            + " WHERE finding_id = %(finding_id)s")


def lock_timeout_ms(deadlock_timeout: str) -> int:
    """How long this job may wait for a row lock: LOCK_TIMEOUT_MS, or half the
    server's deadlock_timeout if that is shorter. Waiting less than the
    deadlock check means that if a scan and this job ever wait on each other,
    THIS job's statement is the one cancelled, before PostgreSQL picks a victim
    (which could be the scan's whole write). PURE."""
    m = re.match(r"^\s*(\d+)\s*(ms|s|min)?\s*$", str(deadlock_timeout or ""))
    if not m:
        return LOCK_TIMEOUT_MS // 2
    n = int(m.group(1)) * {"ms": 1, "s": 1000, "min": 60000, None: 1}[m.group(2)]
    return max(1, min(LOCK_TIMEOUT_MS, n // 2))


def _warn(log, msg):
    log(f"::warning::cve-scoring: {msg}")


def run(conn, get=http_get_json, sleep=time.sleep, log=print, dry_run=False, now=None) -> dict:
    """The whole job on an open autocommit connection. Returns a summary."""
    import psycopg
    now = now or datetime.now(timezone.utc)
    s = {"cves": 0, "kev_loaded": False, "kev_source": None, "kev_entries": 0, "epss": 0,
         "nvd_read": 0, "nvd_missing": 0, "cache_rows_failed": 0, "findings_updated": 0,
         "busy_skipped": 0, "source_errors": []}

    cves = normalize_cves(r["cve"] for r in conn.execute(SELECT_FINDING_CVES_SQL))
    s["cves"] = len(cves)
    if not cves:
        log("cve-scoring: no finding names a CVE; nothing to do")
        return s
    cache = {r["cve_id"]: (r["nvd_fetched_at"], bool(r["scored"])) for r in conn.execute(SELECT_CACHE_SQL)}

    try:
        kev, kev_authoritative = fetch_kev(get)
        s["kev_loaded"], s["kev_entries"] = True, len(kev)
        s["kev_source"] = "cisa.gov" if kev_authoritative else "CISA GitHub copy (adds only)"
    except SourceError as e:
        kev, kev_authoritative = None, False
        s["source_errors"].append(f"KEV: {e}")
    epss, errs = fetch_epss(cves, get)
    s["epss"] = len(epss)
    s["source_errors"] += errs
    nvd, err = fetch_nvd(nvd_due(cves, cache, now), get, sleep)
    s["nvd_read"] = sum(1 for v in nvd.values() if v)
    s["nvd_missing"] = sum(1 for v in nvd.values() if not v)
    if err:
        s["source_errors"].append(err)
    for e in s["source_errors"]:
        _warn(log, f"{e} (kept the values already held)")

    if dry_run:
        log(f"cve-scoring DRY RUN: {s}")
        return s

    for c in cves:
        try:
            with conn.transaction():       # one savepoint per CVE: a bad value skips only this CVE
                conn.execute(ENSURE_ROW_SQL, {"cve_id": c})
                if c in nvd:
                    if nvd[c]:
                        conn.execute(UPDATE_NVD_SQL, {"cve_id": c, **nvd[c]})
                    else:
                        conn.execute(UPDATE_NVD_MISSING_SQL, {"cve_id": c})
                if c in epss:
                    conn.execute(UPDATE_EPSS_SQL, {"cve_id": c, **epss[c]})
                k = kev.get(c) if kev is not None else None
                if k is not None or (kev is not None and kev_authoritative):
                    conn.execute(UPDATE_KEV_SQL, {
                        "cve_id": c, "kev_listed": k is not None,
                        **(k or {"kev_added_date": None, "kev_due_date": None,
                                 "kev_short_desc": None, "kev_required_action": None})})
        except (psycopg.Error, ValueError, TypeError) as e:
            s["cache_rows_failed"] += 1
            _warn(log, f"{c}: cache row not saved ({type(e).__name__}: {str(e)[:120]})")

    dl = conn.execute("SHOW deadlock_timeout").fetchone()["deadlock_timeout"]
    conn.execute(f"SET lock_timeout = '{lock_timeout_ms(dl)}ms'")
    for row in conn.execute(ROLLUP_SQL).fetchall():
        cols = plan_finding_update(row)
        if not cols:
            continue
        try:
            cur = conn.execute(update_finding_sql(sorted(cols)),
                               {"finding_id": row["finding_id"], **cols})
        except (psycopg.errors.LockNotAvailable, psycopg.errors.DeadlockDetected):
            s["busy_skipped"] += 1         # a scan holds it; next run catches up
            continue
        s["findings_updated"] += bool(cur.rowcount)
    log("cve-scoring: {cves} CVEs; KEV {kl} ({kev_entries} in catalog); EPSS {epss}; "
        "NVD read {nvd_read} (not in NVD {nvd_missing}); cache rows failed {cache_rows_failed}; "
        "findings updated {findings_updated}, busy-skipped {busy_skipped}; source problems {ne}".format(
            kl=f"from {s['kev_source']}" if s["kev_loaded"] else "NOT loaded", ne=len(s["source_errors"]), **s))
    return s


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score every CVE finding (NVD, EPSS, CISA KEV).")
    ap.add_argument("--dry-run", action="store_true", help="read the sources, write nothing")
    args = ap.parse_args(argv)
    dsn = os.environ.get("SUPABASE_DSN", "").strip()
    if not dsn:
        print("::error::cve-scoring: SUPABASE_DSN is not set", file=sys.stderr)
        return 2
    import psycopg
    from psycopg.rows import dict_row
    dry = args.dry_run or os.environ.get("DRY_RUN", "").strip().lower() == "true"
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row, connect_timeout=15) as conn:
        conn.execute("SET statement_timeout = '60s'")
        run(conn, dry_run=dry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
