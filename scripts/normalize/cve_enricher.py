#!/usr/bin/env python3
"""
cve_enricher.py — Track 2 enrichment

For every unique CVE referenced by any finding in the DB, hit three free
public APIs and cache the results in cve_enrichments:

  · NVD       — full CVSS v3.1 vector, severity, CWEs, description, refs
                https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-X
  · EPSS      — exploit-prediction probability + percentile
                https://api.first.org/data/v1/epss?cve=CVE-X
  · CISA KEV  — actively-exploited-in-the-wild flag + remediation deadline
                https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Then rolls up the per-CVE data onto each finding row:
  - findings.epss_score      = worst (highest) across the finding's CVEs
  - findings.epss_percentile = same
  - findings.kev_listed      = true if ANY CVE on the finding is on KEV
  - findings.kev_due_date    = soonest due_date across KEV-listed CVEs
  - findings.cvss_vector     = fill from NVD if currently NULL
  - findings.cvss_score      = fill from NVD if currently NULL

Refresh policy:
  · KEV catalog re-fetched on every run (changes ~weekly, costs ~80KB)
  · EPSS re-fetched on every run for CVEs we care about (small payload)
  · NVD per-CVE refreshed only when nvd_fetched_at is NULL or > 30 days old

Usage:
  # Dry-run: print what would be enriched
  python scripts/normalize/cve_enricher.py --dry-run

  # Real run
  python scripts/normalize/cve_enricher.py

  # Force re-fetch of all enrichments (ignore cache freshness)
  python scripts/normalize/cve_enricher.py --force
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path


DEFAULT_SUPABASE_URL = "https://hdygktppfvuspnumpfuq.supabase.co"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cve}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Be polite to NVD — they request ≤ 5 req/30s without an API key.
NVD_DELAY_SECONDS = 6.5

# How stale before we re-fetch NVD per-CVE
NVD_FRESHNESS_DAYS = 30


# ─── HTTP helper ────────────────────────────────────────────────────────────

def _http_get_json(url: str, timeout: int = 20) -> dict | None:
    """GET a URL and parse JSON. Returns None on 404 or network error.
    Raises on non-404 HTTP errors so the caller knows something's wrong."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "COMMANDsentry/1.0 (security tooling; +internal)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        # Rate limit / 5xx — return None, caller can decide
        if e.code in (429, 502, 503, 504):
            print(f"  ! HTTP {e.code} on {url} — retrying once after 10s")
            time.sleep(10)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception as e2:
                print(f"  ! retry failed: {e2}")
                return None
        raise
    except urllib.error.URLError as e:
        print(f"  ! network error on {url}: {e}")
        return None


# ─── NVD ────────────────────────────────────────────────────────────────────

def fetch_nvd(cve: str) -> dict:
    """Fetch NVD detail for one CVE. Returns the structured fields we care
    about (or {} on lookup miss)."""
    data = _http_get_json(NVD_API.format(cve=cve))
    if not data:
        return {}
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {}
    cve_obj = vulns[0].get("cve") or {}
    out: dict = {}

    # CVSS — prefer v3.1, fall back to v3.0
    metrics = cve_obj.get("metrics") or {}
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            cvss_data = metrics[key][0].get("cvssData") or {}
            break
    if cvss_data:
        out["nvd_cvss_v3_vector"] = cvss_data.get("vectorString")
        score = cvss_data.get("baseScore")
        if score is not None:
            out["nvd_cvss_v3_score"] = float(score)
        out["nvd_severity"] = (cvss_data.get("baseSeverity") or "").upper() or None

    # CWE — collect every "Primary" weakness mapped to this CVE
    weaknesses = cve_obj.get("weaknesses") or []
    cwes: list[int] = []
    for w in weaknesses:
        for desc in (w.get("description") or []):
            v = (desc.get("value") or "").strip()
            m = re.match(r"CWE-(\d+)", v, re.I)
            if m:
                cwes.append(int(m.group(1)))
    if cwes:
        out["nvd_cwe_ids"] = sorted(set(cwes))

    # English description
    descs = cve_obj.get("descriptions") or []
    for d in descs:
        if d.get("lang") == "en":
            out["nvd_description"] = d.get("value")
            break

    # Dates
    if cve_obj.get("published"):
        out["nvd_published_at"] = cve_obj["published"]
    if cve_obj.get("lastModified"):
        out["nvd_last_modified"] = cve_obj["lastModified"]

    # References — flatten to URL list
    refs = cve_obj.get("references") or []
    urls = [r.get("url") for r in refs if r.get("url")]
    if urls:
        out["nvd_references"] = urls

    return out


# ─── EPSS ───────────────────────────────────────────────────────────────────

def fetch_epss(cve: str) -> dict:
    """Fetch EPSS score + percentile for one CVE."""
    data = _http_get_json(EPSS_API.format(cve=cve))
    if not data:
        return {}
    items = data.get("data") or []
    if not items:
        return {}
    item = items[0]
    out: dict = {}
    if item.get("epss") is not None:
        out["epss_score"] = float(item["epss"])
    if item.get("percentile") is not None:
        out["epss_percentile"] = float(item["percentile"])
    return out


# ─── KEV catalog ────────────────────────────────────────────────────────────

def fetch_kev_catalog() -> dict[str, dict]:
    """Fetch the entire CISA KEV catalog once and index by CVE."""
    print("  Fetching CISA KEV catalog...")
    data = _http_get_json(KEV_FEED, timeout=30)
    if not data:
        print("  ! KEV catalog fetch failed — kev_listed will stay false")
        return {}
    vulns = data.get("vulnerabilities") or []
    indexed: dict[str, dict] = {}
    for v in vulns:
        cve_id = (v.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        indexed[cve_id] = {
            "kev_listed": True,
            "kev_added_date": v.get("dateAdded"),
            "kev_due_date": v.get("dueDate"),
            "kev_short_desc": v.get("shortDescription"),
            "kev_required_action": v.get("requiredAction"),
        }
    print(f"  ✓ KEV catalog loaded: {len(indexed)} CVEs")
    return indexed


# ─── Per-CVE enrichment workflow ────────────────────────────────────────────

def enrich_one_cve(sb, cve: str, kev_index: dict[str, dict], force: bool) -> dict:
    """Look up one CVE, write/update the cve_enrichments row, return the
    enrichment payload (the dict that was written)."""
    # Check cache first
    cached = (
        sb.table("cve_enrichments")
        .select("*")
        .eq("cve_id", cve)
        .maybe_single()
        .execute()
    )
    cached_row = getattr(cached, "data", None) if cached is not None else None

    needs_nvd = force or not cached_row or not cached_row.get("nvd_fetched_at") or _is_stale(
        cached_row.get("nvd_fetched_at"), NVD_FRESHNESS_DAYS
    )

    payload: dict = {}
    now_iso = datetime.now(timezone.utc).isoformat()

    if needs_nvd:
        nvd = fetch_nvd(cve)
        if nvd:
            payload.update(nvd)
            payload["nvd_fetched_at"] = now_iso
        time.sleep(NVD_DELAY_SECONDS)  # be polite to NVD
    elif cached_row:
        # Carry forward cached NVD fields
        for k in ("nvd_cvss_v3_vector", "nvd_cvss_v3_score", "nvd_severity",
                  "nvd_cwe_ids", "nvd_description", "nvd_published_at",
                  "nvd_last_modified", "nvd_references", "nvd_fetched_at"):
            if cached_row.get(k) is not None:
                payload[k] = cached_row[k]

    # EPSS — fetch every run (small, fast, changes often)
    epss = fetch_epss(cve)
    if epss:
        payload.update(epss)
        payload["epss_fetched_at"] = now_iso

    # KEV — from the bulk catalog we fetched once
    kev = kev_index.get(cve.upper(), {})
    if kev:
        payload.update(kev)
        payload["kev_fetched_at"] = now_iso
    else:
        payload["kev_listed"] = False
        payload["kev_fetched_at"] = now_iso

    payload["updated_at"] = now_iso

    # Upsert
    if cached_row:
        sb.table("cve_enrichments").update(payload).eq("cve_id", cve).execute()
    else:
        payload["cve_id"] = cve
        sb.table("cve_enrichments").insert(payload).execute()

    return payload


def _is_stale(ts: str | None, days: int) -> bool:
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt) > timedelta(days=days)
    except (ValueError, TypeError):
        return True


# ─── Per-finding rollup ─────────────────────────────────────────────────────

def rollup_finding(finding: dict, enrichments_by_cve: dict[str, dict]) -> dict:
    """Compute the denormalized rollup columns to write on the finding row.
    Worst-case (highest EPSS, ANY KEV, soonest KEV due date) across the
    finding's CVE list."""
    cves = [c.upper() for c in (finding.get("cve") or []) if c]
    if not cves:
        return {}

    out: dict = {}

    # EPSS rollup — worst (highest) across CVEs
    worst_epss = None
    worst_percentile = None
    for cve in cves:
        e = enrichments_by_cve.get(cve)
        if not e:
            continue
        if e.get("epss_score") is not None:
            if worst_epss is None or e["epss_score"] > worst_epss:
                worst_epss = e["epss_score"]
                worst_percentile = e.get("epss_percentile")
    if worst_epss is not None:
        out["epss_score"] = worst_epss
        if worst_percentile is not None:
            out["epss_percentile"] = worst_percentile

    # KEV rollup — TRUE if any CVE is on KEV; due date = soonest
    any_kev = False
    soonest_due: str | None = None
    for cve in cves:
        e = enrichments_by_cve.get(cve)
        if not e:
            continue
        if e.get("kev_listed"):
            any_kev = True
            d = e.get("kev_due_date")
            if d and (soonest_due is None or d < soonest_due):
                soonest_due = d
    out["kev_listed"] = any_kev
    if soonest_due:
        out["kev_due_date"] = soonest_due

    # CVSS — fill if currently missing on the finding
    if finding.get("cvss_score") is None or not finding.get("cvss_vector"):
        for cve in cves:
            e = enrichments_by_cve.get(cve)
            if not e:
                continue
            if finding.get("cvss_score") is None and e.get("nvd_cvss_v3_score") is not None:
                out["cvss_score"] = e["nvd_cvss_v3_score"]
            if not finding.get("cvss_vector") and e.get("nvd_cvss_v3_vector"):
                out["cvss_vector"] = e["nvd_cvss_v3_vector"]
            if "cvss_score" in out and "cvss_vector" in out:
                break

    out["cve_enriched_at"] = datetime.now(timezone.utc).isoformat()
    return out


# ─── Main ───────────────────────────────────────────────────────────────────

def load_env(repo_root: Path) -> None:
    env_path = repo_root / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print what would be enriched without writing.")
    parser.add_argument("--force", action="store_true", help="Re-fetch every CVE's NVD entry ignoring cache freshness.")
    parser.add_argument("--cve", help="Process only this CVE (for testing).")
    args = parser.parse_args()

    try:
        from supabase import create_client
    except ImportError:
        sys.exit("Install deps: pip install supabase  (or activate the .venv)")

    repo_root = Path(__file__).resolve().parents[2]
    load_env(repo_root)
    sb_url = os.environ.get("SUPABASE_URL", DEFAULT_SUPABASE_URL)
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not sb_key:
        sys.exit("SUPABASE_SERVICE_ROLE_KEY not set (check .env)")
    sb = create_client(sb_url, sb_key)

    # ── Collect every CVE referenced by any finding
    print("Loading CVE list from findings...")
    if args.cve:
        cves = [args.cve.strip().upper()]
    else:
        # CVE field is text[] — supabase-py returns it as a list per row
        rows = (
            sb.table("findings")
            .select("finding_id, cve")
            .not_.is_("cve", "null")
            .execute()
            .data
            or []
        )
        cve_set: set[str] = set()
        for r in rows:
            for c in (r.get("cve") or []):
                s = (c or "").strip().upper()
                if re.match(r"CVE-\d{4}-\d+", s):
                    cve_set.add(s)
        cves = sorted(cve_set)

    print(f"Unique CVEs to enrich: {len(cves)}")
    if not cves:
        print("Nothing to do.")
        return

    print()
    print("=" * 72)
    print("Fetching CISA KEV catalog (one-shot bulk)...")
    print("=" * 72)
    kev_index = fetch_kev_catalog()
    print()

    print("=" * 72)
    print(f"Enriching {len(cves)} CVEs via NVD + EPSS + KEV...")
    print("=" * 72)

    enrichments_by_cve: dict[str, dict] = {}
    for i, cve in enumerate(cves, 1):
        print(f"[{i}/{len(cves)}] {cve}")
        if args.dry_run:
            # Still hit the APIs in dry-run so the user can verify the data,
            # but don't write to DB
            nvd = fetch_nvd(cve)
            time.sleep(NVD_DELAY_SECONDS)
            epss = fetch_epss(cve)
            kev = kev_index.get(cve, {})
            preview = {**nvd, **epss, **kev}
            for k in ("nvd_cvss_v3_vector", "nvd_cvss_v3_score", "nvd_severity",
                      "epss_score", "epss_percentile", "kev_listed", "kev_due_date"):
                v = preview.get(k)
                if v is not None:
                    print(f"    {k}: {v}")
            enrichments_by_cve[cve] = preview
        else:
            enrichments_by_cve[cve] = enrich_one_cve(sb, cve, kev_index, args.force)
            print(f"    ✓ written")

    if args.dry_run:
        print()
        print("DRY RUN — nothing written. Rerun without --dry-run to commit.")
        return

    # ── Roll up onto findings
    print()
    print("=" * 72)
    print("Rolling up enrichments onto findings...")
    print("=" * 72)

    finding_rows = (
        sb.table("findings")
        .select("finding_id, cve, cvss_score, cvss_vector, kev_listed")
        .not_.is_("cve", "null")
        .execute()
        .data
        or []
    )
    updated_count = 0
    for r in finding_rows:
        updates = rollup_finding(r, enrichments_by_cve)
        if not updates or list(updates.keys()) == ["cve_enriched_at"]:
            continue
        sb.table("findings").update(updates).eq("finding_id", r["finding_id"]).execute()
        updated_count += 1
        # Brief progress every 25
        if updated_count % 25 == 0:
            print(f"  {updated_count} findings updated...")

    print()
    print("=" * 72)
    print(f"Done. {len(cves)} CVEs enriched, {updated_count} findings updated.")


if __name__ == "__main__":
    main()
