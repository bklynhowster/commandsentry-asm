"""
curated_html.py — Parse Command's curated assessment HTML reports.

These are the brand-styled HTML reports (CommandDigital_*_Assessment_*.html)
that Howie has authored over time. They contain finding records that
DON'T appear in any raw tool output — they're the result of human analysis
during scan curation. Examples that only live in HTML reports:

  api 5/14:   A-03 Suspicious 500 Error Responses (CVSS 5.3)
  api 5/14:   W-02 WAF Does Not Block XSS/SQLi Payloads (CVSS 5.8)
  www 5/13:   Various A-XX, W-XX, F-XX rows with manual analysis

Without parsing these, the canonical data layer misses the operator's
curated security posture entirely. The HTML files are the canonical
human-judged finding record.

Format: most reports use row-based tables like:
    A-01  Missing Security Headers          MEDIUM  5.3
    A-02  Server/Technology Disclosure      LOW     3.7
    A-03  Suspicious 500 Error Responses    MEDIUM  5.3
    W-01  FortiGate cookiesession1 ...      LOW     3.1
    W-02  WAF Does Not Block XSS/SQLi       MEDIUM  5.8

Older narrative-style reports (which reference findings inline without
tabulation) aren't covered by this parser yet. They contain status
updates rather than new finding records; lower priority.

ID prefix → category map:
  A-XX  → application (security headers, error handling, etc.)
  W-XX  → waf (WAF-level findings)
  F-XX  → forensic (analysis findings)
  T-XX  → tls
  H/C/M/L/I-XX → fall back to severity-based bucket (these are the named
                 application findings already covered by SUMMARY.md parser;
                 emit them too as a fallback for assets where no SUMMARY.md
                 exists but the curated HTML does)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .common import (
    canonical_asset_id,
    is_fqdn_in_scope,
    FindingEvent,
    infer_asset_id,
    relative_to_scan_root,
    stable_finding_id,
    subdomain_from_url,
    to_utc_iso,
)


# Match the row pattern: ID Title SEVERITY CVSS
ROW_RE = re.compile(
    r"([A-Z])-(\d{2,3})\s+(.+?)\s+(CRITICAL|HIGH|MODERATE|MEDIUM|LOW|INFO)\s+(\d+\.\d+)",
    re.IGNORECASE,
)

# Pull asset/target from filename: CommandDigital_<target>_Assessment_<date>.html
FILENAME_RE = re.compile(
    r"CommandDigital_(.+?)_(?:Assessment|Consolidated|VulnAssessment)_(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


# Category by ID prefix
PREFIX_CATEGORY = {
    "A": "config",          # application — security headers, error handling, config
    "W": "config",          # WAF — generally config; could be more specific
    "F": "info_disclosure", # forensic / analysis
    "T": "tls",             # TLS
    "H": "auth",            # named high-tier — usually auth-related (default; not always)
    "C": "auth",            # named critical — usually credential/crypto
    "M": "config",          # named moderate
    "L": "config",          # named low
    "I": "info_disclosure", # informational
}


def _strip_html(html: str) -> str:
    """Strip tags + collapse whitespace for regex extraction."""
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text)


def _map_severity(sev: str) -> str:
    s = sev.upper()
    if s == "MEDIUM":
        return "MODERATE"
    if s in ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW", "INFO"):
        return s
    return "INFO"


def _normalize_target_from_filename(target_token: str) -> str:
    """
    Turn the filename's target token into a canonical asset_id.
    Examples:
      api.commandcommcentral.com  → api.commandcommcentral.com
      www.commandcommcentral.com  → commandcommcentral.com  (www collapsed)
      commandcommcentral.com      → commandcommcentral.com
      enrollment2.edelivery-...   → enrollment2.edelivery-...
      CABLENET1_NoDNS             → unknown (skip)
    """
    t = target_token.lower()
    # Skip non-FQDN tokens (e.g. CABLENET1_NoDNS, FortiWEB_NaturalWireless)
    if "." not in t:
        return ""
    return canonical_asset_id(t) or t


def parse_curated_html(
    html_path: Path,
    target_dir_asset_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    """Extract findings from one CommandDigital_*_Assessment_*.html file."""
    if not html_path.is_file():
        return []
    try:
        html = html_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Extract target FQDN + report date from filename
    m = FILENAME_RE.search(html_path.name)
    file_asset_id = _normalize_target_from_filename(m.group(1)) if m else ""
    report_date = m.group(2) if m else None
    observed_at = to_utc_iso(report_date) if report_date else fallback_observed_at or ""

    # Asset_id resolution: prefer filename-derived target if it's in scope,
    # else fall back to target dir mapping.
    if file_asset_id and is_fqdn_in_scope(file_asset_id, target_dir_asset_id):
        event_asset_id = file_asset_id
    elif file_asset_id:
        # If filename target is more specific than the target dir's asset, still
        # prefer it (e.g. apex dir had a www.X report — use canonical www collapse).
        event_asset_id = canonical_asset_id(file_asset_id) or target_dir_asset_id
    else:
        event_asset_id = canonical_asset_id(target_dir_asset_id) or target_dir_asset_id

    text = _strip_html(html)
    rel_evidence = relative_to_scan_root(html_path, scan_root)

    events: list[FindingEvent] = []
    seen_finding_ids: set[str] = set()

    for m in ROW_RE.finditer(text):
        prefix = m.group(1).upper()
        num = m.group(2)
        title = m.group(3).strip()
        sev_raw = m.group(4)
        cvss = m.group(5)

        # Skip obviously bogus matches: titles that are too long are usually
        # text snippets that happened to contain the pattern, not real rows.
        if len(title) > 100:
            continue
        # Skip titles that look like instruction text rather than finding names
        lower = title.lower()
        if any(skip in lower for skip in ("description", "recommendation", "click", "scroll", "filter", "↕")):
            continue

        canonical_sev = _map_severity(sev_raw)
        short_id = f"{prefix}-{num.zfill(2)}"
        category = PREFIX_CATEGORY.get(prefix, "other")

        # finding_id includes report ID so different reports on the same asset
        # over time produce different events but the same canonical finding
        # (after rollup dedupe).
        finding_id = f"{event_asset_id}:curated:{short_id}"
        if finding_id in seen_finding_ids:
            continue
        seen_finding_ids.add(finding_id)

        events.append(FindingEvent(
            finding_id=finding_id,
            asset_id=event_asset_id,
            scan_id="",  # filled by caller
            source="manual_named",
            title=f"{short_id}: {title}",
            severity=canonical_sev,
            category=category,
            observed_at=observed_at,
            matched_at=None,
            description=f"Source: {html_path.name} (CVSS {cvss}, severity {sev_raw})",
            cve=[],
            cwe=[],
            references=[],
            raw_excerpt=f"{short_id}  {title}  {sev_raw}  CVSS {cvss}",
            evidence_paths=[rel_evidence],
        ))

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    """Driver entry point — runs once per scan-run with curated_html detected."""
    target = target_entry["target"]
    target_dir_asset_id = infer_asset_id(target)

    scan_run_dir = scan_entry["scan_run_dir"]
    if scan_run_dir.startswith("(target-root") or scan_run_dir == "_target_root":
        scan_id = f"{target}__synthetic_root"
    else:
        scan_id = f"{target}__{scan_run_dir}"

    scan_run_abs = Path(scan_entry["absolute_path"])
    fallback_ts = scan_entry.get("inferred_started_at")

    events: list[FindingEvent] = []
    for tool in scan_entry.get("tools_detected", []):
        if tool.get("parser") != "curated_html":
            continue
        for rel_file in tool.get("files", []):
            html_path = scan_run_abs / rel_file
            file_events = parse_curated_html(
                html_path=html_path,
                target_dir_asset_id=target_dir_asset_id,
                scan_root=scan_root,
                fallback_observed_at=fallback_ts,
            )
            for ev in file_events:
                ev.scan_id = scan_id
            events.extend(file_events)
    return events
