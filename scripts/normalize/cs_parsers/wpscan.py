"""
wpscan.py — Parse WPScan text output into FindingEvents.

WPScan emits ANSI-colored multi-line sections. Key patterns we extract:

1. CVE entries (only present when API token was used at scan time):
       [+] [CVE-2024-12345] Plugin X vulnerable to RCE
        | Fixed in: 1.2.3
        | References:
        |  - https://nvd.nist.gov/vuln/detail/CVE-2024-12345

2. Outdated plugin/theme versions:
       [+] elementor
        | Location: https://x.com/wp-content/plugins/elementor/
        | Latest Version: 3.30.3
        | Version: 2.8.3 (80% confidence)
       (The "Version: X (Latest: Y)" mismatch = outdated finding)

3. WordPress exposures:
       [+] XML-RPC seems to be enabled: https://...
       [+] WordPress readme found: https://...
       [+] User(s) Identified: ...
       [+] Directory listing is enabled at: ...

4. Plugin/theme version banners:
       [+] WordPress theme in use: infinite
        | Latest Version: 1.1.2 (up to date)
       (If "up to date", skip; if outdated, emit finding)

Severity heuristics:
- CVE entries: pulled from severity hints in the body if present, else
  default MODERATE. CVE entries marked "(critical)" or with CVSS hints
  are escalated.
- Outdated plugin (1+ major version behind): LOW
- XML-RPC enabled: INFO (common but worth flagging)
- Readme exposed: INFO
- User enumeration successful: LOW (info disclosure)
- Directory listing: LOW
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
    to_utc_iso,
)


# ANSI escape codes (color, formatting) — strip these before parsing
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[\d+m")

# Top-level finding marker: `[+] description`
PLUS_RE = re.compile(r"^\[\+\]\s+(.+?)\s*$")

# CVE reference anywhere in a line
CVE_INLINE_RE = re.compile(r"CVE-(\d{4})-(\d{3,7})", re.IGNORECASE)

# URL extraction
URL_RE = re.compile(r"https?://[^\s\]'\"<>]+")

# Plugin/theme version with "Latest" hint
VERSION_RE = re.compile(r"^\s*\|\s*Version:\s*(\S+).*?(?:\(([^)]+)\))?\s*$")
LATEST_RE = re.compile(r"^\s*\|\s*Latest Version:\s*(\S+)(?:\s*\((up to date)\))?", re.IGNORECASE)
LOCATION_RE = re.compile(r"^\s*\|\s*Location:\s*(\S+)", re.IGNORECASE)

# URL of scanned site
TOP_URL_RE = re.compile(r"\[\+\]\s*URL:\s*(\S+)")


def _strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _category_for_finding(desc: str) -> str:
    d = desc.lower()
    if "xml-rpc" in d: return "config"
    if "readme" in d: return "info_disclosure"
    if "user" in d and "enum" in d: return "info_disclosure"
    if "user(s) identified" in d: return "info_disclosure"
    if "directory listing" in d: return "info_disclosure"
    if "outdated" in d or "out of date" in d: return "supply_chain"
    if "vulnerability" in d or "vulnerable" in d: return "supply_chain"
    return "config"


def _severity_for_cve_block(body: str, baseline: str = "MODERATE") -> str:
    """Pull a severity hint from CVE block body if present."""
    b = body.lower()
    if "critical" in b: return "CRITICAL"
    if "high" in b and "cvss" in b: return "HIGH"
    if "rce" in b or "remote code execution" in b or "sql injection" in b:
        return "HIGH"
    if "authentication bypass" in b: return "HIGH"
    if "privilege escalation" in b: return "HIGH"
    if "stored xss" in b: return "MODERATE"
    if "reflected xss" in b or "csrf" in b: return "LOW"
    return baseline


def parse_wpscan_file(
    text_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    if not text_path.is_file():
        return []
    try:
        raw_text = text_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    text = _strip_ansi(raw_text)

    rel_evidence = relative_to_scan_root(text_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    # Find target URL
    target_url: Optional[str] = None
    m = TOP_URL_RE.search(text)
    if m:
        target_url = m.group(1).strip()

    # subdomain inference
    target_sub: Optional[str] = None
    if target_url:
        sm = re.match(r"^https?://([^/:\s]+)", target_url)
        if sm: target_sub = sm.group(1).lower()

    # Asset = the FQDN scanned (from URL line), not the target-dir apex
    event_asset_id = canonical_asset_id(target_sub) if is_fqdn_in_scope(target_sub, asset_id) else canonical_asset_id(asset_id)

    events: list[FindingEvent] = []
    seen_finding_ids: set[str] = set()

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        m = PLUS_RE.match(line.strip())
        if not m:
            i += 1
            continue

        section_title = m.group(1).strip()

        # Collect indented body until next [+] or blank-line break
        body_lines: list[str] = []
        j = i + 1
        while j < len(lines):
            nxt = lines[j].rstrip()
            if nxt == "":
                j += 1
                if j < len(lines) and lines[j].strip().startswith("[+]"):
                    break
                if j < len(lines) and lines[j].strip() == "":
                    break
                continue
            if nxt.strip().startswith("[+]"):
                break
            if nxt.strip().startswith("[i]"):
                break
            body_lines.append(nxt)
            j += 1
        body = "\n".join(body_lines)

        # ─── CVE-style finding ─────────────────────────────────────────
        # DISABLED 2026-05-24. WPScan lists every CVE the plugin has EVER had,
        # including ones the installed version has already patched. Emitting
        # those creates noise findings that never close (e.g. wp-smushit 4.0.3
        # was flagged with CVE-2023-3352 even though that's fixed in 3.16.5).
        #
        # The wpvuln_json parser is now the single source of truth for plugin
        # CVE findings — it cross-references against installed_version via
        # wpvulnerability.net's `status: VULNERABLE | PATCHED` field, so only
        # currently-applicable CVEs are emitted.
        #
        # WPScan still emits non-CVE findings below (XML-RPC, readme exposure,
        # directory listings, user enumeration, outdated-version warnings).
        cve_inline = CVE_INLINE_RE.findall(section_title + " " + body)
        if cve_inline:
            # Skip — wpvuln_json owns this now.
            i = j
            continue

        # ─── Outdated plugin/theme version ──────────────────────────────
        # Pattern: section title is plugin/theme name; body has "Version: X" and "Latest Version: Y" mismatch
        version_match = None
        latest_match = None
        location_match = None
        for bl in body_lines:
            if vm := VERSION_RE.match(bl):
                version_match = vm.group(1)
            if lm := LATEST_RE.match(bl):
                latest_match = (lm.group(1), lm.group(2))
            if locm := LOCATION_RE.match(bl):
                location_match = locm.group(1)
        if version_match and latest_match:
            latest_ver, up_to_date = latest_match
            if not up_to_date and version_match != latest_ver:
                # Outdated
                slug = section_title.lower().split()[0]
                matched_at = location_match or target_url or ""
                fid = stable_finding_id(event_asset_id, "wpscan", f"outdated:{slug}", matched_at)
                if fid not in seen_finding_ids:
                    seen_finding_ids.add(fid)
                    events.append(FindingEvent(
                        finding_id=fid,
                        asset_id=event_asset_id,
                        scan_id=scan_id,
                        source="wpscan",
                        title=f"Outdated WordPress component: {section_title} ({version_match} → {latest_ver})",
                        severity="LOW",
                        category="supply_chain",
                        observed_at=observed_at,
                        matched_at=matched_at,
                        description=f"Installed version {version_match} is behind latest {latest_ver}.",
                        cve=[], cwe=[], references=[],
                        raw_excerpt=(line + "\n" + body)[:2000],
                        evidence_paths=[rel_evidence],
                        subdomain=target_sub,
                        port=443,
                        protocol="https",
                    ))
            i = j
            continue

        # ─── Known exposure patterns ────────────────────────────────────
        title_lc = section_title.lower()
        exposure_specs: list[tuple[str, str, str, str]] = []
        # (matcher_substring, finding_short, severity, description)
        if "xml-rpc" in title_lc and "enabled" in title_lc:
            exposure_specs.append(("xmlrpc", "xmlrpc-enabled", "INFO",
                "XML-RPC endpoint is enabled. Frequently abused for pingback DDoS and brute-force amplification."))
        if "readme" in title_lc and "found" in title_lc:
            exposure_specs.append(("readme", "wp-readme-exposed", "INFO",
                "WordPress readme.html is publicly accessible — may leak version info."))
        if "directory listing" in title_lc:
            exposure_specs.append(("dirlisting", "directory-listing-enabled", "LOW",
                "Directory listing is enabled — exposes installed files."))
        if "user(s) identified" in title_lc or ("user" in title_lc and "identified" in title_lc):
            exposure_specs.append(("user-enum", "user-enumeration", "LOW",
                "WordPress user enumeration succeeded — usernames are discoverable."))

        for (_, short, sev, desc) in exposure_specs:
            url_in_title = URL_RE.search(section_title)
            matched_at = (url_in_title.group(0) if url_in_title else (target_url or ""))
            fid = stable_finding_id(event_asset_id, "wpscan", short, matched_at)
            if fid in seen_finding_ids:
                continue
            seen_finding_ids.add(fid)
            events.append(FindingEvent(
                finding_id=fid,
                asset_id=event_asset_id,
                scan_id=scan_id,
                source="wpscan",
                title=f"WordPress: {short.replace('-', ' ')}",
                severity=sev,
                category=_category_for_finding(section_title),
                observed_at=observed_at,
                matched_at=matched_at,
                description=desc,
                cve=[], cwe=[], references=[],
                raw_excerpt=(line + "\n" + body)[:2000],
                evidence_paths=[rel_evidence],
                subdomain=target_sub,
                port=443,
                protocol="https",
            ))

        i = j

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    target = target_entry["target"]
    asset_id = infer_asset_id(target)
    scan_run_dir = scan_entry["scan_run_dir"]
    if scan_run_dir.startswith("(target-root") or scan_run_dir == "_target_root":
        scan_id = f"{target}__synthetic_root"
    else:
        scan_id = f"{target}__{scan_run_dir}"
    scan_run_abs = Path(scan_entry["absolute_path"])
    fallback_ts = scan_entry.get("inferred_started_at")

    events: list[FindingEvent] = []
    for tool in scan_entry.get("tools_detected", []):
        if tool.get("parser") != "wpscan":
            continue
        for rel_file in tool.get("files", []):
            events.extend(parse_wpscan_file(
                text_path=scan_run_abs / rel_file,
                asset_id=asset_id,
                scan_id=scan_id,
                scan_root=scan_root,
                fallback_observed_at=fallback_ts,
            ))
    return events
