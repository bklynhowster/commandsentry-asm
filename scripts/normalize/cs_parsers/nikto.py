"""
nikto.py — Parse Nikto text output into FindingEvents.

Nikto format example:
    + Target IP:        24.38.70.5
    + Target Hostname:  commandcommcentral.com
    + Target Port:      443
    + [999992] /: Server is using a wildcard certificate: *.commandcommcentral.com. See: https://...
    + [013587] /: Suggested security header missing: permissions-policy. See: https://...
    + Server banner changed from 'Microsoft-HTTPAPI/2.0' to ''.

We emit one FindingEvent per finding line. Heuristics:
- `+ [NNNNNN] /path: description` → bracketed test_id, captured as finding
- `+ Suggested security header missing: X` → finding (no bracketed ID — synthesize one)
- `+ Server banner changed from ... to ...` → INFO-level finding
- Metadata lines (Target IP, Target Hostname, Start Time, Scan terminated) → skipped
- `+ ERROR:` lines (host maximum execution time, etc.) → skipped (scan-tool issues)
- `+ Unable to connect` lines → skipped (FortiGate WAF blocked the scan)

Severity policy: nikto doesn't categorize severity in its text output. We
default to LOW for security-relevant findings (missing headers, wildcard certs,
exposed paths) and INFO for benign observations.
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


# Skip patterns — metadata, errors, scan-tool noise
SKIP_PATTERNS = [
    re.compile(r"^Nikto v"),
    re.compile(r"^Target (Host|IP|Hostname|Port):", re.IGNORECASE),
    re.compile(r"^Start Time:", re.IGNORECASE),
    re.compile(r"^End Time:", re.IGNORECASE),
    re.compile(r"^Server:\s*No banner retrieved", re.IGNORECASE),
    re.compile(r"^Your Nikto installation is out of date"),
    re.compile(r"^SSL Info:", re.IGNORECASE),
    re.compile(r"^Platform:", re.IGNORECASE),
    re.compile(r"^Scan terminated", re.IGNORECASE),
    re.compile(r"^\d+ host\(s\)\s+tested", re.IGNORECASE),
    re.compile(r"^No CGI Directories found"),
    re.compile(r"^ERROR:", re.IGNORECASE),
    re.compile(r"^GET\s+Unable to connect"),
    re.compile(r"^OSVDB-\d+:\s*$"),
    re.compile(r"^---+"),
    re.compile(r"^\s*$"),
]

# Bracketed test ID: `[NNNNNN] /path: description`
BRACKETED_RE = re.compile(r"^\[(\d+)\]\s+(.+?)\s*$")

# Suggested security header
HEADER_RE = re.compile(r"^Suggested security header missing:\s*(.+?)\s*(?:\.|$)", re.IGNORECASE)

# Server banner changed
BANNER_RE = re.compile(r"^Server banner changed", re.IGNORECASE)

# Lines that should be treated as findings even without a bracketed ID
GENERIC_FINDING_KEYWORDS = [
    re.compile(r"server is using a wildcard certificate", re.IGNORECASE),
    re.compile(r"is using a default page", re.IGNORECASE),
    re.compile(r"phpinfo\b", re.IGNORECASE),
    re.compile(r"backup files", re.IGNORECASE),
    re.compile(r"weak ssl cipher", re.IGNORECASE),
    re.compile(r"directory indexing", re.IGNORECASE),
    re.compile(r"OPTIONS allowed", re.IGNORECASE),
    re.compile(r"\.git/", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
]


def _strip_url_suffix(text: str) -> str:
    """Remove trailing 'See: https://...' from finding descriptions."""
    return re.sub(r"\s*See:\s*https?://\S+\s*$", "", text)


def _severity_for_text(text: str) -> str:
    t = text.lower()
    if "wildcard certificate" in t or "default page" in t or "phpinfo" in t:
        return "LOW"
    if "missing" in t and "header" in t:
        return "LOW"
    if "banner changed" in t or "server banner" in t:
        return "INFO"
    if ".git/" in t or ".env" in t or "backup" in t:
        return "MODERATE"
    return "INFO"


def _category_for_text(text: str) -> str:
    t = text.lower()
    if "header" in t: return "headers"
    if "certificate" in t or "ssl" in t or "tls" in t: return "tls"
    if "banner" in t: return "info_disclosure"
    if "directory" in t: return "info_disclosure"
    if ".git" in t or ".env" in t or "backup" in t: return "info_disclosure"
    if "options" in t: return "config"
    return "config"


def parse_nikto_file(
    text_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    if not text_path.is_file():
        return []
    try:
        text = text_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel_evidence = relative_to_scan_root(text_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    # Try to capture host/port from the file header
    target_host: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    for line in text.splitlines()[:40]:
        s = line.lstrip("+- ").strip()
        m = re.match(r"^Target Hostname:\s*(\S+)", s, re.IGNORECASE)
        if m: target_host = m.group(1)
        m = re.match(r"^Target Host:\s*(\S+)", s, re.IGNORECASE)
        if m and not target_host: target_host = m.group(1)
        m = re.match(r"^Target IP:\s*(\S+)", s, re.IGNORECASE)
        if m: target_ip = m.group(1)
        m = re.match(r"^Target Port:\s*(\d+)", s, re.IGNORECASE)
        if m:
            try: target_port = int(m.group(1))
            except ValueError: pass

    # Asset = the FQDN scanned, not the target-dir apex
    event_asset_id = canonical_asset_id(target_host.lower()) if (target_host and is_fqdn_in_scope(target_host.lower(), asset_id)) else canonical_asset_id(asset_id)

    events: list[FindingEvent] = []
    seen_finding_ids: set[str] = set()  # dedupe within the same scan file

    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("+"):
            continue
        content = line[1:].strip()
        if any(p.match(content) for p in SKIP_PATTERNS):
            continue

        # Bracketed test ID with path
        m = BRACKETED_RE.match(content)
        if m:
            test_id = m.group(1)
            rest = m.group(2).strip()
            # rest usually starts with "/path: description"
            path_match = re.match(r"^(\S+):\s*(.+?)$", rest)
            if path_match:
                path = path_match.group(1)
                desc = _strip_url_suffix(path_match.group(2))
            else:
                path = "/"
                desc = _strip_url_suffix(rest)

            matched_at = (
                f"https://{target_host}:{target_port or 443}{path}"
                if target_host
                else (f"https://{target_ip}{path}" if target_ip else path)
            )
            severity = _severity_for_text(desc)
            category = _category_for_text(desc)
            fid = stable_finding_id(event_asset_id, "nikto", f"id-{test_id}", matched_at)
            if fid in seen_finding_ids:
                continue
            seen_finding_ids.add(fid)
            events.append(FindingEvent(
                finding_id=fid,
                asset_id=event_asset_id,
                scan_id=scan_id,
                source="nikto",
                title=f"nikto[{test_id}]: {desc[:120]}",
                severity=severity,
                category=category,
                observed_at=observed_at,
                matched_at=matched_at,
                description=desc,
                cve=[], cwe=[], references=[],
                raw_excerpt=line[:1500],
                evidence_paths=[rel_evidence],
                subdomain=target_host,
                host_ip=target_ip,
                port=target_port or 443,
                protocol="https" if (target_port or 443) == 443 else "http",
            ))
            continue

        # Header-missing pattern
        m = HEADER_RE.match(content)
        if m:
            header_name = m.group(1).strip().lower()
            matched_at = f"https://{target_host}" if target_host else (f"https://{target_ip}" if target_ip else "")
            fid = stable_finding_id(event_asset_id, "nikto", f"missing-header:{header_name}", matched_at)
            if fid in seen_finding_ids:
                continue
            seen_finding_ids.add(fid)
            events.append(FindingEvent(
                finding_id=fid,
                asset_id=event_asset_id,
                scan_id=scan_id,
                source="nikto",
                title=f"Missing security header: {header_name}",
                severity="LOW",
                category="headers",
                observed_at=observed_at,
                matched_at=matched_at,
                description=f"Nikto reports missing recommended security header: {header_name}",
                cve=[], cwe=[], references=[],
                raw_excerpt=line[:1500],
                evidence_paths=[rel_evidence],
                subdomain=target_host,
                host_ip=target_ip,
                port=target_port or 443,
                protocol="https",
            ))
            continue

        # Banner changed (info)
        if BANNER_RE.match(content):
            matched_at = f"https://{target_host}" if target_host else ""
            fid = stable_finding_id(event_asset_id, "nikto", "server-banner-changed", matched_at)
            if fid in seen_finding_ids:
                continue
            seen_finding_ids.add(fid)
            events.append(FindingEvent(
                finding_id=fid,
                asset_id=event_asset_id,
                scan_id=scan_id,
                source="nikto",
                title="Server banner changed (server-side hiding)",
                severity="INFO",
                category="info_disclosure",
                observed_at=observed_at,
                matched_at=matched_at,
                description=_strip_url_suffix(content),
                cve=[], cwe=[], references=[],
                raw_excerpt=line[:1500],
                evidence_paths=[rel_evidence],
                subdomain=target_host,
                host_ip=target_ip,
                port=target_port or 443,
                protocol="https",
            ))
            continue

        # Generic-keyword-match fallback (catches some non-bracketed findings)
        for kw_re in GENERIC_FINDING_KEYWORDS:
            if kw_re.search(content):
                matched_at = f"https://{target_host}" if target_host else ""
                # Use the first keyword as the test_id seed
                test_id = kw_re.pattern.replace("\\b", "").replace("\\s+", "_")[:40]
                fid = stable_finding_id(event_asset_id, "nikto", f"kw:{test_id}", matched_at)
                if fid in seen_finding_ids:
                    break
                seen_finding_ids.add(fid)
                desc = _strip_url_suffix(content)
                events.append(FindingEvent(
                    finding_id=fid,
                    asset_id=event_asset_id,
                    scan_id=scan_id,
                    source="nikto",
                    title=f"nikto: {desc[:120]}",
                    severity=_severity_for_text(desc),
                    category=_category_for_text(desc),
                    observed_at=observed_at,
                    matched_at=matched_at,
                    description=desc,
                    cve=[], cwe=[], references=[],
                    raw_excerpt=line[:1500],
                    evidence_paths=[rel_evidence],
                    subdomain=target_host,
                    host_ip=target_ip,
                    port=target_port or 443,
                    protocol="https",
                ))
                break

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
        if tool.get("parser") != "nikto":
            continue
        for rel_file in tool.get("files", []):
            events.extend(parse_nikto_file(
                text_path=scan_run_abs / rel_file,
                asset_id=asset_id,
                scan_id=scan_id,
                scan_root=scan_root,
                fallback_observed_at=fallback_ts,
            ))
    return events
