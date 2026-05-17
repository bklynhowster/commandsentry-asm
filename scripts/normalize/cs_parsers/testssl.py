"""
testssl.py — Parse testssl.sh JSON output into FindingEvents.

Format: flat JSON array of test records:
    [
      {"id": "engine_problem", "ip": "/", "port": "443", "severity": "WARN", "finding": "..."},
      {"id": "cipher-tls1_2_xc028", "ip": "www.x.com/24.38.70.5", "port": "443",
       "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384 ..."},
      {"id": "LUCKY13", "ip": "...", "port": "443", "severity": "LOW", "cwe": "CWE-310", ...}
    ]

Two grouping considerations:
1. testssl emits one record per cipher suite tested. A typical TLS 1.2 scan
   produces 20+ "cipher-tls1_2_xNNNN" records, all LOW severity. We collapse
   those into ONE finding per (protocol, severity) tuple with the cipher
   list in description. Otherwise the dashboard sees 600 TLS findings
   across the fleet.

2. Severity mapping (testssl → canonical):
     CRITICAL → CRITICAL    HIGH    → HIGH
     MEDIUM   → MODERATE    LOW     → LOW
     INFO     → INFO        WARN    → drop (scan-tool warnings, not findings)
     OK       → drop (positive results, not findings)
"""

from __future__ import annotations

import json
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


# Severity map
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MODERATE",
    "LOW":      "LOW",
    "INFO":     "INFO",
}
# Severities we drop entirely (not actionable findings):
SKIP_SEVERITIES = {"WARN", "OK", "DEBUG"}

# Pure scorecard / meta IDs — these are NOT findings. They're testssl
# tool-meta output (overall_grade is the letter grade DERIVED from other
# tests; service is the protocol identification; engine_problem is a
# tool diagnostic). Filtering them out is safe because the underlying
# real findings are emitted by other tests.
#
# Be conservative: only filter things that are unambiguously meta. When
# in doubt, keep the finding at testssl's assigned severity and let the
# operator decide. Howie's principle: 'trust testssl's severity; only
# remove what's truly meta-summary.'
SCORECARD_IDS = {
    "overall_grade",         # letter grade derived from other tests
    "overall_grade_warning",
    "service",               # protocol identification, not a finding
    "engine_problem",        # testssl tool diagnostic
    "scanProblem",           # testssl tool diagnostic
}


# Cipher records have IDs like "cipher-tls1_2_xc028" or "cipher_x6b" — group
# them by stripping the trailing _xNNNN hex token.
CIPHER_ID_RE = re.compile(r"^(cipher[-_][a-z0-9_]+?)(?:_x[0-9a-fA-F]+)$")


def _normalize_id(testssl_id: str) -> tuple[str, bool]:
    """
    Returns (grouped_id, is_cipher_grouping).

    For cipher entries, strip the cipher-hex suffix so all ciphers in one
    protocol collapse to a single grouped ID. Otherwise return the ID as-is.
    """
    if not testssl_id:
        return ("unknown", False)
    m = CIPHER_ID_RE.match(testssl_id)
    if m:
        return (m.group(1), True)
    return (testssl_id, False)


def _parse_host_ip(ip_field: str) -> tuple[Optional[str], Optional[str]]:
    """
    testssl 'ip' field is typically "fqdn/ip" (e.g., "www.commandcommcentral.com/24.38.70.5").
    Returns (subdomain, ip) tuple.
    """
    if not ip_field or ip_field == "/":
        return (None, None)
    parts = ip_field.split("/", 1)
    if len(parts) == 2:
        sub = parts[0] if parts[0] else None
        ip = parts[1] if parts[1] else None
        return (sub, ip)
    return (parts[0] if parts[0] else None, None)


def _category_for_id(testssl_id: str) -> str:
    """Map testssl test ID → canonical category."""
    tid = testssl_id.lower()
    if tid.startswith("cipher") or "cipherlist" in tid:
        return "tls"
    if "cert" in tid or "ocsp" in tid:
        return "tls"
    if "fs_" in tid or "forward" in tid:
        return "tls"
    if "heartbleed" in tid or "lucky13" in tid or "robot" in tid or "ccs" in tid or "breach" in tid:
        return "tls"
    if "dns_caa" in tid:
        return "dns"
    if "protocol" in tid or tid.startswith("tls_") or tid.startswith("ssl_"):
        return "tls"
    return "tls"  # everything testssl reports is TLS-related


def parse_testssl_file(
    json_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    """
    Parse one testssl.json file. Cipher entries are grouped into a single
    FindingEvent per (grouped_id, severity, host:port) tuple, with affected
    cipher details accumulated into the description.
    """
    if not json_path.is_file():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []

    rel_evidence = relative_to_scan_root(json_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    # Group records by (grouped_id, severity, ip_field, port)
    groups: dict[tuple, list[dict]] = {}
    for rec in data:
        raw_sev = (rec.get("severity") or "").strip().upper()
        if raw_sev in SKIP_SEVERITIES:
            continue
        canonical_sev = SEVERITY_MAP.get(raw_sev)
        if not canonical_sev:
            continue
        raw_id = rec.get("id") or ""
        grouped_id, is_cipher = _normalize_id(raw_id)

        # Skip pure meta/scorecard IDs only (overall_grade, service, etc.).
        # Everything else keeps testssl's reported severity — no auto-downgrade.
        if grouped_id in SCORECARD_IDS:
            continue

        ip_field = rec.get("ip") or ""
        port = rec.get("port") or ""
        key = (grouped_id, canonical_sev, ip_field, str(port))
        groups.setdefault(key, []).append(rec)

    events: list[FindingEvent] = []
    for (grouped_id, severity, ip_field, port_str), records in groups.items():
        sub, ip = _parse_host_ip(ip_field)
        try:
            port = int(port_str) if port_str else None
        except ValueError:
            port = None

        # Build title + description
        first = records[0]
        if len(records) == 1:
            title = f"testssl: {grouped_id}"
            description = first.get("finding") or ""
            if first.get("cwe"):
                description = f"{description}  ({first['cwe']})" if description else first["cwe"]
        else:
            # Grouped (cipher list)
            n = len(records)
            title = f"testssl: {grouped_id}  ({n} entries)"
            # Pull just the cipher mnemonic from each "TLSv1.2  xc028  ECDHE-RSA-..." line
            cipher_strs: list[str] = []
            for r in records[:20]:  # cap to avoid huge descriptions
                fin = r.get("finding") or ""
                # Extract the cipher mnemonic (third whitespace-delimited token typically)
                toks = fin.split()
                cipher = None
                for tok in toks:
                    if re.match(r"^[A-Z][A-Z0-9_-]{6,}$", tok):
                        cipher = tok
                        break
                if cipher and cipher not in cipher_strs:
                    cipher_strs.append(cipher)
            description = (
                f"{n} cipher entries reported by testssl at {severity} severity. "
                f"Mnemonics: {', '.join(cipher_strs[:15])}"
                + (", ..." if len(cipher_strs) > 15 else "")
            )

        # Aggregate CWEs
        cwe_list: list[int] = []
        for r in records:
            cwe_val = r.get("cwe") or ""
            m = re.search(r"CWE-(\d+)", str(cwe_val))
            if m:
                try:
                    n = int(m.group(1))
                    if n not in cwe_list:
                        cwe_list.append(n)
                except ValueError:
                    pass

        # matched_at = sub or ip + port
        host = sub or ip or asset_id
        matched_at = f"https://{host}:{port}" if port else f"https://{host}"

        # Asset = the FQDN tested (sub from testssl ip field), not the
        # target-dir apex. Test/api/etc findings → their own asset cards.
        event_asset_id = canonical_asset_id(sub) if is_fqdn_in_scope(sub, asset_id) else canonical_asset_id(asset_id)

        ev = FindingEvent(
            finding_id=stable_finding_id(event_asset_id, "testssl", grouped_id, f"{host}:{port}"),
            asset_id=event_asset_id,
            scan_id=scan_id,
            source="testssl",
            title=title,
            severity=severity,
            category=_category_for_id(grouped_id),
            observed_at=observed_at,
            matched_at=matched_at,
            description=description[:1500] if description else None,
            cve=[],
            cwe=cwe_list,
            references=[],
            raw_excerpt=json.dumps(first, separators=(",", ":"))[:1500],
            evidence_paths=[rel_evidence],
            subdomain=sub,
            host_ip=ip,
            port=port,
            protocol="https" if port in (443, None) else "tcp",
        )
        events.append(ev)

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    """Driver entry point."""
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
        if tool.get("parser") != "testssl":
            continue
        for rel_file in tool.get("files", []):
            events.extend(
                parse_testssl_file(
                    json_path=scan_run_abs / rel_file,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )
    return events
