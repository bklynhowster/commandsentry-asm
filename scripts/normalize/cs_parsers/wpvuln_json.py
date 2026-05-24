"""
wpvuln_json.py — Parse wpvulnerability.net per-plugin JSON output into
FindingEvents.

These files (one per inspected plugin, named `wpvuln-<slug>.json`) live
under `phase02-versions/` inside intensive scan dirs. The format is the
WPVulnerability.net /v3/wordpress/plugin response, but with two extras
our scanner adds for convenience:

    {
      "type": "plugin",
      "slug": "revslider",
      "installed_version": "6.7.54",
      "vuln_count": 21,
      "counts": {
          "VULNERABLE": 2, "UNFIXED": 0,
          "PATCHED": 19,   "UNKNOWN": 0
      },
      "vulnerabilities": [
        {
          "name": "Slider Revolution [revslider] < 7.0.11",
          "fixed_in": "7.0.11",
          "max_operator": "lt",
          "cves": ["CVE-2026-6692"],
          "status": "VULNERABLE"
        },
        ...
      ]
    }

The big win over WPScan text parsing: every record carries a `status`
that's already been cross-referenced against `installed_version`. We
emit one FindingEvent per entry with status == "VULNERABLE" or "UNFIXED"
and skip "PATCHED" / "UNKNOWN" entirely. That cuts noise dramatically:
WPScan's raw output for the 2026-05-23 commandmarketinginnovations scan
listed 17 CVEs, but only 5 actually apply (3 on Mega Main Menu, 2 on
Slider Revolution).

Severity is conservative: VULNERABLE → MODERATE unless the CVE list
hints at higher (XSS keywords → MODERATE-HIGH, RCE/SQLi → HIGH). The
CVE enricher in the post-ingest chain will overwrite this with the real
CVSS-derived severity once it queries NVD.

Category is always "wordpress_plugin_vulnerability". Source is
"wpvulnerability.net".
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from .common import (
    FindingEvent,
    infer_asset_id,
    now_iso,
    relative_to_scan_root,
    stable_finding_id,
    to_utc_iso,
)


# Statuses we treat as "this currently applies to the installed version"
ACTIONABLE_STATUSES = {"VULNERABLE", "UNFIXED"}

# Words in vuln names that hint at higher-than-default severity
RCE_HINTS = re.compile(r"\b(RCE|remote code execution|deserialization|file upload|LFI|SQL injection|SQLi)\b", re.IGNORECASE)
XSS_HINTS = re.compile(r"\b(XSS|cross[- ]site scripting|stored XSS|reflected XSS)\b", re.IGNORECASE)
AUTH_BYPASS = re.compile(r"\b(authentication bypass|auth bypass|unauthenticated|missing authorization|privilege escalation)\b", re.IGNORECASE)


def _hint_severity(name: str, default: str = "MODERATE") -> str:
    """Best-effort severity hint from the vulnerability name."""
    if RCE_HINTS.search(name):
        return "HIGH"
    if AUTH_BYPASS.search(name):
        return "MODERATE-HIGH"
    if XSS_HINTS.search(name):
        return "MODERATE-HIGH"
    return default


def _vuln_title(slug: str, installed_v: str, name: str, cves: list[str]) -> str:
    """Title shaped for the portal — slug, version, short reason."""
    # Strip the redundant "Plugin Name [slug]" prefix if present
    short = re.sub(r"^[^\[]*\[[^\]]+\]\s*", "", name).strip()
    cve_str = f" ({cves[0]})" if cves else ""
    return f"{slug} {installed_v} — {short}{cve_str}"


def parse_wpvuln_file(
    json_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str],
) -> list[FindingEvent]:
    """Parse one wpvuln-<slug>.json file into FindingEvents."""
    try:
        with open(json_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, dict):
        return []
    if data.get("type") != "plugin":
        return []

    slug = data.get("slug") or json_path.stem.replace("wpvuln-", "")
    installed = data.get("installed_version") or ""
    vulns = data.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        return []

    rel_evidence = relative_to_scan_root(json_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or now_iso()

    events: list[FindingEvent] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        status = v.get("status", "").upper()
        if status not in ACTIONABLE_STATUSES:
            continue
        name = v.get("name") or ""
        cves = [c for c in (v.get("cves") or []) if isinstance(c, str)]
        fixed_in = v.get("fixed_in") or ""

        title = _vuln_title(slug, installed, name, cves)
        severity = _hint_severity(name)

        # Build a stable, deterministic finding id. Template id encodes the
        # slug + first CVE (or "no-cve") + fixed_in version, so two scans
        # finding the same vuln on the same plugin emit the same id.
        cve_part = cves[0] if cves else "no-cve"
        template_id = f"wpvuln:{slug}:{cve_part}:fix={fixed_in}"
        matched_at = f"{asset_id}/{slug}@{installed}"

        description_lines = [
            f"Plugin **{slug}** version **{installed}** is currently vulnerable.",
            f"Vulnerability: {name}",
        ]
        if fixed_in:
            description_lines.append(f"Fixed in: {fixed_in} (upgrade target).")
        else:
            description_lines.append(
                "No upstream fix available (plugin abandoned / unfixed). "
                "Replace or remove."
            )
        if cves:
            description_lines.append(
                "CVEs: " + ", ".join(cves)
            )
        description_lines.append(
            f"Source: wpvulnerability.net cross-reference against installed v{installed} "
            f"(status: {status})."
        )
        description = "\n\n".join(description_lines)

        events.append(
            FindingEvent(
                finding_id=stable_finding_id(asset_id, "wpvulnerability", template_id, matched_at),
                asset_id=asset_id,
                scan_id=scan_id,
                # source/category must match the DB enums (finding_source_t /
                # finding_category_t). wpvulnerability.net is functionally
                # equivalent to a WPScan+API-token run (both cross-reference
                # plugin versions against a CVE DB) — using `wpscan` keeps
                # provenance honest within the current enum vocabulary.
                # `sca` (Software Composition Analysis) is the correct
                # category — that's exactly what this is.
                source="wpscan",
                title=title,
                severity=severity,
                category="sca",
                observed_at=observed_at,
                matched_at=matched_at,
                description=description,
                cve=cves,
                cwe=[],
                references=[
                    f"https://www.wpvulnerability.net/plugin/{slug}/",
                ] + [
                    f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves
                ],
                raw_excerpt=json.dumps({
                    "slug": slug,
                    "installed_version": installed,
                    "status": status,
                    "name": name,
                    "fixed_in": fixed_in,
                    "cves": cves,
                }, indent=2),
                evidence_paths=[rel_evidence],
            )
        )

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
        if tool.get("parser") != "wpvuln_json":
            continue
        for rel_file in tool.get("files", []):
            events.extend(
                parse_wpvuln_file(
                    json_path=scan_run_abs / rel_file,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )
    return events
