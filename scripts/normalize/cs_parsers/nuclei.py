"""
nuclei.py — Parse Nuclei JSONL output into FindingEvents.

Nuclei (ProjectDiscovery) writes one JSON object per line. The relevant
shape (from real Command scan output, 2026-05-04):

    {
      "template-id": "CVE-2024-2473",
      "template": "http/cves/2024/CVE-2024-2473.yaml",
      "info": {
        "name": "WPS Hide Login <= 1.9.15.2 - Login Page Disclosure",
        "tags": ["cve", "wordpress", "wp-plugin", ...],
        "description": "...",
        "severity": "medium",                  ← THE severity (top-level "severity" often null)
        "classification": {
          "cve-id": ["cve-2024-2473"],
          "cwe-id": ["cwe-200"],
          "cvss-score": 5.3,
          ...
        },
        "reference": ["https://nvd.nist.gov/...", ...]
      },
      "host": "commandmarketinginnovations.com",
      "matched-at": "https://commandmarketinginnovations.com/wp-admin/?action=postpass",
      "type": "http",
      "severity": null,
      "timestamp": "2026-05-04T12:07:54.027016-04:00"
    }

Notes:
- Older nuclei versions may have severity at the top level instead. We check
  both, prefer info.severity since that's what newer output uses.
- info.classification.cwe-id values are strings like "cwe-200" — we parse to
  integers.
- Some templates produce many events per scan (one per matched URL). Each
  distinct (template-id, matched-at) becomes a distinct finding_id, so 5
  matched URLs from the same template = 5 findings, not 1.
- Empty JSONL files are common when nuclei found nothing — handle as
  zero events, not an error.
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
    infer_category_from_tags,
    map_severity_nuclei,
    port_from_url,
    protocol_from_url,
    relative_to_scan_root,
    stable_finding_id,
    subdomain_from_url,
    to_utc_iso,
)


CWE_RE = re.compile(r"cwe-(\d+)", re.IGNORECASE)


# Noise templates — see nuclei_text.NOISE_TEMPLATE_PATTERNS for the full
# rationale. Same denylist applied here so the JSONL parser drops the same
# tech-fingerprinting / bare-presence detections. Matching is against the
# BASE template-id (text before the first colon), so both `tech-detect`
# and `tech-detect:cloudflare` map to the same `tech-detect` entry.
NOISE_TEMPLATE_PATTERNS: set[str] = {
    # Tech fingerprinting
    "tech-detect",
    "wordpress-plugin-detect",
    "wordpress-passive-detection",
    "wordpress-theme-detect",
    "wordpress-detect",
    "waf-detect",
    # Bare-presence detections
    "wordpress-login",
    "wp-license-file",
    "wp-links-opml",
    "form-detection",
    "robots-txt",
    "robots-txt-endpoint",
    "old-copyright",
    "ssl-issuer",
    "ssl-dns-names",
    "tls-version",
    "google-floc-disabled",
    "missing-sri",
}


def _parse_cwe_list(values) -> list[int]:
    if not values:
        return []
    out: list[int] = []
    for v in values:
        m = CWE_RE.match(str(v))
        if m:
            try:
                out.append(int(m.group(1)))
            except ValueError:
                continue
    return out


def _parse_cve_list(values) -> list[str]:
    if not values:
        return []
    out: list[str] = []
    for v in values:
        s = str(v).upper().replace("CVE-", "CVE-").strip()
        if not s.startswith("CVE-"):
            s = "CVE-" + s
        out.append(s)
    return out


def _truncate(text: Optional[str], n: int = 1500) -> Optional[str]:
    if text is None:
        return None
    s = str(text).strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def parse_jsonl_file(
    jsonl_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    """Parse one nuclei JSONL file → list of FindingEvent."""
    events: list[FindingEvent] = []
    if not jsonl_path.is_file():
        return events
    try:
        text = jsonl_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return events

    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip malformed lines silently — nuclei sometimes emits debug noise

        template_id = rec.get("template-id") or rec.get("templateID") or ""
        if not template_id:
            continue

        # Skip noise templates before doing the rest of the parse work.
        # Strip any sub-matcher (`tech-detect:cloudflare` → `tech-detect`)
        # so the denylist hits both the bare and qualified forms.
        base_template = template_id.split(":", 1)[0]
        if base_template in NOISE_TEMPLATE_PATTERNS:
            continue

        info = rec.get("info") or {}
        # Severity preference: info.severity (new) → top-level severity (old) → INFO
        sev_raw = info.get("severity") or rec.get("severity")
        severity = map_severity_nuclei(sev_raw)

        name = info.get("name") or template_id
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        classification = info.get("classification") or {}
        cwe = _parse_cwe_list(classification.get("cwe-id"))
        cve = _parse_cve_list(classification.get("cve-id"))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        matched_at = rec.get("matched-at") or rec.get("matched_at") or rec.get("host") or ""
        host = rec.get("host") or ""

        timestamp = rec.get("timestamp") or fallback_observed_at or ""
        observed_at = to_utc_iso(timestamp) or fallback_observed_at or ""

        category = infer_category_from_tags(tags, template_id)

        sub = subdomain_from_url(matched_at) or subdomain_from_url(host) or None
        proto = protocol_from_url(matched_at)
        prt = port_from_url(matched_at)
        if prt is None and proto == "https": prt = 443
        elif prt is None and proto == "http": prt = 80

        event_asset_id = canonical_asset_id(sub) if is_fqdn_in_scope(sub, asset_id) else canonical_asset_id(asset_id)

        ev = FindingEvent(
            finding_id=stable_finding_id(event_asset_id, "nuclei", template_id, matched_at),
            asset_id=event_asset_id,
            scan_id=scan_id,
            source="nuclei",
            title=name,
            severity=severity,
            category=category,
            observed_at=observed_at,
            matched_at=matched_at,
            description=_truncate(info.get("description")),
            cve=cve,
            cwe=cwe,
            references=list(refs) if isinstance(refs, list) else [],
            raw_excerpt=_truncate(json.dumps(rec, separators=(",", ":")), 2000),
            evidence_paths=[relative_to_scan_root(jsonl_path, scan_root)],
            subdomain=sub,
            host_ip=None,    # nuclei doesn't reliably provide resolved IP
            port=prt,
            protocol=proto,
        )
        events.append(ev)

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    """
    Driver-facing entry point. Called once per scan-run that has a nuclei
    JSONL detection in the manifest.

    target_entry: one item from manifest["targets"]
    scan_entry:   one item from target_entry["scan_runs"]
    """
    target = target_entry["target"]
    asset_id = infer_asset_id(target)

    scan_run_dir = scan_entry["scan_run_dir"]
    # Scan ID convention: <target>__<scan_run_dir> with synthetic fallback
    if scan_run_dir.startswith("(target-root"):
        scan_id = f"{target}__synthetic_root"
    else:
        scan_id = f"{target}__{scan_run_dir}"

    scan_run_abs = Path(scan_entry["absolute_path"])
    fallback_ts = scan_entry.get("inferred_started_at")

    events: list[FindingEvent] = []
    for tool in scan_entry.get("tools_detected", []):
        if tool.get("parser") != "nuclei":
            continue
        for rel_file in tool.get("files", []):
            jsonl_path = scan_run_abs / rel_file
            events.extend(
                parse_jsonl_file(
                    jsonl_path=jsonl_path,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )

    return events
