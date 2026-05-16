"""
nuclei_text.py — Parse Nuclei human-readable text output.

This is the format nuclei writes by default (or when invoked with the default
`-o output.txt`). Format per line:

    [template-id[:sub-matcher]] [type] [severity] url [extracted_values] [extra_kv]

Examples:
    [CVE-2024-2473] [http] [medium] https://www.commanddigital.com/wp-admin/?action=postpass
    [waf-detect:cloudflare] [http] [info] https://www.commanddigital.com
    [wp-user-enum:usernames] [http] [low] https://www.commanddigital.com/wp-json/wp/v2/users/ ["commanddigit"]
    [wordpress-elementor:outdated_version] [http] [info] https://x.com/wp-content/.../readme.txt ["2.8.3"] [last_version="3.30.3"]

Header lines like `=== nuclei: commandcommcentral.com ===` are skipped.

Severity comes directly from the third bracket. CWE/CVE classification isn't
available in text mode — we infer category from the template-id and sub-matcher.
CVE-id is extracted if the template-id starts with CVE-.

Most Command scan output is in this format (only 2 JSONL files in the whole
corpus vs nuclei_results.txt across every target). This parser is the heavy
hitter for findings volume.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .common import (
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


# Line format: [tpl] [type] [sev] url [extra] [extra]...
# We capture: template-id, sub-matcher (optional), type, severity, url, tail
LINE_RE = re.compile(
    r"^\[(?P<tpl>[^\]:]+)(?::(?P<sub>[^\]]+))?\]\s+"
    r"\[(?P<type>[^\]]+)\]\s+"
    r"\[(?P<sev>[^\]]+)\]\s+"
    r"(?P<url>\S+)"
    r"(?P<tail>.*)$"
)

# Tail bracket parts like ["value1","value2"] or [key="value"]
TAIL_BRACKET_RE = re.compile(r'\[([^\]]+)\]')


def _parse_tail(tail: str) -> dict:
    """Extract extracted-values and key=value pairs from the trailing brackets."""
    out: dict = {"extracted": [], "extras": {}}
    for chunk in TAIL_BRACKET_RE.findall(tail):
        chunk = chunk.strip()
        if not chunk:
            continue
        # key="value" form (no quoted-value before =)
        if "=" in chunk and not chunk.startswith('"'):
            k, _, v = chunk.partition("=")
            out["extras"][k.strip()] = v.strip().strip('"')
        else:
            # quoted-value list ["a","b"] or single ["a"]
            # Strip outer quotes from each element
            values = re.findall(r'"([^"]*)"', chunk)
            if values:
                out["extracted"].extend(values)
            elif chunk:
                out["extracted"].append(chunk)
    return out


CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,7}$", re.IGNORECASE)


def parse_text_file(
    text_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    """Parse one nuclei text-output file → list of FindingEvent."""
    events: list[FindingEvent] = []
    if not text_path.is_file():
        return events
    try:
        text = text_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return events

    rel_evidence = relative_to_scan_root(text_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("==="):
            continue
        m = LINE_RE.match(line)
        if not m:
            # Lines that don't match are typically progress noise or rate-limit
            # warnings; skip them silently.
            continue

        tpl = m.group("tpl").strip()
        sub = (m.group("sub") or "").strip()
        sev_raw = m.group("sev").strip()
        url = m.group("url").strip()
        tail = m.group("tail") or ""

        # Compose the full template identifier including sub-matcher
        full_tpl = f"{tpl}:{sub}" if sub else tpl
        tail_parsed = _parse_tail(tail)

        severity = map_severity_nuclei(sev_raw)

        # CVE inferred from template name
        cve: list[str] = []
        if CVE_RE.match(tpl):
            cve.append(tpl.upper())

        # Tag-set for category inference: include template, sub, and the path
        # tokens (wordpress-X-version → ["wordpress", "x", "version"])
        tag_tokens = set()
        for token in re.split(r"[-_:/]", full_tpl.lower()):
            if token:
                tag_tokens.add(token)
        category = infer_category_from_tags(list(tag_tokens), full_tpl)

        # Build a useful title — template name + sub-matcher if present, plus
        # extracted values when they add context
        title = full_tpl
        if tail_parsed["extracted"]:
            preview = ", ".join(tail_parsed["extracted"][:3])
            if preview and preview != title:
                title = f"{full_tpl}  [{preview}]"

        # Description from extras (e.g., "last_version=3.30.3") if any
        desc_parts: list[str] = []
        if tail_parsed["extras"]:
            for k, v in tail_parsed["extras"].items():
                desc_parts.append(f"{k}={v}")
        description = "; ".join(desc_parts) if desc_parts else None

        sub = subdomain_from_url(url)
        proto = protocol_from_url(url)
        prt = port_from_url(url)
        if prt is None and proto == "https": prt = 443
        elif prt is None and proto == "http": prt = 80
        elif proto == "ssl" or "tls" in full_tpl.lower():
            # tls-version reports as ssl://host:443 sometimes; default 443
            proto = "ssl"
            prt = prt or 443

        ev = FindingEvent(
            finding_id=stable_finding_id(asset_id, "nuclei", full_tpl, url),
            asset_id=asset_id,
            scan_id=scan_id,
            source="nuclei",
            title=title,
            severity=severity,
            category=category,
            observed_at=observed_at,
            matched_at=url,
            description=description,
            cve=cve,
            cwe=[],
            references=[],
            raw_excerpt=line[:1500],
            evidence_paths=[rel_evidence],
            subdomain=sub,
            port=prt,
            protocol=proto,
        )
        events.append(ev)

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    """Driver-facing entry point. Run once per scan-run that has a nuclei text detection."""
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
        if tool.get("parser") != "nuclei_text":
            continue
        for rel_file in tool.get("files", []):
            text_path = scan_run_abs / rel_file
            events.extend(
                parse_text_file(
                    text_path=text_path,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )

    return events
