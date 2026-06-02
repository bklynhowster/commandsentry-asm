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
    canonical_asset_id,
    is_fqdn_in_scope,
    FindingEvent,
    infer_asset_id,
    infer_category_from_tags,
    map_severity_nuclei,
    port_from_url,
    protocol_from_url,
    relative_to_scan_root,
    resolve_finding_asset_id,
    stable_finding_id,
    strip_ansi,
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

# Noise templates — pure tech-fingerprinting / bare-presence detections that
# nuclei emits at INFO severity with no CVE attached. They flood the asset
# detail page with "Elementor is here, Cloudflare is here, FontAwesome is
# here" rows that the Technology Profile card already covers.
#
# Investigation 2026-05-25 (Pattern 3 dedup query) — these accounted for
# ~12 of the 17 duplicate findings on the fleet. Each was multiple INFO
# rows for the same component, no security signal in any of them.
#
# Same fix shape as testssl.py's SKIP_SEVERITIES = {INFO} drop on 5/24.
# This is more targeted: we keep nuclei INFO findings that ARE useful
# (http-missing-security-headers:*, missing-cookie-samesite-strict, the
# wordpress-*:outdated_version family that flags stale plugins, etc.)
# and only drop the bare-presence templates that carry no signal.
#
# Matching: we check the BASE template-id (the part before `:`), so
# `tech-detect:cloudflare` and `tech-detect:font-awesome` both get caught
# by the single `tech-detect` entry.
NOISE_TEMPLATE_PATTERNS: set[str] = {
    # Tech fingerprinting — identifies what's running, no security signal
    "tech-detect",
    "wordpress-plugin-detect",
    "wordpress-passive-detection",
    "wordpress-theme-detect",
    "wordpress-detect",
    "waf-detect",
    # Bare-presence detections — just say "this exists"
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
    # Subresource integrity — emits one row per third-party JS/CSS;
    # floods the asset page with marginal-signal findings.
    "missing-sri",
}

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

        # Strip ANSI SGR escapes nuclei sometimes emits in colored output
        # (e.g. `[92mhttp-missing-security-headers[0m`). Burned 2026-06-01
        # when these survived into normalized_key and the dedup view.
        tpl = strip_ansi(m.group("tpl").strip())
        sub = strip_ansi((m.group("sub") or "").strip())

        # Skip pure tech-fingerprinting / bare-presence templates before
        # doing any further parsing — saves time and stops these from ever
        # becoming FindingEvents that the rollup has to manage.
        if tpl in NOISE_TEMPLATE_PATTERNS:
            continue

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

        # Prefer the URL-derived FQDN as asset_id so test/api/etc findings
        # don't bleed into the apex card.
        event_asset_id = canonical_asset_id(sub) if is_fqdn_in_scope(sub, asset_id) else canonical_asset_id(asset_id)

        ev = FindingEvent(
            finding_id=stable_finding_id(event_asset_id, "nuclei", full_tpl, url),
            asset_id=event_asset_id,
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
