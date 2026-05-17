"""
summary_md.py — Parse SUMMARY.md and VERDICT.md files into FindingEvents.

These are the manually-authored finding records that live alongside each scan
run. Format example (from auth-scan-2026-04-22/SUMMARY.md):

    # Authenticated Vulnerability Assessment — www.commandcommcentral.com
    **Date:** 2026-04-22
    **Target:** https://www.commandcommcentral.com (PRODUCTION)
    **Overall Risk Rating:** MODERATE-HIGH

    ## Findings

    ### HIGH Severity

    #### H-01: ASP.NET Partial View Authentication Bypass (UNPATCHED)
    - **CWE:** CWE-306 (Missing Authentication), CWE-287 (...), CWE-200 (...)
    - **Endpoints:**
      - `/account/_twofactorauthentication` — bypassed with ...
      - `/account/_passwordexpirepartial` — CONFIRMED 302→200 bypass ...
    - **Detection:** Manual probe + custom nuclei template ...
    - **Status vs baseline:** First identified 2026-04-22 (Scan 6), confirmed UNPATCHED
    - **Recommendation:** Add `[Authorize]` attribute ...

    ### MODERATE Severity
    #### M-01: ...

This is the parser that finally lands H-01 / C-01 / M-01 et al as canonical
findings. The status modifier in the title parens (UNPATCHED / UNCHANGED /
REMEDIATED / NEW / etc) becomes the status_hint that drives the rollup's
current_status decision.

VERDICT.md files have a different shape (focused remediation verification for
one finding). First pass handles SUMMARY.md only; VERDICT integration comes
in a follow-up.
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
    normalize_status_hint,
    port_from_url,
    protocol_from_url,
    relative_to_scan_root,
    stable_finding_id,
    subdomain_from_url,
    to_utc_iso,
)


# Severity section header. Empirically observed variants in the corpus:
#   `### Critical`, `### High`, `### Moderate`, `### Medium`, `### Low`,
#   `### Informational`, `### Info`, `### HIGH Severity`, `### MODERATE Severity`,
#   `### LOW Severity`, `### Critical / High` (combined — captures both, takes highest)
# "Medium" maps to MODERATE.
SEVERITY_SECTION_RE = re.compile(
    r"^###\s+"
    r"(CRITICAL|HIGH|MODERATE[- ]HIGH|MODERATE|MEDIUM|LOW|INFO|INFORMATIONAL)"
    r"(?:\s*/\s*(CRITICAL|HIGH|MODERATE[- ]HIGH|MODERATE|MEDIUM|LOW|INFO|INFORMATIONAL))?"
    r"(?:\s+(?:severity|findings))?"
    r"\s*$",
    re.IGNORECASE,
)

# Finding heading. Matches everything starting with `#### X-NN: title ...`
# We DON'T try to capture status in this regex — it's too easy to swallow
# parens that aren't status (e.g. "Session Fixation" in the title). Status
# extraction is a separate pass on the captured title.
FINDING_HEADING_RE = re.compile(
    r"^####\s+([A-Z]+-\d+(?:\.\d+)?)\s*:\s*(.+?)\s*$"
)

# Trailing status patterns inside finding titles:
#   "— **STILL OPEN**" / "— **UNCHANGED**" / "— **REMEDIATED**"
#   "(UNPATCHED)" / "(NEW)"
# Only match if the inner text is recognized in STATUS_HINT_MAP.
TRAILING_BOLD_STATUS_RE = re.compile(r"\s*[—–-]+\s*\*\*([A-Z][A-Z _/-]+)\*\*\s*$")
TRAILING_PAREN_STATUS_RE = re.compile(r"\s*\(([A-Z][A-Z _/-]+)\)\s*$")

# Generic key/value line: `- **Key:** value` or `**Key:** value`
KV_RE = re.compile(r"^\s*-?\s*\*\*([^:*]+):\*\*\s*(.+?)\s*$")

# CWE extraction: "CWE-306", "cwe-200", "cwe:306"
CWE_INLINE_RE = re.compile(r"CWE[-:]\s*(\d+)", re.IGNORECASE)

# Date header: `**Date:** 2026-04-22`
DATE_RE = re.compile(r"^\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)

# Target header: `**Target:** https://...`
TARGET_RE = re.compile(r"^\*\*Target:\*\*\s*(\S+)", re.IGNORECASE)

# Risk rating header: `**Overall Risk Rating:** MODERATE-HIGH`
RISK_RE = re.compile(r"^\*\*Overall Risk Rating:\*\*\s*(\S+)", re.IGNORECASE)


SEVERITY_ORDER = {"CRITICAL": 6, "HIGH": 5, "MODERATE-HIGH": 4, "MODERATE": 3, "LOW": 2, "INFO": 1}


def _normalize_severity(s: str) -> str:
    """Normalize a single severity word to canonical scale."""
    if not s:
        return "INFO"
    s = s.strip().upper().replace(" ", "-")
    if s in ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW", "INFO"):
        return s
    if s == "MEDIUM":           return "MODERATE"
    if s == "INFORMATIONAL":    return "INFO"
    return "INFO"


def _highest_severity(s1: str, s2: Optional[str]) -> str:
    """For combined section headers (e.g. 'Critical / High'), keep the higher."""
    a = _normalize_severity(s1)
    if not s2:
        return a
    b = _normalize_severity(s2)
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _extract_trailing_status(title: str) -> tuple[str, Optional[str]]:
    """
    Pull a trailing status modifier off a title if one is present AND recognized.

    Returns (cleaned_title, status_word_or_None).

    Only strips the modifier if it's a known status keyword in STATUS_HINT_MAP.
    This avoids accidentally treating "(Session Fixation)" as a status.
    """
    from .common import STATUS_HINT_MAP
    # Try bold-trailing pattern first (newer convention: "— **STILL OPEN**")
    m = TRAILING_BOLD_STATUS_RE.search(title)
    if m:
        word = m.group(1).strip()
        if word.upper() in STATUS_HINT_MAP:
            return (TRAILING_BOLD_STATUS_RE.sub("", title).rstrip(), word)
    # Try paren-trailing pattern (older convention: "(UNPATCHED)")
    m = TRAILING_PAREN_STATUS_RE.search(title)
    if m:
        word = m.group(1).strip()
        if word.upper() in STATUS_HINT_MAP:
            return (TRAILING_PAREN_STATUS_RE.sub("", title).rstrip(), word)
    return (title, None)


def _category_for_finding(title: str, body_blob: str) -> str:
    """Heuristic category mapping from title + body content."""
    blob = (title + " " + body_blob).lower()
    pairs = [
        ("auth bypass", "auth"), ("partial view auth", "auth"),
        ("session fixation", "session"), ("session not rotated", "session"),
        ("csp nonce", "config"), ("csp", "config"),
        ("cryptojs", "supply_chain"), ("outdated", "supply_chain"),
        ("aes key", "secret"), ("hardcoded key", "secret"),
        ("tls 1", "tls"), ("ssl ", "tls"), ("cipher", "tls"),
        ("samesite", "session"),
        ("dnssec", "dns"),
        ("spf", "email"), ("dmarc", "email"), ("dkim", "email"),
        ("csrf", "csrf"),
        ("idor", "idor"),
        ("xss", "xss"),
        ("sqli", "sqli"), ("sql injection", "sqli"),
        ("missing security header", "headers"),
        ("missing header", "headers"),
        ("information disclosure", "info_disclosure"),
        ("info leak", "info_disclosure"),
        ("trace method", "config"),
        ("password max length", "config"),
        ("open registration", "config"),
        ("path traversal", "lfi"),
        ("waf gap", "config"),
        ("waf bypass", "config"),
    ]
    for keyword, cat in pairs:
        if keyword in blob:
            return cat
    return "other"


def _extract_endpoints(body_text: str) -> list[str]:
    """Pull bulleted endpoint paths out of an Endpoints section."""
    endpoints: list[str] = []
    in_endpoints = False
    for raw in body_text.splitlines():
        line = raw.strip()
        if re.match(r"\*\*Endpoints:\*\*", line, re.IGNORECASE):
            in_endpoints = True
            continue
        if in_endpoints:
            if line.startswith("- ") or line.startswith("* "):
                # Try to pull a backtick path or URL out
                m = re.search(r"`([^`]+)`", line)
                if m:
                    endpoints.append(m.group(1))
                else:
                    # Fallback: take text up to first em-dash or colon
                    rest = line.lstrip("-* ").strip()
                    m2 = re.match(r"^(\S+)", rest)
                    if m2:
                        endpoints.append(m2.group(1))
            elif line.startswith("**") or line == "":
                # New key OR blank ends the list
                in_endpoints = False
    return endpoints


def parse_summary_md(
    md_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    """Parse one SUMMARY.md → FindingEvents (one per named finding)."""
    events: list[FindingEvent] = []
    if not md_path.is_file():
        return events
    try:
        text = md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return events

    rel_evidence = relative_to_scan_root(md_path, scan_root)

    # ─── pull header metadata ─────────────────────────────────────────────
    observed_at = fallback_observed_at or ""
    target_url: Optional[str] = None
    for line in text.splitlines()[:30]:
        m = DATE_RE.match(line.strip())
        if m:
            observed_at = to_utc_iso(m.group(1)) or observed_at
        m = TARGET_RE.match(line.strip())
        if m:
            target_url = m.group(1)
    target_sub = subdomain_from_url(target_url) if target_url else None

    # ─── walk findings ────────────────────────────────────────────────────
    lines = text.splitlines()
    current_severity = "INFO"
    current_finding: Optional[dict] = None
    body_buf: list[str] = []

    def flush_current():
        if current_finding is None:
            return
        body = "\n".join(body_buf).strip()
        short = current_finding["short"]
        title = current_finding["title"]
        status_hint_raw = current_finding["status_modifier"]

        # CWE list
        cwe_list: list[int] = []
        seen_cwe = set()
        for m in CWE_INLINE_RE.finditer(body):
            try:
                n = int(m.group(1))
                if n not in seen_cwe:
                    seen_cwe.add(n)
                    cwe_list.append(n)
            except ValueError:
                continue

        # CVE list
        cve_list: list[str] = []
        for m in re.finditer(r"CVE-\d{4}-\d{3,7}", body, re.IGNORECASE):
            cve = m.group(0).upper()
            if cve not in cve_list:
                cve_list.append(cve)

        # Endpoints (first becomes matched_at for the finding identity)
        endpoints = _extract_endpoints(body)
        matched_at = endpoints[0] if endpoints else (target_url or "")
        # If matched_at is a relative path, prepend the target_url host
        if matched_at and matched_at.startswith("/") and target_url:
            from urllib.parse import urljoin
            matched_at_full = urljoin(target_url, matched_at)
        else:
            matched_at_full = matched_at

        # Description: build from Detail/Recommendation if present, else body
        detail_match = re.search(r"\*\*Detail:\*\*\s*(.+?)(?:\n\*\*|\n\n|$)", body, re.DOTALL | re.IGNORECASE)
        description = detail_match.group(1).strip() if detail_match else None
        if description and len(description) > 1500:
            description = description[:1497] + "..."

        category = _category_for_finding(title, body)
        status_hint = normalize_status_hint(status_hint_raw)

        sub = subdomain_from_url(matched_at_full) or target_sub
        proto = protocol_from_url(matched_at_full)
        prt = port_from_url(matched_at_full)
        if prt is None and proto == "https": prt = 443
        elif prt is None and proto == "http": prt = 80

        # Asset = the actual scanned FQDN (Target URL or matched endpoint),
        # not the target dir's apex mapping. Keeps test/api/etc findings
        # under the correct asset card.
        event_asset_id = canonical_asset_id(sub) if is_fqdn_in_scope(sub, asset_id) else canonical_asset_id(asset_id)

        ev = FindingEvent(
            finding_id=f"{event_asset_id}:manual:{short}",
            asset_id=event_asset_id,
            scan_id=scan_id,
            source="manual_named",
            title=f"{short}: {title}",
            severity=current_severity,
            category=category,
            observed_at=observed_at,
            matched_at=matched_at_full or None,
            description=description,
            cve=cve_list,
            cwe=cwe_list,
            references=[],
            raw_excerpt=("#### " + short + ": " + title + "\n" + body)[:2000],
            evidence_paths=[rel_evidence],
            subdomain=sub,
            port=prt,
            protocol=proto,
            status_hint=status_hint,
        )
        events.append(ev)

    for raw in lines:
        line = raw.rstrip()
        # Section header → update current severity
        m = SEVERITY_SECTION_RE.match(line.strip())
        if m:
            flush_current()
            current_finding = None
            body_buf = []
            current_severity = _highest_severity(m.group(1), m.group(2))
            continue
        # Finding heading
        m = FINDING_HEADING_RE.match(line)
        if m:
            flush_current()
            short = m.group(1).strip()
            raw_title = m.group(2).strip()
            cleaned_title, status_mod = _extract_trailing_status(raw_title)
            current_finding = {
                "short": short,
                "title": cleaned_title,
                "status_modifier": status_mod,
            }
            body_buf = []
            continue
        if current_finding is not None:
            # Stop the current finding at the next top-level heading or empty section break
            if line.startswith("## ") or line.startswith("# "):
                flush_current()
                current_finding = None
                body_buf = []
                continue
            body_buf.append(raw)

    flush_current()
    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    """Driver-facing entry point. Run once per scan-run that has a summary_md detection."""
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
        if tool.get("parser") != "summary_md":
            continue
        for rel_file in tool.get("files", []):
            md_path = scan_run_abs / rel_file
            # Skip VERDICT.md for now — different shape, separate parser later.
            if md_path.name == "VERDICT.md":
                continue
            events.extend(
                parse_summary_md(
                    md_path=md_path,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )

    return events
