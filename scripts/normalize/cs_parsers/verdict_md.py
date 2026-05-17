"""
verdict_md.py — Parse VERDICT.md files (remediation verification verdicts).

VERDICT.md files live inside `remediation-verify-*` scan-run dirs. They
contain a single verdict for one finding and are written by Howie after
manually re-testing whether a previously-detected vulnerability has been
fixed. Format example (commandcommcentral/remediation-verify-2026-04-28/VERDICT.md):

    # Sprocket Finding 12821 — Remediation Verification
    Run: 2026-04-28T16:33Z (after VPN switch)
    Target: https://www.commandcommcentral.com (24.38.70.5)

    ## Verdict: REMEDIATED

    ## Evidence summary
    | Endpoint | Baseline | Bypass (XHR header) | ...

The parser:
1. Extracts the verdict word from `## Verdict: WORD` (or `Verdict: WORD`)
2. Finds finding-ID references in the body:
   - Direct: H-NN / C-NN / M-NN / L-NN / I-NN patterns
   - Sprocket: 'Sprocket Finding NNNNN' / 'Sprocket #NNNNN'
3. Maps Sprocket IDs to internal finding IDs via SPROCKET_TO_INTERNAL
4. Emits one FindingEvent per (matched finding, verdict) pair with
   status_hint set so the rollup correctly updates current_status.

Without this parser, findings remediated via VERDICT.md (and not also
re-listed as resolved in a subsequent SUMMARY.md) stay stuck at their last
SUMMARY.md status — which is what made H-01 show as 'open' even after the
4/28 remediation verification confirmed it fixed.
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
    relative_to_scan_root,
    stable_finding_id,
    subdomain_from_url,
    to_utc_iso,
)


# Target URL line in VERDICT.md — e.g. "Target: https://www.commandcommcentral.com (24.38.70.5)"
TARGET_LINE_RE = re.compile(r"^\s*Target:\s*(https?://\S+)", re.IGNORECASE | re.MULTILINE)


# Sprocket external finding ID → internal short ID mapping.
# Add new entries here when Sprocket files new findings. Keeping this as a
# small hardcoded dict (not a separate JSON) because the set is tiny and
# Sprocket-finding lookups are rare. Can be promoted to a sidecar file
# later if it grows.
SPROCKET_TO_INTERNAL_SHORT = {
    "12821": "H-01",  # ASP.NET partial-view auth bypass on commandcommcentral.com
}


VERDICT_LINE_RE = re.compile(
    r"^#{0,3}\s*\*?\*?Verdict[:\*]?\*?\s*[:\-]?\s*\*?\*?([A-Z][A-Z _/-]+?)\*?\*?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

FINDING_ID_RE = re.compile(r"\b([HCMLI]-\d{1,3}(?:\.\d{1,2})?)\b")
SPROCKET_REF_RE = re.compile(r"Sprocket\s+(?:Finding\s+|#)(\d{4,7})", re.IGNORECASE)


def _extract_verdict(text: str) -> Optional[str]:
    """Find the verdict word in the file body. Returns the raw word or None."""
    m = VERDICT_LINE_RE.search(text)
    if not m:
        return None
    return m.group(1).strip().upper().replace("  ", " ")


def _extract_finding_short_ids(text: str) -> list[str]:
    """Find all finding short-IDs (H-01, M-02, Sprocket 12821→H-01, etc.) in text."""
    shorts: list[str] = []
    seen: set[str] = set()

    # Direct H-01 / M-02 / etc.
    for m in FINDING_ID_RE.finditer(text):
        s = m.group(1).upper()
        if s not in seen:
            seen.add(s)
            shorts.append(s)

    # Sprocket Finding NNNNN — map via hardcoded dict
    for m in SPROCKET_REF_RE.finditer(text):
        sprocket = m.group(1)
        mapped = SPROCKET_TO_INTERNAL_SHORT.get(sprocket)
        if mapped and mapped not in seen:
            seen.add(mapped)
            shorts.append(mapped)

    return shorts


def parse_verdict_md(
    md_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    if not md_path.is_file():
        return []
    try:
        text = md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    verdict_word = _extract_verdict(text)
    if not verdict_word:
        return []

    status_hint = normalize_status_hint(verdict_word)
    if not status_hint:
        return []

    finding_shorts = _extract_finding_short_ids(text)
    if not finding_shorts:
        return []

    rel_evidence = relative_to_scan_root(md_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    # Pull the Target URL — verdict applies to whatever FQDN was tested.
    # Use that as asset_id so the verdict lands on the SAME asset that the
    # original SUMMARY.md finding landed on (both use FQDN-as-asset_id).
    tm = TARGET_LINE_RE.search(text)
    target_url = tm.group(1) if tm else None
    target_sub = subdomain_from_url(target_url) if target_url else None
    event_asset_id = canonical_asset_id(target_sub) if is_fqdn_in_scope(target_sub, asset_id) else canonical_asset_id(asset_id)

    events: list[FindingEvent] = []
    for short in finding_shorts:
        finding_id = f"{event_asset_id}:manual:{short}"

        # We don't know the original title/severity from VERDICT.md alone —
        # those came from the original SUMMARY.md. Use placeholder values;
        # the rollup's merge logic preserves the original finding's title
        # and severity from earlier events and only overwrites status.
        # severity is required, so use INFO as a non-blocking default; the
        # rollup will pick the latest SUMMARY.md's severity for the canonical
        # record (the verdict event's severity isn't displayed alone).
        events.append(FindingEvent(
            finding_id=finding_id,
            asset_id=event_asset_id,
            scan_id=scan_id,
            source="manual_named",
            title=f"{short}: verdict from remediation verification",
            severity="INFO",  # placeholder — rollup keeps original severity
            category="other",
            observed_at=observed_at,
            matched_at=None,
            description=f"Verdict from {md_path.name}: {verdict_word}",
            cve=[],
            cwe=[],
            references=[],
            raw_excerpt=text[:1500],
            evidence_paths=[rel_evidence],
            status_hint=status_hint,
        ))

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
        if tool.get("parser") != "verdict_md":
            continue
        for rel_file in tool.get("files", []):
            md_path = scan_run_abs / rel_file
            events.extend(parse_verdict_md(
                md_path=md_path,
                asset_id=asset_id,
                scan_id=scan_id,
                scan_root=scan_root,
                fallback_observed_at=fallback_ts,
            ))
    return events
