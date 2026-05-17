"""
posture_rollup.py — Synthesize raw findings into per-asset posture verdicts.

Reads findings.jsonl + assets.jsonl, computes a current_risk + current_risk_reason
for each asset, and writes the updated assets back. The verdict is what the
CISO-tier dashboard view actually displays — not the raw severity counts.

Verdict rules (conservative, deliberately simple):
    Any open CRITICAL          → CRITICAL
    Any open HIGH              → HIGH
    Any MODERATE-HIGH OR ≥3 MODERATE → MODERATE-HIGH
    1-2 open MODERATE          → MODERATE
    ≥3 open LOW                → LOW
    1-2 open LOW               → LOW
    INFO only                  → INFO
    No findings at all (ASM-tracked) → UNKNOWN

"Open" means current_status is one of: detected, confirmed, open, regressed.
RESOLVED statuses (remediated, validated_remediated, false_positive, wont_fix,
accepted_risk) do NOT count toward the verdict.

The reason string is a one-line summary suitable for a dashboard card.
Format: "<count> open <severity>[; top: <top finding title>]"
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW", "INFO"]
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}

OPEN_STATUSES = {"detected", "confirmed", "open", "regressed"}
RESOLVED_STATUSES = {"remediated", "validated_remediated", "false_positive", "wont_fix", "accepted_risk"}


def _plural(n: int) -> str:
    return "s" if n != 1 else ""


def _top_finding_summary(findings: list[dict], severity_filter: Optional[str] = None) -> str:
    """
    Pick the most descriptive finding to mention in the reason string.
    Prefers named findings (manual_named source — H-01, M-01, etc.) over
    auto-generated ones (testssl ciphers, nuclei templates) since the former
    have human-curated titles.
    """
    candidates = [f for f in findings if not severity_filter or f.get("severity") == severity_filter]
    if not candidates:
        return ""
    # Prefer manual_named findings
    named = [f for f in candidates if f.get("source") == "manual_named"]
    pool = named or candidates
    pick = pool[0]
    title = pick.get("title", "")
    # Truncate aggressively for a one-line reason
    if len(title) > 70:
        title = title[:67] + "..."
    return title


def compute_asset_verdict(findings_for_asset: list[dict]) -> tuple[str, str, list[str]]:
    """
    Returns (current_risk, current_risk_reason, top_finding_ids).

    top_finding_ids: up to 3 finding_ids that drove the verdict — these are
    what the dashboard card surfaces as "the things you should look at first."
    """
    if not findings_for_asset:
        return ("UNKNOWN", "Asset tracked in ASM but no vulnerability scans run against it yet.", [])

    open_findings = [f for f in findings_for_asset if f.get("current_status") in OPEN_STATUSES]
    if not open_findings:
        return ("LOW", f"All {len(findings_for_asset)} previously-detected findings are resolved.", [])

    # Sort open findings: highest severity first, then most recently observed first
    open_findings_sorted = sorted(
        open_findings,
        key=lambda f: (
            SEVERITY_INDEX.get(f.get("severity", "INFO"), 99),
            -(_iso_sortable(f.get("last_observed_at") or f.get("first_detected_at"))),
        )
    )

    counts = Counter(f.get("severity", "INFO") for f in open_findings)

    # Decide verdict
    if counts.get("CRITICAL", 0) > 0:
        verdict = "CRITICAL"
        n = counts["CRITICAL"]
        top_title = _top_finding_summary(open_findings_sorted, "CRITICAL")
        reason = f"{n} open CRITICAL finding{_plural(n)}" + (f"; top: {top_title}" if top_title else "")
    elif counts.get("HIGH", 0) > 0:
        verdict = "HIGH"
        n = counts["HIGH"]
        top_title = _top_finding_summary(open_findings_sorted, "HIGH")
        reason = f"{n} open HIGH finding{_plural(n)}" + (f"; top: {top_title}" if top_title else "")
    elif counts.get("MODERATE-HIGH", 0) > 0 or counts.get("MODERATE", 0) >= 3:
        verdict = "MODERATE-HIGH"
        total_m = counts.get("MODERATE", 0) + counts.get("MODERATE-HIGH", 0)
        top_title = _top_finding_summary(open_findings_sorted)
        reason = f"{total_m} open MODERATE-or-higher findings" + (f"; top: {top_title}" if top_title else "")
    elif counts.get("MODERATE", 0) > 0:
        verdict = "MODERATE"
        n = counts["MODERATE"]
        top_title = _top_finding_summary(open_findings_sorted, "MODERATE")
        reason = f"{n} open MODERATE finding{_plural(n)}" + (f"; top: {top_title}" if top_title else "")
    elif counts.get("LOW", 0) >= 3:
        verdict = "LOW"
        n = counts["LOW"]
        reason = f"{n} open LOW findings — baseline hardening recommended"
    elif counts.get("LOW", 0) > 0:
        verdict = "LOW"
        n = counts["LOW"]
        reason = f"{n} minor finding{_plural(n)}"
    else:
        verdict = "INFO"
        n = counts.get("INFO", 0)
        reason = f"Only informational findings ({n}); baseline posture acceptable"

    top_ids = [f.get("finding_id") for f in open_findings_sorted[:3] if f.get("finding_id")]
    return (verdict, reason, top_ids)


def _iso_sortable(iso: Optional[str]) -> float:
    """Convert ISO timestamp to a sortable float (seconds since epoch). Missing → 0."""
    if not iso:
        return 0.0
    try:
        from datetime import datetime
        # Handle both "Z" and "+00:00" forms
        s = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return 0.0


def run_rollup(output_dir: Path) -> dict:
    """
    Read findings.jsonl and assets.jsonl from output_dir, compute per-asset
    verdicts, and rewrite assets.jsonl with current_risk + current_risk_reason
    + top_finding_ids populated.

    Returns stats dict.
    """
    findings_path = output_dir / "findings.jsonl"
    assets_path = output_dir / "assets.jsonl"

    if not assets_path.exists():
        return {"updated": 0, "skipped": 0, "verdicts": {}}

    # Group findings by asset_id
    by_asset: dict[str, list[dict]] = defaultdict(list)
    if findings_path.exists():
        for line in findings_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                f = json.loads(line)
                by_asset[f.get("asset_id", "")].append(f)
            except json.JSONDecodeError:
                continue

    # Compute verdict per asset, rewrite assets.jsonl
    updated_assets: list[dict] = []
    verdict_counts: Counter = Counter()
    for line in assets_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        aid = a.get("asset_id", "")
        verdict, reason, top_ids = compute_asset_verdict(by_asset.get(aid, []))
        a["current_risk"] = verdict
        a["current_risk_reason"] = reason
        a["top_finding_ids"] = top_ids
        # Also expose open-count summary so the dashboard doesn't have to re-compute
        open_findings = [f for f in by_asset.get(aid, []) if f.get("current_status") in OPEN_STATUSES]
        a["open_findings_by_severity"] = dict(Counter(f.get("severity", "INFO") for f in open_findings))
        a["open_findings_total"] = len(open_findings)
        updated_assets.append(a)
        verdict_counts[verdict] += 1

    # Write back
    assets_path.write_text(
        "\n".join(json.dumps(a, separators=(",", ":")) for a in updated_assets) + "\n"
    )

    return {
        "updated": len(updated_assets),
        "verdicts": dict(verdict_counts),
    }
