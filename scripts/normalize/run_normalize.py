#!/usr/bin/env python3
"""
run_normalize.py — Drive the normalization pipeline.

Reads the walker manifest, dispatches every scan-run / tool detection to the
appropriate parser, accumulates FindingEvents, rolls them up into canonical
Finding records with history arrays, and writes JSONL output.

Output files (under --output):
    findings.jsonl    — one line per unique finding identity (with history merged)
    scans.jsonl       — one line per scan-run
    events.jsonl      — raw per-observation events (audit trail; helpful for debugging)
    normalize-summary.txt — human-readable run summary

Usage:
    python3 scripts/normalize/run_normalize.py \
        --manifest "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized/manifest.json" \
        --scan-root "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning" \
        --output "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized"

Re-runs are idempotent: same inputs → same canonical outputs. Each run
overwrites the previous JSONL output.

Design notes:
- Parsers are registered by their `parser` name in the manifest's tool detections.
- The driver doesn't know how to parse anything; it just dispatches.
- Rollup logic: group events by finding_id, sort by observed_at, build history
  array, compute current_status, first_detected_at, last_observed_at.
- current_status logic is conservative:
    * detected:        first event for this finding identity
    * confirmed:       observed in 2+ consecutive scans (asset-aware logic comes later)
    * open:            still observed in latest scan, more than 2 scans of history
    * absent_in_latest_scan: was observed before but not in the most recent scan
                       of the same asset — pending dedicated regression detection
  Note: full regression / remediation status will be enriched by the manual
  findings parser (which reads SUMMARY.md verdicts and Obsidian status).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Add scripts/normalize/ to path so we can import parsers as a package.
THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR))

from parsers import nuclei, nuclei_text, summary_md, testssl, sslyze  # noqa: E402
from parsers.common import FindingEvent, now_iso  # noqa: E402


# ─── parser registry ──────────────────────────────────────────────────────────
PARSERS = {
    "nuclei":      nuclei.parse,
    "nuclei_text": nuclei_text.parse,
    "summary_md":  summary_md.parse,
    "testssl":     testssl.parse,
    "sslyze":      sslyze.parse,
    # Future entries get registered here as parsers come online:
    # "zap":         zap.parse,
    # "semgrep":     semgrep.parse,
    # "gitleaks":    gitleaks.parse,
    # "trivy":       trivy.parse,
    # "trufflehog":  trufflehog.parse,
    # "testssl":     testssl.parse,
    # "sslyze":      sslyze.parse,
    # ...
}


def event_to_dict(ev: FindingEvent) -> dict:
    return asdict(ev)


# ─── rollup ───────────────────────────────────────────────────────────────────
def rollup_findings(events: list[FindingEvent]) -> list[dict]:
    """Group events by finding_id, build canonical Finding records with history."""
    by_id: dict[str, list[FindingEvent]] = defaultdict(list)
    for ev in events:
        by_id[ev.finding_id].append(ev)

    findings: list[dict] = []
    for fid, evs in by_id.items():
        # Stable sort by observed_at; events with no timestamp sort first
        evs_sorted = sorted(evs, key=lambda e: e.observed_at or "")
        first = evs_sorted[0]
        last = evs_sorted[-1]

        history = []
        for i, ev in enumerate(evs_sorted):
            # Prefer explicit status_hint from manual sources; else default to
            # "detected" (first) / "confirmed" (later) heuristic.
            if ev.status_hint:
                status = ev.status_hint
            else:
                status = "detected" if i == 0 else "confirmed"
            history.append({
                "scan_id":          ev.scan_id,
                "observed_at":      ev.observed_at,
                "status":           status,
                "severity_at_scan": ev.severity,
                "matched_at":       ev.matched_at,
                "raw_excerpt":      ev.raw_excerpt,
                "notes":            None,
            })

        # Pull merged CWE/CVE/refs across events (in case the same finding appears
        # in scans where different metadata was emitted)
        all_cwe = sorted({c for ev in evs_sorted for c in ev.cwe})
        all_cve = sorted({c for ev in evs_sorted for c in ev.cve})
        all_refs = []
        seen_refs = set()
        for ev in evs_sorted:
            for r in ev.references:
                if r not in seen_refs:
                    seen_refs.add(r)
                    all_refs.append(r)

        # Current severity = latest scan's severity. Title prefers the most
        # recent observation in case names shifted.
        current_severity = last.severity
        title = last.title or first.title

        # current_status: latest event's status_hint wins; else count heuristic.
        if last.status_hint:
            current_status = last.status_hint
        elif len(evs_sorted) == 1:
            current_status = "detected"
        else:
            current_status = "confirmed"

        # remediated_at: scan time of the most recent remediated/validated event
        remediated_at = None
        for h in reversed(history):
            if h["status"] in ("remediated", "validated_remediated"):
                remediated_at = h["observed_at"]
                break

        # New schema fields — use latest observation's values for current state
        finding = {
            "finding_id":            fid,
            "asset_id":              first.asset_id,
            "title":                 title,
            "severity":              current_severity,
            "category":              first.category,
            "description":           last.description or first.description,
            "cwe":                   all_cwe,
            "cve":                   all_cve,
            "references":            all_refs,
            "current_status":        current_status,
            "first_detected_at":     first.observed_at,
            "first_detected_scan":   first.scan_id,
            "last_observed_at":      last.observed_at,
            "remediated_at":         remediated_at,
            "owner":                 None,
            "deadline":              None,
            "source":                first.source,
            "subdomain":             last.subdomain or first.subdomain,
            "host_ip":               last.host_ip or first.host_ip,
            "port":                  last.port or first.port,
            "protocol":              last.protocol or first.protocol,
            "history":               history,
            "evidence_ids":          [],   # populated by evidence-artifact parser
            "tags":                  [],
        }
        findings.append(finding)

    findings.sort(key=lambda f: (f["asset_id"], f["finding_id"]))
    return findings


# ─── scan record extraction ───────────────────────────────────────────────────
def extract_scans(manifest: dict) -> list[dict]:
    """Build one canonical Scan record per scan-run in the manifest."""
    scans: list[dict] = []
    for tgt in manifest.get("targets", []):
        target = tgt["target"]
        for sr in tgt.get("scan_runs", []):
            scan_run_dir = sr["scan_run_dir"]
            if scan_run_dir.startswith("(target-root"):
                scan_id = f"{target}__synthetic_root"
            else:
                scan_id = f"{target}__{scan_run_dir}"
            scans.append({
                "scan_id":      scan_id,
                "asset_id":     None,  # filled in by driver below using parsers.common
                "scan_type":    None,  # classified below
                "started_at":   sr.get("inferred_started_at"),
                "completed_at": None,
                "command_line": None,
                "exit_code":    None,
                "output_dir":   sr.get("absolute_path"),
                "tools_run":    [t["tool"] for t in sr.get("tools_detected", [])],
                "source":       "mac_local_scan",
                "notes":        "; ".join(sr.get("notes", [])) or None,
            })
    return scans


def classify_scan_type(scan_run_dir: str, tools_run: list[str]) -> str:
    """Map a scan-run dirname + tool set to a canonical scan_type."""
    d = scan_run_dir
    if d.startswith("auth-bypass-"):       return "auth_bypass_probe"
    if d.startswith("auth-scan-gapfill-"): return "authenticated_gapfill"
    if d.startswith("prod-auth-scan-"):    return "authenticated_scan_prod"
    if d.startswith("auth-scan-"):         return "authenticated_scan"
    if d.startswith("comprehensive-scan-prod-"): return "vuln_full_assessment"
    if d.startswith("comprehensive-scan-"): return "vuln_full_assessment"
    if d.startswith("remediation-verify-"): return "remediation_verification"
    if d.startswith("deep-validate-"):     return "surgical_validation"
    if d.startswith("stringent-"):         return "vuln_full_aggressive"
    if d.startswith("probes-only-"):       return "surgical_validation"
    if d.startswith("api-comprehensive-"): return "api_external"
    if d.startswith("api-hardcore-"):      return "api_hardcore"
    if d.startswith("api-probes-only-"):   return "api_external"
    if d.startswith("api-dotnet-"):        return "api_dotnet_probe"
    if d.startswith("sqli-probe-"):        return "surgical_validation"
    if d.startswith("security-scan-"):     return "vuln_full_assessment"
    if d in ("www", "www-deep"):           return "vuln_full_assessment"
    if d.startswith("(target-root"):       return "vuln_full_assessment"
    return "vuln_quick_recon"


# ─── main ─────────────────────────────────────────────────────────────────────
def main() -> int:
    from parsers.common import infer_asset_id  # local import to avoid early sys.path race

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--scan-root", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    scan_root = Path(args.scan_root).expanduser().resolve()
    output_dir = Path(args.output).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text())

    # Collect events across every scan-run
    all_events: list[FindingEvent] = []
    parser_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"runs": 0, "events": 0})

    for tgt_entry in manifest.get("targets", []):
        for sr_entry in tgt_entry.get("scan_runs", []):
            for tool in sr_entry.get("tools_detected", []):
                parser_name = tool.get("parser")
                if parser_name not in PARSERS:
                    continue
                parser_fn = PARSERS[parser_name]
                evs = parser_fn(tgt_entry, sr_entry, scan_root)
                parser_stats[parser_name]["runs"] += 1
                parser_stats[parser_name]["events"] += len(evs)
                all_events.extend(evs)

    # Rollup
    findings = rollup_findings(all_events)

    # Scans + asset assignment
    scans = extract_scans(manifest)
    for s in scans:
        target = s["scan_id"].split("__", 1)[0]
        s["asset_id"] = infer_asset_id(target)
        s["scan_type"] = classify_scan_type(s["scan_id"].split("__", 1)[1] if "__" in s["scan_id"] else "", s["tools_run"])

    # Write JSONL outputs
    (output_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(event_to_dict(e), separators=(",", ":")) for e in all_events) + ("\n" if all_events else "")
    )
    (output_dir / "findings.jsonl").write_text(
        "\n".join(json.dumps(f, separators=(",", ":")) for f in findings) + ("\n" if findings else "")
    )
    (output_dir / "scans.jsonl").write_text(
        "\n".join(json.dumps(s, separators=(",", ":")) for s in scans) + ("\n" if scans else "")
    )

    # Summary
    lines = []
    lines.append("=" * 72)
    lines.append("NORMALIZE RUN SUMMARY")
    lines.append(f"Generated: {now_iso()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Manifest:       {manifest_path}")
    lines.append(f"Output:         {output_dir}")
    lines.append(f"Total events:   {len(all_events):>6}")
    lines.append(f"Total findings: {len(findings):>6}")
    lines.append(f"Total scans:    {len(scans):>6}")
    lines.append("")
    lines.append("Per-parser:")
    for name, stats in sorted(parser_stats.items()):
        lines.append(f"  {name:14s}  runs={stats['runs']:>4}  events={stats['events']:>6}")
    lines.append("")

    # Severity rollup
    sev_count = defaultdict(int)
    for f in findings:
        sev_count[f["severity"]] += 1
    lines.append("Findings by severity:")
    for sev in ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW", "INFO"):
        lines.append(f"  {sev:14s}  {sev_count.get(sev, 0):>6}")
    lines.append("")

    # Per-asset rollup
    per_asset = defaultdict(lambda: defaultdict(int))
    for f in findings:
        per_asset[f["asset_id"]][f["severity"]] += 1
    lines.append("Findings per asset (CRITICAL / HIGH / MODERATE / LOW / INFO):")
    for asset in sorted(per_asset.keys()):
        counts = per_asset[asset]
        c = counts.get("CRITICAL", 0)
        h = counts.get("HIGH", 0)
        m = counts.get("MODERATE", 0)
        l = counts.get("LOW", 0)
        i = counts.get("INFO", 0)
        total = c + h + m + l + i
        lines.append(f"  {asset:45s}  C={c:>3} H={h:>3} M={m:>3} L={l:>3} I={i:>3}   total={total}")

    text = "\n".join(lines)
    (output_dir / "normalize-summary.txt").write_text(text)
    print(text)
    print("")
    print(f"Output written to: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
