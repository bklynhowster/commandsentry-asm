#!/usr/bin/env python3
"""
walker.py — Crawl per-target scan directories and emit a coverage manifest.

Identifies every dated scan-run subdirectory under each target, detects which
tools produced output (by known filenames), and writes a manifest describing
exactly what's on disk. The manifest is the input to the per-tool parsers.

Usage:
    python3 walker.py \
        --scan-root "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning" \
        --commandsentry-data "$(pwd)/web/data" \
        --output  "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized"

The walker is read-only — it never modifies the source data. It emits:
    <output>/manifest.json          — full coverage report (every scan-run, every tool detected)
    <output>/walker.log             — execution log (skipped dirs, parse errors)

Design notes:
- A "target dir" is any direct child of <scan-root> that isn't underscore-prefixed
  (underscore-prefix folders are utilities: _archive, _cross-site, _logs, etc.)
- A "scan-run" is a subdirectory of a target whose name matches one of the known
  scan-run patterns. We deliberately keep this list explicit and easy to extend
  rather than trying to guess from "looks like a scan run."
- Each tool has a small fingerprint object: which filenames mean "tool X ran"
  and what its output_format is. Parsers downstream use this to know what to read.
- COMMANDsentry asset JSONs (in --commandsentry-data) are a separate source type;
  the walker also enumerates those so a single manifest covers both worlds.

Not in scope for the walker:
- Reading the actual tool output. That's each parser's job.
- Identifying scan_type from the scan-run dirname. The manifest just records the
  raw dirname; the scan parser will classify it.
- Deduplication. The walker just enumerates what's there.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── scan-run dirname patterns ────────────────────────────────────────────────
# Each entry is a regex that matches one of the conventions Howie has used.
# Order matters only for documentation; matching is OR.
SCAN_RUN_PATTERNS = [
    # Comprehensive scans: comprehensive-scan-YYYYMMDD-HHMM
    re.compile(r"^comprehensive-scan-\d{8}-\d{4}$"),
    re.compile(r"^comprehensive-scan-prod-\d{8}-\d{4}$"),
    # Intensive scans (commandmarketinginnovations etc.)
    re.compile(r"^intensive-scan-\d{4}-\d{2}-\d{2}$"),
    # Authenticated: auth-scan-YYYY-MM-DD or auth-scan-YYYYMMDD-HHMM
    re.compile(r"^auth-scan-\d{4}-\d{2}-\d{2}$"),
    re.compile(r"^auth-scan-\d{8}-\d{4}$"),
    re.compile(r"^auth-scan-gapfill-\d{8}-\d{4}$"),
    re.compile(r"^prod-auth-scan-\d{8}-\d{4}$"),
    # Auth bypass / surgical
    re.compile(r"^auth-bypass-\d{8}-\d{4}$"),
    re.compile(r"^remediation-verify-\d{4}-\d{2}-\d{2}$"),
    # Test-environment unauth scan (2026-04-29 convention)
    re.compile(r"^test-unauth-scan-\d{4}-\d{2}-\d{2}$"),
    # Full comprehensive scans (5/12 TEST convention)
    re.compile(r"^full-scan-\d{8}-\d{6}$"),
    re.compile(r"^full-scan-\d{8}-\d{4}$"),
    # Deep-validate family (4-digit and 6-digit time suffixes, plus -lite variant)
    re.compile(r"^deep-validate-\d{8}-\d{4}$"),
    re.compile(r"^deep-validate-\d{8}-\d{6}$"),
    re.compile(r"^deep-validate-lite-\d{8}-\d{4}$"),
    re.compile(r"^deep-validate-lite-\d{8}-\d{6}$"),
    # Stringent family — prod-stringent + variants, both time formats
    re.compile(r"^stringent-\d{8}-\d{4}$"),
    re.compile(r"^stringent-\d{8}-\d{6}$"),
    re.compile(r"^prod-stringent-\d{8}-\d{4}$"),
    re.compile(r"^prod-stringent-\d{8}-\d{6}$"),
    re.compile(r"^prod-stringent-auth-\d{8}-\d{4}$"),
    re.compile(r"^prod-stringent-auth-\d{8}-\d{6}$"),
    re.compile(r"^test-stringent-\d{8}-\d{4}$"),
    re.compile(r"^test-stringent-\d{8}-\d{6}$"),
    re.compile(r"^test-stringent-auth-\d{8}-\d{4}$"),
    re.compile(r"^test-stringent-auth-\d{8}-\d{6}$"),
    re.compile(r"^stringent-auth-\d{8}-\d{4}$"),
    re.compile(r"^stringent-auth-\d{8}-\d{6}$"),
    # Surgical verification scripts (2026-05-20 verification pattern)
    re.compile(r"^verify-mediums-\d{8}-\d{4}$"),
    re.compile(r"^verify-mediums-\d{8}-\d{6}$"),
    re.compile(r"^m02-m03-verify-\d{8}-\d{4}$"),
    re.compile(r"^m02-m03-verify-\d{8}-\d{6}$"),
    # Probes
    re.compile(r"^probes-only-\d{8}-\d{6}$"),
    re.compile(r"^probes-only-\d{8}-\d{4}$"),
    # API-focused
    re.compile(r"^api-comprehensive-scan-run-\d{14}$"),
    re.compile(r"^api-hardcore-scan-run-\d{14}$"),
    re.compile(r"^api-hardcore-scan-v2-run-\d{14}$"),
    re.compile(r"^api-probes-only-run-\d{14}$"),
    re.compile(r"^api-dotnet-probe-run-\d{14}$"),
    re.compile(r"^api-probes-only-\d{8}-\d{6}$"),
    re.compile(r"^api-probes-only-\d{8}-\d{4}$"),
    re.compile(r"^api-deep-\d{8}-\d{6}$"),
    re.compile(r"^api-deep-\d{8}-\d{4}$"),
    re.compile(r"^dotnet-probe-\d{8}-\d{6}$"),
    # SQLi-specific probes
    re.compile(r"^sqli-probe-\d{8}-\d{4}$"),
    # ASM-related (cross-site)
    re.compile(r"^asm-discovery-\d{8}-\d{4}$"),
    re.compile(r"^asm-phase2-results$"),
    # DAST per-target
    re.compile(r"^dast-[a-z0-9._-]+-\d{8}-\d{4}$"),
    # Generic security-scan- format
    re.compile(r"^security-scan-[^/]+-\d{8}-\d{4}$"),
    # WP-specific / target-rooted older convention
    re.compile(r"^www$"),                        # commanddigital/www/ — older convention, single canonical scan dir
    re.compile(r"^www-deep$"),                   # unimacgraphics, etc.
    re.compile(r"^www-deep-v3$"),                # commandmarketinginnovations
    # Test subdomain variants
    re.compile(r"^test3$"),                      # cablenet-test3-testapi/test3
    re.compile(r"^testapi$"),
]


# ─── known tool fingerprints ──────────────────────────────────────────────────
# Each tool has:
#   files: filename patterns whose presence signals "this tool ran in this scan-run"
#   output_format: hint to the parser (jsonl, json, text, xml)
#   parser: short name of the parser module that handles it
TOOL_FINGERPRINTS = [
    # Structured-JSON tools (easiest wins)
    {"tool": "nuclei",         "files": ["nuclei-output.jsonl", "nuclei.jsonl", "nuclei_results.jsonl"], "output_format": "jsonl", "parser": "nuclei"},
    {"tool": "nuclei_text",    "files": ["nuclei_results.txt", "nuclei.txt", "nuclei_quick.txt"],         "output_format": "text",  "parser": "nuclei_text"},
    {"tool": "zap",            "files": ["zap_alerts.json", "alerts.json"],                              "output_format": "json",  "parser": "zap"},
    {"tool": "testssl",        "files": ["testssl.json"],                                                "output_format": "json",  "parser": "testssl"},
    {"tool": "sslyze",         "files": ["sslyze.json"],                                                 "output_format": "json",  "parser": "sslyze"},
    {"tool": "semgrep",        "files": ["semgrep_custom.json", "semgrep.json"],                         "output_format": "json",  "parser": "semgrep"},
    {"tool": "gitleaks",       "files": ["gitleaks.json"],                                               "output_format": "json",  "parser": "gitleaks"},
    {"tool": "trivy",          "files": ["trivy_js.json", "trivy.json"],                                 "output_format": "json",  "parser": "trivy"},
    {"tool": "trufflehog",     "files": ["trufflehog.json", "trufflehog_results.json"],                  "output_format": "json",  "parser": "trufflehog"},
    {"tool": "osv_scanner",    "files": ["osv-scanner.json", "osv.json"],                                "output_format": "json",  "parser": "osv"},
    {"tool": "ffuf",           "files": ["ffuf_api_curated.json", "ffuf_authenticated.json", "ffuf-unauth.json", "ffuf.json"], "output_format": "json", "parser": "ffuf"},
    {"tool": "subzy",          "files": ["subzy_takeover.json"],                                         "output_format": "json",  "parser": "subzy"},
    {"tool": "theharvester",   "files": ["theharvester.json"],                                           "output_format": "json",  "parser": "theharvester"},
    {"tool": "dnstwist",       "files": ["dnstwist.json", "typosquat.json"],                             "output_format": "json",  "parser": "dnstwist"},
    # Auth-scan structured outputs
    {"tool": "auth_state",     "files": ["auth_state.json"],                                             "output_format": "json",  "parser": "auth_state"},
    {"tool": "spa_drive",      "files": ["spa_drive_summary.json"],                                      "output_format": "json",  "parser": "spa_drive"},
    {"tool": "session_tests",  "files": ["session_tests/login_summary.json"],                            "output_format": "json",  "parser": "session_tests"},
    # Text-output tools
    {"tool": "nmap",           "files": ["nmap_full.txt", "nmap_quick.txt", "nmap.txt"],                 "output_format": "text",  "parser": "nmap"},
    {"tool": "nmap_xml",       "files": ["nmap.xml", "nmap_full.xml"],                                   "output_format": "xml",   "parser": "nmap_xml"},
    {"tool": "nikto",          "files": ["nikto_results.txt", "nikto.txt", "nikto.txt.txt", "nikto_results.txt.txt", "nikto-unauth.txt", "nikto-unauth.txt.txt", "nikto_auth.txt", "nikto_auth.txt.txt"], "output_format": "text", "parser": "nikto"},
    # wpscan-with-cves.txt is the API-token-enriched variant. List it FIRST so
    # it's the preferred match when both files exist (intensive-scan emits both,
    # but the bare wpscan.txt has 0 CVEs).
    {"tool": "wpscan",         "files": ["wpscan-with-cves.txt", "wpscan_with_cves.txt", "wpscan.txt", "wpscan_v2.txt"], "output_format": "text",  "parser": "wpscan"},
    # wpvulnerability.net per-plugin status JSONs (phase02 of intensive scans).
    # One file per plugin; carries already-cross-referenced VULNERABLE/PATCHED
    # status against the installed version. Highest-value parser for
    # intensive scans.
    {"tool": "wpvuln",         "files": ["wpvuln-*.json"],                                               "output_format": "json",  "parser": "wpvuln_json"},
    # Backup/config-file sweep table (phase04 of intensive scans). Emits an
    # info-disclosure finding for any 2xx response on a sensitive path.
    {"tool": "probe_results",  "files": ["probe-results.txt"],                                           "output_format": "text",  "parser": "probe_results"},
    {"tool": "feroxbuster",    "files": ["feroxbuster.txt", "feroxbuster-unauth.txt"],                   "output_format": "text",  "parser": "feroxbuster"},
    {"tool": "whatweb",        "files": ["whatweb.txt"],                                                 "output_format": "text",  "parser": "whatweb"},
    {"tool": "headers",        "files": ["headers.txt"],                                                 "output_format": "text",  "parser": "headers"},
    {"tool": "waf_fingerprint","files": ["waf.txt", "waf_fingerprint.txt"],                              "output_format": "text",  "parser": "waf"},
    {"tool": "dns",            "files": ["dns.txt", "dns_deep.txt"],                                     "output_format": "text",  "parser": "dns"},
    {"tool": "email_security", "files": ["email_security.txt", "email_deep.txt"],                        "output_format": "text",  "parser": "email"},
    {"tool": "ssl_quick",      "files": ["ssl_quick.txt", "ssl_tls.txt"],                                "output_format": "text",  "parser": "ssl_text"},
    {"tool": "homepage",       "files": ["homepage_analysis.txt"],                                       "output_format": "text",  "parser": "homepage"},
    {"tool": "wp_probes",      "files": ["wp_probes.txt"],                                               "output_format": "text",  "parser": "wp_probes"},
    {"tool": "katana_urls",    "files": ["katana_urls.txt"],                                             "output_format": "text",  "parser": "katana"},
    # Markdown summaries — manual finding source
    {"tool": "summary_md",     "files": ["SUMMARY.md"],                                                 "output_format": "markdown","parser": "summary_md"},
    {"tool": "verdict_md",     "files": ["VERDICT.md"],                                                 "output_format": "markdown","parser": "verdict_md"},
    # Curated assessment HTML reports — Howie's branded final reports with
    # human-judged findings (often the ONLY place findings like W-02 or A-03
    # exist, since they're added during scan curation, not from raw tool output).
    # Walker detects by glob pattern handled in detect_tools_in_scan_run.
    {"tool": "curated_html",   "files": ["CommandDigital_*_Assessment_*.html", "CommandDigital_*_Consolidated_*.html"], "output_format": "html", "parser": "curated_html"},
]


# ─── dataclasses ──────────────────────────────────────────────────────────────
@dataclass
class ToolDetection:
    tool: str
    files: list[str]                # actual filenames found (relative to scan-run dir)
    output_format: str
    parser: str

@dataclass
class ScanRun:
    target: str                     # target dir name
    scan_run_dir: str               # scan-run dir name (relative to target)
    absolute_path: str              # full path on disk
    inferred_started_at: Optional[str]   # ISO timestamp parsed from dirname if possible
    tools_detected: list[ToolDetection] = field(default_factory=list)
    artifact_count: int = 0         # all files in the scan-run dir, recursive
    has_summary_md: bool = False
    has_html_report: bool = False
    notes: list[str] = field(default_factory=list)

@dataclass
class TargetInventory:
    target: str
    absolute_path: str
    scan_runs: list[ScanRun] = field(default_factory=list)
    loose_artifacts: list[str] = field(default_factory=list)  # files directly in target dir, not under a scan-run

@dataclass
class CSAssetEntry:
    """A COMMANDsentry asset JSON entry. Source: web/data/*.json"""
    asset_id: str
    json_path: str
    subdomain_count: int
    history_entries: int
    schema_version: Optional[str]


# ─── helpers ──────────────────────────────────────────────────────────────────
def parse_scan_run_timestamp(dirname: str) -> Optional[str]:
    """Try to extract an ISO timestamp from a scan-run dirname. Returns None if can't."""
    # YYYYMMDD-HHMM
    m = re.search(r"(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})", dirname)
    if m:
        y, mo, d, h, mi = m.groups()
        try:
            return datetime(int(y), int(mo), int(d), int(h), int(mi), tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    # YYYY-MM-DD
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", dirname)
    if m:
        y, mo, d = m.groups()
        try:
            return datetime(int(y), int(mo), int(d), tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    # YYYYMMDDHHMMSS
    m = re.search(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", dirname)
    if m:
        y, mo, d, h, mi, s = m.groups()
        try:
            return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return None


def matches_scan_run_pattern(name: str) -> bool:
    return any(p.match(name) for p in SCAN_RUN_PATTERNS)


def detect_tools_in_scan_run(scan_run_path: Path) -> list[ToolDetection]:
    """Walk scan-run dir; for each tool fingerprint, check if any of its files exist."""
    detections: list[ToolDetection] = []
    for fp in TOOL_FINGERPRINTS:
        found = []
        for fname in fp["files"]:
            for candidate in scan_run_path.rglob(fname):
                if candidate.is_file():
                    rel = str(candidate.relative_to(scan_run_path))
                    found.append(rel)
        if found:
            detections.append(ToolDetection(
                tool=fp["tool"],
                files=found,
                output_format=fp["output_format"],
                parser=fp["parser"],
            ))
    return detections


def count_artifacts(scan_run_path: Path) -> int:
    return sum(1 for _ in scan_run_path.rglob("*") if _.is_file())


# ─── main walking ─────────────────────────────────────────────────────────────
def walk_targets(scan_root: Path) -> list[TargetInventory]:
    inventories: list[TargetInventory] = []
    for entry in sorted(scan_root.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("_") or entry.name.startswith("."):
            continue
        # Skip a few known non-target dirs that aren't underscore-prefixed
        if entry.name in {"nuclei-templates", "semgrep-rules"}:
            continue
        inv = TargetInventory(target=entry.name, absolute_path=str(entry))
        for sub in sorted(entry.iterdir()):
            if sub.is_dir() and matches_scan_run_pattern(sub.name):
                # Try dirname-encoded date first; fall back to oldest file mtime.
                ts = parse_scan_run_timestamp(sub.name) or oldest_mtime_in_dir(sub)
                sr = ScanRun(
                    target=entry.name,
                    scan_run_dir=sub.name,
                    absolute_path=str(sub),
                    inferred_started_at=ts,
                    tools_detected=detect_tools_in_scan_run(sub),
                    artifact_count=count_artifacts(sub),
                    has_summary_md=(sub / "SUMMARY.md").exists(),
                    has_html_report=any(sub.glob("*.html")),
                )
                inv.scan_runs.append(sr)
            elif sub.is_file():
                inv.loose_artifacts.append(sub.name)
        # ALWAYS check the target dir itself for tool outputs at root level.
        # Many old scans (commanddigital, commandmarketinginnovations, etc.) dump
        # nuclei_results.txt etc. directly under the target dir without a dated
        # scan-run subdir. We emit a synthetic `_target_root` scan-run alongside
        # any dated subdirs — this catches target-root tools whether or not
        # other scan-runs exist underneath.
        #
        # Important: detect_tools_in_scan_run uses rglob, so it would also re-find
        # files inside scan-run subdirs and double-count. We need to restrict
        # target-root detection to NON-RECURSIVE matching here.
        exclude_dirs = set(sub.scan_run_dir for sub in inv.scan_runs)
        root_tools = detect_tools_at_target_root(entry, exclude_dirs=exclude_dirs)
        if root_tools:
            inferred = oldest_mtime_at_target_root(entry, exclude_dirs=exclude_dirs)
            inv.scan_runs.append(ScanRun(
                target=entry.name,
                scan_run_dir="_target_root",
                absolute_path=str(entry),
                inferred_started_at=inferred,
                tools_detected=root_tools,
                artifact_count=sum(1 for p in entry.iterdir() if p.is_file()),
                has_summary_md=(entry / "SUMMARY.md").exists(),
                has_html_report=any(entry.glob("*.html")),
                notes=["target-root scan output (no dated scan-run wrapper)"]
                      + ([] if inferred else ["no datable artifacts to infer started_at"]),
            ))
        inventories.append(inv)
    return inventories


def oldest_mtime_in_dir(scan_run_path: Path) -> Optional[str]:
    """
    Oldest mtime among files anywhere under scan_run_path, as ISO UTC string.
    Fallback for scan-runs whose dirname doesn't encode a date (www, www-deep,
    test3, etc.). Returns None if no files exist or the dir can't be read.
    """
    from datetime import datetime, timezone

    oldest_ts: Optional[float] = None
    try:
        for p in scan_run_path.rglob("*"):
            if p.is_file():
                try:
                    ts = p.stat().st_mtime
                    if oldest_ts is None or ts < oldest_ts:
                        oldest_ts = ts
                except OSError:
                    continue
    except OSError:
        return None
    if oldest_ts is None:
        return None
    return datetime.fromtimestamp(oldest_ts, tz=timezone.utc).isoformat()


def oldest_mtime_at_target_root(target_path: Path, exclude_dirs: set[str]) -> Optional[str]:
    """
    Return the oldest mtime ISO timestamp among files at target_path + inside
    non-scan-run child dirs. Used as a fallback for synthetic target-root scans
    whose scan_run_dir doesn't encode a date.

    Mirrors the candidate-gathering logic of detect_tools_at_target_root so the
    timestamp matches the scope of tools that get attributed to this scan.

    Returns None if no datable files exist (empty target dirs, etc.).
    """
    from datetime import datetime, timezone

    oldest_ts: Optional[float] = None
    try:
        for p in target_path.iterdir():
            if p.is_file():
                ts = p.stat().st_mtime
                if oldest_ts is None or ts < oldest_ts:
                    oldest_ts = ts
            elif p.is_dir() and p.name in exclude_dirs:
                continue
            elif p.is_dir() and not p.name.startswith("_") and not p.name.startswith("."):
                for sub in p.rglob("*"):
                    if sub.is_file():
                        try:
                            ts = sub.stat().st_mtime
                            if oldest_ts is None or ts < oldest_ts:
                                oldest_ts = ts
                        except OSError:
                            continue
    except OSError:
        return None

    if oldest_ts is None:
        return None
    return datetime.fromtimestamp(oldest_ts, tz=timezone.utc).isoformat()


def detect_tools_at_target_root(target_path: Path, exclude_dirs: set[str]) -> list[ToolDetection]:
    """
    Like detect_tools_in_scan_run but only looks at files directly in target_path
    and inside child dirs that aren't already classified as scan-runs.

    Avoids double-counting tools that live in dated scan-run subdirs.
    """
    detections: list[ToolDetection] = []
    # Build a set of candidate file paths: target-root files + files inside
    # non-scan-run subdirs (like commanddigital/www/, commandcompanies/www-deep/).
    candidates: list[Path] = []
    for p in target_path.iterdir():
        if p.is_file():
            candidates.append(p)
        elif p.is_dir() and p.name in exclude_dirs:
            # Already counted as scan-run; skip
            continue
        elif p.is_dir() and not p.name.startswith("_") and not p.name.startswith("."):
            # Non-scan-run subdir — include its files for old-convention scans
            for sub in p.rglob("*"):
                if sub.is_file():
                    candidates.append(sub)

    import fnmatch
    # Track which candidate paths matched, with the relative path back to target_path
    for fp in TOOL_FINGERPRINTS:
        found = []
        for fname in fp["files"]:
            # Plain filename — exact match OR glob (e.g. CommandDigital_*_Assessment_*.html)
            if "/" not in fname:
                has_glob = any(ch in fname for ch in "*?[")
                for c in candidates:
                    if (has_glob and fnmatch.fnmatch(c.name, fname)) or (not has_glob and c.name == fname):
                        try:
                            found.append(str(c.relative_to(target_path)))
                        except ValueError:
                            found.append(str(c))
            else:
                # Path-with-slash fingerprint (rare; matches like "session_tests/login_summary.json")
                for c in candidates:
                    try:
                        rel = str(c.relative_to(target_path))
                    except ValueError:
                        continue
                    if rel.endswith(fname):
                        found.append(rel)
        if found:
            detections.append(ToolDetection(
                tool=fp["tool"],
                files=found,
                output_format=fp["output_format"],
                parser=fp["parser"],
            ))
    return detections


def walk_commandsentry_assets(cs_data_dir: Path) -> list[CSAssetEntry]:
    entries: list[CSAssetEntry] = []
    if not cs_data_dir.exists():
        return entries
    for json_file in sorted(cs_data_dir.glob("*.json")):
        if json_file.name == "_manifest.json":
            continue
        try:
            data = json.loads(json_file.read_text())
        except Exception:
            continue
        asset_block = data.get("asset") or {}
        subs = data.get("subdomains") or []
        hist = data.get("history") or []
        entries.append(CSAssetEntry(
            asset_id=asset_block.get("apex") or asset_block.get("name") or json_file.stem,
            json_path=str(json_file),
            subdomain_count=len(subs),
            history_entries=len(hist),
            schema_version=data.get("schema_version"),
        ))
    return entries


# ─── output ───────────────────────────────────────────────────────────────────
def emit_manifest(inventories: list[TargetInventory], cs_assets: list[CSAssetEntry], output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_root_targets_scanned": len(inventories),
        "commandsentry_assets_scanned": len(cs_assets),
        "totals": {
            "scan_runs": sum(len(i.scan_runs) for i in inventories),
            "tools_detected": sum(len(sr.tools_detected) for i in inventories for sr in i.scan_runs),
            "artifacts": sum(sr.artifact_count for i in inventories for sr in i.scan_runs),
        },
        "targets": [
            {
                "target": i.target,
                "scan_runs_count": len(i.scan_runs),
                "loose_artifacts_count": len(i.loose_artifacts),
                "scan_runs": [
                    {
                        "scan_run_dir": sr.scan_run_dir,
                        "inferred_started_at": sr.inferred_started_at,
                        "absolute_path": sr.absolute_path,
                        "artifact_count": sr.artifact_count,
                        "has_summary_md": sr.has_summary_md,
                        "has_html_report": sr.has_html_report,
                        "tools_detected": [asdict(t) for t in sr.tools_detected],
                        "notes": sr.notes,
                    }
                    for sr in i.scan_runs
                ],
            }
            for i in inventories
        ],
        "commandsentry_assets": [asdict(a) for a in cs_assets],
    }
    out_path = output_dir / "manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2))
    return manifest


def emit_summary(manifest: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("WALKER COVERAGE MANIFEST")
    lines.append(f"Generated: {manifest['generated_at']}")
    lines.append("=" * 72)
    lines.append("")
    t = manifest["totals"]
    lines.append(f"Targets scanned:        {manifest['scan_root_targets_scanned']}")
    lines.append(f"CommandSentry assets:   {manifest['commandsentry_assets_scanned']}")
    lines.append(f"Total scan-runs:        {t['scan_runs']}")
    lines.append(f"Total tool detections:  {t['tools_detected']}")
    lines.append(f"Total artifact files:   {t['artifacts']:,}")
    lines.append("")
    lines.append("Per-target breakdown:")
    lines.append("-" * 72)
    for tgt in manifest["targets"]:
        srs = tgt["scan_runs"]
        if not srs:
            lines.append(f"  {tgt['target']:40s}  (no scan-runs detected — {tgt['loose_artifacts_count']} loose files)")
            continue
        lines.append(f"  {tgt['target']:40s}  scan-runs={len(srs)}")
        for sr in srs:
            tools = ", ".join(t["tool"] for t in sr["tools_detected"]) or "(no tools detected)"
            ts = sr["inferred_started_at"] or "(no timestamp)"
            lines.append(f"      └─ {sr['scan_run_dir']:50s}  [{ts}]")
            lines.append(f"         tools: {tools}")
            lines.append(f"         files: {sr['artifact_count']}   summary_md={sr['has_summary_md']}   html={sr['has_html_report']}")
    lines.append("")
    lines.append("CommandSentry assets:")
    lines.append("-" * 72)
    for a in manifest["commandsentry_assets"]:
        lines.append(f"  {a['asset_id']:40s}  subs={a['subdomain_count']:3d}  history={a['history_entries']:3d}  schema={a['schema_version']}")
    text = "\n".join(lines)
    (output_dir / "walker-summary.txt").write_text(text)
    return text


# ─── entrypoint ───────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan-root", required=True, help="Root of the vuln-scan target directories.")
    ap.add_argument("--commandsentry-data", default=None, help="Path to COMMANDsentry web/data dir (optional).")
    ap.add_argument("--output", required=True, help="Output directory for the manifest.")
    args = ap.parse_args()

    scan_root = Path(args.scan_root).expanduser().resolve()
    output_dir = Path(args.output).expanduser().resolve()
    if not scan_root.is_dir():
        print(f"error: scan-root not found: {scan_root}", file=sys.stderr)
        return 2

    inventories = walk_targets(scan_root)

    cs_assets: list[CSAssetEntry] = []
    if args.commandsentry_data:
        cs_dir = Path(args.commandsentry_data).expanduser().resolve()
        cs_assets = walk_commandsentry_assets(cs_dir)

    manifest = emit_manifest(inventories, cs_assets, output_dir)
    summary = emit_summary(manifest, output_dir)

    print(summary)
    print("")
    print(f"Manifest written: {output_dir / 'manifest.json'}")
    print(f"Summary written:  {output_dir / 'walker-summary.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
