#!/usr/bin/env python3
"""
run_heavy.py — Phase 4a heavy-tier scanner (v1)

v1 SCOPE (locked per RUN_HEAVY_V1_BUILD_SPEC.md + HEAVY_TIER_READINESS_ASSESSMENT.md):
  - testssl.sh   — TLS depth (handshake-level; WAF-immune)
  - naabu        — port discovery (PENDING in this commit — P4)
  - fingerprintx — service ID on open ports (PENDING in this commit — P4)

  NOT v1: nmap (v1.1, image rebuild), ZAP / Playwright DAST (v2).

WHY THIS EXISTS:
  The note-127 auto-closer (asm_autoclose_stale_findings) can't reconcile
  the ~85-finding stranded testssl backlog (incl. the only 3 open MODERATES)
  until a producer tool re-scans those assets — and testssl runs heavy-only.
  v1 unblocks that backlog clearing.

THE load-bearing identity decision (RATIFIED by Howie 2026-06-29):
  Heavy MUST NOT mint its own testssl identity. Reusing the offline parser
  (`cs_parsers/testssl.py::parse_testssl_file`) is what makes a re-scan of
  a still-present issue bump the EXISTING `source='testssl'` row's
  last_observed_at — which is what the note-127 auto-closer keys on. Mint
  a different identity here and a re-scan looks like "tool ran, didn't see
  the old finding" → auto-closer false-closes a live finding + creates a
  duplicate. Unacceptable for a security tool.

  Consequence: run_heavy emits `FindingEvent` (not `MediumFinding`), and
  the writer below (`write_event_findings_and_artifacts`) reads
  `source`/`finding_id` from each FindingEvent rather than hardcoding
  them. ADR-001 scanner_version + derive_validation_status() stamping
  preserved from run_medium's writer pattern.

  Net-depth findings (naabu/fingerprintx, P4) have no offline-import twin
  and may use source='commandsentry_heavy'. They won't auto-close until a
  commandsentry_heavy producer-map entry is added to
  asm_autoclose_producer_patterns — fine for v1.

EXACT testssl.sh INVOCATION (settled with Howie's Mac runbook):
  testssl.sh --warnings batch --color 0 \\
             --jsonfile <out.json> --htmlfile <out.html> \\
             https://<host>

  Hard rules:
    - NO --severity flag. It filters the JSON output; a filtered rescan
      vs a full-pass original-import → the auto-closer sees filtered
      rows as "not observed" → false-closes live findings.
    - --jsonfile (NOT --jsonfile-pretty). parse_testssl_file reads the
      flat record array `[{id, ip, port, severity, finding}, ...]`.
      --jsonfile-pretty emits a different nested structure the parser
      won't read.
    - --warnings batch suppresses interactive "press Enter" prompts.

USAGE:
  python scripts/scanner/run_heavy.py /tmp/scan_descriptor.json

ENVIRONMENT:
  SUPABASE_DSN — required (or pass --dsn)
  SKIP_VPN     — validate-mode interlock (heavy carries the same
                 batch-2 step-d semantic; non-allowlisted targets fail
                 closed under skip_vpn=true).

EXIT CODES:
  0 — scan ran (findings written, scan_run closed). Findings may be 0
      (no TLS on host is a valid negative — see testssl_is_degraded).
      Also returned for routine ROE refusals (workflow stays green).
  1 — fatal error (DB unreachable, descriptor invalid, missing tool
      at runtime, etc.). scan_run is marked 'failed' before exit.
      ROE fail-closed on uncertainty also exits 1 (workflow goes red).
  3 — degraded cascade (testssl flaked beyond recovery, validate-mode
      refused the target, etc.). scan_run marked 'degraded'.

BUILD STATUS (this file, 2026-06-29):
  [x] P0 — workflow branch unstubbed (scanner.yml)
  [x] P1 — skeleton (this module)
  [x] P2 — testssl invocation + FindingEvent writer + parse_testssl_file bridge
  [x] P3 — testssl_is_degraded (basic). Comprehensive unit tests = follow-up.
  [ ] P4 — naabu / fingerprintx net depth (follow-up)
  [ ] P5 — validated-SHA proof on demo.testfire.net (operational)
  [ ] P6 — wild-parity dry-run vs Mac testssl (operational)
  [ ] P7 — enable on backlog assets (CMI, Unimac) (operational)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

# ─── Reuse run_medium scaffolding wholesale ─────────────────────────────
# Per spec "Reuse, don't reinvent." Helpers we share with the medium
# runner live in run_medium and stay there (single source of truth);
# heavy imports them. Importing a script-module is fine here: run_medium
# has no module-level side effects beyond a filesystem read of the
# WireGuard config dir (harmless if absent).
from run_medium import (
    _import_deps,
    log,
    run_cmd,
    capture_egress_ip,
    capture_vpn_config_used,
    get_scanner_version,
    derive_validation_status,
    flush_progress,
    build_rotation_log,
    mark_tool_ok,
    mark_tool_degraded,
    mark_tool_skipped,
    INSERT_ARTIFACT_SQL,
    CLOSE_SCAN_RUN_SQL,
    CLOSE_SCAN_QUEUE_SQL,
    FAIL_SCAN_RUN_SQL,
    FAIL_SCAN_QUEUE_SQL,
    DEGRADED_SCAN_RUN_SQL,
    DEGRADED_SCAN_QUEUE_SQL,
    STAMP_FINDINGS_DEGRADED_SQL,
    flush_artifacts_to_db,
    reconcile_tool_status_invariant,
)
from finding_history_writer import write_finding_history_for_scan_run
from run_light import derive_hostname

# Pure differential WAF-presence logic (4.7 Cloud Armor Q1–Q8). No I/O — the
# collector below does the HTTP (benign baseline + payload GETs) and hands the
# captured responses to the classifier. Same-dir module, imported like run_medium.
from waf_differential import classify_waf_differential, INDEPENDENT_CLASSES

# Degradation primitives (SPEC_SCANNER_DEGRADATION_HARDENING.md).
from degradation import (
    DegradedRunError,
    VALIDATION_TARGETS,
    assert_tool_status_invariant,
    assert_validate_mode_target_allowed,
)

# ─── Canonical parser reuse (THE load-bearing decision) ─────────────────
# parse_testssl_file lives in the OFFLINE import path (cs_parsers/). The
# whole point of this runner is to call it directly from the LIVE path
# so live+import worlds produce identical FindingEvents (same
# stable_finding_id, source='testssl'). Re-scanning a still-present
# issue then bumps the EXISTING backlog row's last_observed_at — exactly
# what the note-127 auto-closer keys on. See module docstring.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_NORMALIZE_PATH = _REPO_ROOT / "scripts" / "normalize"
if str(_NORMALIZE_PATH) not in sys.path:
    sys.path.insert(0, str(_NORMALIZE_PATH))
from cs_parsers.testssl import parse_testssl_file  # noqa: E402
from cs_parsers.common import FindingEvent, stable_finding_id  # noqa: E402


# ─── Scanner version override for tests (mirrors run_medium pattern) ────
# heavy uses the same env var run_medium uses; both stamp findings with
# the same GITHUB_SHA when run from Actions.


# ============================================================================
# Constants
# ============================================================================

# testssl.sh invocation — settled from Howie's Mac runbook
# api-probes-only-2026-05-14.sh "TLS audit redo, properly." NOT tunable
# without ratification — flag drift breaks parity with the existing 85-row
# backlog AND can break the auto-closer (see module docstring).
TESTSSL_BINARY = os.environ.get("TESTSSL_BINARY", "testssl.sh")
TESTSSL_WALL_S = int(os.environ.get("TESTSSL_WALL_S", "600"))  # 10 min — generous for slow TLS stacks
TESTSSL_PORT = int(os.environ.get("TESTSSL_PORT", "443"))


# ============================================================================
# HeavyScanContext — slimmer than medium's ScanContext
# ============================================================================

@dataclass
class HeavyScanContext:
    """Heavy-tier scan context. Slimmer than run_medium.ScanContext —
    no WAF-survival fields (heavy's TLS-handshake/port-probe surface
    doesn't share medium's HTTP-fuzzing WAF problem, per the readiness
    assessment §4). Shape mirrors the medium contract on the fields
    close_out / degraded_out / write_event_findings_and_artifacts read.
    """

    descriptor: dict
    hostname: str
    asset_id: str
    scan_run_id: str
    queue_id: str
    intensity: str  # 'heavy'
    # Canonical FindingEvent list — NOT MediumFinding (load-bearing per
    # module docstring; the writer reads source/finding_id from each event).
    findings: list[FindingEvent] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    artifacts: list[tuple[str, str, str]] = field(default_factory=list)
    # ADR-001 Step 4 — per-tool completeness map. Required by
    # assert_tool_status_invariant in close_out. Set via mark_tool_ok /
    # mark_tool_skipped / mark_tool_degraded.
    tool_status: dict[str, dict] = field(default_factory=dict)
    # VPN forensics (Bug C). Populated at startup, written by close_out
    # / degraded_out.
    egress_ip_initial: str | None = None
    vpn_config_used: str | None = None
    egress_ips_seen: list[str] = field(default_factory=list)
    # ban_events / healthcheck_failures kept for build_rotation_log()
    # compatibility — heavy doesn't rotate but the helper expects the
    # fields to exist.
    ban_events: list[dict] = field(default_factory=list)
    healthcheck_failures: list[dict] = field(default_factory=list)
    rotation_count: int = 0
    rotation_storm: bool = False
    # Live scan progress (note 103). flush_progress reads dsn to open
    # short-lived autocommit conns. None elsewhere → no-op.
    dsn: str | None = None
    planned_steps: list[str] | None = None
    # Validate-mode interlock (SPEC_SCANNER_DEGRADATION_HARDENING.md
    # Batch 2 step d carries to heavy when v1 lands — Task #15). Set True
    # iff SKIP_VPN env was passed. Forces target-allowlist enforcement
    # at the gate AND tells any future rotation logic to short-circuit.
    validate_mode: bool = False
    # target_proven_reachable — heavy keeps the field shape for
    # compatibility with mark_tool_* helpers that may reference it.
    target_proven_reachable: bool = False
    # waf_detected / waf_kind / tech_stack — heavy doesn't probe these
    # but the medium-side helpers (build_rotation_log, scan metadata
    # writer) read them. Default to "not detected."
    waf_detected: bool = False
    waf_kind: str | None = None
    tech_stack: set[str] = field(default_factory=set)


# ============================================================================
# testssl.sh — invocation, parse, degraded-detector
# ============================================================================

def run_testssl(ctx: HeavyScanContext, work_dir: Path) -> tuple[int, Path, str, str]:
    """Run testssl.sh against ctx.hostname:443. Returns
    (returncode, jsonfile_path, stdout, stderr). Writes JSON + HTML
    artifacts into work_dir. Caller is responsible for parsing the JSON
    and feeding it through testssl_is_degraded BEFORE marking the tool
    ok/degraded.

    Exact flags settled from Howie's Mac runbook (see module docstring).
    """
    jsonfile = work_dir / f"testssl_{ctx.hostname}_{TESTSSL_PORT}.json"
    htmlfile = work_dir / f"testssl_{ctx.hostname}_{TESTSSL_PORT}.html"
    target = f"https://{ctx.hostname}:{TESTSSL_PORT}"
    cmd = [
        TESTSSL_BINARY,
        "--warnings", "batch",
        "--color", "0",
        "--jsonfile", str(jsonfile),
        "--htmlfile", str(htmlfile),
        target,
    ]
    log(f"  testssl: {' '.join(cmd)}  (wall={TESTSSL_WALL_S}s)")
    rc, stdout, stderr = run_cmd(cmd, timeout=TESTSSL_WALL_S)
    log(f"  testssl rc={rc} jsonfile={jsonfile.name} ({jsonfile.stat().st_size if jsonfile.exists() else 0} bytes)")
    return rc, jsonfile, stdout, stderr


def testssl_is_degraded(
    rc: int, jsonfile: Path, stdout: str, stderr: str
) -> tuple[bool, str]:
    """SAFETY-CRITICAL — distinguishes a VALID NEGATIVE (host was reached
    + TLS scan ran to completion — auto-closer can credit coverage)
    from a DEGRADED run (timeout, binary missing, unparseable JSON,
    host-unreachable, OR truncated mid-scan → scan_run must NOT be
    'complete'). The note-127 auto-closer treats a complete scan whose
    tools_run includes 'testssl.sh' as evidence of remediation on every
    previously-observed testssl finding for that asset. A flaky-but-
    mislabeled-complete run → false-close of live findings.

    EVOLUTION:
      - 87f09d4 — JSON shape only. Hole: engine_problem-only output
        read as valid-negative.
      - e9340ff — count records that survive parser drop list. Over-
        corrected: reachable+remediated hosts produce only INFO/OK
        reach records → 0 eligible → falsely degraded → backlog for
        clean hosts never clears.
      - 4c149cd — reach-based (service / TLS1_x) + diagnostic wins
        unconditionally. Over-corrected differently: real complete
        testssl scans routinely carry one `engine_problem` WARN
        (OCSP hiccup / STARTTLS quirk), so "diagnostic wins" flagged
        essentially every real scan as degraded — proven by live
        heavy run #794 against demo.testfire.net (rc=0, 195-record
        scan, mis-degraded by the e_p WARN).
      - THIS (round 4) — judge by testssl's own COMPLETION MARKERS,
        not by diagnostic noise. testssl emits `overall_grade` and/or
        `scanTime` records at end-of-run; their presence means the
        scan ran to completion regardless of any non-fatal e_p WARN
        encountered along the way. Reach guards the "did we even
        reach the host" axis; completion guards the "did we finish
        the test battery" axis. Engine_problem / scanProblem records
        are NOT a standalone degrade trigger anymore — the truncation
        guard (reach without completion) catches the truly-interrupted
        case without false-positiving on every real scan.

    Detection order:
      - Tool not found / binary missing                    → DEGRADED
      - Subprocess timed out (rc == 124)                   → DEGRADED
      - Output file missing / 0 bytes / unparseable JSON   → DEGRADED
      - Non-list root (e.g. --jsonfile-pretty mistake)     → DEGRADED
      - has_reach AND has_completion                       → OK
        (even with engine_problem / scanProblem records —
        non-fatal diagnostic noise routine in real scans)
      - has_reach AND NOT has_completion                   → DEGRADED
        (truncated mid-scan; don't trust partial verdict)    (`scan_incomplete`)
      - NOT has_reach                                      → DEGRADED
                                                              (`no_reach_evidence`
                                                              / `nonzero_rc_no_reach_evidence:N`)

      has_reach      = any record id in {service, TLS1, TLS1_1,
                       TLS1_2, TLS1_3, SSLv2, SSLv3}
                       (testssl emits `TLS1`, not `TLS1_0`.)
      has_completion = any record id in {overall_grade, scanTime}

    Returns (is_degraded, reason_slug). Empty slug iff not degraded.
    """
    # Binary missing — run_cmd surfaces FileNotFoundError as rc=127 or
    # raises depending on shell vs list invocation. We use list mode so
    # the typical signal is rc=127 + stderr containing "No such file or
    # directory" OR rc=-1 from a Python-side OSError caught upstream.
    if "no such file or directory" in (stderr or "").lower() and TESTSSL_BINARY in (stderr or ""):
        return True, "tool_missing"
    if rc == 127:
        return True, "tool_missing"

    # Timeout — run_cmd convention is rc == 124 (subprocess kill via
    # `timeout` semantics). Confirm by inspecting the run_medium
    # convention; tightening this if the actual exit code differs is
    # cheap.
    if rc == 124:
        return True, "wall_timeout"

    # Output file presence + parseability — the canonical signal that
    # testssl actually ran a TLS handshake (or honestly recorded its
    # inability to start one).
    if not jsonfile.exists():
        return True, "no_jsonfile"
    try:
        size = jsonfile.stat().st_size
    except OSError:
        return True, "stat_failed"
    if size == 0:
        return True, "empty_jsonfile"
    try:
        data = json.loads(jsonfile.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        return True, f"json_parse_failed:{type(e).__name__}"
    if not isinstance(data, list):
        # parse_testssl_file expects a flat record array. A non-list root
        # means we got --jsonfile-pretty by mistake (different structure)
        # OR testssl crashed and emitted an error envelope. Either way,
        # we don't trust this output as a clean scan.
        return True, "unexpected_json_shape"

    # Completion-marker gate (round 4, 4.8 verify defect 3 fix).
    # Round-3's "diagnostic wins unconditionally" rule was wrong: real
    # complete testssl scans routinely carry one engine_problem WARN
    # (OCSP hiccup, STARTTLS quirk) without being broken. Proven by
    # the failing live heavy run #794 on demo.testfire.net — 195
    # records, rc=0, full battery, mis-degraded by a single non-fatal
    # WARN. The reliable trust axis is "did the test battery run to
    # completion," and testssl tells us that directly with two
    # end-of-run records:
    #
    #   `overall_grade` — the A/B/C/F letter grade derived from all
    #                     other tests. Only emitted when scoring
    #                     completes.
    #   `scanTime`      — total runtime stamp. Only emitted at end-
    #                     of-scan.
    #
    # Either of these present means the scan ran to completion. We
    # treat them as an OR (testssl variants / target classes don't
    # always emit both; one is sufficient proof).
    #
    # Reach is still the necessary first axis: a JSON that never
    # touched the host can't be valid-negative even if some completion
    # field accidentally landed in the array.
    #
    # NOTE: testssl emits `TLS1` (not `TLS1_0`) for the TLS 1.0 probe.
    # Round-3 had this wrong; fixed here.
    _REACH_IDS = {
        "service",
        "TLS1_3", "TLS1_2", "TLS1_1", "TLS1",
        "SSLv3", "SSLv2",
    }
    _COMPLETION_IDS = {"overall_grade", "scanTime"}

    has_reach_evidence = False
    has_completion = False
    for rec in data:
        if not isinstance(rec, dict):
            continue
        rid = rec.get("id") or ""
        if rid in _REACH_IDS:
            has_reach_evidence = True
        if rid in _COMPLETION_IDS:
            has_completion = True

    if not has_reach_evidence:
        # No service / TLS1_x / SSLv2 / SSLv3 record → testssl didn't
        # reach the TLS stack at all. Unreachable host or malformed
        # output. SAFE default: DEGRADED. The legacy
        # `tool_diagnostic_records_only` slug is gone — engine_problem-
        # only output now lands here via no_reach_evidence (no service,
        # no TLS1_x → no_reach_evidence is the correct + sufficient
        # signal; the diagnostic-marker slug was a forensics nicety the
        # real-world fix doesn't need).
        if rc != 0:
            return True, f"nonzero_rc_no_reach_evidence:{rc}"
        return True, "no_reach_evidence"

    if not has_completion:
        # Reached but no overall_grade / scanTime → scan was interrupted
        # mid-battery. Even with reach records, we don't trust a
        # truncated verdict on what was/wasn't checked. The truncation
        # guard 4.8 explicitly called for.
        return True, "scan_incomplete"

    # has_reach AND has_completion → testssl ran the full battery
    # against the host. Engine_problem / scanProblem records here are
    # non-fatal diagnostic noise (the routine OCSP / STARTTLS hiccups
    # in real scans); the completion records prove the test suite
    # finished anyway. Non-zero rc is fine (testssl returns rc!=0 on
    # real findings). Zero LOW+ findings is fine — that's the
    # fully-remediated state v1 exists to detect.
    return False, ""


# ============================================================================
# Round 9 Part 1 — testssl instrumentation (instrument first, fix gated)
# ============================================================================
#
# Heavy-v2 commit 0bfc7d7 cleared the ROE-gate timeout (DB carve-out
# from round 8) but testssl itself still fails post-VPN-bring-up. We
# don't know whether it's IPv6, tunnel-wide TLS, or testssl-specific.
# Per 4.8's Part 1 spec: STOP GUESSING. Add three instrumentation
# surfaces; let the next live run tell us what's happening; THEN fix.
#
#   1. run_pre_testssl_probes — diagnostic block that runs BEFORE
#      testssl. getent v4/v6, ip route get for both, curl -4/-6 HEAD,
#      openssl s_client -4 raw handshake. Splits the v4-vs-v6 and
#      isolates testssl from openssl. Best-effort, never raises —
#      probe failures don't block the scan; the log lines are the
#      product.
#
#   2. _log_stderr_tail — print last N lines of testssl's stderr on
#      every run (success or degrade). Catches non-fatal warnings
#      we're currently dropping on the floor + provides forensic
#      context on degrades without needing a second run.
#
#   3. _dump_small_testssl_json — when the jsonfile is suspiciously
#      small (<4KB) on a degraded exit, log its full contents AND
#      extract any engine_problem / scanProblem records' finding
#      text. testssl's degraded output usually puts the actual
#      error in scanProblem.finding — this dumps the smoking gun
#      directly to the runner log instead of hoping somebody fetches
#      the artifact later.


def run_pre_testssl_probes(ctx: HeavyScanContext, work_dir: Path) -> None:
    """Round 9 Part 1 — pre-testssl diagnostic probe block.

    Goal per 4.8 spec: definitively tell us whether a subsequent testssl
    failure is IPv6, tunnel-wide TLS, or testssl-specific. Each probe
    is short-timeout + result logged inline so 4.8 can read the runner
    log directly without joining to a separate artifact.

    Best-effort: every probe is wrapped + bounded. Failures are LOGGED
    (so we see them) but never raised — the probe block must not
    short-circuit the scan it's diagnosing.
    """
    target = ctx.hostname
    log(f"─── pre-testssl probe block (round 9 Part 1) target={target} ───")

    # 1. DNS — v4 + v6 separately. getent ahostsv4/v6 reflects what
    #    libnss-dns would hand to a connect() call from this runner.
    log(f"  [probe-dns] getent ahostsv4 {target}:")
    try:
        rc, out, _ = run_cmd(["getent", "ahostsv4", target], timeout=8)
        for line in (out or "").splitlines():
            log(f"    {line}")
        if not out:
            log(f"    (no IPv4 records, rc={rc})")
    except Exception as e:
        log(f"    probe failed: {e!r}")

    log(f"  [probe-dns] getent ahostsv6 {target}:")
    try:
        rc, out, _ = run_cmd(["getent", "ahostsv6", target], timeout=8)
        for line in (out or "").splitlines():
            log(f"    {line}")
        if not out:
            log(f"    (no IPv6 records, rc={rc})")
    except Exception as e:
        log(f"    probe failed: {e!r}")

    # 2. Routing decisions per family. `ip route get` shows the kernel's
    #    actual routing decision for a specific destination, which is
    #    the ground truth on whether the destination flows via the wg
    #    interface or the original gateway (post-round-8 carve-out).
    def _first_ip(family_arg: str) -> str:
        try:
            rc, out, _ = run_cmd(["getent", family_arg, target], timeout=8)
            for line in (out or "").splitlines():
                ip = line.strip().split()[0] if line.strip() else ""
                if ip:
                    return ip
        except Exception:
            pass
        return ""

    v4_ip = _first_ip("ahostsv4")
    v6_ip = _first_ip("ahostsv6")

    if v4_ip:
        log(f"  [probe-route] ip route get {v4_ip} (v4):")
        try:
            rc, out, _ = run_cmd(["ip", "route", "get", v4_ip], timeout=5)
            for line in (out or "").splitlines():
                log(f"    {line}")
        except Exception as e:
            log(f"    probe failed: {e!r}")
    else:
        log("  [probe-route] no IPv4 address to route-check")

    if v6_ip:
        log(f"  [probe-route] ip route get {v6_ip} (v6):")
        try:
            rc, out, _ = run_cmd(["ip", "route", "get", v6_ip], timeout=5)
            for line in (out or "").splitlines():
                log(f"    {line}")
        except Exception as e:
            log(f"    probe failed: {e!r}")
    else:
        log("  [probe-route] no IPv6 address (or v6 disabled in resolver)")

    # 3. HTTPS reachability split by family. curl -4 forces IPv4,
    #    curl -6 forces IPv6. -sIv = silent + HEAD + verbose so we
    #    get the connection negotiation in stderr without dragging
    #    the response body.
    target_url = f"https://{target}/"
    for flag, label in (("-4", "v4"), ("-6", "v6")):
        log(f"  [probe-https] curl {flag} -sIv --max-time 10 {target_url}:")
        try:
            rc, _, err = run_cmd(
                ["curl", flag, "-sIv", "--max-time", "10", target_url],
                timeout=15,
            )
            log(f"    rc={rc}")
            # Last few stderr lines tell us how far the TLS / HTTP
            # connection got (handshake, cert load, response code).
            tail = (err or "").splitlines()[-8:]
            for line in tail:
                log(f"    {line}")
            if not tail:
                log("    (no stderr; curl produced no diagnostic output)")
        except Exception as e:
            log(f"    probe failed: {e!r}")

    # 4. Raw TLS handshake via openssl — isolates testssl from openssl.
    #    If openssl s_client succeeds and testssl still fails, the
    #    problem is testssl-specific (its tool flags, parallelism,
    #    parser); if both fail the same way, it's a transport/TLS
    #    layer problem. Limit to v4 first; spec calls v6 the prime
    #    suspect but openssl-v6 isn't load-bearing for the diagnostic.
    log(f"  [probe-tls] openssl s_client -4 -connect {target}:443:")
    try:
        rc, out, err = run_cmd(
            ["sh", "-c",
             f"echo Q | timeout 10 openssl s_client -4 "
             f"-connect {target}:443 -servername {target} 2>&1 | head -30"],
            timeout=15,
        )
        log(f"    rc={rc}")
        # openssl writes the handshake trace to stdout when -2>&1'd
        # via the shell; print what we got.
        for line in (out or "").splitlines()[:30]:
            log(f"    {line}")
        if not out:
            log("    (no output)")
    except Exception as e:
        log(f"    probe failed: {e!r}")

    log("─── end pre-testssl probe block ───")


def _log_stderr_tail(stderr: str, *, label: str = "testssl",
                     max_lines: int = 40) -> None:
    """Round 9 Part 1 — log the last N lines of a tool's stderr.

    Bounded by max_lines (default 40) so a chatty tool can't flood
    the runner log; the tail is usually where the useful diagnostic
    text lives (warnings, fatal errors, last-handshake state).
    """
    if not stderr:
        log(f"  [{label}-stderr] (empty)")
        return
    lines = stderr.splitlines()
    shown = min(max_lines, len(lines))
    log(f"  [{label}-stderr] last {shown} of {len(lines)} line(s):")
    for line in lines[-max_lines:]:
        log(f"    {line}")


def _dump_small_testssl_json(jsonfile: Path) -> None:
    """Round 9 Part 1 — on degraded exit, log the contents of a
    suspiciously-small testssl JSON file (likely contains scanProblem
    records with the actual error text) plus an explicit per-record
    extraction of any engine_problem / scanProblem entries.

    Threshold: 4096 bytes. testssl emits ≥30KB for any real scan;
    anything under 4KB is almost certainly a diagnostic-only output
    from a crashed/aborted run, and worth dumping inline. Larger
    files get a size-only line + the dedicated artifact (already
    captured to scan_run_artifacts) for offline inspection.
    """
    if not jsonfile.exists():
        log("  [forensics] no jsonfile to dump")
        return
    try:
        size = jsonfile.stat().st_size
    except OSError as e:
        log(f"  [forensics] stat failed: {e!r}")
        return
    log(f"  [forensics] jsonfile size: {size} bytes")
    if size > 4096:
        log("  [forensics] jsonfile > 4KB, full dump skipped "
            "(see scan_run_artifacts for the captured copy)")
        return
    try:
        content = jsonfile.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log(f"  [forensics] read failed: {e!r}")
        return
    log("  [forensics] jsonfile contents:")
    for line in content.splitlines():
        log(f"    {line}")
    # Extract diagnostic records specifically — testssl's degraded
    # output usually puts the actual error in scanProblem.finding.
    try:
        data = json.loads(content)
    except Exception as e:
        log(f"  [forensics] JSON unparseable ({type(e).__name__}); "
            f"can't extract scanProblem records")
        return
    if not isinstance(data, list):
        log(f"  [forensics] JSON root is {type(data).__name__}, not list — "
            f"unexpected shape")
        return
    diag_records = [
        r for r in data
        if isinstance(r, dict)
        and r.get("id") in ("engine_problem", "scanProblem")
    ]
    if diag_records:
        log(f"  [forensics] {len(diag_records)} diagnostic record(s):")
        for r in diag_records:
            log(f"    id={r.get('id')!r} severity={r.get('severity')!r} "
                f"finding={(r.get('finding') or '')!r}")
    else:
        log("  [forensics] no engine_problem/scanProblem records found "
            "in the JSON — degradation reason came from a structural "
            "check (rc, file size, parse) rather than testssl's own "
            "diagnostic")


def run_testssl_phase(ctx: HeavyScanContext, work_dir: Path) -> None:
    """Run testssl.sh and emit FindingEvents into ctx.findings. Marks
    'testssl.sh' in ctx.tools_run + ctx.tool_status. On degradation,
    raises DegradedRunError — caller routes to degraded_out.

    Note 'testssl.sh' (with .sh suffix) is the canonical tool token; the
    note-127 producer map matches on 'testssl.sh' OR 'testssl'.

    Round 9 Part 1 — wraps the invocation with diagnostic probes
    (run_pre_testssl_probes) and always logs the stderr tail
    (_log_stderr_tail) regardless of outcome. On degraded exit also
    dumps small JSON files (_dump_small_testssl_json) so the smoking
    gun lands directly in the runner log, no second run required.
    """
    tool_name = "testssl.sh"
    # Append to tools_run UP FRONT so close_out's set-equality invariant
    # holds even if we abort mid-tool. mark_tool_* will also write
    # tool_status accordingly. Mirrors run_medium pre-chunk pattern.
    ctx.tools_run.append(tool_name)

    # Round 9 Part 1: pre-flight probe block. Best-effort; never raises
    # — probe failures don't short-circuit the scan they're diagnosing.
    try:
        run_pre_testssl_probes(ctx, work_dir)
    except Exception as e:
        log(f"  [probe-block] unexpected failure (non-fatal): {e!r}")

    rc, jsonfile, stdout, stderr = run_testssl(ctx, work_dir)

    # Capture raw testssl output as a scan_run_artifact regardless of
    # outcome — forensics. Cheap and the medium pattern.
    if jsonfile.exists():
        try:
            artifact_blob = jsonfile.read_text(encoding="utf-8", errors="replace")
            ctx.artifacts.append((tool_name, "json", artifact_blob))
        except OSError as e:
            log(f"  testssl: artifact read failed (non-fatal): {e!r}")

    # Round 9 Part 1: always log a stderr tail. Catches non-fatal
    # warnings on success paths AND provides forensic context on
    # degraded paths without needing a second run.
    _log_stderr_tail(stderr, label="testssl")

    degraded, reason = testssl_is_degraded(rc, jsonfile, stdout, stderr)
    if degraded:
        log(f"  testssl DEGRADED: reason={reason} rc={rc}")
        # Round 9 Part 1: dump small JSON contents (likely contains
        # scanProblem records with the actual error text) + extract
        # any diagnostic records explicitly.
        _dump_small_testssl_json(jsonfile)
        mark_tool_degraded(ctx, tool_name, reason)
        flush_progress(ctx)
        # DegradedRunError signature is (reason, context=""). The reason
        # slug is the primary signal (matches the run_medium pattern slugs
        # in degradation.py); the tool name lives in context.
        raise DegradedRunError(reason, context=tool_name)

    # Bridge to the canonical parser. fallback_observed_at = now() so
    # downstream UTC normalization (to_utc_iso) keeps shape.
    fallback_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = parse_testssl_file(
        json_path=jsonfile,
        asset_id=ctx.asset_id,
        # scan_id is used by the offline path to build finding_history
        # entries; in the live path we don't write finding_history (the
        # legacy scans-table FK doesn't match scan_run UUIDs). The
        # FindingEvent's finding_id is the canonical identity that
        # matters here.
        scan_id=ctx.scan_run_id,
        scan_root=work_dir,
        fallback_observed_at=fallback_ts,
    )
    log(f"  testssl: parsed {len(events)} FindingEvent(s) "
        f"(canonical source='testssl', stable_finding_id)")
    ctx.findings.extend(events)
    mark_tool_ok(ctx, tool_name)
    ctx.target_proven_reachable = True
    flush_progress(ctx)


def run_httpx_phase(ctx: HeavyScanContext, work_dir: Path) -> None:
    """Run httpx for an HTTP-layer fingerprint; emit one INFO FindingEvent
    (server + tech + status) into ctx.findings.

    ADDITIVE + NON-FATAL. Unlike testssl (heavy's load-bearing tool, which
    raises DegradedRunError on failure), an httpx failure here just marks the
    tool degraded and RETURNS — it never aborts the tier, because testssl has
    already produced heavy's core findings. A bolted-on tool must not be able
    to fail the whole scan.

    This is the entire surface of "add a tool to heavy": one phase fn + one
    call in run(). The FindingEvent writer, the tool_status set-equality
    invariant, and close_out are all tool-agnostic — they read source/finding_id
    off each event and need no changes. Invocation mirrors
    run_light.check_httpx_tech (baked binary, proven flags)."""
    tool_name = "httpx"
    ctx.tools_run.append(tool_name)

    rc, stdout, stderr = run_cmd(
        ["httpx", "-u", f"https://{ctx.hostname}",
         "-td", "-silent", "-json", "-timeout", "15"],
        timeout=45,
    )
    if stdout.strip():
        ctx.artifacts.append((tool_name, "json", stdout))
    _log_stderr_tail(stderr, label="httpx")

    if rc != 0 or not stdout.strip():
        reason = "binary_unavailable" if rc == 127 else "no_output"
        log(f"  httpx DEGRADED (non-fatal, additive tool): reason={reason} rc={rc}")
        mark_tool_degraded(ctx, tool_name, reason)
        flush_progress(ctx)
        return

    try:
        rec = json.loads(stdout.strip().splitlines()[0])
    except (ValueError, IndexError) as e:
        log(f"  httpx: JSON parse failed (non-fatal): {e!r}")
        mark_tool_degraded(ctx, tool_name, "json_parse_failed")
        flush_progress(ctx)
        return

    server = rec.get("webserver") or "n/a"
    tech = rec.get("tech") or []
    tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
    status = rec.get("status_code")
    page_title = (rec.get("title") or "").strip()
    target_url = rec.get("url") or f"https://{ctx.hostname}"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = FindingEvent(
        finding_id=stable_finding_id(ctx.asset_id, tool_name, "httpx-http-surface", target_url),
        asset_id=ctx.asset_id,
        scan_id=ctx.scan_run_id,
        source=tool_name,
        title=f"HTTP surface (httpx) — server: {server}",
        severity="INFO",
        category="recon",
        observed_at=now_iso,
        matched_at=target_url,
        description=(
            f"httpx HTTP-layer snapshot at scan time: {target_url} -> HTTP {status} "
            f"'{page_title}'. Server: {server}. Tech: {tech_str or 'none detected'}."
        ),
        subdomain=ctx.hostname,
        port=443,
        protocol="https",
    )
    ctx.findings.append(ev)
    log(f"  httpx: parsed 1 FindingEvent (source='httpx', server='{server}', "
        f"tech=[{tech_str}])")
    mark_tool_ok(ctx, tool_name)
    flush_progress(ctx)


# ============================================================================
# Security-stack identification — P0 passive collectors (Obsidian 146; 4.7 R1/R2)
# ============================================================================
# PERSIST-ONLY. Collects the passive stack-id signals available from tools already
# in heavy — the TLS cert O/CN and the asset's response headers + Set-Cookie NAMES
# — and stores them RAW as one `stack_id_passive` scan_run artifact. It does NOT
# feed the classifier: P1 will read this artifact (via gather_observations, exactly
# like the fingerprint/testssl artifacts) and wire the signals into device_class /
# vendor_product under a SINGLE soak reset. That collect-vs-wire separation is what
# keeps P0 additive / no-reset (4.7 R2).
#
# DELIBERATELY NOT a "tool": this phase does NOT append to tools_run / tool_status
# and emits NO findings — it only appends an artifact. So it cannot perturb
# close_out's tool-completeness invariant or the note-127 autocloser, and a total
# failure just yields an artifact with no signals (zero blast radius).
#
# Set-Cookie: NAMES only, never values — the name (cookiesession1 = FortiWeb,
# incap_ses = Imperva, ak_bm = Akamai, AWSALB = AWS ELB, ...) is the vendor
# fingerprint; the value is session material we do not persist.
#
# NOT here (deliberate scope): JARM (needs pyjarm baked into the scanner image —
# 4.7 ruling 8, phase P0b) and the wafw00f verdict (runs in run_medium, not heavy
# — rides with E1). Header/cookie collection uses a browser-UA `curl -sSI` (the
# method proven to capture cookiesession1) after httpx's default GET returned
# cookies=0 on WAF'd assets in P0 validation (heavy #1061, 2026-07-19).

# Browser UA so WAF'd origins serve the same Set-Cookie a real browser gets
# (validated: cookiesession1 only surfaced under a browser-like request).
_BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")


def _parse_cert_dn(dn: str) -> dict:
    """Best-effort {o, cn} from an openssl DN string. No regex (run_heavy has no
    `import re`). Comma-split is imperfect for quoted values containing commas
    (e.g. issuer O="GoDaddy.com, Inc.") — that's why the caller ALSO stores the
    raw DN text; this parse is convenience, the raw is ground truth for P1."""
    out: dict = {}
    for chunk in dn.replace("/", ",").split(","):
        if "=" not in chunk:
            continue
        k, v = chunk.split("=", 1)
        k = k.strip().upper()
        v = v.strip().strip('"')
        if k in ("O", "CN") and v:
            out[k.lower()] = v
    return out


def _parse_cert_subject_issuer(openssl_out: str) -> dict:
    """Parse `openssl x509 -noout -subject -issuer` into
    {subject_o, subject_cn, issuer_o, issuer_cn} (best-effort)."""
    out: dict = {}
    for line in openssl_out.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("subject=") or low.startswith("issuer="):
            prefix = "subject" if low.startswith("subject=") else "issuer"
            for k, v in _parse_cert_dn(s.split("=", 1)[1]).items():
                out[f"{prefix}_{k}"] = v
    return out


def _extract_set_cookie_names(header_obj) -> list:
    """Distinct Set-Cookie NAMES (token before '='), never values. httpx -irh
    puts response headers under 'header' (dict; a Set-Cookie may be str or list);
    also handles a raw header block (str)."""
    raw: list = []
    if isinstance(header_obj, dict):
        for k, v in header_obj.items():
            if k.lower() == "set-cookie":
                raw.extend(v if isinstance(v, list) else [v])
    elif isinstance(header_obj, str):
        for line in header_obj.splitlines():
            if line.lower().startswith("set-cookie:"):
                raw.append(line.split(":", 1)[1])
    names: list = []
    for c in raw:
        name = str(c).split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


# Cloud-edge / CDN marker headers captured as VALUE-FREE presence (4.7 cloud-edge Q6).
# NAME-only: the fact that the header is present is the vendor tell; the value is not
# persisted (lean artifact, no arbitrary-value leakage). `server` + `via` keep their
# values because that's where GFE / "via: 1.1 google" / AkamaiGHost name themselves.
_EDGE_MARKER_HEADERS = frozenset({
    "cf-ray", "cf-cache-status",          # Cloudflare (cf- prefix — missed by the x- catch-all)
    "x-amz-cf-id",                        # AWS CloudFront
    "x-azure-ref", "x-azure-fdid",        # Azure Front Door
    "x-served-by", "x-timer",             # Fastly
    "x-akamai-transformed", "x-akamai-request-id",  # Akamai
    "x-goog-generation",                  # Google (GCS/edge)
    "x-cache", "age", "cache-control",    # caching evidence -> CDN vs LB tie-break (Q2)
})


def _vendor_header_subset(header_obj) -> dict:
    """Small, value-free header view for vendor fingerprinting (4.7 cloud-edge Q1/Q6):
    the Server + Via VALUES (the edge names itself there — GFE, 'via: 1.1 google',
    AkamaiGHost) + PRESENCE booleans for a curated set of cloud-edge / CDN marker headers
    (cf-ray, x-amz-cf-id, x-azure-ref, x-served-by, ... + caching headers for the CDN
    tie-break) and any other x-* header. Marker values are NOT persisted — name-presence
    is the tell — keeping the artifact lean and avoiding arbitrary-value leakage."""
    if not isinstance(header_obj, dict):
        return {}
    keep: dict = {}
    for k, v in header_obj.items():
        lk = k.lower()
        val = v[0] if isinstance(v, list) and v else v
        if lk in ("server", "via"):
            keep[lk] = str(val)[:80]
        elif lk in _EDGE_MARKER_HEADERS or lk == "x-powered-by" or lk.startswith("x-"):
            keep[lk] = True
    return keep


def _parse_raw_headers(text: str) -> dict:
    """Raw HTTP header block (curl -sSI output) -> {lower-name: value | [values]}.
    Resets on each `HTTP/` status line so we keep the LAST response block; repeated
    same-name headers (Set-Cookie) collect into a list."""
    hdrs: dict = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.upper().startswith("HTTP/"):
            hdrs = {}
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if not k:
            continue
        if k in hdrs:
            prev = hdrs[k]
            hdrs[k] = (prev if isinstance(prev, list) else [prev]) + [v]
        else:
            hdrs[k] = v
    return hdrs


def run_stack_id_passive_phase(ctx: HeavyScanContext, work_dir: Path) -> None:
    """P0 passive stack-id collector (Obsidian 146). ADDITIVE + NON-FATAL; never
    aborts the tier. Appends one `stack_id_passive` artifact; touches no tool
    machinery and no classifier state."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signals: dict = {"schema": 1, "collected_at": now_iso, "hostname": ctx.hostname}

    # TLS cert O/CN — openssl already present in heavy (first-party O + vendor CN)
    rc, out, _ = run_cmd(
        ["bash", "-c",
         f"echo | openssl s_client -connect {ctx.hostname}:443 "
         f"-servername {ctx.hostname} 2>/dev/null | openssl x509 -noout -subject -issuer"],
        timeout=30,
    )
    if rc == 0 and out.strip():
        signals["cert_raw"] = out.strip()
        cert = _parse_cert_subject_issuer(out)
        if cert:
            signals["cert"] = cert

    # Response headers + Set-Cookie NAMES — curl HEAD with a browser UA.
    # P0-validation finding (heavy #1061, 2026-07-19): httpx's default GET returned
    # cookies=0 on WAF'd commandcommcentral.com even though cookiesession1 IS served
    # — a browser-UA `curl -sSI` is the method that provably captured it, and its
    # raw-header output is a format we fully control (vs guessing httpx's -irh JSON).
    rc2, out2, _ = run_cmd(
        ["curl", "-sSIk", "-A", _BROWSER_UA, "--max-time", "15", f"https://{ctx.hostname}/"],
        timeout=25,
    )
    if rc2 == 0 and out2.strip():
        hdrs = _parse_raw_headers(out2)
        names = _extract_set_cookie_names(hdrs)
        if names:
            signals["set_cookie_names"] = names
        vh = _vendor_header_subset(hdrs)
        if vh:
            signals["headers"] = vh

    ctx.artifacts.append(("stack_id_passive", "json", json.dumps(signals)))
    got = [k for k in ("cert", "set_cookie_names", "headers") if k in signals]
    log(f"  stack_id_passive (persist-only): collected {got or 'nothing'} "
        f"(cookies={len(signals.get('set_cookie_names', []))})")


# ── Active-probe tier: FortiWeb /fwbbot_check challenge (4.7 Q3/Q4/Q7, Obsidian 146) ─
# The program's FIRST active probe. P3 active-tier guardrails applied INLINE:
#   * per-asset opt-in (assets.active_probe_authorized) = the gate AND kill switch
#   * a single, DETECT-ONLY request (never solves/bypasses the challenge)
#   * DRY-RUN by default (env ACTIVE_PROBE_LIVE unset) — logs + audits, fires nothing
#   * one active_probe_audit row per evaluation (authorized?, dry_run?, observed?)
#   * corroborating context to assert (Q7): /fwbbot_check path AND a WAF-challenge
#     shape (redirect TO it) — never path-alone
# Persist-only, self-registers NO tool (like the passive phase). gather_observations
# does NOT read the artifact yet — that wiring + the gen-4 reset are Phase D.
_ACTIVE_PROBE_LIVE = os.environ.get("ACTIVE_PROBE_LIVE", "").strip().lower() in ("1", "true", "yes")
# Egress vantage (4.7 Q1) is PER-ASSET (assets.active_probe_egress), DB-authoritative:
# VPN Mullvad — which ccc is KNOWN to ban — vs a direct datacenter IP. Default vpn; an
# asset escalates to 'direct' ONLY when a VPN ban is DOCUMENTED (active_probe_egress_
# reason). This module env is just the FALLBACK default when the column is unset. 'direct'
# binds curl to PROBE_EGRESS_INTERFACE to bypass the tunnel when heavy has VPN up; without
# it, 'direct' records intent and uses default egress (no faked bypass — the audit's
# egress_ip is ground truth either way).
_ACTIVE_PROBE_EGRESS = (os.environ.get("ACTIVE_PROBE_EGRESS", "vpn").strip().lower() or "vpn")
_PROBE_EGRESS_INTERFACE = os.environ.get("PROBE_EGRESS_INTERFACE", "").strip()
# 4.7 Q2 bot-shape UA: a KNOWN non-browser UA (NOT a spoofed browser — the point is to
# look like automated tooling so FortiWeb's bot-mitigation issues the /fwbbot_check
# challenge). Fixed, never randomized (reproducible probe behaviour).
_PROBE_BOT_UA = "curl/7.81.0"


def _read_active_probe_policy(ctx: HeavyScanContext) -> tuple[bool, str, str]:
    """Per-asset active-probe policy read (4.7 Q1). Returns (authorized, egress, reason).
    egress ∈ {vpn, direct}: which vantage this asset's probe uses — DB-authoritative,
    falling back to the module default when unset. 4.7 Q1: default vpn; an asset escalates
    to 'direct' ONLY when a VPN ban is DOCUMENTED (reason column). Missing dsn / any error
    -> NOT authorized + default egress (fail closed)."""
    if not ctx.dsn:
        return False, _ACTIVE_PROBE_EGRESS, ""
    try:
        psycopg, dict_row, _ = _import_deps()   # lazy deps — module-level import is intentionally absent (matches run())
        with psycopg.connect(ctx.dsn, autocommit=True, connect_timeout=10) as c:
            with c.cursor(row_factory=dict_row) as cur:
                cur.execute("select active_probe_authorized, active_probe_egress, "
                            "active_probe_egress_reason from public.assets where asset_id=%s",
                            (ctx.asset_id,))
                r = cur.fetchone()
        if not r:
            return False, _ACTIVE_PROBE_EGRESS, ""
        egress = (r.get("active_probe_egress") or _ACTIVE_PROBE_EGRESS).strip().lower()
        if egress not in ("vpn", "direct"):
            egress = _ACTIVE_PROBE_EGRESS
        return bool(r.get("active_probe_authorized")), egress, (r.get("active_probe_egress_reason") or "")
    except Exception as e:  # non-fatal: unknown authorization -> treat as NOT authorized
        log(f"  fwbbot_check probe: policy read failed ({e}) — treating as unauthorized")
        return False, _ACTIVE_PROBE_EGRESS, ""


def _write_active_probe_audit(ctx: HeavyScanContext, v: dict) -> None:
    """One audit row per evaluation (4.7 Q3/Q8). Non-fatal on any error."""
    if not ctx.dsn:
        return
    try:
        psycopg, _dict_row, _Json = _import_deps()   # lazy deps — module-level import is intentionally absent
        with psycopg.connect(ctx.dsn, autocommit=True, connect_timeout=10) as c:
            with c.cursor() as cur:
                cur.execute(
                    "insert into public.active_probe_audit (asset_id, probe_class, authorized, "
                    "dry_run, egress_ip, observed, corroborated, scan_run_id, details) "
                    "values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                    (ctx.asset_id, v["probe_class"], v["authorized"], v["dry_run"],
                     ctx.egress_ip_initial, v["observed"], v["corroborated"],
                     ctx.scan_run_id, json.dumps(v.get("details") or {})))
    except Exception as e:  # pragma: no cover
        log(f"  fwbbot_check probe: audit write failed ({e}) — non-fatal")


def _classify_fwbbot_response(raw_headers: str) -> tuple[bool, bool, dict]:
    """Pure response classifier (4.7 Q4; unit-tested, no I/O). (observed, corroborated,
    details). EVERY outcome other than a corroborated challenge leaves the signal dormant
    — the empirical bar: assert NOTHING without corroboration. Four outcomes:
      challenge_elicited          — 3xx whose Location IS /fwbbot_check → observed+corroborated (the SIGNAL)
      banned                      — 403/429 WAF block               → not corroborated
      path_mentioned_not_redirect — /fwbbot_check in headers, not a redirect target → observed, NOT corroborated (4.7 Q7 honeypot guard)
      no_challenge                — normal response, no /fwbbot_check → neither
    corroborated is TRUE only for the redirect-to-challenge shape; nothing else can set it."""
    hdrs = raw_headers or ""
    status = 0
    loc = ""
    for line in hdrs.splitlines():
        s = line.strip()
        if not status and s.upper().startswith("HTTP/"):
            parts = s.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif not loc and s.lower().startswith("location:"):
            loc = s.split(":", 1)[1].strip()
    path_present = "fwbbot_check" in hdrs.lower()
    loc_is_challenge = "/fwbbot_check" in loc.lower()
    is_redirect = status in (301, 302, 303, 307, 308)
    if loc_is_challenge and is_redirect:
        result, observed, corroborated = "challenge_elicited", True, True
    elif status in (403, 429):
        result, observed, corroborated = "banned", path_present, False
    elif path_present:
        result, observed, corroborated = "path_mentioned_not_redirect", True, False
    else:
        result, observed, corroborated = "no_challenge", False, False
    return observed, corroborated, {"result": result, "status": status, "location": loc[:200]}


def _probe_curl_args(hostname: str, egress_mode: str, interface: str) -> list[str]:
    """Pure argv builder (unit-tested). 4.7 Q2 — ONE detect-only, bot-shaped GET to the
    root: a known non-browser UA + NO Accept/Accept-Language/Accept-Encoding + empty cookie
    jar + no Referer + default TLS (L7 shape only; uTLS deferred per 4.7 Q3). Body
    discarded, headers dumped, redirect NOT followed — we read the 302 Location, never
    execute the challenge JS. Fixed shape (never randomized) so behaviour is reproducible.
    'direct' egress binds curl to `interface` (bypass the VPN tunnel) when one is set."""
    args = ["curl", "-sSk", "-o", "/dev/null", "-D", "-", "--max-time", "15",
            "-A", _PROBE_BOT_UA, "-H", "Accept:", "-H", "Accept-Language:",
            "-H", "Accept-Encoding:"]
    if egress_mode == "direct" and interface:
        args += ["--interface", interface]
    args.append(f"https://{hostname}/")
    return args


def _fire_fwbbot_check_probe(ctx: HeavyScanContext, egress: str) -> tuple[bool, bool, dict]:
    """ONE detect-only bot-shaped GET via the asset's egress, then the pure classifier.
    Detect the /fwbbot_check challenge PRESENCE — never follow it, never solve it."""
    args = _probe_curl_args(ctx.hostname, egress, _PROBE_EGRESS_INTERFACE)
    _rc, out, _ = run_cmd(args, timeout=25)
    observed, corroborated, det = _classify_fwbbot_response(out or "")
    det["egress_mode"] = egress
    det["egress_interface"] = _PROBE_EGRESS_INTERFACE or None
    return observed, corroborated, det


def run_fwbbot_check_probe_phase(ctx: HeavyScanContext, work_dir: Path) -> None:
    authorized, egress, egress_reason = _read_active_probe_policy(ctx)
    fire = authorized and _ACTIVE_PROBE_LIVE
    observed = corroborated = None
    details: dict = {"live_flag": _ACTIVE_PROBE_LIVE, "egress_mode": egress}
    if egress_reason:
        details["egress_reason"] = egress_reason[:200]
    if not authorized:
        log("  fwbbot_check probe: SKIP — asset not active_probe_authorized (opt-in false / kill switch)")
    elif not _ACTIVE_PROBE_LIVE:
        log(f"  fwbbot_check probe: authorized but DRY-RUN (ACTIVE_PROBE_LIVE unset), egress={egress} — would probe, firing nothing")
    else:
        observed, corroborated, pd = _fire_fwbbot_check_probe(ctx, egress)
        details.update(pd)
        log(f"  fwbbot_check probe: LIVE detect-only egress={egress} — result={details.get('result')} observed={observed} corroborated={corroborated}")
    verdict = {"schema": 1, "probe_class": "fwbbot_check_elicit", "authorized": authorized,
               "dry_run": not fire, "observed": observed, "corroborated": corroborated,
               "details": details}
    ctx.artifacts.append(("stack_id_fwbbot_check", "json", json.dumps(verdict)))
    _write_active_probe_audit(ctx, verdict)


# ============================================================================
# Active probe — differential WAF-presence (4.7 Cloud Armor Q1–Q8; presence-only)
#
# The GFE lesson carried forward: a "WAF present" claim is EARNED BY BEHAVIOUR —
# >=2 of 3 INDEPENDENT payload classes (SQLi/XSS/LFI) blocked vs a clean benign
# baseline — never by a hosting fingerprint, and it NEVER names a vendor (Q3/Q8:
# not even Cloud Armor on a GCP asset). The pure decision lives in
# waf_differential.classify_waf_differential; this collector only fires the HTTP
# and shapes the responses for it. The INVERSE — a clean baseline that blocks
# NOTHING — is the affirmative "no enforcing WAF" signal, emitted HIGH
# (PCI DSS 6.4.2 / NIST SP 800-53 SC-7).
#
# Safety (4.7 Q4): GET-only, ONE random query param, a self-identifying
# X-CS-Stack-ID-Probe header, detect-only (redirects read from headers, never
# followed/executed), URL-encoded LFI, fixed pacing between requests. Per-asset
# opt-in + egress + DRY-RUN default reuse the fwbbot rig verbatim (Q5); DRY-RUN
# (ACTIVE_PROBE_LIVE unset) fires nothing. Persist-only artifact + one
# active_probe_audit row, exactly like run_fwbbot_check_probe_phase.
# ============================================================================

_WAF_PROBE_HEADER = "X-CS-Stack-ID-Probe: 1"                   # Q4 self-identifying probe marker
_WAF_PROBE_PACING_S = float(os.environ.get("WAF_PROBE_PACING_S", "5") or "5")   # Q4 pacing between requests
_WAF_BENIGN_VALUE = "commandsentry-baseline"                   # benign baseline query value
_WAF_TOKEN_CAP = 40                                            # bound the app-context token set
# Q4 payloads: signature-tripping but INERT as GET query values. LFI is pre-percent-
# encoded (sent as-is); sqli/xss are URL-encoded at send time. Fixed (reproducible).
_WAF_PAYLOADS = (
    ("sqli", "1' OR '1'='1"),
    ("xss",  "<script>alert(1)</script>"),
    ("lfi",  "..%2f..%2f..%2f..%2fetc%2fpasswd"),
)
_WAF_LFI_PREENCODED = {"lfi"}                                  # already %-encoded per Q4 — don't double-encode


def _read_text_safe(p: Path) -> str:
    """Read a probe body file, tolerant of binary / missing (never fatal)."""
    try:
        return p.read_text(errors="replace")
    except Exception:
        return ""


def _waf_cookie_names(raw_headers: str) -> set:
    """Set of Set-Cookie cookie-NAMES (lowercased) from the header dump. App sessions set
    named cookies; a generic edge deny rarely re-sets the app's cookies, so an overlap with
    the baseline's cookies marks an app-rendered deny — NOT an edge block (Q2 gate 5)."""
    names = set()
    for line in (raw_headers or "").splitlines():
        s = line.strip()
        if s.lower().startswith("set-cookie:"):
            name = s.split(":", 1)[1].strip().split("=", 1)[0].strip().lower()
            if name:
                names.add(name)
    return names


def _waf_body_tokens(body: str) -> set:
    """A bounded app-context fingerprint of a response body: the <title> words (len>=4) plus
    a capped set of CSS class names. These recur on the app's OWN error page but not on a
    generic edge deny, so an intersection with the baseline's tokens is the tell that a deny
    was app-rendered, not edge-blocked (Q2 gate 4). Prefixed (t:/c:) so a title word and a
    class of the same spelling stay distinct."""
    b = (body or "")[:20000].lower()
    toks: set = set()
    mt = re.search(r"<title[^>]*>(.*?)</title>", b, re.S)
    if mt:
        for w in re.findall(r"[a-z0-9]{4,}", mt.group(1)):
            toks.add("t:" + w)
    for attr in re.findall(r'class="([^"]{1,160})"', b):
        for c in attr.split():
            if len(c) >= 4:
                toks.add("c:" + c)
                if len(toks) >= _WAF_TOKEN_CAP:
                    return toks
    return toks


def _parse_waf_probe(stdout: str, body: str) -> dict:
    """One probe response -> the classifier's shape {status, size, tokens, headers}. status
    and size come from curl's OWN -w sentinel (CS_STATUS/CS_SIZE) — ground truth, not a header
    re-parse. headers = app Set-Cookie names; tokens = app-context body fingerprints."""
    status, size = 0, len(body or "")
    m = re.search(r"CS_STATUS:(\d+)\s+CS_SIZE:(\d+)", stdout or "")
    if m:
        status, size = int(m.group(1)), int(m.group(2))
    return {"status": status, "size": size,
            "tokens": _waf_body_tokens(body or ""),
            "headers": _waf_cookie_names(stdout or "")}


def _waf_probe_curl_args(hostname: str, param: str, value: str, preencoded: bool,
                         body_sink: str, egress_mode: str, interface: str) -> list[str]:
    """Pure argv builder (unit-tested). 4.7 Q4 — ONE detect-only GET with the probe value in a
    single query param + the self-identifying probe header; no browser Accept*/cookie/Referer;
    redirect NOT followed (no -L — we read the edge deny, never execute it). Headers dumped to
    stdout (-D -), body to `body_sink` (-o), status+size via a -w sentinel. sqli/xss are
    URL-encoded here; a pre-encoded value (LFI) is sent as-is (Q4). 'direct' egress binds curl
    to `interface` to bypass the VPN tunnel."""
    qv = value if preencoded else quote(value, safe="")
    args = ["curl", "-sSk", "-o", body_sink, "-D", "-",
            "-w", "\nCS_STATUS:%{http_code} CS_SIZE:%{size_download}",
            "--max-time", "15", "-A", _PROBE_BOT_UA,
            "-H", "Accept:", "-H", "Accept-Language:", "-H", "Accept-Encoding:",
            "-H", _WAF_PROBE_HEADER]
    if egress_mode == "direct" and interface:
        args += ["--interface", interface]
    args.append(f"https://{hostname}/?{param}={qv}")
    return args


def _fire_waf_differential_probe(ctx: HeavyScanContext, work_dir: Path,
                                 egress: str) -> tuple[dict, list, dict]:
    """Fire the benign baseline + one GET per independent payload class through the asset's
    egress, pace-limited (Q4). Returns (baseline, payloads, details) — baseline/payloads are
    classifier-shaped dicts. Detect-only: a redirect is captured from headers, never followed."""
    param = "q" + secrets.token_hex(3)             # Q4 per-run random param name
    base_sink = work_dir / "waf_probe_baseline.body"
    _rc, out, _ = run_cmd(
        _waf_probe_curl_args(ctx.hostname, param, _WAF_BENIGN_VALUE, False,
                             str(base_sink), egress, _PROBE_EGRESS_INTERFACE), timeout=25)
    baseline = _parse_waf_probe(out, _read_text_safe(base_sink))
    fired = [{"cls": "benign", "status": baseline["status"], "size": baseline["size"]}]
    payloads = []
    for cls, val in _WAF_PAYLOADS:
        time.sleep(_WAF_PROBE_PACING_S)            # Q4 pacing between requests
        sink = work_dir / f"waf_probe_{cls}.body"
        _rc, pout, _ = run_cmd(
            _waf_probe_curl_args(ctx.hostname, param, val, cls in _WAF_LFI_PREENCODED,
                                 str(sink), egress, _PROBE_EGRESS_INTERFACE), timeout=25)
        resp = _parse_waf_probe(pout, _read_text_safe(sink))
        resp["cls"] = cls
        payloads.append(resp)
        fired.append({"cls": cls, "status": resp["status"], "size": resp["size"]})
    details = {"param": param, "egress_mode": egress,
               "egress_interface": _PROBE_EGRESS_INTERFACE or None,
               "pacing_s": _WAF_PROBE_PACING_S, "fired": fired}
    return baseline, payloads, details


def _no_waf_proven(baseline: dict, verdict: dict) -> bool:
    """Affirmative 'no enforcing WAF' gate. True ONLY when the benign baseline was clean
    (2xx/3xx) AND the classifier blocked ZERO classes — the one False-verdict shape that proves
    ABSENCE. A non-2xx baseline is inconclusive (dead origin) and a single-class block is
    ambiguous (app input-validator); NEITHER earns the finding (the empirical bar)."""
    if verdict.get("waf_present"):
        return False
    if not (200 <= int(baseline.get("status") or 0) < 400):
        return False
    return len(verdict.get("blocked") or []) == 0


def _maybe_emit_no_waf_finding(ctx: HeavyScanContext, baseline: dict, verdict: dict) -> None:
    """Emit the affirmative 'no enforcing WAF in front of a live app' HIGH finding when proven
    (PCI DSS 6.4.2 / NIST SP 800-53 SC-7). The positive 'Behind a WAF' verdict is device-class
    metadata (persisted artifact); the ABSENCE of a compensating control is a security finding
    in its own right. source='commandsentry_heavy'; presence-only (names no product)."""
    if not _no_waf_proven(baseline, verdict):
        return
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctx.findings.append(FindingEvent(
        finding_id=stable_finding_id(ctx.asset_id, "commandsentry_heavy",
                                     "waf-absent-differential", ctx.hostname),
        asset_id=ctx.asset_id, scan_id=ctx.scan_run_id, source="commandsentry_heavy",
        title="No enforcing WAF in front of live application",
        severity="HIGH", category="config", observed_at=now_iso, matched_at=ctx.hostname,
        description=(
            f"Differential probe: a benign baseline returned HTTP {baseline.get('status')} and "
            f"all {len(INDEPENDENT_CLASSES)} independent attack-payload classes (SQLi, XSS, LFI) "
            "passed through to the origin unblocked — no payload-inspecting WAF is enforcing in "
            "front of this live application. A WAF is a required compensating control (PCI DSS "
            "6.4.2) and boundary protection (NIST SP 800-53 SC-7); its absence leaves the origin "
            "directly exposed to application-layer attacks. Presence-only method: this asserts "
            "the ABSENCE of blocking and names no product."),
        subdomain=ctx.hostname, port=TESTSSL_PORT, protocol="https",
    ))
    log("  waf_differential probe: NO ENFORCING WAF proven -> HIGH finding (PCI 6.4.2 / SC-7)")


def run_waf_differential_probe_phase(ctx: HeavyScanContext, work_dir: Path) -> None:
    """Differential WAF-presence active probe (4.7 Cloud Armor Q1–Q8). Same rig as
    run_fwbbot_check_probe_phase: per-asset opt-in (assets.active_probe_authorized) + per-asset
    egress, DRY-RUN default (ACTIVE_PROBE_LIVE unset fires nothing), persist-only
    stack_id_waf_differential artifact + one active_probe_audit row. Presence-only — NEVER names
    a vendor (Q3/Q8). On a clean baseline that blocks NOTHING, emits the affirmative 'no
    enforcing WAF' HIGH finding (PCI 6.4.2 / SC-7). gather_observations turning a POSITIVE
    presence verdict into the waf_present_differential device-class observation is the follow-up."""
    authorized, egress, egress_reason = _read_active_probe_policy(ctx)
    fire = authorized and _ACTIVE_PROBE_LIVE
    waf_present = None
    blocked: list = []
    reason = ""
    details: dict = {"live_flag": _ACTIVE_PROBE_LIVE, "egress_mode": egress}
    if egress_reason:
        details["egress_reason"] = egress_reason[:200]
    if not authorized:
        log("  waf_differential probe: SKIP — asset not active_probe_authorized (opt-in false / kill switch)")
    elif not _ACTIVE_PROBE_LIVE:
        log(f"  waf_differential probe: authorized but DRY-RUN (ACTIVE_PROBE_LIVE unset), egress={egress} "
            f"— would fire baseline+{len(_WAF_PAYLOADS)} payload classes, firing nothing")
    else:
        baseline, payloads, pd = _fire_waf_differential_probe(ctx, work_dir, egress)
        details.update(pd)
        verdict = classify_waf_differential(baseline, payloads)
        waf_present, blocked, reason = verdict["waf_present"], verdict["blocked"], verdict["reason"]
        details.update({"baseline_status": baseline["status"], "baseline_size": baseline["size"],
                        "blocked": blocked, "classify_reason": reason,
                        "evidence_class": verdict["evidence_class"]})
        log(f"  waf_differential probe: LIVE egress={egress} — waf_present={waf_present} "
            f"blocked={blocked} ({reason})")
        _maybe_emit_no_waf_finding(ctx, baseline, verdict)
    v = {"schema": 1, "probe_class": "waf_differential", "authorized": authorized,
         "dry_run": not fire,
         "observed": (None if not fire else True),
         "corroborated": (None if not fire else bool(waf_present)),
         "details": details}
    # persist-only stack-id artifact (parity with fwbbot) — gather_observations reads
    # waf_present_differential from here (follow-up wiring). NULL until a live run classifies.
    ctx.artifacts.append(("stack_id_waf_differential", "json", json.dumps({
        "schema": 1, "probe_class": "waf_differential",
        "waf_present_differential": (None if waf_present is None else bool(waf_present)),
        "blocked": blocked, "reason": reason, "details": details})))
    _write_active_probe_audit(ctx, v)


# ============================================================================
# Heavy Phase 1 — net depth (naabu port discovery + fingerprintx service ID)
# Spec: HEAVY_PHASE1_NETDEPTH_SPEC v2 + HEAVY_PHASE1_BUILD_DELTA (4.7 D1-D5).
#
# These two phases are a PAIR. run() credits tools_run with BOTH 'naabu' AND
# 'fingerprintx' ONLY when both pass their four-gate (4.7 D1 all-or-nothing
# autoclose credit) — so, UNLIKE run_httpx_phase, they do NOT self-register in
# tools_run / tool_status; run() does it after the pair returns. If either
# degrades, findings still emit (observations recorded) but neither name enters
# tools_run, so the note-127 autocloser never false-closes the OTHER tool's
# commandsentry_heavy findings on a partial scan.
#
# Findings-only (4.7 D3): heavy MUST NOT write asset_surface — the discovery
# importer owns asset_surface.service_count, which the P2 went-dark writer reads;
# a heavy dual-writer could feed a false zero-service into that lifecycle.
# source='commandsentry_heavy' ALWAYS (NEVER 'naabu'/'fingerprintx' — those are
# not finding_source_t labels; emitting them fails the insert). Identity excludes
# the service (4.7 D4): finding_id is stable per (asset, source, port, proto); the
# service is mutable TITLE metadata so a fingerprintx flap re-observes, not churns.
# ============================================================================

NAABU_RATE = int(os.environ.get("NAABU_RATE", "250"))        # 4.7 D5 pilot rate; ratchet -> 500 after clean single-asset runs
NAABU_TOP_PORTS = int(os.environ.get("NAABU_TOP_PORTS", "1000"))
FPX_SKIP_PORTS = {80, 443}                                   # 4.7 D5: WAF L7 exposure + already covered by httpx / medium


def _parse_naabu_ports(stdout: str) -> list[dict]:
    """naabu -json emits one JSON object per open port: {host, ip, port, protocol}."""
    out = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        port = rec.get("port")
        if not isinstance(port, int):
            continue
        out.append({"port": port,
                    "proto": (rec.get("protocol") or "tcp").lower(),
                    "ip": rec.get("ip") or rec.get("host")})
    return out


def _parse_fingerprintx(stdout: str) -> dict:
    """fingerprintx --json emits one object per probed port. Return {(port, proto): service}."""
    svc = {}
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        port = rec.get("port")
        if not isinstance(port, int):
            continue
        proto = (rec.get("transport") or "tcp").lower()
        service = (rec.get("protocol") or rec.get("service") or "unknown").lower()
        svc[(port, proto)] = service
    return svc


def run_naabu_phase(ctx: HeavyScanContext, work_dir: Path) -> tuple[bool, list[dict]]:
    """naabu CONNECT top-ports port discovery. Returns (naabu_ok, open_ports).

    Does NOT self-register in tools_run / tool_status — run() credits the
    net-depth PAIR (4.7 D1). Emits one INFO 'Service inventory: <port>/<proto>
    open' FindingEvent per open port (source='commandsentry_heavy'; finding_id
    stable per (asset, source, port, proto)).

    FOUR-GATE (4.7 D5/Q5, conservative for findings-only Phase 1a):
      naabu_ok = target_proven_reachable (testssl already completed a handshake =
      the real-egress proof) AND rc==0 AND non-empty ports.
    Empty/failed -> ok=False, NOT credited by run() -> the autocloser can never
    false-close prior port findings on a silent naabu failure (absence-of-evidence
    != evidence-of-absence). CONNECT scan: no raw sockets over the WireGuard tunnel.
    """
    if not ctx.target_proven_reachable:
        log("  naabu SKIP — testssl did not prove reachability (no egress proof); not credited")
        return False, []

    rc, stdout, stderr = run_cmd(
        ["naabu", "-host", ctx.hostname, "-top-ports", str(NAABU_TOP_PORTS),
         "-rate", str(NAABU_RATE), "-scan-type", "CONNECT", "-silent", "-json"],
        timeout=300,
    )
    if stdout.strip():
        ctx.artifacts.append(("naabu", "json", stdout))
    _log_stderr_tail(stderr, label="naabu")

    if rc != 0:
        log(f"  naabu DEGRADED (not credited, absence-of-evidence): rc={rc}")
        return False, []
    open_ports = _parse_naabu_ports(stdout)
    if not open_ports:
        log("  naabu: rc=0 but zero open ports — NOT credited (4.7 Q5 absence-of-evidence)")
        return False, []

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for p in open_ports:
        port, proto = p["port"], p["proto"]
        mid = f"{ctx.hostname}:{port}/{proto}"
        ctx.findings.append(FindingEvent(
            finding_id=stable_finding_id(ctx.asset_id, "commandsentry_heavy",
                                         f"naabu-open-port-{port}-{proto}", mid),
            asset_id=ctx.asset_id, scan_id=ctx.scan_run_id, source="commandsentry_heavy",
            title=f"Service inventory: {port}/{proto} open",
            severity="INFO", category="recon", observed_at=now_iso, matched_at=mid,
            description=(f"naabu observed {port}/{proto} open on {ctx.hostname} at scan time "
                         f"(CONNECT, top-{NAABU_TOP_PORTS}, rate {NAABU_RATE})."),
            subdomain=ctx.hostname, port=port, protocol=proto,
        ))
    log(f"  naabu OK: {len(open_ports)} open port(s) -> {len(open_ports)} INFO finding(s)")
    return True, open_ports


def run_fingerprintx_phase(ctx: HeavyScanContext, work_dir: Path,
                           open_ports: list[dict]) -> bool:
    """fingerprintx service ID on naabu's open ports. Returns fpx_ok.

    Skips 80/443 (4.7 D5 — WAF L7 exposure; already covered by httpx / medium).
    Does NOT self-register (run() credits the pair). Emits one INFO
    'Service inventory: <port>/<proto>/<service>' FindingEvent per identified
    service; finding_id stable per (asset, source, port, proto) with the service
    in the mutable TITLE (4.7 D4 — a fingerprintx flap re-observes, never churns).
    NOTE: the service-change WATCH alert (4.7 D4 correction) is a persist-time diff
    (needs the prior title) — tracked as the immediate follow, not dropped.

    Four-gate: rc==0 AND non-empty output (matches asm-discover K2 fpx.ok).
    """
    targets = [p for p in open_ports if p["port"] not in FPX_SKIP_PORTS]
    if not targets:
        log("  fingerprintx: no eligible ports after 80/443 skip — nothing to probe (ok)")
        return True

    stdin = "\n".join(f"{ctx.hostname}:{p['port']}" for p in targets) + "\n"
    rc, stdout, stderr = run_cmd(["fingerprintx", "--json"], timeout=600, input_str=stdin)
    if stdout.strip():
        ctx.artifacts.append(("fingerprintx", "json", stdout))
    _log_stderr_tail(stderr, label="fingerprintx")

    if rc != 0 or not stdout.strip():
        log(f"  fingerprintx DEGRADED (not credited): rc={rc} empty={not stdout.strip()}")
        return False

    svc = _parse_fingerprintx(stdout)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for (port, proto), service in svc.items():
        mid = f"{ctx.hostname}:{port}/{proto}"
        ctx.findings.append(FindingEvent(
            finding_id=stable_finding_id(ctx.asset_id, "commandsentry_heavy",
                                         f"fingerprintx-service-{port}-{proto}", mid),
            asset_id=ctx.asset_id, scan_id=ctx.scan_run_id, source="commandsentry_heavy",
            title=f"Service inventory: {port}/{proto}/{service}",
            severity="INFO", category="recon", observed_at=now_iso, matched_at=mid,
            description=(f"fingerprintx identified '{service}' on {port}/{proto} at "
                         f"{ctx.hostname} at scan time. Service is mutable metadata; "
                         f"finding identity is the port, not the service."),
            subdomain=ctx.hostname, port=port, protocol=proto,
        ))
    log(f"  fingerprintx OK: {len(svc)} service(s) -> {len(svc)} INFO finding(s)")
    return True


# ============================================================================
# FindingEvent-aware writer (the load-bearing P2 adapter)
# ============================================================================

def write_event_findings_and_artifacts(
    conn, ctx: HeavyScanContext, Json, *, write_artifacts: bool = True
) -> tuple[int, int]:
    """Persist ctx.findings (FindingEvent[]) + (optionally) ctx.artifacts.
    Mirrors run_medium.write_findings_and_artifacts's structure, but
    reads finding_id + source FROM EACH FindingEvent rather than
    hardcoding them. This is what makes a re-scan of a still-present
    testssl finding bump the EXISTING source='testssl' backlog row
    instead of minting a new source='commandsentry_heavy' row.

    ADR-001 scanner_version + derive_validation_status() stamping
    preserved — heavy findings start UNvalidated until P5's
    scanner_validations INSERT lands.

    Reuses the canonical UPSERT_FINDING_SQL + INSERT_ARTIFACT_SQL
    from run_medium so column shape can't drift.

    write_artifacts (note 129 follow-up #3): controls whether the
    artifact loop runs. Defaults True for the clean path. The degraded
    path calls flush_artifacts_to_db separately (Task #21-style
    pre-abort flush so forensics survive even if this write fails),
    so it MUST pass write_artifacts=False here — otherwise both code
    paths write the same artifacts and scan_run_artifacts ends up
    with duplicate rows (the minor 4.8 flagged on heavy run #794).
    """
    # Local re-import — UPSERT_FINDING_SQL is module-private in run_medium.
    from run_medium import UPSERT_FINDING_SQL

    inserted = 0
    updated = 0
    scanner_version = get_scanner_version()
    validation_status = derive_validation_status(conn, ctx.intensity, scanner_version)
    log(f"  ADR-001: scanner_version={scanner_version[:12]} "
        f"validation_status={validation_status} (heavy starts unvalidated "
        f"until P5 scanner_validations INSERT)")

    # Map FindingEvent.category (free-form strings like 'tls', 'dns',
    # 'transport') to the finding_category_t enum the DB expects. The
    # parser uses these tokens; the DB enum accepts: web, network,
    # email, tls, dns, secrets, cve, misconfig, other (and possibly
    # more — UPSERT will raise on a bad value; we surface that cleanly).
    # Keep it conservative — fall back to 'other' on anything not
    # known-safe.
    KNOWN_CATEGORIES = {
        "web", "network", "email", "tls", "dns",
        "secrets", "cve", "misconfig", "other",
    }

    with conn.cursor() as cur:
        for ev in ctx.findings:
            category = ev.category if ev.category in KNOWN_CATEGORIES else "other"
            params = {
                # KEY DIFFERENCE FROM MEDIUM WRITER — read identity from
                # the event, NOT from a hardcoded {asset_id}:{tier}:{check}
                # pattern. testssl events arrive with source='testssl'
                # + canonical stable_finding_id; net-depth events (P4)
                # arrive with source='commandsentry_heavy' + their own
                # stable id. Either way, UPSERT_FINDING_SQL keys on
                # finding_id, so identity matches drive existing-row
                # updates rather than duplicate inserts.
                "finding_id": ev.finding_id,
                "asset_id": ev.asset_id,
                "title": ev.title,
                "severity": ev.severity,
                "category": category,
                "description": ev.description,
                "cwe": ev.cwe,
                "references": ev.references,
                "source": ev.source,
                # Heavy events from parse_testssl_file don't carry tags;
                # default to empty list to match column type.
                "tags": [],
                # 4.7 I1/I2 — required by the shared UPSERT_FINDING_SQL now that it
                # writes normalized_key. FindingEvents from cs_parsers carry the
                # class-collapse key; testssl/net events default to None.
                "normalized_key": ev.normalized_key,
                "validation_status": validation_status,
                "scanner_version": scanner_version,
                "scan_run_id": ctx.scan_run_id,
            }
            cur.execute(UPSERT_FINDING_SQL, params)
            row = cur.fetchone()
            if row and row["inserted"]:
                inserted += 1
            else:
                updated += 1

        if write_artifacts:
            for tool_name, output_format, content_str in ctx.artifacts:
                try:
                    content_obj = json.loads(content_str)
                except Exception:
                    content_obj = {"raw": content_str}
                cur.execute(INSERT_ARTIFACT_SQL, {
                    "scan_run_id": ctx.scan_run_id,
                    "tool_name": tool_name,
                    "output_format": output_format,
                    "size_bytes": len(content_str.encode("utf-8")),
                    "content_jsonb": Json(content_obj),
                })
    return inserted, updated


# ============================================================================
# Regress-on-observed (centralized via SQL helper — round 6)
# ============================================================================
#
# Note 129 round 6 / migration 20260629a: the regression logic was
# centralized into a SQL function that both medium + heavy call —
# regress_observed_for_scan_run(p_scan_run_id, p_source). It mirrors
# delta_close_for_scan_run as a structural sibling:
#   delta_close:  current_status IN open      AND last_seen <> this
#                 → mark remediated
#   regress:      current_status IN remediated AND last_seen =  this
#                 → mark regressed (+ clear remediated_at)
#
# Both clauses are mutually exclusive (open-set vs remediated-set, <>
# vs =) so disjoint, order-independent, and idempotent. The SQL fn
# writes one admin_audit_log row per flip (rule=
# 'regress_observed_for_scan_run_v1') and captures the prior status
# via a CTE so the audit before_state is accurate.
#
# Heavy's previous Python helper (regress_observed_remediated +
# _SELECT_OBSERVED_REMEDIATED_SQL + _REGRESS_FINDING_SQL) was retired
# in this round — the SQL function is the single source of truth.
# Call site lives in run() below: clean path only, one SELECT per
# distinct source observed in ctx.findings (today: 'testssl'; future
# net-depth P4 adds 'commandsentry_heavy').
#
# CLEAN-PATH ONLY discipline preserved — never call from the
# degraded except branch. A degraded scan isn't trustworthy evidence
# of presence (it can't credit "I saw it" against an existing
# remediated finding).
#
# Why scope per-source: a heavy scan emits findings under multiple
# sources (canonical 'testssl' for TLS depth, 'commandsentry_heavy'
# for net depth). Source-scoping the SQL call mirrors delta_close's
# discipline — closes/reopens stay confined to what THIS source
# actually emitted, so an unrelated source's findings can't be
# touched by accident.


# ============================================================================
# Close-out variants — heavy mirrors of run_medium's close_out/degraded_out/fail_out
# ============================================================================

def close_out_heavy(conn, ctx: HeavyScanContext, inserted: int, updated: int, Json) -> None:
    """Mark scan_run + scan_queue complete. Mirrors run_medium.close_out
    but does NOT call delta_close_for_scan_run — heavy emits findings
    under MULTIPLE sources (canonical 'testssl' for TLS depth, future
    'commandsentry_heavy' for net depth), so the source-scoped delta
    close doesn't apply uniformly. The note-127 auto-closer
    (`asm_autoclose_stale_findings`) is the heavy-tier remediation
    engine — it reads scan_run.tools_run + completed_at across runs to
    decide closure. Don't double up.
    """
    assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)
    with conn.cursor() as cur:
        params = {
            "tools_run": ctx.tools_run,
            "findings_added": inserted,
            "findings_updated": updated,
            "findings_count": inserted + updated,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
            "tool_status": Json(ctx.tool_status or {}),
            "egress_ip": ctx.egress_ip_initial,
            "vpn_config_used": ctx.vpn_config_used,
            "rotation_log": Json(build_rotation_log(ctx)),
        }
        cur.execute(CLOSE_SCAN_RUN_SQL, params)
        cur.execute(CLOSE_SCAN_QUEUE_SQL, params)


def degraded_out_heavy(conn, ctx: HeavyScanContext, error: str,
                      inserted: int, updated: int, Json) -> None:
    """Mark scan_run + scan_queue degraded. Stamps any findings this
    scan_run first detected with scan_quality='degraded' (mirrors
    run_medium.degraded_out's STAMP_FINDINGS_DEGRADED_SQL). The
    note-127 auto-closer only treats COMPLETE scans as evidence of
    coverage, so a degraded heavy run does NOT trigger false-closes
    on stranded testssl findings — the safety property the spec
    calls out (P3).
    """
    reconcile_tool_status_invariant(ctx)
    with conn.cursor() as cur:
        params = {
            "tools_run": ctx.tools_run,
            "findings_added": inserted,
            "findings_updated": updated,
            "findings_count": inserted + updated,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
            "tool_status": Json(ctx.tool_status or {}),
            "error": error,
            "egress_ip": ctx.egress_ip_initial,
            "vpn_config_used": ctx.vpn_config_used,
            "rotation_log": Json(build_rotation_log(ctx)),
        }
        cur.execute(DEGRADED_SCAN_RUN_SQL, params)
        cur.execute(DEGRADED_SCAN_QUEUE_SQL, params)
        # Demote any findings from this scan_run to scan_quality=degraded
        # + validation_status=unvalidated (trust-layer Part 4). Idempotent.
        cur.execute(STAMP_FINDINGS_DEGRADED_SQL, {"scan_run_id": ctx.scan_run_id})


def fail_out_heavy(conn, ctx: HeavyScanContext, error: str) -> None:
    """Mark scan_run + scan_queue failed (operational failure — DB
    unreachable, descriptor invalid, etc., not a degraded scan)."""
    with conn.cursor() as cur:
        params = {
            "error": error,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
        }
        cur.execute(FAIL_SCAN_RUN_SQL, params)
        cur.execute(FAIL_SCAN_QUEUE_SQL, params)


# ============================================================================
# Entry point
# ============================================================================

def run(descriptor_path: str, dsn: str) -> int:
    psycopg, dict_row, Json = _import_deps()

    log(f"reading descriptor: {descriptor_path}")
    try:
        descriptor = json.loads(Path(descriptor_path).read_text())
    except Exception as e:
        log(f"descriptor read/parse failed: {e}")
        return 1

    if descriptor.get("intensity") != "heavy":
        log(f"WARNING: descriptor intensity is '{descriptor.get('intensity')}', not 'heavy'")

    # ─── ROE / ownership pull-time gate ─────────────────────────────────
    # MUST run before any target-bound network op (no DNS, no curl, no
    # tool — nothing). Catches direct-REST + SQL-Editor inserts that
    # bypassed the portal-side helper. Mirrors run_medium's gate
    # precisely — same failure modes, same exit-code split.
    try:
        from roe_gate import check_ownership_or_block
    except ImportError as e:
        log(f"FATAL: roe_gate module not importable: {e!r} — aborting (fail-closed, exit 1)")
        return 1
    gate_conn = None
    try:
        gate_conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        gh_url = (
            os.environ.get("GITHUB_SERVER_URL")
            and os.environ.get("GITHUB_REPOSITORY")
            and os.environ.get("GITHUB_RUN_ID")
        )
        gh_run_url = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
            if gh_url else None
        )
        queue_source = None
        try:
            with gate_conn.cursor() as cur:
                cur.execute(
                    "SELECT source FROM public.scan_queue WHERE queue_id = %s",
                    (descriptor["queue_id"],),
                )
                qrow = cur.fetchone()
                if qrow is not None:
                    queue_source = qrow["source"] if isinstance(qrow, dict) else qrow[0]
        except Exception as e:
            log(f"[gate] could not read scan_queue.source for alert enrichment: {e!r}")

        block = check_ownership_or_block(
            conn=gate_conn,
            asset_id=descriptor["asset_id"],
            intensity=descriptor["intensity"],
            scan_run_id=descriptor["scan_run_id"],
            queue_id=descriptor["queue_id"],
            github_run_url=gh_run_url,
            queue_source=queue_source,
        )
    except Exception as e:
        log(f"FATAL: ROE gate raised: {e!r} — aborting (fail-closed, exit 1)")
        try:
            if gate_conn is not None:
                gate_conn.close()
        except Exception:
            pass
        return 1
    finally:
        try:
            if gate_conn is not None:
                gate_conn.close()
        except Exception:
            pass

    if block is not None:
        log(
            f"ROE BLOCK — asset={block.asset_id} intensity={block.intensity} "
            f"ownership={block.ownership!r} reason={block.reason}"
        )
        log(f"  message: {block.message}")
        log("  zero target-bound tools ran. scan_run + scan_queue stamped failed.")
        if block.is_routine_refusal():
            log("  routine refusal — exit 0 (workflow stays green).")
            return 0
        log("  gate failed closed on uncertainty — exit 1 (workflow goes red).")
        return 1

    # ─── Gate cleared — proceed with normal heavy scan ──────────────────
    asset = descriptor["asset"]
    ctx = HeavyScanContext(
        descriptor=descriptor,
        hostname=derive_hostname(asset),
        asset_id=descriptor["asset_id"],
        scan_run_id=descriptor["scan_run_id"],
        queue_id=descriptor["queue_id"],
        intensity=descriptor["intensity"],
        dsn=dsn,
    )
    log(f"asset_id={ctx.asset_id} hostname={ctx.hostname} "
        f"scan_run_id={ctx.scan_run_id}")

    # Validate-mode interlock — same primitive medium uses (batch 2 step d
    # carries to heavy; Task #15). Non-allowlisted target under skip_vpn
    # = DegradedRunError caught below, routed to degraded_out_heavy.
    skip_vpn = os.environ.get("SKIP_VPN", "").lower() in ("true", "1", "yes")
    ctx.validate_mode = skip_vpn
    if skip_vpn:
        log(f"validate_mode active — skip_vpn={skip_vpn}; "
            f"VALIDATION_TARGETS={sorted(VALIDATION_TARGETS)}; "
            f"rotation N/A for heavy (no nuclei/ffuf chunks)")

    start_egress = capture_egress_ip()
    if start_egress:
        ctx.egress_ips_seen.append(start_egress)
        log(f"pre-scan egress IP: {start_egress}")
        ctx.egress_ip_initial = start_egress
    ctx.vpn_config_used = capture_vpn_config_used()
    if ctx.vpn_config_used:
        log(f"vpn config in use: {ctx.vpn_config_used}")

    # DB connection deferred until write phase (Supabase idle-close
    # lesson from scan #35, 2026-05-30).
    conn = None
    work_dir = Path("/tmp") / f"heavy_{ctx.scan_run_id}"
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Phase 0 — validate-mode safety interlock. Inside the try so
        # DegradedRunError lands in the except branch below and routes
        # cleanly through degraded_out_heavy.
        assert_validate_mode_target_allowed(ctx.hostname, skip_vpn)

        # Phase 1 — testssl.sh (P2). The whole point of v1 — clears the
        # stranded backlog so the note-127 auto-closer can reconcile.
        run_testssl_phase(ctx, work_dir)

        # httpx — HTTP-layer fingerprint (ADDITIVE, non-fatal). One phase fn +
        # this call are the entire "add a tool" surface; the writer + close_out
        # are tool-agnostic. Runs after testssl has proven reachability.
        run_httpx_phase(ctx, work_dir)

        # Security-stack identification P0 — passive collectors (Obsidian 146).
        # ADDITIVE, persist-only: appends a `stack_id_passive` artifact and
        # touches no findings/tool machinery. P1 wires these signals into the
        # classifier (with its own single soak reset).
        run_stack_id_passive_phase(ctx, work_dir)

        # Active-probe tier — FortiWeb /fwbbot_check challenge (4.7 Q3, Obsidian 146).
        # DRY-RUN by default (fires nothing); gated on assets.active_probe_authorized
        # (opt-in + kill switch); persist-only + audited to active_probe_audit.
        # gather_observations reads the artifact only in Phase D (with the gen-4 reset).
        run_fwbbot_check_probe_phase(ctx, work_dir)

        # Active-probe tier — differential WAF-presence probe (4.7 Cloud Armor Q1–Q6).
        # Same rig: DRY-RUN default, per-asset opt-in + egress, persist-only + audited.
        # Benign baseline vs >=2 independent payload classes -> "Behind a WAF" (presence
        # only). gather_observations wiring (obs waf_present_differential) is the follow-up.
        run_waf_differential_probe_phase(ctx, work_dir)

        # Phase 2 — naabu + fingerprintx net depth (Heavy Phase 1). PAIR with
        # all-or-nothing tools_run credit (4.7 D1): both names enter tools_run
        # (crediting the note-127 autocloser for source=commandsentry_heavy) ONLY
        # when BOTH pass their four-gate. If either degrades, findings still emit
        # but NEITHER is credited — so a partial net-depth scan cannot false-close
        # the other tool's findings. tool_status is set to match tools_run so the
        # close_out_heavy set-equality invariant holds either way (net tools are
        # in BOTH or NEITHER). Additive: a net-depth failure never fails the tier
        # (testssl is the reachability proof).
        naabu_ok, open_ports = run_naabu_phase(ctx, work_dir)
        fpx_ok = run_fingerprintx_phase(ctx, work_dir, open_ports) if naabu_ok else False
        if naabu_ok and fpx_ok:
            ctx.tools_run.append("naabu")
            ctx.tools_run.append("fingerprintx")
            mark_tool_ok(ctx, "naabu")
            mark_tool_ok(ctx, "fingerprintx")
        else:
            log(f"  net-depth PARTIAL (naabu_ok={naabu_ok} fpx_ok={fpx_ok}) — findings "
                f"emitted, tools_run NOT credited (4.7 D1 all-or-nothing autoclose guard)")
        flush_progress(ctx)

        # ─── Persist + close ────────────────────────────────────────────
        conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        inserted, updated = write_event_findings_and_artifacts(conn, ctx, Json)
        log(f"persisted: {inserted} new + {updated} re-observed "
            f"({inserted + updated} total)")
        # Note 129 round 6 — centralized regress-on-observed via the
        # SQL helper regress_observed_for_scan_run (migration
        # 20260629a). One call per distinct source observed in
        # ctx.findings — source-scoped to mirror delta_close's
        # discipline so each source's reopen stays confined to its
        # own findings (a heavy scan can emit both 'testssl' and
        # future 'commandsentry_heavy' findings; each gets its own
        # gate). CLEAN PATH ONLY — the except DegradedRunError
        # branch below explicitly does NOT call this. The SQL
        # function reads findings.last_seen_scan_run (stamped by
        # the UPSERT in write_event_findings_and_artifacts) to
        # identify what this scan actually re-emitted, and writes
        # one admin_audit_log row per flip.
        # Alerter regressed-semantics fix (spec 2026-07-11, 4.7 Q3): settle
        # prior-scan regressions BEFORE the regress loop, per source. Heavy has
        # no delta_close (the note-127 autocloser is its remediation engine), so
        # settle is the first close-out flip. A finding regressed on a PRIOR scan
        # that this scan re-observed settles regressed→confirmed ('regressed' is a
        # one-scan transition state, not sticky).
        _settle_sources = sorted({ev.source for ev in ctx.findings})
        total_settled = 0
        for src in _settle_sources:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT settle_regressed_for_scan_run(%s, %s) AS n_settled",
                    (ctx.scan_run_id, src),
                )
                _st_row = cur.fetchone()
                total_settled += (_st_row["n_settled"] if _st_row else 0) or 0
            finally:
                cur.close()
        if total_settled:
            log(f"settle-regressed: {total_settled} prior-regressed finding(s) "
                f"re-observed → flipped back to 'confirmed'")

        distinct_sources = sorted({ev.source for ev in ctx.findings})
        total_regressed = 0
        for src in distinct_sources:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT regress_observed_for_scan_run(%s, %s) AS n_regressed",
                    (ctx.scan_run_id, src),
                )
                _rg_row = cur.fetchone()
                n_regressed = (_rg_row["n_regressed"] if _rg_row else 0) or 0
            finally:
                cur.close()
            if n_regressed:
                log(f"regress-on-observed[{src}]: {n_regressed} previously-"
                    f"remediated finding(s) re-emitted → flipped to "
                    f"'regressed', remediated_at cleared (audit rows in "
                    f"admin_audit_log)")
                total_regressed += n_regressed
        if total_regressed == 0 and distinct_sources:
            log(f"regress-on-observed: 0 flipped across sources "
                f"{distinct_sources} (no returned remediated findings)")

        # Alerter regressed-semantics fix (spec 2026-07-11, 4.7 Q4): stamp
        # last_regressed_at for findings THIS scan just flipped to 'regressed',
        # per source, so the "was regressed" signal survives a later settle.
        for src in distinct_sources:
            cur = conn.cursor()
            try:
                cur.execute(
                    "UPDATE public.findings SET last_regressed_at = now() "
                    "WHERE current_status = 'regressed' AND last_regressed_at IS NULL "
                    "AND source::text = %s AND last_seen_scan_run = %s",
                    (src, ctx.scan_run_id),
                )
            finally:
                cur.close()

        # Note 129 round 7 — finding_history per re-emitted finding.
        # Runs AFTER the per-source regress loop so the recorded
        # status reflects any flips that just happened. CLEAN-PATH
        # ONLY (the except DegradedRunError branch below does NOT
        # call this — partial last_seen stamps from a degraded scan
        # shouldn't drive the observation timeline).
        n_history = write_finding_history_for_scan_run(
            conn, ctx.scan_run_id,
            notes=f"observed by run_heavy scan_run {ctx.scan_run_id}",
        )
        if n_history:
            log(f"finding-history: {n_history} observation row(s) "
                f"written (scan_id={ctx.scan_run_id})")
        else:
            log("finding-history: 0 rows written (no re-emitted findings)")
        close_out_heavy(conn, ctx, inserted, updated, Json)
        conn.commit()
        log("scan_run + scan_queue marked complete.")
        return 0

    except DegradedRunError as dre:
        log(f"DegradedRunError: reason={dre.reason} context={dre.context}")
        # Open conn now (we deferred until write phase) so degraded
        # bookkeeping persists. Per the medium pattern, this conn is
        # short-lived and committed at the end of this branch.
        try:
            if conn is None:
                conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
            # Flush any partial artifacts so forensics survive (Task
            # #21 fix carried over).
            try:
                flush_artifacts_to_db(conn, ctx, Json)
            except Exception as flush_err:
                log(f"flush_artifacts_to_db: {flush_err!r}")
            # write_event_findings still runs in degraded mode so any
            # already-emitted findings get persisted (they'll get
            # scan_quality=degraded via STAMP_FINDINGS_DEGRADED_SQL).
            # write_artifacts=False because flush_artifacts_to_db above
            # already wrote them — pre-#3 the artifact loop ran twice,
            # producing duplicate scan_run_artifacts rows per tool.
            try:
                inserted, updated = write_event_findings_and_artifacts(
                    conn, ctx, Json, write_artifacts=False,
                )
            except Exception as write_err:
                log(f"write in degraded path failed (non-fatal): {write_err!r}")
                inserted, updated = 0, 0
            # error_message format: "<context>:<reason>" when context is
            # present (e.g. "testssl.sh:wall_timeout"), else just the
            # reason slug. Mirrors the medium runner's convention.
            error_msg = (
                f"{dre.context}:{dre.reason}" if dre.context else dre.reason
            )
            degraded_out_heavy(conn, ctx, error_msg,
                              inserted, updated, Json)
            conn.commit()
            log("scan_run + scan_queue marked degraded.")
        except Exception as bookkeep_err:
            log(f"FATAL: degraded bookkeeping failed: {bookkeep_err!r}")
            try:
                if conn is not None:
                    conn.rollback()
            except Exception:
                pass
            return 1
        return 3

    except Exception as e:
        log(f"FATAL: unhandled exception: {e!r}")
        # Best-effort fail stamping.
        try:
            if conn is None:
                conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
            fail_out_heavy(conn, ctx, f"unhandled:{type(e).__name__}:{e}")
            conn.commit()
        except Exception as fail_err:
            log(f"fail_out_heavy also failed: {fail_err!r}")
            try:
                if conn is not None:
                    conn.rollback()
            except Exception:
                pass
        return 1

    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
        end_egress = capture_egress_ip()
        if end_egress and end_egress != ctx.egress_ip_initial:
            log(f"egress drifted during scan: start={ctx.egress_ip_initial} end={end_egress}")
        elif end_egress:
            log(f"post-scan egress IP: {end_egress}")


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Heavy-tier scanner (v1)")
    parser.add_argument("descriptor", help="path to /tmp/scan_descriptor.json")
    parser.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"),
                       help="Supabase DSN (or set SUPABASE_DSN env)")
    args = parser.parse_args()
    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)
    sys.exit(run(args.descriptor, args.dsn))


if __name__ == "__main__":
    main()
