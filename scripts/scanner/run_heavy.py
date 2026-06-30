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
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    write_finding_history_for_scan_run,
)
from run_light import derive_hostname

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
from cs_parsers.common import FindingEvent  # noqa: E402


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

        # Phase 2 — naabu / fingerprintx port + service depth (P4 —
        # FOLLOW-UP commit). Mark explicitly as skipped so the
        # set-equality invariant in close_out_heavy holds. When P4 lands,
        # replace these skip-marks with real invocations.
        for net_tool in ("naabu", "fingerprintx"):
            ctx.tools_run.append(net_tool)
            mark_tool_skipped(ctx, net_tool, "v1_p4_pending")
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
