"""
test_run_heavy.py — unit tests for run_heavy.py

Phase coverage (RUN_HEAVY_V1_BUILD_SPEC.md):

  [x] P3 — testssl_is_degraded: VALID NEGATIVE (no-TLS host → complete +
           0 findings) vs DEGRADED (timeout, tool missing, empty/bad JSON,
           wrong --jsonfile-pretty shape, nonzero-rc-empty-records). The
           safety hinge against the note-127 auto-closer false-closing on
           a flaky-but-mislabeled-complete run.

  [ ] P2 parity test — placeholder. The parity check (same testssl JSON
           through (a) live run_heavy path and (b) offline run_normalize
           path → identical finding_id / source / severity / normalized_key
           per finding) is gated on having a real testssl JSON artifact to
           feed both. Captured as a TODO; 4.8 will run the parity check
           against demo.testfire.net's output in P5 / P6.

Run with:
  cd scripts/scanner && python3 -m pytest test_run_heavy.py -v
  (or plain `python3 test_run_heavy.py` — main() exercises the same paths
   without pytest).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Ensure module is importable when run from anywhere.
sys.path.insert(0, str(Path(__file__).parent))

from run_heavy import testssl_is_degraded


# ─── testssl_is_degraded — VALID NEGATIVE cases (must NOT be degraded) ──
#
# Note 129 follow-up #2 (4.8 re-verify of e9340ff): the discriminator is
# REACH evidence, not eligible-record count. A reach-positive record is
# any `service` / `TLS1_x` / `SSLv2` / `SSLv3` — testssl ID that proves
# the tool actually completed enough handshake / probe work to
# characterize the target's TLS stack. Their parser-drop status (INFO/OK
# severity → dropped) is irrelevant; their PRESENCE is the trust signal.
# All NOT-degraded fixtures below carry realistic reach records.

def _write_json(payload, suffix=".json") -> Path:
    """Helper: write JSON to a temp file, return its Path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    json.dump(payload, f)
    f.close()
    return Path(f.name)


# Realistic reach fixture — what every reached testssl scan produces
# regardless of TLS posture. Used in every NOT-degraded test so the
# fixture shape matches what a real scan emits (vs the minimal toy
# JSON in pre-#2 tests that lacked reach evidence).
_REACH_RECORDS = [
    {"id": "service", "ip": "host/1.2.3.4", "port": "443",
     "severity": "INFO", "finding": "HTTPS"},
    {"id": "TLS1_3", "ip": "host/1.2.3.4", "port": "443",
     "severity": "OK", "finding": "offered"},
    {"id": "TLS1_2", "ip": "host/1.2.3.4", "port": "443",
     "severity": "OK", "finding": "offered"},
]


def test_reach_records_only_zero_findings_is_NOT_degraded():
    """4.8's specific gap: a reachable + fully-remediated host emits
    only `service` + `TLS1_x` records (parser drops them all as INFO/OK)
    and zero LOW+ findings. This IS the success state v1 exists to
    detect — the auto-closer credits coverage and closes the prior
    backlog. Pre-#2 the e9340ff "eligible record count" gate flipped
    this to degraded; the reach-based gate gets it right.
    """
    p = _write_json(list(_REACH_RECORDS))
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"clean-modern-TLS misclassified as degraded: {reason!r}"
        assert reason == "", f"reason should be empty for clean scan, got {reason!r}"
    finally:
        p.unlink()


def test_reach_with_low_cipher_record_is_NOT_degraded():
    """Reach records + a LOW-severity cipher finding. Reach gate
    passes; finding count is irrelevant to the gate.
    """
    p = _write_json(list(_REACH_RECORDS) + [
        {"id": "cipher-tls1_2_xc028", "ip": "host/1.2.3.4", "port": "443",
         "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"valid scan misclassified as degraded: {reason!r}"
    finally:
        p.unlink()


def test_reach_with_named_attack_record_is_NOT_degraded():
    """Reach records + a MEDIUM-severity named-attack finding. NOT degraded."""
    p = _write_json(list(_REACH_RECORDS) + [
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"healthy scan misclassified as degraded: {reason!r}"
    finally:
        p.unlink()


def test_nonzero_rc_with_reach_is_NOT_degraded():
    """testssl frequently returns rc!=0 on findings (rc reflects severity
    count, not failure). Reach evidence present → NOT degraded regardless
    of exit code. Without this carve-out we'd flip every productive
    testssl scan to degraded.
    """
    p = _write_json(list(_REACH_RECORDS) + [
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(200, p, "", "")
        assert not degraded, f"nonzero-rc-with-reach misclassified: {reason!r}"
    finally:
        p.unlink()


def test_service_only_no_protocol_is_NOT_degraded():
    """4.8's wording: "a `service` record (or any `TLS1_x` protocol
    record) present and no diagnostic marker → NOT degraded." `service`
    alone (no TLS1_x) qualifies as reach evidence per spec — testssl
    identified the protocol on the port, which is a meaningful probe
    even if it didn't complete the protocol-detect battery.
    """
    p = _write_json([
        {"id": "service", "ip": "host/1.2.3.4", "port": "443",
         "severity": "INFO", "finding": "HTTPS"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"service-only misclassified: {reason!r}"
    finally:
        p.unlink()


def test_tls1x_only_no_service_is_NOT_degraded():
    """And the other half of the OR: any TLS1_x record alone is also
    reach evidence (we got far enough to probe a protocol)."""
    p = _write_json([
        {"id": "TLS1_3", "ip": "host/1.2.3.4", "port": "443",
         "severity": "OK", "finding": "offered"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"TLS1_3-only misclassified: {reason!r}"
    finally:
        p.unlink()


# ─── testssl_is_degraded — DEGRADED cases (must be degraded) ────────────

def test_tool_missing_rc127_is_degraded():
    """testssl.sh not installed: rc=127. Auto-closer must NOT credit this
    run with coverage — otherwise it'd false-close every prior testssl
    finding on the asset.
    """
    degraded, reason = testssl_is_degraded(
        127, Path("/nonexistent/missing.json"), "",
        "bash: testssl.sh: command not found",
    )
    assert degraded, "rc=127 must be degraded (tool missing)"
    assert "tool_missing" in reason or "no_jsonfile" in reason, f"got {reason!r}"


def test_wall_timeout_rc124_is_degraded():
    """Subprocess killed by `timeout` wrapper (rc=124). Tool didn't
    finish its handshake battery — degraded.
    """
    degraded, reason = testssl_is_degraded(
        124, Path("/nonexistent/timed_out.json"), "", "",
    )
    assert degraded, "rc=124 must be degraded (timeout)"
    assert "wall_timeout" in reason or "no_jsonfile" in reason, f"got {reason!r}"


def test_missing_jsonfile_is_degraded():
    """Even rc=0 isn't enough if testssl didn't write its output file —
    we have nothing to parse. Degraded.
    """
    degraded, reason = testssl_is_degraded(
        0, Path("/nonexistent/never_created.json"), "", "",
    )
    assert degraded, "missing jsonfile must be degraded"
    assert reason == "no_jsonfile", f"got {reason!r}"


def test_empty_jsonfile_is_degraded():
    """testssl crashed before emitting anything. Empty file → degraded."""
    f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    f.close()
    p = Path(f.name)
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "empty jsonfile must be degraded"
        assert reason == "empty_jsonfile", f"got {reason!r}"
    finally:
        p.unlink()


def test_garbage_json_is_degraded():
    """Output file exists but isn't valid JSON. Degraded — can't trust it."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    f.write("{not valid json at all")
    f.close()
    p = Path(f.name)
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "unparseable JSON must be degraded"
        assert reason.startswith("json_parse_failed"), f"got {reason!r}"
    finally:
        p.unlink()


def test_jsonfile_pretty_shape_is_degraded():
    """Mistakenly used --jsonfile-pretty (object root, not list). The
    parser expects the flat record array; a nested-object root means we
    can't read the records. Degraded — this is the safety guard against
    a future flag-set drift breaking the auto-closer.
    """
    p = _write_json({"scanResult": []})
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "nested-object JSON shape must be degraded"
        assert reason == "unexpected_json_shape", f"got {reason!r}"
    finally:
        p.unlink()


def test_nonzero_rc_with_no_reach_records_is_degraded():
    """testssl exited non-zero AND produced no reach records → degraded.
    The combination signals a crash before the protocol-detect battery
    completed. Reason slug encodes both signals so forensics can tell
    "exited nonzero with no reach" apart from the generic
    "no_reach_evidence" path.
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(2, p, "", "")
        assert degraded, "nonzero-rc + no reach must be degraded"
        assert reason.startswith("nonzero_rc_no_reach_evidence:"), f"got {reason!r}"
    finally:
        p.unlink()


# ─── testssl_is_degraded — host-unreachable cases (reach-based gate) ────

def test_rc_zero_empty_array_IS_degraded():
    """Empty JSON array — no reach evidence. Degraded.
    (Pre-87f09d4 this was treated as a valid negative; the safety fix
    + reach gate both reject it.)
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "empty JSON array must be degraded (no reach evidence)"
        assert reason == "no_reach_evidence", f"got {reason!r}"
    finally:
        p.unlink()


def test_engine_problem_only_IS_degraded():
    """THE original bug 4.8 caught. Host unreachable: testssl emits only
    engine_problem records at WARN severity. No reach evidence + a
    diagnostic marker → DEGRADED with the diagnostic-marker slug.
    Auto-closer doesn't credit testssl.sh coverage → backlog stays
    intact (correct).
    """
    p = _write_json([
        {"id": "engine_problem", "ip": "/", "port": "443",
         "severity": "WARN", "finding": "TCP connection refused"},
        {"id": "engine_problem", "ip": "/", "port": "443",
         "severity": "WARN", "finding": "scan aborted"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "engine_problem-only output must be degraded"
        assert reason == "tool_diagnostic_records_only", f"got {reason!r}"
    finally:
        p.unlink()


def test_scanproblem_only_IS_degraded():
    """Variant of the above: scanProblem records also trip the
    diagnostic-marker gate. Must be DEGRADED.
    """
    p = _write_json([
        {"id": "scanProblem", "ip": "host/1.2.3.4", "port": "443",
         "severity": "FATAL", "finding": "could not connect"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "scanProblem-only output must be degraded"
        assert reason == "tool_diagnostic_records_only", f"got {reason!r}"
    finally:
        p.unlink()


def test_overall_grade_only_no_reach_IS_degraded():
    """overall_grade record alone — no `service`, no TLS1_x, no
    diagnostic marker. Pre-#2 this had `service` in it and was
    asserted degraded (wrong by the reach-based rule, since `service`
    IS reach evidence). Reworked: drop `service` so the assertion holds
    via the no_reach_evidence path. Realistic shape: testssl somehow
    emitted only the scorecard preamble without protocol identification
    — unusual but degradation if it happens.
    """
    p = _write_json([
        {"id": "overall_grade", "severity": "OK", "finding": "A"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "scorecard-without-reach must be degraded"
        assert reason == "no_reach_evidence", f"got {reason!r}"
    finally:
        p.unlink()


def test_diagnostic_plus_reach_IS_degraded():
    """FLIPPED from pre-#2 — diagnostic marker now wins UNCONDITIONALLY.
    Mixed engine_problem + cipher LOW record: testssl got a partial
    result but logged a connection problem, so we can't trust the
    verdict on what was missed. Conservative call per 4.8: diagnostic
    marker present → degraded, period. Auto-closer doesn't credit
    coverage; backlog stays intact until a clean re-scan.
    """
    p = _write_json(list(_REACH_RECORDS) + [
        {"id": "engine_problem", "ip": "/", "port": "443",
         "severity": "WARN", "finding": "scan interrupted"},
        {"id": "cipher-tls1_2_xc028", "ip": "host/1.2.3.4", "port": "443",
         "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "diagnostic-marker-with-reach must be degraded (conservative)"
        assert reason == "tool_diagnostic_records_only", f"got {reason!r}"
    finally:
        p.unlink()


# ─── Test driver — bare-Python fallback when pytest isn't installed ─────

def _all_tests():
    """Return the list of test functions defined in this module."""
    return [
        v for k, v in globals().items()
        if k.startswith("test_") and callable(v)
    ]


def main() -> int:
    """Run every test_* function. Returns 0 on all-pass, 1 on any fail."""
    tests = _all_tests()
    failed: list[tuple[str, str]] = []
    for t in tests:
        name = t.__name__
        try:
            t()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append((name, str(e)))
            print(f"  FAIL  {name}: {e}")
        except Exception as e:
            failed.append((name, f"{type(e).__name__}: {e}"))
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print()
    print(f"{len(tests) - len(failed)} / {len(tests)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
