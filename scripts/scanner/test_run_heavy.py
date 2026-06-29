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
# Note 129 follow-up (4.8 verify of 87f09d4): a valid negative now
# requires POSITIVE EVIDENCE the host was actually reached + scanned —
# at least one record that survives the parser's drop list
# (cs_parsers/testssl.py SKIP_SEVERITIES + SCORECARD_IDS). Pre-fix the
# detector said "rc=0 + parseable non-empty array = valid negative,"
# which let unreachable-host runs (only engine_problem records) read
# as clean scans → note-127 auto-closer would false-close the entire
# testssl backlog. The new gate prevents that.

def _write_json(payload, suffix=".json") -> Path:
    """Helper: write JSON to a temp file, return its Path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    json.dump(payload, f)
    f.close()
    return Path(f.name)


def test_rc_zero_with_low_cipher_record_is_NOT_degraded():
    """Real testssl on a host with TLS: rc=0, contains LOW-severity
    cipher records. parse_testssl_file would emit at least one
    FindingEvent → positive evidence the host was reached + scanned →
    valid scan. Auto-closer can credit testssl.sh coverage.
    """
    p = _write_json([
        {"id": "cipher-tls1_2_xc028", "ip": "host/1.2.3.4", "port": "443",
         "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"valid negative misclassified as degraded: {reason!r}"
        assert reason == "", f"reason should be empty for valid scan, got {reason!r}"
    finally:
        p.unlink()


def test_rc_zero_with_named_attack_record_is_NOT_degraded():
    """Real testssl with a named-attack finding: rc=0, MEDIUM severity
    record that survives the parser's drop list. NOT degraded."""
    p = _write_json([
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"healthy scan misclassified as degraded: {reason!r}"
    finally:
        p.unlink()


def test_nonzero_rc_with_eligible_record_is_NOT_degraded():
    """testssl frequently returns rc!=0 on findings (rc reflects severity
    count, not failure). As long as at least one eligible record exists,
    the scan IS clean — the data is what matters. Without this carve-out
    we'd flip every productive testssl scan to degraded.
    """
    p = _write_json([
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(200, p, "", "")
        assert not degraded, f"nonzero-rc-with-records misclassified: {reason!r}"
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


def test_nonzero_rc_with_empty_records_is_degraded():
    """testssl exited non-zero AND produced zero records → degraded.
    rc!=0 + no eligible records is the crash shape, not the findings
    shape. Reason slug encodes both signals so forensics can tell
    "exited nonzero with nothing parseable" apart from the generic
    "produced records but all got dropped" path.
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(2, p, "", "")
        assert degraded, "nonzero-rc + empty records must be degraded"
        assert reason.startswith("nonzero_rc_no_eligible_records:"), f"got {reason!r}"
    finally:
        p.unlink()


# ─── testssl_is_degraded — host-unreachable cases (4.8 verify safety fix) ─

def test_rc_zero_empty_array_IS_degraded():
    """Empty JSON array. Pre-fix this was treated as "valid negative"
    (host has no TLS, no findings to report). Post-fix: an empty array
    means testssl emitted nothing at all — not even diagnostic records
    — which is a crash shape, not a clean-no-findings shape. DEGRADED
    (no_eligible_records). The "real testssl on a clean modern TLS
    endpoint" case ALWAYS emits at least cipher records that survive
    the drop list; an empty array means we didn't actually scan.
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "empty JSON array must be degraded (no positive evidence)"
        assert reason == "no_eligible_records", f"got {reason!r}"
    finally:
        p.unlink()


def test_engine_problem_only_IS_degraded():
    """THE bug 4.8 caught. Host unreachable: testssl emits only
    engine_problem records at WARN severity. The offline parser drops
    these (severity in SKIP_SEVERITIES + id in SCORECARD_IDS) → returns
    0 events. Pre-fix the live detector saw rc=0 + parseable non-empty
    array and called it valid-negative → scan_run marked complete →
    note-127 auto-closer credited testssl.sh coverage → false-closed
    the entire prior testssl backlog for the asset. Post-fix: this
    case MUST be DEGRADED with the diagnostic-marker slug.
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
    """Variant of the above: scanProblem records (also in SCORECARD_IDS)
    indicate testssl failed to scan. Must be DEGRADED with the
    diagnostic-marker slug — auto-closer doesn't credit coverage.
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


def test_scorecard_meta_only_IS_degraded():
    """testssl emitted only overall_grade / service meta records — no
    cipher / protocol / named-attack records. Without positive evidence
    of a TLS evaluation, we don't credit testssl.sh coverage. DEGRADED
    with the generic no_eligible_records slug (no diagnostic marker
    here, so we can't claim "unreachable" specifically).
    """
    p = _write_json([
        {"id": "overall_grade", "severity": "OK", "finding": "A"},
        {"id": "service", "severity": "INFO", "finding": "HTTPS"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "scorecard/meta-only output must be degraded"
        assert reason == "no_eligible_records", f"got {reason!r}"
    finally:
        p.unlink()


def test_all_skipped_severities_IS_degraded():
    """Output contains only WARN / OK / DEBUG / INFO severity records.
    parse_testssl_file would drop every one (SKIP_SEVERITIES gate) →
    0 events. Positive-evidence gate must reject this → DEGRADED.
    Tests the severity half of the drop list independent of the
    SCORECARD_IDS half.
    """
    p = _write_json([
        {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
        {"id": "ALPN", "severity": "INFO", "finding": "h2,http/1.1"},
        {"id": "some_diagnostic", "severity": "DEBUG", "finding": "..."},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "all-skipped-severity output must be degraded"
        assert reason == "no_eligible_records", f"got {reason!r}"
    finally:
        p.unlink()


def test_diagnostic_plus_eligible_record_is_NOT_degraded():
    """Mixed output: engine_problem AND at least one real finding. The
    positive evidence (cipher LOW record) wins — testssl actually got
    far enough to evaluate at least one part of the TLS stack, so the
    scan IS real. Auto-closer can credit coverage. (Realistic shape:
    a partial TLS handshake that surfaces one cipher before the
    connection drops, recording an engine_problem alongside it.)
    """
    p = _write_json([
        {"id": "engine_problem", "ip": "/", "port": "443",
         "severity": "WARN", "finding": "scan interrupted"},
        {"id": "cipher-tls1_2_xc028", "ip": "host/1.2.3.4", "port": "443",
         "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"mixed-eligible scan misclassified: {reason!r}"
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
