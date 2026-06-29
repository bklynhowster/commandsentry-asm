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

def _write_json(payload, suffix=".json") -> Path:
    """Helper: write JSON to a temp file, return its Path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    json.dump(payload, f)
    f.close()
    return Path(f.name)


def test_rc_zero_empty_array_is_NOT_degraded():
    """Real testssl on a no-TLS host: rc=0, valid empty JSON array. This
    IS the "valid negative" outcome — scan must register as complete +
    0 findings. The note-127 auto-closer will then correctly treat the
    asset as having been scanned with no current TLS findings.
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"valid negative misclassified as degraded: {reason!r}"
        assert reason == "", f"reason should be empty for valid scan, got {reason!r}"
    finally:
        p.unlink()


def test_rc_zero_populated_records_is_NOT_degraded():
    """Real testssl with findings: rc=0, populated JSON array. NOT degraded."""
    p = _write_json([{"id": "TLS1", "severity": "LOW", "finding": "offered"}])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"healthy scan misclassified as degraded: {reason!r}"
    finally:
        p.unlink()


def test_nonzero_rc_with_records_is_NOT_degraded():
    """testssl frequently returns rc!=0 on findings (rc reflects severity
    count, not failure). As long as records parsed, the scan IS clean —
    the data is what matters. Without this carve-out we'd flip every
    productive testssl scan to degraded.
    """
    p = _write_json([{"id": "BEAST", "severity": "MEDIUM", "finding": "detected"}])
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
    Distinguishes "rc!=0 because findings exist" (clean) from "rc!=0
    because something broke" (degraded). Empty + nonzero rc is the
    crash shape, not the findings shape.
    """
    p = _write_json([])
    try:
        degraded, reason = testssl_is_degraded(2, p, "", "")
        assert degraded, "nonzero-rc + empty records must be degraded"
        assert reason.startswith("nonzero_rc_empty_records:"), f"got {reason!r}"
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
