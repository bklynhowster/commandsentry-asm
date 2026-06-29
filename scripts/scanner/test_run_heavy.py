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
# Note 129 follow-up #3 (4.8 re-verify of 4c149cd, live heavy run #794):
# the discriminator is reach AND completion. has_completion uses
# testssl's own end-of-run markers (overall_grade OR scanTime). All
# NOT-degraded fixtures carry both reach and completion records to
# match what a real complete testssl run emits. Round-3 had a
# "diagnostic wins unconditionally" rule that mis-degraded the real
# heavy run on demo.testfire.net — dropped in this round.

def _write_json(payload, suffix=".json") -> Path:
    """Helper: write JSON to a temp file, return its Path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    json.dump(payload, f)
    f.close()
    return Path(f.name)


# Realistic complete-scan fixture — what every reached + finished
# testssl scan produces. service (protocol ident) + TLS1_x (probe
# battery) + overall_grade (final scorecard) + scanTime (end-of-run
# stamp). Used in NOT-degraded tests so fixtures match real testssl
# output shape.
_COMPLETE_SCAN_RECORDS = [
    {"id": "service", "ip": "host/1.2.3.4", "port": "443",
     "severity": "INFO", "finding": "HTTPS"},
    {"id": "TLS1_3", "ip": "host/1.2.3.4", "port": "443",
     "severity": "OK", "finding": "offered"},
    {"id": "TLS1_2", "ip": "host/1.2.3.4", "port": "443",
     "severity": "OK", "finding": "offered"},
    {"id": "overall_grade", "ip": "host/1.2.3.4", "port": "443",
     "severity": "OK", "finding": "A"},
    {"id": "scanTime", "ip": "host/1.2.3.4", "port": "443",
     "severity": "INFO", "finding": "98s"},
]


def test_complete_scan_zero_findings_is_NOT_degraded():
    """Reachable + fully-remediated host: complete scan, zero LOW+
    findings. THE success state v1 exists to detect — auto-closer
    credits coverage and closes the prior backlog. Round-2 over-flagged
    this as degraded; round-3 over-flagged it differently; round-4
    (completion-marker gate) gets it right.
    """
    p = _write_json(list(_COMPLETE_SCAN_RECORDS))
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"clean-modern-TLS misclassified: {reason!r}"
        assert reason == "", f"reason should be empty for clean scan, got {reason!r}"
    finally:
        p.unlink()


def test_complete_scan_with_engine_problem_warn_is_NOT_degraded():
    """4.8 regression: the live-heavy-run-#794 shape. Full real scan
    (service + TLS1_x + overall_grade + scanTime, 195 records) that
    ALSO carries a non-fatal engine_problem WARN (OCSP hiccup,
    STARTTLS quirk — routine in real testssl output). Round-3's
    "diagnostic wins unconditionally" rule mis-degraded this; round-4
    treats completion as the trust signal and ignores the WARN.
    """
    p = _write_json(list(_COMPLETE_SCAN_RECORDS) + [
        {"id": "engine_problem", "ip": "host/1.2.3.4", "port": "443",
         "severity": "WARN", "finding": "OCSP stapling: unable to fetch responder"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, (
            f"real complete scan with non-fatal e_p WARN misclassified: "
            f"{reason!r} — this WAS heavy run #794 mis-degrade"
        )
        assert reason == ""
    finally:
        p.unlink()


def test_complete_scan_with_low_cipher_record_is_NOT_degraded():
    """Complete scan + a LOW-severity cipher finding. NOT degraded."""
    p = _write_json(list(_COMPLETE_SCAN_RECORDS) + [
        {"id": "cipher-tls1_2_xc028", "ip": "host/1.2.3.4", "port": "443",
         "severity": "LOW", "finding": "TLSv1.2  xc028  ECDHE-RSA-AES256-SHA384"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"valid scan misclassified: {reason!r}"
    finally:
        p.unlink()


def test_complete_scan_with_named_attack_record_is_NOT_degraded():
    """Complete scan + a MEDIUM-severity named-attack finding. NOT degraded."""
    p = _write_json(list(_COMPLETE_SCAN_RECORDS) + [
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"healthy scan misclassified: {reason!r}"
    finally:
        p.unlink()


def test_nonzero_rc_with_complete_scan_is_NOT_degraded():
    """testssl frequently returns rc!=0 on findings. Completion records
    present → NOT degraded regardless of exit code.
    """
    p = _write_json(list(_COMPLETE_SCAN_RECORDS) + [
        {"id": "BEAST", "severity": "MEDIUM", "finding": "detected"},
    ])
    try:
        degraded, reason = testssl_is_degraded(200, p, "", "")
        assert not degraded, f"nonzero-rc-with-completion misclassified: {reason!r}"
    finally:
        p.unlink()


def test_service_only_plus_completion_is_NOT_degraded():
    """`service` alone satisfies the reach half (per 4.8's OR-wording).
    Pair with completion records → NOT degraded. Verifies the reach
    branch of `service OR TLS1_x` independently of full _COMPLETE_SCAN
    fixture.
    """
    p = _write_json([
        {"id": "service", "ip": "host/1.2.3.4", "port": "443",
         "severity": "INFO", "finding": "HTTPS"},
        {"id": "overall_grade", "ip": "host/1.2.3.4", "port": "443",
         "severity": "OK", "finding": "A"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"service+completion misclassified: {reason!r}"
    finally:
        p.unlink()


def test_tls1_legacy_id_satisfies_reach():
    """testssl emits `TLS1` (NOT `TLS1_0`) for the TLS 1.0 probe.
    Round-3 had the ID wrong; round-4 fixes the reach set. Verify the
    canonical token works as reach evidence.
    """
    p = _write_json([
        {"id": "TLS1", "ip": "host/1.2.3.4", "port": "443",
         "severity": "OK", "finding": "not offered"},
        {"id": "scanTime", "ip": "host/1.2.3.4", "port": "443",
         "severity": "INFO", "finding": "98s"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"TLS1+completion misclassified: {reason!r}"
    finally:
        p.unlink()


def test_completion_via_scantime_alone_is_NOT_degraded():
    """has_completion is OR (overall_grade OR scanTime). scanTime alone
    paired with reach proves end-of-run; NOT degraded.
    """
    p = _write_json([
        {"id": "service", "severity": "INFO", "finding": "HTTPS"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
        {"id": "scanTime", "severity": "INFO", "finding": "98s"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert not degraded, f"scanTime-alone completion misclassified: {reason!r}"
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
    started. Reason slug encodes both signals so forensics can tell
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


# ─── testssl_is_degraded — host-unreachable + truncated cases ───────────

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
    engine_problem records at WARN severity. No reach + no completion →
    DEGRADED via the no_reach_evidence path (round-3's standalone
    diagnostic-marker slug is gone — engine_problem-only lands here
    via the reach gate, which is the sufficient signal).
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
        assert reason == "no_reach_evidence", f"got {reason!r}"
    finally:
        p.unlink()


def test_scanproblem_only_IS_degraded():
    """Variant of the above: scanProblem records also produce no reach
    evidence → DEGRADED via no_reach_evidence.
    """
    p = _write_json([
        {"id": "scanProblem", "ip": "host/1.2.3.4", "port": "443",
         "severity": "FATAL", "finding": "could not connect"},
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "scanProblem-only output must be degraded"
        assert reason == "no_reach_evidence", f"got {reason!r}"
    finally:
        p.unlink()


def test_overall_grade_only_no_reach_IS_degraded():
    """overall_grade alone — has_completion=True but has_reach=False.
    Order matters: NO REACH wins regardless of completion (you can't
    have a valid scan without reach). Slug = no_reach_evidence.
    Realistic shape: scorecard preamble without any protocol probe —
    unusual but defensively flagged.
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


def test_reach_without_completion_IS_degraded():
    """Truncated scan: testssl reached the host (service + TLS1_x
    records present) but the scan was interrupted before scoring
    (no overall_grade, no scanTime). 4.8's truncation guard — even
    with reach, we don't trust a partial verdict. DEGRADED scan_incomplete.
    """
    p = _write_json([
        {"id": "service", "severity": "INFO", "finding": "HTTPS"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
        {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
        # NOTE: no overall_grade, no scanTime — the truncation signature.
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "reach-without-completion must be degraded"
        assert reason == "scan_incomplete", f"got {reason!r}"
    finally:
        p.unlink()


def test_reach_truncated_with_engine_problem_IS_degraded():
    """Variant: reached the host, hit a problem mid-scan, never emitted
    completion. Slug = scan_incomplete (the reach+no-completion path).
    Demonstrates the truncation guard catches "interrupted-with-diagnostic"
    cases that pre-#3 needed the diagnostic-wins rule to flag.
    """
    p = _write_json([
        {"id": "service", "severity": "INFO", "finding": "HTTPS"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
        {"id": "engine_problem", "severity": "WARN",
         "finding": "scan interrupted mid-handshake"},
        # No overall_grade / scanTime → truncated.
    ])
    try:
        degraded, reason = testssl_is_degraded(0, p, "", "")
        assert degraded, "truncated scan with e_p must be degraded"
        assert reason == "scan_incomplete", f"got {reason!r}"
    finally:
        p.unlink()


# ─── regress-on-observed (round 6 — centralized SQL helper) ────────────
#
# Note 129 round 6: regression logic moved from a Python helper in
# run_heavy to a shared SQL function (migration 20260629a)
# regress_observed_for_scan_run(scan_run_id, source) that both medium
# AND heavy call — mirror of delta_close_for_scan_run.
#
# Round-4's Python-helper unit tests + mock-cursor scaffolding were
# retired with the helper. The SQL fn is the single source of truth
# now; its idempotency / disjoint-from-delta_close / 126-invariant
# properties live in the migration body + comment block. 4.8's
# live-verify gates (REGRESSION_CENTRALIZATION_SPEC.md):
#   1. Re-run heavy on ftp.sciimage.com → cert_chain_of_trust stays
#      regressed, NO new auto_regress_observed audit row (idempotency).
#   2. Engineer a medium remediated→re-observe case → flips to
#      regressed + remediated_at cleared + one audit row, nothing
#      unseen got touched.
#   3. Confirm heavy still flips a freshly-engineered remediated
#      testssl finding (parity with the retired Python helper —
#      same behavior via the new shared path).
#
# Unit-test surface in this file narrows to testssl_is_degraded
# (above). DB-coupled tests would force a Supabase dep into the
# suite; the migration's sanity-queries section + 4.8's gates cover
# the function-body verification.


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
