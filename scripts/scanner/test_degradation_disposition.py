#!/usr/bin/env python3
"""test_degradation_disposition.py — the producer→disposition INVARIANT.

Audit Obsidian 193 + 4.7 correction 2026-08-29. The audit's durable finding is
that whether a degradation aborts the scan or merely degrades is determined
MECHANICALLY by which function produced the reason slug. The correction: encode
that structurally (typed producer output), never as a slug lookup table — a
table drifts, and its failure DIRECTION is a harm-condition silently degrading,
i.e. a scan that keeps hammering a target that already banned us.

These tests assert the INVARIANT AT THE PRODUCER, not a list of strings:

  * every slug `is_tool_output_degraded` can return maps to abort — enumerated
    from its AST, so ADDING a slug without making it abort FAILS here
  * every slug `testssl_is_degraded` can emit is EXPLICITLY classified — so a
    new slug cannot ride the conservative default unnoticed
  * the always-abort / always-degrade producers cannot be talked out of it

Run: python3 test_degradation_disposition.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from degradation import (Degradation, ABORT_SCAN, DEGRADED,  # noqa: E402
                         egress_degradation, b1_degradation, tool_degradation,
                         is_tool_output_degraded)
from run_heavy import (testssl_degradation,  # noqa: E402
                       _TESTSSL_ABORT_SLUGS, _TESTSSL_DEGRADE_SLUGS)

HERE = pathlib.Path(__file__).parent


def _returned_str_literals(path: str, fnname: str) -> set[str]:
    """Every string a function can RETURN, read from the AST.

    Enumerating from source (not from a hand-kept list) is what makes these
    tests catch a NEW slug. Handles bare returns, tuple returns like
    `(True, 'no_reach_evidence')`, and f-strings (recorded by their literal
    prefix, e.g. 'nonzero_rc_no_reach_evidence')."""
    tree = ast.parse((HERE / path).read_text())
    out: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == fnname):
            continue
        for r in ast.walk(node):
            if not isinstance(r, ast.Return) or r.value is None:
                continue
            vals = (r.value.elts if isinstance(r.value, ast.Tuple) else [r.value])
            for v in vals:
                if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                    out.add(v.value)
                elif isinstance(v, ast.JoinedStr):      # f-string slug
                    lead = "".join(p.value for p in v.values
                                   if isinstance(p, ast.Constant) and isinstance(p.value, str))
                    if lead:
                        out.add(lead.rstrip(":"))
    return out


# ── the always-abort producers ──────────────────────────────────────────────

def test_every_b1_slug_aborts_enumerated_from_source():
    """🔴 THE LOAD-BEARING ONE. All of is_tool_output_degraded's slugs mean "we
    could not reach the target", so "no findings" is not evidence of no
    findings. Enumerated from the AST: add a slug there and this test forces you
    to confirm it aborts."""
    slugs = _returned_str_literals("degradation.py", "is_tool_output_degraded")
    assert slugs, "enumeration found nothing — the AST walk is broken, not the code"
    assert len(slugs) >= 3, f"expected >=3 B1 slugs, found {slugs}"
    for s in slugs:
        assert b1_degradation(s).disposition == ABORT_SCAN, s


def test_b1_producer_cannot_yield_degraded():
    """The producer, not the call site, decides. No argument changes the class."""
    for s in ("anything", "", "parse_failed"):
        assert b1_degradation(s).aborts


def test_egress_producer_always_aborts():
    """ensure_healthy_egress fires only after rotations are exhausted; its
    artifact records banned:True."""
    for s in ("vpn_unhealthy", "probe_403", ""):
        assert egress_degradation(s).disposition == ABORT_SCAN


def test_tool_producer_always_degrades():
    """<tool>_is_degraded: target reachable, one tool unusable — keep scanning."""
    for s in ("parse_failed", "output_unreadable", "nikto_runtime_error"):
        assert tool_degradation(s).disposition == DEGRADED


# ── the one straddler ───────────────────────────────────────────────────────

def test_every_testssl_slug_is_explicitly_classified():
    """🔴 The straddler must have NO unclassified slug. testssl_degradation
    defaults unknown slugs to ABORT (fail-closed), which is safe in production
    but would let a new slug ride the default forever — this test is what makes
    the omission loud."""
    emitted = _returned_str_literals("run_heavy.py", "testssl_is_degraded")
    assert len(emitted) >= 9, f"enumeration looks wrong, found {emitted}"
    known = set(_TESTSSL_ABORT_SLUGS) | set(_TESTSSL_DEGRADE_SLUGS)
    unclassified = {s for s in emitted if s.split(":", 1)[0] not in known}
    assert not unclassified, (
        f"testssl slug(s) not explicitly classified: {sorted(unclassified)} — "
        "add to _TESTSSL_ABORT_SLUGS or _TESTSSL_DEGRADE_SLUGS")


def test_testssl_reachability_slugs_abort():
    """These ARE the reachability anchor failing, reported via testssl."""
    for s in ("no_reach_evidence", "nonzero_rc_no_reach_evidence:3"):
        assert testssl_degradation(s).disposition == ABORT_SCAN, s


def test_testssl_scan_incomplete_aborts_conservatively():
    """4.7 ratified 2026-08-29: truncation on a WAF-fronted host is a plausible
    ban signature. Wrong abort = slower re-scan; wrong continue = false-clean
    recorded + more traffic at a banning target."""
    assert testssl_degradation("scan_incomplete").disposition == ABORT_SCAN


def test_testssl_tool_problems_degrade_not_abort():
    """🔴 THE ANCHOR DISTINCTION. The anchor is the reachability CONDITION, not
    testssl-the-tool. A missing binary or a timeout must NOT kill a 16-phase
    cumulative run."""
    for s in ("tool_missing", "wall_timeout", "no_jsonfile", "empty_jsonfile",
              "unexpected_json_shape", "stat_failed", "json_parse_failed:ValueError"):
        assert testssl_degradation(s).disposition == DEGRADED, s


def test_unknown_testssl_slug_fails_closed_to_abort():
    """A reason we cannot classify is treated as the dangerous case."""
    assert testssl_degradation("brand_new_mystery_slug").aborts


def test_suffixed_slugs_match_on_prefix():
    """Slugs carry suffixes (`json_parse_failed:ValueError`); disposition must
    survive the suffix, and the full reason must be preserved for forensics."""
    d = testssl_degradation("json_parse_failed:ValueError")
    assert d.disposition == DEGRADED
    assert d.reason == "json_parse_failed:ValueError"


# ── the type itself ─────────────────────────────────────────────────────────

def test_degradation_is_immutable():
    """The disposition must not be re-writable downstream — that would put the
    classification back at the call site, which is what this design removes."""
    d = b1_degradation("target_unreachable_after_run")
    try:
        d.disposition = DEGRADED
    except AttributeError:
        return
    raise AssertionError("Degradation allowed mutation of its disposition")


def test_unknown_disposition_rejected():
    try:
        Degradation("x", "sort_of_bad")
    except ValueError:
        return
    raise AssertionError("unknown disposition accepted")


def test_b1_helper_agrees_with_the_real_detector():
    """Belt and braces: exercise the REAL detector and confirm the reason it
    returns is abort-class. post_health=False is the banned-mid-tool case."""
    reason = is_tool_output_degraded("nuclei", "", "", 0,
                                     pre_health=True, post_health=False)
    assert reason == "target_unreachable_after_run"
    assert b1_degradation(reason).aborts


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 12, f"expected >=12 tests, collected {len(tests)}"
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{len(tests) - failed} / {len(tests)} passed")
    sys.exit(1 if failed else 0)
