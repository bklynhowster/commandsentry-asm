#!/usr/bin/env python3
"""test_waf_context_plan.py — the nuclei plan MUST see WAF context (spec 194/195).

WHY. 4.7 named this the 5th risk on step 4 and my verification confirmed it is
real, not hypothetical: `build_chunk_plan` decides between the FortiGate
SAFE-ONLY plan, a softened rate, and the aggressive stack-aware plan by reading
IN-SCAN MUTABLE STATE — `ctx.waf_kind` / `ctx.waf_detected`, set by
`run_wafw00f`. Cumulative heavy will run nuclei; if the WAF context is not
populated by then, heavy fires the AGGRESSIVE plan at a WAF-fronted target,
which is the precise self-inflicted ban the safe-only branch exists to avoid.

These tests lock the two branch behaviours the cumulative ordering depends on.
The third test 4.7 asked for — that wafw00f is ORDERED before nuclei — needs the
ordered cumulative selection that lands in increment 3, and belongs with it.

Run: python3 test_waf_context_plan.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from run_medium import (build_chunk_plan, needs_softened_rate,  # noqa: E402
                        is_fortigate_target, ScanContext)

SRC = (pathlib.Path(__file__).parent / "run_heavy.py").read_text()


def _ctx(**kw) -> ScanContext:
    """A ScanContext with only the fields these branches read."""
    ctx = ScanContext.__new__(ScanContext)
    ctx.hostname = kw.get("hostname", "example.com")
    ctx.waf_detected = kw.get("waf_detected", False)
    ctx.waf_kind = kw.get("waf_kind", None)
    ctx.tech_stack = set(kw.get("tech_stack", ()))
    return ctx


# ── the FortiGate safe-only branch ─────────────────────────────────────────

def test_fortigate_context_yields_the_safe_only_plan():
    """🔴 'Broad templates proven to ban every time on these targets.' With
    waf_kind='fortiweb' the plan must collapse to the 5 safe chunks — breadth
    via IP rotation, not via templates."""
    plan = build_chunk_plan(_ctx(waf_kind="fortiweb", waf_detected=True))
    assert len(plan) == 5, f"expected 5 safe chunks, got {len(plan)}: {plan}"
    assert all(sev == "medium" and tag == "tech" for sev, tag, _desc in plan), plan


def test_without_waf_context_a_fortigate_target_gets_the_AGGRESSIVE_plan():
    """🔴 THE RISK, MADE EXPLICIT. Same host, no WAF context populated → the
    broad `critical,high` chunk is planned. This is exactly what happens if
    wafw00f has not run before nuclei plans in a cumulative heavy, and it is why
    ordering is load-bearing rather than cosmetic."""
    plan = build_chunk_plan(_ctx(waf_kind=None, waf_detected=False))
    sevs = [sev for sev, _tag, _d in plan]
    assert "critical,high" in sevs, (
        "no-WAF-context plan should include the broad chunk — if this changed, "
        "re-derive the risk this whole test file documents")
    assert len(plan) != 5 or sevs != ["medium"] * 5


# ── the softened-rate branch (what waf_differential can earn) ──────────────

def test_waf_detected_alone_triggers_the_softened_rate():
    """waf_differential is presence-only: it can set waf_detected but never
    waf_kind. needs_softened_rate() keys on waf_detected, so a behavioural WAF
    positive still earns the gentler rate."""
    assert needs_softened_rate(_ctx(waf_detected=True)) is True


def test_no_waf_and_no_wordpress_needs_no_softening():
    assert needs_softened_rate(_ctx()) is False


def test_fortigate_does_not_double_up_softening():
    """FortiGate targets get PATIENT mode, which already includes the slower
    rate plus cooldowns. Softening on top would be redundant."""
    assert needs_softened_rate(_ctx(waf_kind="fortiweb", waf_detected=True)) is False


# ── the wiring that makes the above reachable from heavy ───────────────────

def test_waf_differential_sets_waf_detected_not_waf_kind():
    """🔴 THE INCREMENT-2 WIRING. A behavioural WAF positive must feed the plan
    context — but presence-only, so it must NOT claim a vendor. Asserting the
    ABSENCE of a waf_kind write matters as much as the presence of the
    waf_detected write: claiming a vendor from behaviour would let the
    FortiGate-safe branch fire on evidence that cannot support it."""
    import ast
    tree = ast.parse(SRC)
    body = None
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == "run_waf_differential_probe_phase":
            body = ast.unparse(n)
    assert body, "run_waf_differential_probe_phase not found"
    assert "ctx.waf_detected = True" in body, (
        "waf_differential must feed ctx.waf_detected so nuclei softens its rate")
    assert "ctx.waf_kind" not in body, (
        "presence-only probe must NEVER set waf_kind (names no vendor)")


def test_heavy_context_carries_the_waf_fields():
    """HeavyScanContext must actually have the fields for the wiring to land on."""
    from run_heavy import HeavyScanContext
    import dataclasses
    names = {f.name for f in dataclasses.fields(HeavyScanContext)}
    assert {"waf_detected", "waf_kind"} <= names, names


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 7, f"expected >=7 tests, collected {len(tests)}"
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
