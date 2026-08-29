#!/usr/bin/env python3
"""test_phase_contract.py — MECHANISM tests for the @phase executor (spec 190/191).

WHY THESE ARE MECHANISM TESTS, NOT OUTCOME TESTS. 4.7's 5th risk (ruling 191):
centralising ~150 hand-written bookkeeping calls makes phase_contract.py
load-bearing for EVERY phase — a bug here hits all phases uniformly, where the
old hand-wiring failed one tool at a time. So each of the executor's five
obligations gets a test that FAILS IF THE OBLIGATION IS BROKEN, and each was
mutation-verified against the real failure mode it guards:

  obligation 1 (credit AFTER work)  ← mutate: move the append above spec.fn()
  obligation 2 (tool_status lockstep) ← mutate: skip the mark_* call
  obligation 3 (artifacts always)   ← mutate: guard the append on outcome==OK
  obligation 4 (source by tier)     ← mutate: tag from ctx.intensity
  degradation taxonomy              ← mutate: convert ABORT_SCAN to DEGRADED

Run: python3 test_phase_contract.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import phase_contract as pc  # noqa: E402
from phase_contract import (PhaseResult, PhaseSpec, Outcome, PhaseAbort,  # noqa: E402
                            run_phase, phase, phases_for_tier, clear_registry)
from phase_source import LIGHT, MEDIUM, HEAVY  # noqa: E402


class FakeCtx:
    """Minimal stand-in for ScanContext — only what the executor touches."""
    def __init__(self, authorized=False, intensity="heavy"):
        self.tools_run = []
        self.tool_status = {}
        self.artifacts = []
        self.findings = []
        self.active_probe_authorized = authorized
        self.intensity = intensity


class FakeFinding:
    def __init__(self, source=None):
        self.source = source


# Marker stubs — mirror mark_tool_* without importing run_medium (which would
# drag the whole medium runner and its DB deps into a unit test).
def _markers(ctx):
    def ok(c, n):
        c.tool_status[n] = {"ok": True}

    def degraded(c, n, reason, **kw):
        c.tool_status[n] = {"degraded": reason}

    def skipped(c, n, reason):
        c.tool_status[n] = {"skipped": reason}
    return dict(mark_ok=ok, mark_degraded=degraded, mark_skipped=skipped)


def _spec(fn, **kw):
    kw.setdefault("name", "t")
    kw.setdefault("tier", HEAVY)
    return PhaseSpec(fn=fn, **kw)


def _run(fn, ctx=None, **kw):
    ctx = ctx or FakeCtx()
    return run_phase(_spec(fn, **kw), ctx, pathlib.Path("/tmp"), **_markers(ctx)), ctx


# ── obligation 1: credit tools_run AFTER the work ───────────────────────────

def test_tools_run_is_credited_after_the_work_not_before():
    """🔴 THE 20260828a BUG. ctx.tools_run.append() at the TOP of a phase meant a
    tool that ran and DEGRADED still counted as full coverage for the note-127
    autocloser. The phase body asserts it is NOT yet credited while it runs."""
    seen = {}

    def fn(ctx, wd):
        seen["during"] = list(ctx.tools_run)
        return PhaseResult.ok()

    res, ctx = _run(fn)
    assert seen["during"] == [], (
        "obligation 1: tools_run must be EMPTY while the phase runs — "
        f"credited too early: {seen['during']}")
    assert ctx.tools_run == ["t"], "obligation 1: not credited after success"


def test_degraded_tool_is_still_credited_but_marked_degraded():
    """It MUST appear in tools_run (close_out's set-equality invariant) while
    tool_status says degraded — that pair is what migration 20260828a's
    `tool_status -> tool ->> 'ok' = 'true'` predicate reads to refuse coverage."""
    res, ctx = _run(lambda c, w: PhaseResult.degraded("boom"))
    assert ctx.tools_run == ["t"]
    assert ctx.tool_status["t"] == {"degraded": "boom"}


# ── obligation 2: tool_status lockstep (invariant true by construction) ──────

def test_every_credited_tool_has_a_tool_status_entry():
    """close_out asserts set(tools_run) == set(tool_status). The executor sets
    both in the same breath so they cannot diverge."""
    for fn in (lambda c, w: PhaseResult.ok(),
               lambda c, w: PhaseResult.degraded("x"),
               lambda c, w: (_ for _ in ()).throw(RuntimeError("kaboom"))):
        _res, ctx = _run(fn)
        assert set(ctx.tools_run) == set(ctx.tool_status), (
            f"invariant broken: {ctx.tools_run} vs {list(ctx.tool_status)}")


# ── a phase that did not run is NOT coverage ────────────────────────────────

def test_disabled_phase_does_not_enter_tools_run():
    """DISABLED = dark launch / feature-flag off (content_fetch today). The phase
    is not operational for ANY asset, so it is not in the set of things that
    could have run — no tools_run entry, no tool_status entry. Distinct from
    GATE_SKIPPED below; see the executor comment on why they must not merge."""
    res, ctx = _run(lambda c, w: PhaseResult.ok(), enabled=False)
    assert res.outcome == Outcome.DISABLED
    assert ctx.tools_run == [] and ctx.tool_status == {}


def test_gate_skipped_phase_IS_credited_with_skipped_status():
    """🔴 THE Q4 RECONCILIATION (4.7 2026-08-29). A per-asset gate means the
    phase EXISTS but does not apply HERE — the autocloser must know we did NOT
    establish coverage, which requires a recorded entry. Safe only because
    20260828a requires tool_status ok='true' for coverage."""
    res, ctx = _run(lambda c, w: PhaseResult.skipped("not_applicable"))
    assert res.outcome == Outcome.GATE_SKIPPED
    assert ctx.tools_run == ["t"], "gate-skipped phase must be credited"
    assert ctx.tool_status["t"] == {"skipped": "not_applicable"}


def test_gate_skipped_cannot_be_read_as_coverage_by_the_autocloser():
    """The 20260828a predicate is `tool_status -> tool ->> 'ok' = 'true'`.
    Mirror it here: a skipped entry must NOT satisfy it. This is the enabling
    condition for crediting a skip at all — if it ever became coverage, a gated
    phase would auto-close findings it never looked for."""
    _res, ctx = _run(lambda c, w: PhaseResult.skipped("not_applicable"))
    entry = ctx.tool_status["t"]
    assert entry.get("ok") is not True, "gate_skipped must never satisfy ok=true"


def test_unauthorized_active_probe_is_gated_credited_but_never_executed():
    """4.7 Q6 — attack-shaped phases (probes, dalfox, arjun) only fire on assets
    flagged active_probe_authorized. The gate is the ROE boundary. It must NOT
    execute, but it IS recorded so the absence of findings is not mistaken for
    'we looked'."""
    fired = {"n": 0}

    def fn(ctx, wd):
        fired["n"] += 1
        return PhaseResult.ok()

    res, ctx = _run(fn, ctx=FakeCtx(authorized=False), is_active_probe=True)
    assert fired["n"] == 0, "unauthorized active probe MUST NOT execute"
    assert res.outcome == Outcome.GATE_SKIPPED
    assert ctx.tools_run == ["t"]
    assert ctx.tool_status["t"] == {"skipped": "active_probe_not_authorized"}


# ── double-EXECUTION guard (4.7 Q1) ─────────────────────────────────────────

def test_double_execution_of_one_phase_raises():
    """🔴 THE HYBRID-WINDOW GUARD. Registration overlap between registry and a
    legacy runner is LEGAL (only one path fires per scan); execution overlap is
    corruption — tools_run credited twice, set-equality silently broken."""
    ctx = FakeCtx()
    spec = _spec(lambda c, w: PhaseResult.ok())
    run_phase(spec, ctx, pathlib.Path("/tmp"), **_markers(ctx))
    try:
        run_phase(spec, ctx, pathlib.Path("/tmp"), **_markers(ctx))
    except pc.DoubleExecutionError:
        assert ctx.tools_run == ["t"], "guard must fire BEFORE the second credit"
        return
    raise AssertionError("second execution of the same phase was allowed")


def test_guard_fires_before_any_second_write():
    """The guard must precede execution, not follow it — otherwise the phase
    runs twice (double traffic at the target) even if crediting is prevented."""
    fired = {"n": 0}

    def fn(c, w):
        fired["n"] += 1
        return PhaseResult.ok()

    ctx = FakeCtx()
    spec = _spec(fn)
    run_phase(spec, ctx, pathlib.Path("/tmp"), **_markers(ctx))
    try:
        run_phase(spec, ctx, pathlib.Path("/tmp"), **_markers(ctx))
    except pc.DoubleExecutionError:
        pass
    assert fired["n"] == 1, "phase body executed twice — guard is too late"


def test_distinct_phases_do_not_trip_the_guard():
    ctx = FakeCtx()
    for name in ("a", "b", "c"):
        run_phase(_spec(lambda c, w: PhaseResult.ok(), name=name),
                  ctx, pathlib.Path("/tmp"), **_markers(ctx))
    assert ctx.tools_run == ["a", "b", "c"]


def test_authorized_active_probe_runs():
    res, ctx = _run(lambda c, w: PhaseResult.ok(),
                    ctx=FakeCtx(authorized=True), is_active_probe=True)
    assert res.outcome == Outcome.OK and ctx.tools_run == ["t"]


def test_probe_gate_fails_closed_when_flag_absent():
    """An unreadable/absent policy is NOT authorization."""
    ctx = FakeCtx()
    del ctx.active_probe_authorized
    res = run_phase(_spec(lambda c, w: PhaseResult.ok(), is_active_probe=True),
                    ctx, pathlib.Path("/tmp"), **_markers(ctx))
    assert res.outcome == Outcome.SKIPPED


# ── degradation taxonomy (4.7 Q2) ───────────────────────────────────────────

def test_phase_exception_becomes_degraded_and_never_propagates():
    """One flaky tool must not sink a cumulative run."""
    res, ctx = _run(lambda c, w: (_ for _ in ()).throw(ValueError("nope")))
    assert res.outcome == Outcome.DEGRADED
    assert res.reason == "exception_ValueError"
    assert ctx.tool_status["t"] == {"degraded": "exception_ValueError"}


def test_abort_scan_raises_and_is_not_silently_degraded():
    """🔴 HARM CONDITIONS SURVIVE. ban detected / VPN lost / unreachable must
    STOP the scan — continuing deepens a ban or scans from the wrong egress.
    This is why medium's 15 aborts cannot be blanket-converted."""
    ctx = FakeCtx()
    try:
        run_phase(_spec(lambda c, w: PhaseResult.abort("ban_detected")),
                  ctx, pathlib.Path("/tmp"), **_markers(ctx))
    except PhaseAbort as e:
        assert e.reason == "ban_detected"
        assert ctx.tools_run == ["t"], "abort must still record what happened"
        assert ctx.tool_status["t"] == {"degraded": "ban_detected"}
        return
    raise AssertionError("ABORT_SCAN did not raise PhaseAbort")


# ── obligation 3: artifacts persisted on EVERY outcome ──────────────────────

def test_artifacts_are_persisted_even_when_degraded():
    """🔴 THE GAU BUG. The artifact append was guarded by `if urls:`, so the first
    real failure persisted NOTHING and had to be diagnosed from the Actions log.
    Evidence is least available exactly when it is most needed."""
    res, ctx = _run(lambda c, w: PhaseResult.degraded(
        "boom", artifacts=[("t", "json", "{}")]))
    assert ctx.artifacts == [("t", "json", "{}")]


def test_artifacts_persisted_on_success_too():
    res, ctx = _run(lambda c, w: PhaseResult.ok(artifacts=[("t", "json", "{}")]))
    assert ctx.artifacts == [("t", "json", "{}")]


# ── obligation 4: source tagged by DECLARED tier ────────────────────────────

def test_findings_are_tagged_with_the_phases_declared_tier_source():
    """Step 1's rule, now enforced by the framework: a LIGHT phase emits
    commandsentry_light even inside a HEAVY run. ctx.intensity is 'heavy' here —
    if the executor ever reads it, this fails."""
    ctx = FakeCtx(intensity="heavy")
    run_phase(_spec(lambda c, w: PhaseResult.ok(findings=[FakeFinding()]),
                    tier=LIGHT), ctx, pathlib.Path("/tmp"), **_markers(ctx))
    assert ctx.findings[0].source == "commandsentry_light", ctx.findings[0].source


def test_explicit_finding_source_is_not_overwritten():
    """testssl/httpx findings carry their own canonical source."""
    ctx = FakeCtx()
    run_phase(_spec(lambda c, w: PhaseResult.ok(findings=[FakeFinding("testssl")])),
              ctx, pathlib.Path("/tmp"), **_markers(ctx))
    assert ctx.findings[0].source == "testssl"


# ── declared yield floor (the gau lesson) ───────────────────────────────────

def test_yield_floor_demotes_ok_to_degraded():
    """'ok' means rc==0 and non-empty — NOT that the tool did its job."""
    res, ctx = _run(lambda c, w: PhaseResult.ok(meta={"paths": 0}),
                    healthy_yield=lambda m: ("root_only_no_surface"
                                             if m.get("paths") == 0 else None))
    assert res.outcome == Outcome.DEGRADED
    assert res.reason == "root_only_no_surface"
    assert ctx.tool_status["t"] == {"degraded": "root_only_no_surface"}


def test_yield_floor_passes_a_healthy_result():
    res, _ = _run(lambda c, w: PhaseResult.ok(meta={"paths": 3}),
                  healthy_yield=lambda m: ("bad" if m.get("paths") == 0 else None))
    assert res.outcome == Outcome.OK


# ── cumulative tier selection — the whole point ─────────────────────────────

def test_heavy_selection_is_cumulative_light_medium_heavy():
    """🔴 THE MEASURED PROBLEM. Today heavy REPLACES light (4.5 vs 12.3 tools).
    Selection must be additive."""
    clear_registry()
    try:
        phase(name="l", tier=LIGHT)(lambda c, w: PhaseResult.ok())
        phase(name="m", tier=MEDIUM)(lambda c, w: PhaseResult.ok())
        phase(name="h", tier=HEAVY)(lambda c, w: PhaseResult.ok())
        assert [p.name for p in phases_for_tier(HEAVY)] == ["l", "m", "h"]
        assert [p.name for p in phases_for_tier(MEDIUM)] == ["l", "m"]
        assert [p.name for p in phases_for_tier(LIGHT)] == ["l"]
    finally:
        clear_registry()


def test_double_registration_is_rejected_loudly():
    """4.7 Q3 — a phase in both the registry and a legacy runner double-credits
    and silently breaks the invariant. Fail loud at declaration."""
    clear_registry()
    try:
        phase(name="dup", tier=HEAVY)(lambda c, w: PhaseResult.ok())
        try:
            phase(name="dup", tier=HEAVY)(lambda c, w: PhaseResult.ok())
        except ValueError:
            return
        raise AssertionError("double registration was allowed")
    finally:
        clear_registry()


def test_unknown_tier_rejected_at_declaration():
    clear_registry()
    try:
        try:
            phase(name="x", tier="enormous")(lambda c, w: PhaseResult.ok())
        except ValueError:
            return
        raise AssertionError("unknown tier accepted")
    finally:
        clear_registry()


def test_spec_source_is_declared_tier_not_intensity():
    assert _spec(lambda c, w: None, tier=LIGHT).source == "commandsentry_light"
    assert _spec(lambda c, w: None, tier=MEDIUM).source == "commandsentry_medium"
    assert _spec(lambda c, w: None, tier=HEAVY).source == "commandsentry_heavy"


def test_phase_returning_none_is_treated_as_ok():
    """Migration ergonomics: a ported phase that still returns None must not be
    mistaken for a failure."""
    res, ctx = _run(lambda c, w: None)
    assert res.outcome == Outcome.OK and ctx.tool_status["t"] == {"ok": True}


def test_elapsed_is_always_recorded():
    res, _ = _run(lambda c, w: PhaseResult.ok())
    assert "elapsed_s" in res.meta


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 26, f"expected >=26 tests, collected {len(tests)}"
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
