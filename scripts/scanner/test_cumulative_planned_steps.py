#!/usr/bin/env python3
"""test_cumulative_planned_steps.py — #17.

Not a cosmetic denominator fix. Observed on Command run #2637: with
planned_steps = heavy's 6 own steps while tools_run = 19, the portal's
ScanProgress card built its phase list from planned_steps and therefore had NO
"Vulnerability scan" row at all — so formatPhaseIssues never inspected the
nuclei entry carrying chunks_cut, and the "cut short" label shipped in the
portal could not render. #17 gates the partial UI.

These call build_cumulative_planned_steps() DIRECTLY. An earlier draft
recomputed the expected plan inside the test instead, and two mutants survived
because of it — the test was a mirror of the logic, not a check on it
(feedback_wiring_untested_by_pure_function_tests, again).
"""
import inspect

import phase_registry  # noqa: F401 — registers the phases
import run_heavy
from run_heavy import build_cumulative_planned_steps
from phase_contract import phases_for_tier
from phase_source import HEAVY

HEAVY_OWN = ["testssl.sh", "httpx", "gau", "content_fetch", "naabu", "fingerprintx"]


def test_plan_matches_what_actually_gets_credited():
    """19 planned == 19 credited on run #2637. Drift either sticks the bar
    short of 100% or overshoots it."""
    assert len(build_cumulative_planned_steps(HEAVY_OWN)) == 19


def test_disabled_phases_are_excluded():
    """content_fetch is registered but enabled=False, so it credits nothing.
    Leaving it in parks the card one step short forever."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    assert "content_fetch" not in plan
    disabled = [s.name for s in phases_for_tier(HEAVY) if not s.enabled]
    assert disabled == ["content_fetch"], (
        "a new disabled phase appeared — confirm it is excluded from the plan")


def test_registry_phases_come_first():
    """The card derives 'current step' from the first planned step with no
    tool_status entry, so plan order must mirror run order: run_phases executes
    the registry before heavy's own hand-called phases. Reversed, the card
    points at the wrong phase for the entire scan."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    assert plan[0] == "wafw00f", "ban-detector must lead (ORDER_BAN_DETECT)"
    assert plan.index("nuclei") < plan.index("testssl.sh")
    assert plan.index("ffuf") < plan.index("naabu")
    # every registry phase precedes every heavy-own phase
    last_registry = max(plan.index(s.name) for s in phases_for_tier(HEAVY)
                        if s.enabled)
    first_own = min(plan.index(s) for s in ("testssl.sh", "httpx", "gau",
                                            "naabu", "fingerprintx"))
    assert last_registry < first_own


def test_plan_contains_the_vulnerability_scan_phase():
    """THE regression #2637 exposed. Without 'nuclei' in planned_steps the
    portal has no phase row for it and the cut-short label is unreachable."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    for n in ("nuclei", "nikto", "ffuf"):
        assert n in plan, f"{n} missing — its phase row cannot render"


def test_entries_are_phase_names_not_chunk_names():
    """Ship 1 (ruling ⑱) made run_phase credit spec.name, which is what lets us
    enumerate the plan UP FRONT — chunk names depend on ctx.tech_stack/waf_kind
    that are not populated until the ban-detect phases have run. If per-chunk
    crediting returns (ruling ⑬) this plan goes stale mid-run."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    assert "nuclei" in plan
    assert not any(p.startswith("nuclei[") for p in plan)
    assert not any(p.startswith("ffuf[") for p in plan)


def test_no_duplicates_even_though_lists_overlap():
    """content_fetch is in BOTH the registry and heavy's own list. The overlap
    is removed deliberately; it is not a coincidence of ordering."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    assert len(plan) == len(set(plan))


def test_heavy_own_steps_survive_when_not_registry_owned():
    """The filter must drop ONLY the overlap, not heavy's whole list."""
    plan = build_cumulative_planned_steps(HEAVY_OWN)
    for own in ("testssl.sh", "httpx", "gau", "naabu", "fingerprintx"):
        assert own in plan


def test_pure_function_does_not_touch_ctx():
    sig = inspect.signature(build_cumulative_planned_steps)
    assert list(sig.parameters) == ["heavy_own_steps"]


def test_expansion_is_unconditional_no_flag():
    """4.7 ㉙ — heavy is always cumulative, so the planned_steps expansion is
    no longer gated. It must run before flush_planned_steps or the portal's
    ScanProgress denominator is the pre-expansion 6."""
    src = inspect.getsource(run_heavy)
    i = src.index('ctx.planned_steps = ["testssl.sh"')
    seg = src[i:i + 400]
    assert "build_cumulative_planned_steps(ctx.planned_steps)" in seg
    assert "_CUMULATIVE_HEAVY_ENABLED" not in seg, (
        "the expansion is gated on a flag again — see Obsidian 206")
    assert src.index("flush_planned_steps(ctx)") > i
