#!/usr/bin/env python3
"""test_phase_registry.py — the registered phase set + its ORDER (step 4 inc 3b).

The registry is what cumulative heavy will iterate. A wrong tier or a wrong
order here does not crash — it silently changes what a scan does, and the two
specific ways it goes wrong are both ban-inducing:

  * wafw00f after nuclei  → build_chunk_plan sees no ctx.waf_kind → AGGRESSIVE
    template plan against a WAF-fronted host.
  * httpx[-td] after nuclei → no ctx.tech_stack → stack-specific chunks never
    fire, and the plan is both wronger and broader than it should be.

So these are ordering/registration MECHANISM tests, not smoke tests.

Run: python3 test_phase_registry.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import phase_registry  # noqa: F401,E402  — import registers the phases
import phase_contract as pc  # noqa: E402
from phase_source import LIGHT, MEDIUM, HEAVY  # noqa: E402

ORDERED = [p.name for p in pc.phases_for_tier(HEAVY)]
BY_NAME = {p.name: p for p in pc.REGISTRY}


# ── the set that got registered ─────────────────────────────────────────────

def test_all_nine_light_phases_are_registered():
    expected = {"dns_posture", "tls_check", "headers_check", "common_paths",
                "httpx_tech", "methods_check", "csp_nonce_check",
                "wpvulnerability", "behavioral_probes"}
    got = {p.name for p in pc.REGISTRY if p.tier == LIGHT}
    assert expected <= got, f"missing light phases: {expected - got}"


def test_all_five_medium_phases_are_registered():
    expected = {"wafw00f", "httpx[-td]", "nuclei", "nikto", "ffuf"}
    got = {p.name for p in pc.REGISTRY if p.tier == MEDIUM}
    assert expected <= got, f"missing medium phases: {expected - got}"


def test_cumulative_heavy_now_selects_far_more_than_heavy_alone():
    """🔴 THE WHOLE POINT. Heavy ran ~4 finding-producing tools; light ran 12.3.
    Cumulative selection must now return the union."""
    heavy_only = [p for p in pc.REGISTRY if p.tier == HEAVY]
    assert len(ORDERED) >= 14, f"cumulative heavy selected only {len(ORDERED)}"
    assert len(ORDERED) > len(heavy_only) * 3


def test_light_selection_stays_light_only():
    """Cumulative must not leak medium/heavy phases into a light scan."""
    names = {p.name for p in pc.phases_for_tier(LIGHT)}
    assert "nuclei" not in names and "wafw00f" not in names
    assert "dns_posture" in names


# ── ORDER — the ban-inducing failure modes ──────────────────────────────────

def test_wafw00f_is_ordered_before_nuclei():
    """🔴 THE TEST 4.7 ASKED FOR (spec 195 finding 1). wafw00f is the only
    phase that sets ctx.waf_kind; build_chunk_plan reads it to choose the
    FortiGate SAFE-ONLY plan."""
    assert ORDERED.index("wafw00f") < ORDERED.index("nuclei"), ORDERED


def test_tech_stack_detection_is_ordered_before_nuclei():
    """httpx -td populates ctx.tech_stack, which build_chunk_plan reads for its
    stack-specific chunks."""
    assert ORDERED.index("httpx[-td]") < ORDERED.index("nuclei"), ORDERED


def test_wafw00f_runs_before_every_attack_shaped_tool():
    """Not just nuclei — nikto and ffuf are attack-shaped too."""
    w = ORDERED.index("wafw00f")
    for tool in ("nuclei", "nikto", "ffuf"):
        assert w < ORDERED.index(tool), f"wafw00f after {tool}: {ORDERED}"


def test_light_checks_precede_the_attack_shaped_tools():
    """Cheap, non-attack-shaped signal first; if an ABORT_SCAN fires we still
    have the light findings."""
    assert max(ORDERED.index(n) for n in ("dns_posture", "tls_check")) \
        < ORDERED.index("nuclei")


def test_ban_detection_group_is_at_the_front():
    """wafw00f sits in the ban-detection band, not medium's default band."""
    assert BY_NAME["wafw00f"].effective_order == pc.ORDER_BAN_DETECT
    assert BY_NAME["nuclei"].effective_order == pc.ORDER_MEDIUM_TOOLS


# ── registration hygiene ────────────────────────────────────────────────────

def test_no_duplicate_phase_names():
    names = [p.name for p in pc.REGISTRY]
    assert len(names) == len(set(names)), f"duplicates: {names}"


def test_registered_names_match_the_tool_names_the_legacy_code_credits():
    """🔴 If a registry name diverges from the tool name the legacy function
    credits, tool_status keys differ by path and findings stop reconciling."""
    import re
    import ast
    light_src = pathlib.Path(__file__).parent.joinpath("run_light.py").read_text()
    tree = ast.parse(light_src)
    defs = {n.name: n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef)}
    pairs = {"dns_posture": "check_dns_posture", "tls_check": "check_tls",
             "headers_check": "check_headers", "httpx_tech": "check_httpx_tech"}
    for phase_name, fn_name in pairs.items():
        body = ast.unparse(defs[fn_name])
        credited = set(re.findall(r"tools_run\.append\('([^']+)'\)", body))
        assert phase_name in credited, (
            f"{fn_name} credits {credited}, registry calls it {phase_name!r}")


def test_every_registered_phase_declares_a_known_tier():
    for p in pc.REGISTRY:
        assert p.tier in (LIGHT, MEDIUM, HEAVY), (p.name, p.tier)


def test_every_registered_phase_is_callable():
    for p in pc.REGISTRY:
        assert callable(p.fn), p.name


def test_port_scoped_checks_are_deliberately_unregistered():
    """check_ssh/smtp/ftp take a port and fan out per open port; the contract
    has no fan-out shape yet. Registering them naively would credit one tool
    name N times. Documented as a known gap rather than half-done."""
    names = {p.name for p in pc.REGISTRY}
    for absent in ("check_ssh", "check_smtp", "check_ftp", "ssh", "smtp", "ftp"):
        assert absent not in names


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 14, f"expected >=14 tests, collected {len(tests)}"
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
