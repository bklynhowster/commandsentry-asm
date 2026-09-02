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


# ── context compatibility (found in production, run #2620) ──────────────────

def test_heavy_context_is_a_superset_of_medium_context():
    """🔴 FOUND IN PRODUCTION, NOT BY A TEST. The first cumulative heavy run
    (#2620, unimacgraphics.com, 2026-08-29) degraded nuclei, nikto AND ffuf with
    exception_AttributeError: all three are written against
    run_medium.ScanContext (34 fields) but cumulative heavy hands them
    HeavyScanContext, which was deliberately 'slimmer' (24 fields). The legacy
    recording proxy forwards attribute access faithfully — it cannot invent
    fields that never existed.

    Registering a MEDIUM phase means heavy's context must satisfy medium's
    contract. Assert the superset property so adding a field to medium without
    adding it to heavy fails HERE instead of in a live scan."""
    import dataclasses
    from run_medium import ScanContext
    from run_heavy import HeavyScanContext
    med = {f.name for f in dataclasses.fields(ScanContext)}
    heavy = {f.name for f in dataclasses.fields(HeavyScanContext)}
    missing = med - heavy
    assert not missing, (
        f"HeavyScanContext is missing {len(missing)} field(s) medium phases "
        f"read: {sorted(missing)} — a cumulative heavy will AttributeError")


def test_the_three_medium_scanners_can_read_every_field_they_need():
    """Belt and braces on the specific tools that broke: instantiate heavy's
    context and touch the fields medium's scanners reach for."""
    from run_heavy import HeavyScanContext
    ctx = HeavyScanContext(descriptor={}, hostname="x", asset_id="x",
                           scan_run_id="x", queue_id="x", intensity="heavy",
                           dsn="")
    for attr in ("response_codes", "total_requests", "region_idx",
                 "threshold_probe_results", "ffuf_catchall_redirect",
                 "ffuf_catchall_count", "ffuf_catchall_status",
                 "ffuf_catchall_size", "ffuf_catchall_status_count",
                 "auth_gated", "waf_detected", "waf_kind", "tech_stack"):
        getattr(ctx, attr)


# ── the cumulative-heavy master switch (inc 3c) ─────────────────────────────

def test_heavy_is_unconditionally_cumulative_no_flag():
    """🔴 4.7 ㉙ — THE FLAG IS GONE AND MUST STAY GONE.

    It used to be _CUMULATIVE_HEAVY_ENABLED, fed by
    `${{ github.event.inputs.cumulative_heavy || 'false' }}`. That expression is
    empty on cron, workflow_run and the self-chain, so the flag survived only
    one manual dispatch. Measured 2026-09-01: of six Prodex assets enqueued
    heavy, the two claimed by their own dispatch ran 19 tools and the four
    claimed by cron ran 5 — four silently ran plain heavy with nothing recording
    the loss.

    Re-adding ANY flag (env var, queue column, kill-switch) re-creates the
    two-sources-of-truth condition that caused it. Rollback is a code revert.
    """
    import run_heavy
    assert not hasattr(run_heavy, "_CUMULATIVE_HEAVY_ENABLED"), (
        "the cumulative-heavy flag is back — 4.7 ㉙/㉛ deleted it deliberately; "
        "rollback is a code revert, not a flag. See Obsidian 206.")
    src = pathlib.Path(__file__).parent.joinpath("run_heavy.py").read_text()
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    assert "CUMULATIVE_HEAVY_ENABLED" not in code, (
        "CUMULATIVE_HEAVY_ENABLED referenced in run_heavy code (not comment)")


def test_no_trigger_path_can_disable_cumulative_heavy():
    """The workflow must not carry the input or the env var either — the flag
    was lost BECAUSE it came from github.event.inputs. Assert on the file an
    operator actually gets."""
    wf = pathlib.Path(__file__).parents[2] / ".github/workflows/scanner.yml"
    text = wf.read_text()
    assert "cumulative_heavy" not in text, (
        "scanner.yml still references cumulative_heavy")
    assert "CUMULATIVE_HEAVY_ENABLED" not in text, (
        "scanner.yml still exports CUMULATIVE_HEAVY_ENABLED")


def test_content_fetch_handcall_is_gone_not_merely_guarded():
    """content_fetch is a REGISTERED phase, so the always-on cumulative loop
    executes it. The old hand-call ran only when the flag was off; leaving it
    would be a second execution and would raise DoubleExecutionError."""
    src = pathlib.Path(__file__).parent.joinpath("run_heavy.py").read_text()
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    assert 'run_phase(get_phase("content_fetch"), ctx, work_dir)' not in code, (
        "the content_fetch hand-call is back — the registry loop already runs it")


def test_cumulative_block_runs_before_the_heavy_specific_phases():
    """Ban-detectors first: the registry loop (which contains wafw00f) must be
    positioned before heavy's own attack-shaped work."""
    src = pathlib.Path(__file__).parent.joinpath("run_heavy.py").read_text()
    assert src.index("run_phases(") < src.index("run_testssl_phase(ctx, work_dir)")


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 19, f"expected >=19 tests, collected {len(tests)}"
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
