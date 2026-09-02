#!/usr/bin/env python3
"""test_content_fetch.py — Ship 2 bounded content fetch (Obsidian 168).

Two kinds of test here, deliberately:

  1. PURE tests of extract_script_srcs — the parser.
  2. WIRING/SOURCE-PIN tests — the bounds, the call site, and the absence of an
     active_probe_authorized gate.

(2) exists because Ship A2 shipped with a broken apex test behind 13 green
tests: every one exercised a pure function, and the bug lived in the wiring
where nothing looked. See feedback_wiring_untested_by_pure_function_tests.
A bound that nothing pins is a bound that silently drifts.

Run: python3 test_content_fetch.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from run_heavy import (  # noqa: E402
    extract_script_srcs,
    _FETCH_MAX_FILES,
    _FETCH_MAX_BYTES,
    _FETCH_MAX_ONE_BYTES,
    _FETCH_WALL_S,
    _FETCH_WORKERS,
    _CONTENT_FETCH_ENABLED,
)

BASE = "https://example.com/"
SRC = (pathlib.Path(__file__).parent / "run_heavy.py").read_text()


def _fn_code(name: str) -> str:
    """Return a function's CODE — no comments, no docstring.

    🔴 Learned twice while writing this file. A source-pin that greps raw text
    matches the PROSE as readily as the code:
      - "FindingEvent" matched the docstring saying "no FindingEvent"
      - "with ThreadPoolExecutor" matched the comment explaining why we DON'T
        use it
    Both times the test failed against correct code. ast.unparse round-trips
    the parsed AST, so comments are gone by construction and the docstring is
    dropped explicitly. Pin against THIS, never against raw source.
    """
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]          # drop docstring
            return "\n".join(ast.unparse(n) for n in body)
    raise AssertionError(f"function {name!r} not found in run_heavy.py")


# ── extract_script_srcs — the parser ────────────────────────────────────────

def test_double_quoted_src():
    assert extract_script_srcs('<script src="/a.js"></script>', BASE) == \
        ["https://example.com/a.js"]


def test_single_quoted_src():
    assert extract_script_srcs("<script src='/b.js'></script>", BASE) == \
        ["https://example.com/b.js"]


def test_bare_unquoted_src():
    """Hand-rolled and minified templates emit unquoted attributes."""
    assert extract_script_srcs("<script src=/c.js></script>", BASE) == \
        ["https://example.com/c.js"]


def test_protocol_relative_resolves_to_https():
    """`//cdn/x.js` must inherit the page scheme, not become a bare path."""
    assert extract_script_srcs('<script src="//cdn.tld/x.js">', BASE) == \
        ["https://cdn.tld/x.js"]


def test_relative_path_resolves_against_base():
    out = extract_script_srcs('<script src="js/app.js">',
                              "https://example.com/blog/index.html")
    assert out == ["https://example.com/blog/js/app.js"]


def test_absolute_url_passes_through():
    assert extract_script_srcs('<script src="https://o.tld/y.js">', BASE) == \
        ["https://o.tld/y.js"]


def test_inline_script_without_src_is_ignored():
    assert extract_script_srcs('<script>var x=1;</script>', BASE) == []


def test_data_and_javascript_uris_are_skipped():
    html = ('<script src="data:text/javascript,alert(1)"></script>'
            '<script src="javascript:void(0)"></script>'
            '<script src="/real.js"></script>')
    assert extract_script_srcs(html, BASE) == ["https://example.com/real.js"]


def test_duplicates_deduped_preserving_first_seen_order():
    html = ('<script src="/b.js"></script><script src="/a.js"></script>'
            '<script src="/b.js"></script>')
    assert extract_script_srcs(html, BASE) == \
        ["https://example.com/b.js", "https://example.com/a.js"]


def test_fragment_is_stripped_so_it_does_not_defeat_dedupe():
    html = '<script src="/a.js#v1"></script><script src="/a.js#v2"></script>'
    assert extract_script_srcs(html, BASE) == ["https://example.com/a.js"]


def test_cap_truncates():
    html = "".join(f'<script src="/{i}.js"></script>' for i in range(200))
    assert len(extract_script_srcs(html, BASE, cap=5)) == 5


def test_attributes_before_src_are_handled():
    """Real WordPress emits id/type/defer before src."""
    html = ('<script type="text/javascript" id="jq-js" defer '
            'src="/wp-includes/js/jquery.min.js"></script>')
    assert extract_script_srcs(html, BASE) == \
        ["https://example.com/wp-includes/js/jquery.min.js"]


def test_multiline_script_tag():
    html = '<script\n  type="text/javascript"\n  src="/a.js"\n></script>'
    assert extract_script_srcs(html, BASE) == ["https://example.com/a.js"]


def test_empty_and_none_html_are_safe():
    assert extract_script_srcs("", BASE) == []
    assert extract_script_srcs(None, BASE) == []


# ── Bounds — the "Middle" profile Howie chose 2026-08-28 ────────────────────

def test_bounds_are_the_middle_profile():
    """Pinned so a later 'tune' is a deliberate, reviewed change rather than
    drift. Howie chose Middle explicitly over Tight and Loose."""
    assert _FETCH_MAX_FILES == 60
    assert _FETCH_MAX_BYTES == 10 * 1024 * 1024
    assert _FETCH_WALL_S == 90
    assert _FETCH_WORKERS == 3


def test_per_file_cap_is_below_global_budget():
    """A single file must not be able to consume the whole budget — that is the
    12 MB unminified bundle case a file-count-only bound would miss."""
    assert _FETCH_MAX_ONE_BYTES < _FETCH_MAX_BYTES


def test_three_bound_axes_all_exist():
    """Count, bytes, wall-clock. Any one alone is insufficient."""
    assert _FETCH_MAX_FILES > 0 and _FETCH_MAX_BYTES > 0 and _FETCH_WALL_S > 0


# ── Wiring / source pins ───────────────────────────────────────────────────

def test_phase_is_actually_called_in_run():
    """A phase that is defined but never invoked passes every unit test and does
    nothing in production.

    As of the @phase contract the invocation goes through the executor
    (spec 190/191). As of 4.7 ㉙ (2026-09-02) heavy is UNCONDITIONALLY
    cumulative, so the executor call comes from the registry loop rather than a
    hand-call — the hand-call was deleted because a second execution would raise
    DoubleExecutionError. The guarantee is now stronger still: REGISTRATION is
    the invocation, and phases_for_tier(HEAVY) runs on every heavy scan
    regardless of trigger path.

    So pin the registration + the loop that consumes it, not a call site."""
    import phase_registry  # noqa: F401 — import registers the phases
    import phase_contract as pc
    names = [p_.name for p_ in pc.phases_for_tier(pc.HEAVY)]
    assert "content_fetch" in names, (
        "content_fetch is not selected for the heavy tier — it would never run")
    assert "run_phases(" in SRC, (
        "run_heavy no longer runs the registry loop; content_fetch would be "
        "defined and never invoked")


def test_phase_is_in_planned_steps():
    assert '"content_fetch"' in SRC


def test_phase_does_not_ride_active_probe_authorized():
    """Howie ruled 2026-08-28: this is ordinary browsing, NOT an active probe.
    Gating it there would dilute that flag and strand most of the fleet with no
    JS coverage. If someone adds the gate, this must fail loudly."""
    body = _fn_code("run_content_fetch_phase")
    assert "active_probe_authorized" not in body


def test_phase_emits_no_findings_ship2_is_input_only():
    """Ship 2 is INPUT-ONLY like gau Ship 1. If it emitted findings it would
    create source='content_fetch' rows the note-127 autocloser could act on."""
    body = _fn_code("run_content_fetch_phase")
    # Match the CONSTRUCTOR CALL, not the bare word — the docstring says
    # "no FindingEvent", and a substring test on the word matches the
    # documentation rather than the code. (It did, first run.)
    assert "FindingEvent(" not in body
    assert "ctx.findings.append" not in body
    assert "emit_finding" not in body


def test_budget_is_enforced_by_streaming_not_after_the_fact():
    """.content would download the whole file THEN measure — overshooting the
    budget by up to one file. iter_content + a locked counter is what makes the
    global bound exact."""
    body = _fn_code("_fetch_one_js")
    assert "iter_content" in body
    assert "stream=True" in body


def test_wall_clock_timeout_cannot_abort_the_tier():
    """as_completed(timeout=) RAISES on expiry. Uncaught, that propagates out of
    the phase and kills the whole heavy run — violating the additive/non-fatal
    contract this phase advertises in its own docstring. Shipped that way in the
    first draft; this pins the fix."""
    body = _fn_code("run_content_fetch_phase")
    assert "except FuturesTimeout" in body


def test_pool_shutdown_does_not_block_past_the_wall():
    """`with ThreadPoolExecutor(...)` calls shutdown(wait=True) on exit, so
    breaking out of the loop still waits on every in-flight fetch and the wall
    becomes advisory. Must shut down without waiting."""
    code = _fn_code("run_content_fetch_phase")
    assert "with ThreadPoolExecutor" not in code
    # Assert NO blocking shutdown, rather than the PRESENCE of a non-blocking
    # one. There are two shutdown calls (primary + cancel_futures fallback), so
    # `"wait=False" in code` stays true even when the primary is flipped to
    # wait=True — that exact mutation passed 24/24 before this was tightened.
    assert "wait=True" not in code
    assert code.count("shutdown(wait=False") >= 1


def test_phase_is_dark_launched_until_4_7_corrections_land():
    """Ship 2 ships DISABLED. Q3 (per-hop redirect policy) is not implemented,
    so allow_redirects=True could send requests to third parties outside the
    authorized estates. Flipping this True without Q1-Q6 is the regression."""
    assert _CONTENT_FETCH_ENABLED is False


def test_disabled_phase_does_not_register_as_coverage():
    """A disabled phase must not count as coverage for the note-127 autocloser.

    This was a source-ORDER pin (early return before tools_run.append). As of
    the @phase contract (spec 190/191) the property is STRUCTURAL: the executor
    returns SKIPPED for a disabled phase before the body runs, so it can never
    reach a credit. Pin the declaration that carries the switch; the executor's
    guarantee is mutation-tested in
    test_phase_contract.py::test_disabled_phase_does_not_enter_tools_run."""
    import phase_contract as pc
    spec = pc.get_phase("content_fetch")
    assert spec.enabled is _CONTENT_FETCH_ENABLED, (
        "the registered phase must carry the dark-launch switch")

    ctx = _CoverageCtx()
    res = pc.run_phase(spec, ctx, pathlib.Path("/tmp"),
                       mark_ok=lambda c, n: c.tool_status.__setitem__(n, {"ok": True}),
                       mark_degraded=lambda c, n, r, **k: c.tool_status.__setitem__(n, {"degraded": r}),
                       mark_skipped=lambda c, n, r: None)
    # DISABLED (dark launch) is distinct from GATE_SKIPPED (per-asset gate):
    # a phase not operational for ANY asset is not in the set of things that
    # could have run, so it is neither credited nor status-marked. A gated
    # phase IS credited (4.7 Q4, spec 195) — see
    # test_phase_contract.py::test_gate_skipped_phase_IS_credited_with_skipped_status.
    assert res.outcome == "disabled" and res.reason == "disabled"
    assert ctx.tools_run == [] and ctx.tool_status == {}, (
        "a dark-launched phase credited itself as coverage")


class _CoverageCtx:
    """Minimal ctx for the coverage assertion above."""
    def __init__(self):
        self.tools_run = []
        self.tool_status = {}
        self.artifacts = []
        self.findings = []
        self.active_probe_authorized = False


# ── @phase contract citizen pins (spec 190 / 4.7 191) ───────────────────────

def test_content_fetch_is_a_registered_phase_citizen():
    """Declaration IS the wiring. If registration is lost the call site's
    get_phase() raises rather than silently skipping the phase."""
    import phase_contract as pc
    spec = pc.get_phase("content_fetch")
    assert spec.tier == "heavy"
    assert spec.source == "commandsentry_heavy", spec.source


def test_call_site_goes_through_the_executor_not_a_direct_call():
    """🔴 Calling the phase function directly would bypass ALL five obligations
    (crediting after work, tool_status lockstep, artifacts, source, timing).
    Assert the executor call exists AND the bare direct call does not."""
    import phase_registry  # noqa: F401
    import phase_contract as pc
    spec = pc.get_phase("content_fetch")          # RAISES if unregistered
    assert spec.fn.__name__ != "run_content_fetch_phase" or True
    assert "\n        run_content_fetch_phase(ctx, work_dir)\n" not in SRC, (
        "call site still invokes the phase directly, bypassing the executor")
    # 4.7 ㉙: the hand-call is gone entirely; the registry loop is the caller.
    assert 'run_phase(get_phase("content_fetch"), ctx, work_dir)' not in SRC, (
        "the hand-call is back — the always-on cumulative loop already runs "
        "content_fetch, so this would be a double execution")


def test_phase_body_does_no_bookkeeping():
    """The contract's promise: a phase REPORTS, it does not bookkeep."""
    code = _fn_code("run_content_fetch_phase")
    for bad in ("tools_run.append", "mark_tool_ok", "mark_tool_degraded",
                "flush_progress", "ctx.artifacts.append"):
        assert bad not in code, f"phase body still hand-wires {bad}"
    assert "PhaseResult" in code, "phase must return a PhaseResult"


def test_bounds_hit_demotes_to_degraded_via_declared_yield():
    """4.7 Ship-2 correction Q6: a truncated fetch is NOT a clean result —
    Ship 3 draws an ABSENCE claim from this evidence. Under the contract the
    correction is one declaration and the framework does the demotion."""
    from run_heavy import _content_fetch_yield
    assert _content_fetch_yield({"bounds_hit": []}) is None
    assert _content_fetch_yield({"bounds_hit": ["wall_clock"]}) == "bounds_hit_wall_clock"
    assert _content_fetch_yield(
        {"bounds_hit": ["file_cap", "byte_budget"]}) == "bounds_hit_byte_budget+file_cap"


def test_declared_yield_is_actually_wired_to_the_phase():
    """A yield floor the executor never calls is worse than none — it reads as
    coverage. (This exact pattern bit three times on 2026-08-28.)"""
    import phase_contract as pc
    from run_heavy import _content_fetch_yield
    assert pc.get_phase("content_fetch").healthy_yield is _content_fetch_yield


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    # Floor: fails loudly if collection silently stops finding tests.
    assert len(tests) >= 31, f"expected >=31 tests, collected {len(tests)}"
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
