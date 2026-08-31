#!/usr/bin/env python3
"""test_nuclei_stats_flag.py — increment 2a (4.7 ruling ⑭).

`-stats` is an OBSERVATION instrument, shipped dark. These pin the two things
that make it safe to merge before we have ever seen nuclei's stats output:

  1. default OFF — a merged-but-unarmed flag changes nothing on cron/scheduled
     scans, which is the whole point of shipping it dark;
  2. the ABORT RISK is real and documented — stderr with 3+ reachability
     patterns makes is_tool_output_degraded return a slug, and on the nuclei
     path that RAISES DegradedRunError and kills the scan. If nuclei's stats
     text ever contains such phrases, arming this flag would start aborting
     WAF-fronted scans. The test asserts the mechanism so the risk cannot be
     quietly forgotten when someone flips the default.
"""
import importlib
import os

import pytest

import degradation as D


def _reload_with(**env):
    """Re-import run_medium with a patched environment (module-level consts)."""
    old = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items()})
    try:
        import run_medium
        return importlib.reload(run_medium)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture(autouse=True)
def _restore_run_medium():
    yield
    import run_medium
    importlib.reload(run_medium)


def test_empty_env_means_unset_and_uses_the_default():
    """THE 2b WIRING BUG. The workflow sets this env var on EVERY run, so a
    set-but-empty value (cron, where github.event.inputs is null) must fall back
    to the code default — not read as False. With `os.environ.get(k, "true")`
    the default was unreachable and "default ON" was on for nobody."""
    assert _reload_with(NUCLEI_STATS_ENABLED="").NUCLEI_STATS_ENABLED is True
    assert _reload_with(NUCLEI_STATS_ENABLED="   ").NUCLEI_STATS_ENABLED is True


def test_explicit_false_is_still_honoured():
    """An operator who unchecks the box sends the string 'false' and must be
    obeyed — the empty-means-default rule must not swallow that."""
    for v in ("false", "FALSE", "0", "no"):
        assert _reload_with(NUCLEI_STATS_ENABLED=v).NUCLEI_STATS_ENABLED is False


def test_stats_flag_parses_truthy_forms():
    for v in ("1", "true", "TRUE", "yes"):
        assert _reload_with(NUCLEI_STATS_ENABLED=v).NUCLEI_STATS_ENABLED is True


def test_workflow_passes_the_raw_input_with_no_false_fallback():
    """Pinned against the real workflow. `|| 'false'` there makes the code-side
    default unreachable on every cron run — the bug this test exists to stop
    from coming back."""
    import pathlib
    wf = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/scanner.yml"
    line = [l for l in wf.read_text().splitlines()
            if "NUCLEI_STATS_ENABLED:" in l]
    assert len(line) == 1, f"expected one env line, got {len(line)}"
    assert "|| 'false'" not in line[0], (
        "the `|| 'false'` fallback disables stats on every scheduled scan")
    assert "github.event.inputs.nuclei_stats" in line[0]


def test_stats_flags_absent_from_cmd_when_disabled():
    """Source-level pin: the -stats args must be inside the conditional, not in
    the unconditional cmd list. Pinned against real source text — a passing run
    of a re-implemented mirror proves nothing about the shipped builder."""
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nuclei_chunk)
    head, sep, tail = src.partition("if NUCLEI_STATS_ENABLED:")
    assert sep, "the -stats args must be behind the NUCLEI_STATS_ENABLED gate"
    assert '"-stats"' not in head, "-stats leaked into the unconditional cmd list"
    assert '"-stats"' in tail and "-stats-interval" in tail


def test_stats_artifact_capture_is_also_gated():
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nuclei_chunk)
    assert "if NUCLEI_STATS_ENABLED and stderr.strip():" in src
    assert "_stats" in src


def test_jsonl_stdout_is_untouched_by_stats():
    """-stats writes to STDERR. If it ever went to stdout it would corrupt the
    JSONL the finding parser reads, so keep -silent + -jsonl unconditional."""
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nuclei_chunk)
    head = src.partition("if NUCLEI_STATS_ENABLED:")[0]
    assert '"-silent", "-jsonl", "-no-color",' in head


# ── the risk that justifies shipping dark ──────────────────────────────────

def test_three_reachability_phrases_in_stderr_would_abort():
    """THE reason -stats is default-off. This is not hypothetical: the same
    stderr that carries stats also feeds is_tool_output_degraded, and on the
    nuclei path a non-None verdict raises DegradedRunError."""
    noisy = ("[INF] Requests: 120/3200\n"
             "[ERR] i/o timeout\n[ERR] i/o timeout\n[ERR] i/o timeout\n")
    verdict = D.is_tool_output_degraded(
        tool="nuclei[critical,high]", stdout="", stderr=noisy, rc=0,
        pre_health=True, post_health=True)
    assert verdict == "output_stderr_contains_unreachable_pattern"


def test_below_threshold_stats_noise_is_tolerated():
    """One or two such lines are downgraded to a warning — only 3+ trips it.
    So the risk is real but bounded, which is why one observation run is enough
    to settle whether a stats-line filter is needed in 2b."""
    mild = "[INF] Requests: 120/3200\n[ERR] i/o timeout\n"
    assert D.is_tool_output_degraded(
        tool="nuclei[critical,high]", stdout="", stderr=mild, rc=0,
        pre_health=True, post_health=True) is None


def test_plain_stats_lines_do_not_trip_the_detector():
    """A stats line with no reachability vocabulary is harmless — this is the
    outcome we EXPECT, and the observation run is what confirms nuclei's real
    format looks like this rather than the noisy case above."""
    plausible = ("[INF] Templates: 3200, Hosts: 1, RPS: 5, Matched: 0, "
                 "Errors: 0, Requests: 900/3200 (28%)\n") * 40
    assert D.is_tool_output_degraded(
        tool="nuclei[critical,high]", stdout="", stderr=plausible, rc=124,
        pre_health=True, post_health=True) is None


def test_parser_arrived_in_2b_against_observed_output():
    """REPLACES test_no_parser_exists_yet_on_purpose (2026-08-31).

    That test asserted no parser existed, and said whoever added one should
    remove it and say why. This is the why: runs #2637 and #2640 armed -stats
    and showed the real emission — JSON, not the "Requests sent: N" text a blind
    regex would have hunted. 2a's emit-only staging did its job; the parser in
    2b is written against observed bytes, and its fixtures in
    test_nuclei_stats_parse.py are verbatim from those runs.
    """
    import run_medium
    assert hasattr(run_medium, "parse_nuclei_stats")
    assert hasattr(run_medium, "coverage_bucket_from_stats")
    assert hasattr(run_medium, "nuclei_yield_floor_failed")
