#!/usr/bin/env python3
"""test_nuclei_stats_parse.py — increment 2b (4.7 rulings ③ ④ ⑲).

Fixtures are VERBATIM from Command runs #2637/#2640 with -stats armed, not
invented. 2a shipped emit-only precisely so this parser could be written against
observed output; a `Requests sent: N` regex — the human-readable form I would
have guessed — would have matched nothing and silently reported no coverage
forever.
"""
import pytest

from degradation import (COVERAGE_COMPLETE, COVERAGE_PARTIAL_MINIMAL,
                         COVERAGE_PARTIAL_SIGNIFICANT, COVERAGE_UNKNOWN)
from run_medium import (coverage_bucket_from_stats, nuclei_yield_floor_failed,
                        parse_nuclei_stats)

# Real emission from run #2637, chunk `critical,high` (687/7255 = 9%).
_LINE_EARLY = ('{"duration":"0:00:05","errors":"0","hosts":"1","matched":"0",'
               '"percent":"0","requests":"14","rps":"2",'
               '"startedAt":"2026-08-30T21:42:14Z","templates":"3799","total":"7255"}')
_LINE_LAST = ('{"duration":"0:02:35","errors":"0","hosts":"1","matched":"0",'
              '"percent":"9","requests":"687","rps":"4",'
              '"startedAt":"2026-08-30T21:42:14Z","templates":"3799","total":"7255"}')
# run_cmd appends this on the cut path — so it, not a stats line, is last.
REAL_CUT_STDERR = f"{_LINE_EARLY}\n{_LINE_LAST}\n\ntimeout after 180s"


# ── parsing ────────────────────────────────────────────────────────────────

def test_parses_the_last_stats_line_not_the_last_line():
    """TRAP 1. `splitlines()[-1]` gets our own 'timeout after 180s' and
    json.loads raises — so a naive parser reports nothing on exactly the runs
    we care about."""
    s = parse_nuclei_stats(REAL_CUT_STDERR)
    assert s is not None
    assert s["requests"] == 687, "took an earlier emission, or our appended text"
    assert s["total"] == 7255
    assert s["percent"] == 9


def test_values_are_coerced_from_strings():
    """TRAP 2. nuclei emits "requests":"687" — strings. Left as-is, every
    comparison against the yield floor silently misbehaves."""
    s = parse_nuclei_stats(REAL_CUT_STDERR)
    for k in ("requests", "total", "percent", "rps", "templates"):
        assert isinstance(s[k], int), f"{k} not coerced to int"


def test_no_stats_returns_none_not_zero():
    """Unmeasurable is NOT zero. Returning {} or zeros here would make the
    yield floor fire on every chunk that simply had the flag off."""
    assert parse_nuclei_stats("") is None
    assert parse_nuclei_stats("timeout after 180s") is None
    assert parse_nuclei_stats(None) is None


def test_ragged_final_json_is_skipped_for_an_earlier_complete_one():
    """A killed process can be mid-write. Fall back to the last COMPLETE line
    rather than losing the whole measurement."""
    s = parse_nuclei_stats(f'{_LINE_LAST}\n{{"duration":"0:02:40","req')
    assert s["requests"] == 687


def test_garbage_stderr_does_not_raise():
    assert parse_nuclei_stats("not json at all\nnor this") is None


# ── bucketing (ruling ③) ───────────────────────────────────────────────────

@pytest.mark.parametrize("pct,expected", [
    (100, COVERAGE_COMPLETE),
    (92, COVERAGE_PARTIAL_SIGNIFICANT),   # medium:wordpress,cms on #2637
    (50, COVERAGE_PARTIAL_SIGNIFICANT),   # boundary
    (48, COVERAGE_PARTIAL_MINIMAL),       # medium:exposure,config
    (9, COVERAGE_PARTIAL_MINIMAL),        # critical,high
    (0, COVERAGE_PARTIAL_MINIMAL),
])
def test_buckets_match_the_observed_chunks(pct, expected):
    assert coverage_bucket_from_stats({"percent": pct}) == expected


def test_falls_back_to_requests_over_total_when_percent_absent():
    assert coverage_bucket_from_stats(
        {"requests": 1199, "total": 1299}) == COVERAGE_PARTIAL_SIGNIFICANT
    assert coverage_bucket_from_stats(
        {"requests": 687, "total": 7255}) == COVERAGE_PARTIAL_MINIMAL


def test_unknown_when_nothing_measurable():
    """Never guess a bucket. 'unknown' was the honest value for two weeks and
    must stay reachable."""
    assert coverage_bucket_from_stats(None) == COVERAGE_UNKNOWN
    assert coverage_bucket_from_stats({}) == COVERAGE_UNKNOWN
    assert coverage_bucket_from_stats({"rps": 4}) == COVERAGE_UNKNOWN
    assert coverage_bucket_from_stats({"requests": 5, "total": 0}) == COVERAGE_UNKNOWN


# ── yield floor (rulings ④ + ⑲) ────────────────────────────────────────────

def test_broken_and_cut_fails_the_floor():
    """A chunk killed having sent ~nothing is BROKEN, not partial — WAF banned
    us at chunk start, or templates never loaded. Claiming partial coverage for
    it is the same lie in a smaller box."""
    assert nuclei_yield_floor_failed({"requests": 0}) == "yield_floor_failed_0_requests"
    assert nuclei_yield_floor_failed({"requests": 2}) == "yield_floor_failed_2_requests"


def test_every_real_observed_chunk_passes_the_floor():
    """Calibration guard. All six chunks from #2637 — including the two that
    completed in seconds (29 and 10 requests) — must clear it. A floor that
    false-degrades real work is worse than no floor."""
    for req in (687, 1249, 923, 1199, 29, 10):
        assert nuclei_yield_floor_failed({"requests": req}) is None, (
            f"{req} requests false-degraded — floor is calibrated too high")


def test_unmeasurable_is_not_a_floor_failure():
    """Absent stats must not degrade the chunk. Otherwise turning the flag off
    would start failing scans."""
    assert nuclei_yield_floor_failed(None) is None
    assert nuclei_yield_floor_failed({}) is None
    assert nuclei_yield_floor_failed({"rps": 4}) is None


# ── wiring ─────────────────────────────────────────────────────────────────

def test_stats_default_is_now_on():
    """2a shipped dark; the abort risk was then measured at 0/7 pattern matches
    across two full runs, so 2b arms it."""
    import run_medium
    assert run_medium.NUCLEI_STATS_ENABLED is True


def test_cut_path_measures_coverage_and_gates_on_the_floor():
    """Pinned to real source: the floor must be checked BEFORE mark_tool_partial
    (⑲ — yield failure wins over the cut), and coverage must be computed rather
    than hard-coded 'unknown'."""
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nuclei_chunked)
    branch = src.partition("if rc == 124:")[2].split("\n        else:")[0]
    # Comments in this branch discuss `raise`/`continue` deliberately, so strip
    # them before any keyword assertion — see the same note in
    # test_wall_clock_partial.
    code = "\n".join(l for l in branch.splitlines()
                     if not l.strip().startswith("#"))
    assert "parse_nuclei_stats(chunk_stderr)" in code
    assert code.index("nuclei_yield_floor_failed") < code.index("mark_tool_partial"), (
        "yield floor must be evaluated before recording PARTIAL (⑲)")
    assert "coverage_bucket_from_stats(stats)" in code
    assert "wall_clock_degradation(NUCLEI_CHUNK_WALL_S, coverage)" in code
    # ⑲ routes a floor failure to mark_tool_degraded, NOT mark_tool_partial.
    assert "mark_tool_degraded(ctx, chunk_name, floor" in code
    # …and neither path aborts or skips the rotation.
    assert "raise" not in code and "continue" not in code


def test_evidence_counts_ride_alongside_the_bucket():
    """Ruling ③ said the bucket is the verdict — but bucketing alone flattens
    '92%, a hundred requests short' into the same value as 51%, and that 92%
    chunk was the WordPress one on a WordPress target."""
    import types
    from degradation import wall_clock_degradation
    from run_medium import mark_tool_partial
    ctx = types.SimpleNamespace(tool_status={}, tools_run=[], artifacts=[],
                                findings=[], dsn=None, scan_run_id="s")
    mark_tool_partial(ctx, "nuclei[medium:wordpress,cms]",
                      wall_clock_degradation(180, COVERAGE_PARTIAL_SIGNIFICANT),
                      matches=0,
                      stats={"requests": 1199, "total": 1299, "percent": 92, "rps": 6})
    e = ctx.tool_status["nuclei[medium:wordpress,cms]"]
    assert e["ok"] is False and e["partial"] is True
    assert e["coverage"] == COVERAGE_PARTIAL_SIGNIFICANT
    assert (e["requests"], e["total"], e["percent"]) == (1199, 1299, 92)


def test_partial_entry_without_stats_still_valid():
    """Flag off / nuclei too fast to emit — the entry must still be coherent."""
    import types
    from degradation import wall_clock_degradation
    from run_medium import mark_tool_partial
    ctx = types.SimpleNamespace(tool_status={}, tools_run=[], artifacts=[],
                                findings=[], dsn=None, scan_run_id="s")
    mark_tool_partial(ctx, "nuclei[x]", wall_clock_degradation(180), stats=None)
    e = ctx.tool_status["nuclei[x]"]
    assert e["coverage"] == COVERAGE_UNKNOWN
    assert "requests" not in e
