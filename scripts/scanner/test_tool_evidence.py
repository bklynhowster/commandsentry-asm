"""Tests for the Evidence type (4.7 rulings 83-87, spec 220).

The load-bearing properties here are the ones that stop Evidence becoming the
old bug in a new costume:

  * measured() with NO counts must RAISE — an "evidence" object carrying
    nothing is exactly what we are replacing
  * unmeasurable() with no reason must RAISE — an unexplained gap is the
    silent ok:true bug wearing a different hat
  * absent stats must be UNMEASURABLE, never a zero measurement — "we cannot
    tell" and "it did nothing" are different claims

Run: python -m pytest scripts/scanner/test_tool_evidence.py -q
"""

from __future__ import annotations

import pytest

from tool_evidence import MEASURED, UNMEASURABLE, Evidence


# ─── The properties that stop this becoming the old bug ──────────────────


def test_measured_with_no_counts_raises():
    with pytest.raises(ValueError, match="at least one count"):
        Evidence.measured()


def test_measured_with_only_extras_still_raises():
    """Extras are context, not evidence of work."""
    with pytest.raises(ValueError):
        Evidence.measured(templates=4290, errors=0)


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_unmeasurable_requires_a_reason(bad):
    with pytest.raises(ValueError, match="requires a reason"):
        Evidence.unmeasurable(bad)


def test_absent_stats_is_unmeasurable_not_zero():
    """'Cannot tell' must never collapse into 'did nothing'."""
    e = Evidence.from_nuclei_stats(None)
    assert e.kind == UNMEASURABLE
    assert e.reason == "nuclei_stats_absent"
    assert e.requests is None, "must NOT synthesise a zero count"
    assert e.completion_ratio is None


def test_stats_present_but_countless_is_unmeasurable():
    e = Evidence.from_nuclei_stats({"duration": "0:00:05", "rps": 3})
    assert e.kind == UNMEASURABLE
    assert e.reason == "nuclei_stats_had_no_counts"


# ─── Measurement ─────────────────────────────────────────────────────────


def test_from_nuclei_stats_carries_counts():
    e = Evidence.from_nuclei_stats(
        {"requests": 8225, "total": 9039, "percent": 90,
         "templates": 4290, "matched": 0, "errors": 13, "rps": 21}
    )
    assert e.is_measured
    assert (e.requests, e.total, e.percent) == (8225, 9039, 90)
    assert e.extra["templates"] == 4290


def test_rps_is_not_carried_as_evidence():
    """nuclei's rps is NOT a network rate (measured 148 real sends vs a counter
    claiming 457). It must not ride along as if it were evidence of work."""
    e = Evidence.from_nuclei_stats({"requests": 100, "total": 200, "rps": 999})
    assert "rps" not in e.to_status()["evidence"]


def test_completion_ratio_prefers_percent():
    e = Evidence.measured(requests=10, total=1000, percent=95)
    assert e.completion_ratio == pytest.approx(0.95)


def test_completion_ratio_falls_back_to_requests_over_total():
    e = Evidence.measured(requests=50, total=200)
    assert e.completion_ratio == pytest.approx(0.25)


def test_completion_ratio_none_when_total_missing_or_zero():
    assert Evidence.measured(requests=50).completion_ratio is None
    assert Evidence.measured(requests=50, total=0).completion_ratio is None


def test_low_template_chunk_ratio_is_high_not_low():
    """4.7 (85): medium:tech legitimately completes at ~10 requests. A RATIO
    sees that as complete; an absolute floor would false-DEGRADE it."""
    tech = Evidence.measured(requests=10, total=10)
    waffled = Evidence.measured(requests=5, total=9039)
    assert tech.completion_ratio == pytest.approx(1.0)
    assert waffled.completion_ratio < 0.001
    assert tech.completion_ratio > waffled.completion_ratio, (
        "ratio must rank a small COMPLETE chunk above a large REFUSED one — "
        "this is the whole reason the floor is a ratio"
    )


# ─── Serialisation / data contract ───────────────────────────────────────


def test_to_status_is_namespaced_under_evidence():
    """Must not collide with verdict keys the ⑰ autoclose predicate reads."""
    body = Evidence.measured(requests=1, total=2).to_status()
    assert set(body) == {"evidence"}
    for verdict_key in ("ok", "degraded", "partial", "reason", "coverage"):
        assert verdict_key not in body


def test_unmeasurable_status_states_the_reason():
    body = Evidence.unmeasurable("tool_exposes_no_counts").to_status()["evidence"]
    assert body["kind"] == UNMEASURABLE
    assert body["reason"] == "tool_exposes_no_counts"


def test_measured_status_includes_ratio():
    body = Evidence.measured(requests=45, total=100).to_status()["evidence"]
    assert body["kind"] == MEASURED
    assert body["completion_ratio"] == pytest.approx(0.45)
    assert body["requests"] == 45


def test_evidence_carries_no_verdict_of_its_own():
    """Observation and verdict stay separate — that separation is what lets
    Phase 1 record measurements with zero behaviour change."""
    e = Evidence.measured(requests=1, total=9999)
    assert not hasattr(e, "ok")
    assert not hasattr(e, "degraded")
    # A dismal ratio is still not a verdict at this phase.
    assert e.completion_ratio < 0.001
    assert "ok" not in e.to_status()["evidence"]


def test_evidence_is_frozen():
    e = Evidence.measured(items=3)
    with pytest.raises(Exception):
        e.items = 4  # type: ignore[misc]


def test_items_supports_non_nuclei_tools():
    """gau URLs / httpx rows / ffuf hits migrate without a bespoke type."""
    e = Evidence.measured(items=14)
    assert e.is_measured
    assert e.to_status()["evidence"]["items"] == 14
