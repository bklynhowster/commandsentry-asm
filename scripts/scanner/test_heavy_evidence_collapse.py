"""Clean-path evidence must survive the cumulative-heavy collapse (spec 220).

WHY THIS FILE EXISTS
--------------------
test_clean_path_evidence.py proves run_nuclei_chunked WRITES evidence. It does
not prove anyone can still READ it two layers later — and under a cumulative
heavy there are two layers.

A cumulative heavy runs medium's `run_nuclei_chunked` against a
`HeavyScanContext` wrapped in the phase_contract recorder. The recorder's
per-chunk `tool_status` is then collapsed by `_units_from_recorder` into
UnitResults, `aggregate_coverage` sums those, and `run_phase` writes ONE
`nuclei` entry. That collapse is where the DB gets its row: the 5.2-minute
commandcommcentral heavy recorded exactly one `nuclei%` key.

The defect this pins: `_units_from_recorder` was written for the CUT path,
which records FLAT `requests`/`total`/`percent` via mark_tool_partial(stats=…).
`mark_tool_ok_evidenced` records them NAMESPACED under `evidence` — deliberately,
so they cannot collide with the verdict keys the ⑰ all-match predicate reads.
So every clean unit arrived with requests=None, aggregate_coverage summed to
tot == 0, and the phase entry came out with no evidence at all.

⇒ Without this widening, the run that MOTIVATED spec 220 would have looked
byte-identical after spec 220 shipped. Same family as ⑭′ defect A: run_phase
discarding what a phase recorded because the collapse did not know the key.

Run: python -m pytest scripts/scanner/test_heavy_evidence_collapse.py -q
"""

from __future__ import annotations

import pytest

from phase_contract import Outcome, _units_from_recorder, aggregate_coverage
from tool_evidence import Evidence


def _clean(**kw):
    """What mark_tool_ok_evidenced() actually puts in tool_status."""
    entry = {"ok": True}
    entry.update(Evidence.measured(**kw).to_status())
    return entry


# ─── the collapse ────────────────────────────────────────────────────────


def test_clean_path_evidence_reaches_the_unit():
    units = _units_from_recorder(
        {"nuclei[medium:cve]": _clean(requests=8225, total=9039, percent=90)}
    )
    assert len(units) == 1
    u = units[0]
    assert u.outcome == Outcome.OK
    assert (u.requests, u.total, u.percent) == (8225, 9039, 90), (
        "namespaced evidence was dropped at the recorder collapse — this is "
        "the defect that would have made spec 220 invisible on heavy"
    )


def test_a_fully_clean_heavy_phase_aggregates_real_coverage():
    """The motivating case. Five chunks, all clean, all evidenced."""
    units = _units_from_recorder({
        "nuclei[critical,high]": _clean(requests=1200, total=1200),
        "nuclei[medium:cve]":    _clean(requests=8225, total=9039),
        "nuclei[medium:expo]":   _clean(requests=900, total=900),
        "nuclei[medium:tech]":   _clean(requests=10, total=10),
        "nuclei[medium:wp]":     _clean(requests=430, total=430),
    })
    bucket, evidence = aggregate_coverage(units)
    assert evidence, "phase-level evidence must not be empty for a clean phase"
    assert evidence["requests"] == 10765
    assert evidence["total"] == 11579
    assert bucket is not None


def test_before_the_fix_this_would_have_been_empty():
    """Pins the exact failure shape: counts present but ONLY namespaced.

    If someone re-narrows _units_from_recorder to flat-only, aggregate_coverage
    returns ({}, None-bucket) and this fails — which is what the DB showed.
    """
    units = _units_from_recorder({"nuclei[x]": _clean(requests=5, total=9039)})
    bucket, evidence = aggregate_coverage(units)
    assert evidence != {}, "clean-path units contributed nothing to the phase"
    assert evidence["total"] == 9039


# ─── the widening must not disturb the established cut path ──────────────


def test_flat_cut_path_shape_still_wins():
    """mark_tool_partial(stats=…) writes FLAT counts. Unchanged behaviour, and
    flat takes precedence so this stays a pure widening."""
    units = _units_from_recorder({
        "nuclei[cut]": {
            "partial": True, "reason": "wall_clock", "coverage": "partial_minimal",
            "requests": 340, "total": 7255, "percent": 4,
            "evidence": {"kind": "measured", "requests": 999, "total": 999},
        }
    })
    u = units[0]
    assert u.outcome == Outcome.PARTIAL
    assert (u.requests, u.total, u.percent) == (340, 7255, 4)


def test_unmeasurable_contributes_no_counts():
    """'Cannot tell' must not become 'did nothing' at the aggregate either."""
    entry = {"ok": True}
    entry.update(Evidence.unmeasurable("nuclei_stats_absent").to_status())
    units = _units_from_recorder({"nuclei[q]": entry})
    assert units[0].outcome == Outcome.OK
    assert units[0].requests is None and units[0].total is None
    bucket, evidence = aggregate_coverage(units)
    assert evidence == {}, "an unmeasurable unit must not invent coverage"


def test_rps_is_not_widened():
    """nuclei's rps is not a network rate — Evidence refuses to carry it, and
    this adapter must not resurrect it from the evidence block."""
    units = _units_from_recorder(
        {"nuclei[y]": {"ok": True,
                       "evidence": {"kind": "measured", "requests": 1,
                                    "total": 2, "rps": 999}}}
    )
    assert units[0].rps is None


def test_degraded_and_skipped_shapes_are_untouched():
    units = {u.name: u for u in _units_from_recorder({
        "a": {"degraded": "banned"},
        "b": {"skipped": "auth_gated"},
        "c": {"ok": False},
    })}
    assert units["a"].outcome == Outcome.DEGRADED
    assert units["b"].outcome == Outcome.GATE_SKIPPED
    assert units["c"].outcome == Outcome.DEGRADED, (
        "unrecognised/false shapes must never be credited OK")


def test_evidence_that_is_not_a_dict_is_ignored_safely():
    units = _units_from_recorder({"n": {"ok": True, "evidence": "garbage"}})
    assert units[0].outcome == Outcome.OK
    assert units[0].requests is None


def test_partial_percent_only_evidence_still_lands():
    """Evidence may carry percent without requests/total."""
    entry = {"ok": True}
    entry.update(Evidence.measured(percent=73).to_status())
    assert _units_from_recorder({"n": entry})[0].percent == 73
