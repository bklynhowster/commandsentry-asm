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


# ─── the OK path: an ALL-CLEAN phase must still carry evidence ───────────
#
# The collapse widening above is necessary but NOT sufficient. run_phase's OK
# branch calls mark_ok(), which defaults to the deprecated bare mark_tool_ok;
# only the PARTIAL/MIXED branch ever consulted the units. So 5-of-5 clean —
# exactly commandcommcentral.com — recorded {"ok": true, actual_chunks: 5,
# planned_chunks: 5} both before spec 220 and after it.


def _res(units):
    from phase_contract import PhaseResult
    return PhaseResult.ok(per_unit_state=units)


def _ctx(entry=None):
    import types
    return types.SimpleNamespace(
        tool_status={"nuclei": dict(entry or {"ok": True})}, tool_diag={})


def test_all_clean_phase_records_summed_evidence():
    from phase_contract import _merge_phase_evidence
    units = _units_from_recorder({
        "nuclei[a]": _clean(requests=8225, total=9039),
        "nuclei[b]": _clean(requests=10, total=10),
    })
    ctx = _ctx()
    _merge_phase_evidence(ctx, "nuclei", _res(units))
    e = ctx.tool_status["nuclei"]
    assert e["ok"] is True, "phase 1 changes no verdicts"
    assert e["evidence"]["requests"] == 8235
    assert e["evidence"]["total"] == 9049
    assert e["chunks_ok"] == 2
    assert [u["name"] for u in e["per_chunk"]] == ["nuclei[a]", "nuclei[b]"]


def test_all_clean_phase_with_no_counts_says_unmeasurable():
    from phase_contract import _merge_phase_evidence
    entry = {"ok": True}
    entry.update(Evidence.unmeasurable("nuclei_stats_absent").to_status())
    ctx = _ctx()
    _merge_phase_evidence(ctx, "nuclei", _res(_units_from_recorder({"nuclei[a]": entry})))
    ev = ctx.tool_status["nuclei"]["evidence"]
    assert ev["kind"] == "unmeasurable"
    assert ev["reason"] == "no_unit_carried_a_count"
    assert "requests" not in ev, "must not fabricate a zero"


def test_merge_is_additive_and_touches_no_verdict_key():
    """⑰ all-match reads tool_status->tool->>'ok'. Widening must not disturb it."""
    from phase_contract import _merge_phase_evidence
    ctx = _ctx({"ok": True, "actual_chunks": 5, "planned_chunks": 5})
    units = _units_from_recorder({"nuclei[a]": _clean(requests=1, total=2)})
    _merge_phase_evidence(ctx, "nuclei", _res(units))
    e = ctx.tool_status["nuclei"]
    assert e["ok"] is True
    assert e["actual_chunks"] == 5 and e["planned_chunks"] == 5
    for k in ("degraded", "partial", "mixed", "skipped", "coverage"):
        assert k not in e


def test_single_unit_named_for_the_phase_gets_no_per_chunk():
    """A per_chunk of length 1 that IS the phase implies chunking that never
    happened — same harm as ⑭′.4's meaningless planned_chunks."""
    from phase_contract import _merge_phase_evidence
    ctx = _ctx()
    _merge_phase_evidence(ctx, "nuclei", _res(_units_from_recorder({"nuclei": _clean(items=3)})))
    assert "per_chunk" not in ctx.tool_status["nuclei"]
    assert "chunks_ok" not in ctx.tool_status["nuclei"]


def test_no_units_is_a_no_op():
    from phase_contract import _merge_phase_evidence
    ctx = _ctx()
    _merge_phase_evidence(ctx, "nuclei", _res([]))
    assert ctx.tool_status["nuclei"] == {"ok": True}


def test_legacy_adapter_carries_units_on_the_CLEAN_path():
    """PhaseResult is the only carrier between recorder and run_phase (the ⑪
    lesson). A clean phase returning empty per_unit_state has thrown the
    evidence away before run_phase can write it."""
    import re
    from pathlib import Path
    src = Path(__file__).with_name("phase_contract.py").read_text()
    body = re.search(r"def legacy_adapter\(.*?\n(?=def |# ── )", src, re.S).group(0)
    code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "PhaseResult.ok(per_unit_state=_units_from_recorder(rec.tool_status)" in code, (
        "legacy_adapter's clean path must carry the units")
    assert "coverage=" not in code.split("PhaseResult.ok(")[1][:200], (
        "coverage is the PARTIAL/MIXED bucket — an OK result must not assert one")


def test_run_phase_ok_branch_merges_evidence():
    import re
    from pathlib import Path
    src = Path(__file__).with_name("phase_contract.py").read_text()
    body = re.search(r"if result\.outcome == Outcome\.OK:.*?elif result\.outcome",
                     src, re.S).group(0)
    code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "_merge_phase_evidence(ctx, spec.name, result)" in code, (
        "the OK branch writes a bare {'ok': True} without this — the exact "
        "shape commandcommcentral recorded before AND after spec 220")
