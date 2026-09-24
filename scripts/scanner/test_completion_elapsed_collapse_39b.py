"""#39b — elapsed_s must survive the phase COLLAPSE into per_chunk.

THE DEFECT THIS PINS (found live 2026-09-24, uat.prodexlabs.com heavy, 1951s):
#39 taught mark_tool_ok_evidenced to write elapsed_s onto the per-chunk
recorder entry. UnitResult had no field for it, so _units_from_recorder
dropped it and the persisted phase entry showed the two OK chunks with
reason="completed" and NO elapsed. A unit test of the primitive passed the
whole time — testing the decision is not testing the collapse. So this test
drives the boundary that failed.
"""
from phase_contract import UnitResult, Outcome, _units_from_recorder


def test_recorder_carries_elapsed_off_a_completed_chunk():
    units = _units_from_recorder({
        "nuclei[medium:tech]": {
            "ok": True, "elapsed_s": 12.3, "reason": "completed",
            "evidence": {"kind": "measured", "requests": 10},
        },
    })
    assert len(units) == 1
    assert units[0].outcome == Outcome.OK
    assert units[0].elapsed_s == 12.3, "elapsed_s dropped at the recorder boundary"


def test_as_dict_emits_elapsed_so_it_reaches_per_chunk():
    d = UnitResult(name="nuclei[medium:tech]", outcome=Outcome.OK,
                   elapsed_s=12.3).as_dict()
    assert d["elapsed_s"] == 12.3, "elapsed_s never reaches the persisted per_chunk"


def test_a_cut_chunk_records_no_elapsed_key_at_all():
    # the cut path writes no elapsed; the key must be absent, not null
    d = UnitResult(name="nuclei[critical,high]", outcome=Outcome.PARTIAL,
                   reason="wall_clock_cut_400s", rps=6, requests=2677).as_dict()
    assert "elapsed_s" not in d
