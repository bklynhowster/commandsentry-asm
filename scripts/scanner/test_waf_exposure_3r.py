"""(KB 12 job 3r, 2026-10-23) No WAF in front of out-of-date components: capped below High.

Howie, 2026-10-23 11:50, asked whether "no enforcing WAF + an open finding with a published
flaw" (3b D2, 2026-10-21: HIGH) still holds now that every version-based flaw is only "out of
date" (Moderate): "Cap it below High". Pinned: the 'exposed' finding is MODERATE-HIGH when every
finding behind the gap is below HIGH, HIGH when at least one is HIGH or CRITICAL (the ladder
keeps those for proven problems), worded for which it is; the absence finding itself stays
MODERATE; nothing changes when the read fails or finds nothing.
"""
import run_heavy as h
from test_waf_scoring_3b import ABSENT, SERVED, _ctx, _fid, _no_exposure

OUT_OF_DATE = [
    {"finding_id": "app.example.com:light:wpvuln-cve-2026-6728", "title": "Slider Revolution [revslider] < 7.0.10",
     "severity": "MODERATE", "cve": ["CVE-2026-6728"]},
    {"finding_id": "app.example.com:light:libflaw-jquery-ui-x", "title": "jQuery UI 1.12.1: XSS",
     "severity": "MODERATE-HIGH", "cve": ["CVE-2021-41184"]},
]


def _emit(monkeypatch, rows):
    _no_exposure(monkeypatch, ok=True, rows=rows)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    return ctx, {f.finding_id: f for f in ctx.findings}


def test_no_waf_in_front_of_out_of_date_flaws_only_is_moderate_high(monkeypatch):
    ctx, ids = _emit(monkeypatch, OUT_OF_DATE)
    exp = ids[_fid(ctx, h.WAF_EXPOSED_CHECK_ID)]
    assert exp.severity == "MODERATE-HIGH"
    assert exp.title == "Out-of-date component with no enforcing WAF in front (2 open)"
    assert "out of date" in exp.description and "CVE-2026-6728" in exp.description
    assert "Known-vulnerable" not in exp.title
    assert ids[_fid(ctx, h.WAF_ABSENT_CHECK_ID)].severity == "MODERATE"
    assert ctx.waf_exposed_emitted


def test_one_proven_finding_behind_the_gap_makes_it_high(monkeypatch):
    for sev in ("HIGH", "CRITICAL"):
        rows = OUT_OF_DATE + [{"finding_id": "app.example.com:heavy:x", "title": "Proven hole",
                               "severity": sev, "cve": ["CVE-2020-1"]}]
        ctx, ids = _emit(monkeypatch, rows)
        exp = ids[_fid(ctx, h.WAF_EXPOSED_CHECK_ID)]
        assert exp.severity == "HIGH", sev
        assert exp.title.startswith("Known-vulnerable component with no enforcing WAF in front"), sev


def test_the_absence_finding_says_both_kinds_of_exposure(monkeypatch):
    ctx, ids = _emit(monkeypatch, [])
    d = ids[_fid(ctx, h.WAF_ABSENT_CHECK_ID)].description
    assert "HIGH behind a proven problem, MODERATE-HIGH behind out-of-date components" in d
    assert "separate HIGH finding" not in d


def test_nothing_behind_the_gap_or_a_failed_read_adds_nothing(monkeypatch):
    for ok in (True, False):
        _no_exposure(monkeypatch, ok=ok, rows=[])
        ctx = _ctx()
        h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
        assert [f.finding_id for f in ctx.findings] == [_fid(ctx, h.WAF_ABSENT_CHECK_ID)]
        assert not ctx.waf_exposed_emitted
