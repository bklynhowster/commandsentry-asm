"""(S1, 2026-10-29) The flaw's own published record decides what it affects.

Howie, 2026-10-29 17:55: "Go with number one. Let's proceed." wpvulnerability.net files
CVE-2026-6728 as one range, "Slider Revolution [revslider] < 7.0.10"; the record its CNA
published (Wordfence) has two, 6.0 to 6.7.54 and 7.0 to 7.0.9, and says everything else is
"unaffected". Five Command sites run 6.7.58 or 6.8.1 and were told to "fix soon".

Pinned here: the record (its CNA part, as served by cveawg.mitre.org 2026-10-29) leaves 6.7.58
and 6.8.1 out and keeps every version inside either range; anything unclear keeps the finding
(no record, a product the names don't match exactly, defaultStatus not "unaffected", `changes`,
a version type or bound it can't compare, an open-ended range); the record is read only after
an entry point turns reads on, once per CVE, never raising; the writer drops the match and
notes a retraction, also through a medium/heavy phase recorder; the retraction touches only
this writer's open row, with an audit row and a history row, once per finding.
"""
from __future__ import annotations

import copy
import json
import os

import pytest

import evidence
import run_light

HERE = os.path.dirname(os.path.abspath(__file__))

# CVE-2026-6728 as cveawg.mitre.org served it on 2026-10-29 (cveMetadata + the CNA's affected,
# descriptions and title; the ADP container and references left out).
REC_6728 = json.loads("""{
 "dataType": "CVE_RECORD", "dataVersion": "5.2",
 "cveMetadata": {"cveId": "CVE-2026-6728", "assignerShortName": "Wordfence", "state": "PUBLISHED"},
 "containers": {"cna": {
   "affected": [{"vendor": "Revolution Slider", "product": "Slider Revolution",
                 "versions": [{"version": "6.0", "status": "affected", "lessThanOrEqual": "6.7.54", "versionType": "semver"},
                              {"version": "7.0", "status": "affected", "lessThanOrEqual": "7.0.9", "versionType": "semver"}],
                 "defaultStatus": "unaffected"}],
   "descriptions": [{"lang": "en", "value": "The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 7.0.9 via the 'get_stream_data()' function."}],
   "title": "Slider Revolution <= 7.0.9 - Unauthenticated Sensitive Information Exposure via 'sliders/stream'"}}
}""")
NAMES = ["Slider Revolution", "revslider", "revslider"]
WHY = "Wordfence's record: affected 6.0 to 6.7.54, 7.0 to 7.0.9"


def _rec(**cna_entry):
    r = copy.deepcopy(REC_6728)
    r["containers"]["cna"]["affected"][0].update(cna_entry)
    return r


# ── the decision ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("version", ["6.7.58", "6.8.1", "6.7.55", "5.9", "7.0.10", "7.1", "8.0"])
def test_the_slider_record_leaves_these_out(version):
    assert evidence.cna_leaves_out(version, REC_6728, NAMES) == WHY


@pytest.mark.parametrize("version", ["6.0", "6.0.0", "6.5", "6.7.54", "7.0", "7.0.0", "7.0.5", "7.0.9"])
def test_inside_either_range_keeps_it(version):
    assert evidence.cna_leaves_out(version, REC_6728, NAMES) is None


def test_less_than_is_exclusive_and_from_the_start_reads():
    r = _rec(versions=[{"version": "0", "status": "affected", "lessThan": "7.0.10", "versionType": "semver"}])
    assert evidence.cna_leaves_out("7.0.9", r, NAMES) is None
    assert evidence.cna_leaves_out("7.0.10", r, NAMES) == "Wordfence's record: affected from the start up to, not including, 7.0.10"
    r2 = _rec(versions=[{"version": "n/a", "status": "affected", "lessThanOrEqual": "2.5.14"}])
    assert evidence.cna_leaves_out("2.5.14", r2, NAMES) is None and evidence.cna_leaves_out("2.6.1", r2, NAMES)


def test_one_exact_version():
    r = _rec(versions=[{"version": "6.8.1", "status": "affected", "versionType": "custom"}])
    assert evidence.cna_leaves_out("6.8.1", r, NAMES) is None
    assert evidence.cna_leaves_out("6.8.2", r, NAMES) == "Wordfence's record: affected exactly 6.8.1"


def test_two_entries_for_the_product_inside_either_keeps_it():
    r = copy.deepcopy(REC_6728)
    r["containers"]["cna"]["affected"].append({"vendor": "x", "product": "Slider Revolution", "defaultStatus": "unaffected",
                                               "versions": [{"version": "6.8.0", "status": "affected", "lessThanOrEqual": "6.8.1"}]})
    assert evidence.cna_leaves_out("6.8.1", r, NAMES) is None
    assert evidence.cna_leaves_out("6.7.58", r, NAMES) is not None


def test_an_entry_for_another_product_is_not_read():
    r = copy.deepcopy(REC_6728)
    r["containers"]["cna"]["affected"].append({"vendor": "x", "product": "Another Plugin", "defaultStatus": "affected"})
    assert evidence.cna_leaves_out("6.8.1", r, NAMES) == WHY


@pytest.mark.parametrize("record, names, version", [
    (None, NAMES, "6.8.1"),                                               # no record
    ({}, NAMES, "6.8.1"),                                                 # not a record
    (REC_6728, ["Slider"], "6.8.1"),                                      # "Slider" is not "Slider Revolution"
    (REC_6728, [], "6.8.1"),                                              # no names
    (REC_6728, NAMES, "6.8.1-beta"),                                      # a version it can't compare
    (REC_6728, NAMES, ""),
    (REC_6728, NAMES, None),
    (_rec(defaultStatus="affected"), NAMES, "6.8.1"),
    (_rec(defaultStatus="unknown"), NAMES, "6.8.1"),
    ({**REC_6728, "containers": {"cna": {"affected": [{"product": "Slider Revolution", "versions": [
        {"version": "6.0", "status": "affected", "lessThanOrEqual": "6.7.54"}]}]}}}, NAMES, "6.8.1"),   # no defaultStatus
    (_rec(versions=[]), NAMES, "6.8.1"),
    (_rec(versions=[{"version": "6.0", "status": "unaffected", "lessThan": "7.0"}]), NAMES, "6.8.1"),   # nothing affected
    (_rec(versions=[{"version": "6.0", "status": "affected", "lessThanOrEqual": "6.7.54",
                     "changes": [{"at": "6.5", "status": "unaffected"}]}]), NAMES, "6.8.1"),
    (_rec(versions=[{"version": "6.0", "status": "affected", "lessThanOrEqual": "6.7.54", "versionType": "git"}]), NAMES, "6.8.1"),
    (_rec(versions=[{"version": "6.x", "status": "affected", "lessThanOrEqual": "6.7.54"}]), NAMES, "6.8.1"),
    (_rec(versions=[{"version": "6.0", "status": "affected", "lessThanOrEqual": "6.7.54-rc1"}]), NAMES, "6.8.1"),
    (_rec(versions=[{"version": "6.0", "status": "affected", "lessThan": "*"}]), NAMES, "6.8.1"),       # open above
])
def test_anything_unclear_keeps_the_finding(record, names, version):
    assert evidence.cna_leaves_out(version, record, names) is None


# ── reading the record ───────────────────────────────────────────────────────────────
def test_reads_are_off_until_an_entry_point_turns_them_on(monkeypatch):
    monkeypatch.setattr(evidence, "_CNA_CACHE", {})
    monkeypatch.setattr(evidence, "_CNA_READS_ON", False)
    called = []
    monkeypatch.setattr(evidence.urllib.request, "urlopen", lambda *a, **k: called.append(a) or 1 / 0)
    assert evidence.cna_record("CVE-2026-6728") is None and not called


def test_one_read_per_cve_and_a_failure_is_remembered(monkeypatch):
    monkeypatch.setattr(evidence, "_CNA_CACHE", {})
    calls = []

    def get(url):
        calls.append(url)
        return REC_6728
    assert evidence.cna_record("cve-2026-6728", get) == REC_6728
    assert evidence.cna_record("CVE-2026-6728", get) == REC_6728
    assert calls == ["https://cveawg.mitre.org/api/cve/CVE-2026-6728"]

    def boom(url):
        calls.append(url)
        raise OSError("no route")
    assert evidence.cna_record("CVE-2026-0001", boom) is None
    assert evidence.cna_record("CVE-2026-0001", boom) is None
    assert calls.count("https://cveawg.mitre.org/api/cve/CVE-2026-0001") == 1


def test_a_wrong_or_malformed_answer_is_no_record(monkeypatch):
    monkeypatch.setattr(evidence, "_CNA_CACHE", {})
    assert evidence.cna_record("CVE-2026-9999", lambda url: REC_6728) is None      # not that CVE's record
    assert evidence.cna_record("CVE-2026-9998", lambda url: ["x"]) is None
    assert evidence.cna_record("not-a-cve", lambda url: REC_6728) is None
    assert evidence.cna_record(None, lambda url: REC_6728) is None


def test_every_entry_point_that_runs_the_wordpress_check_turns_reads_on():
    for f in ("run_light.py", "run_medium.py", "run_heavy.py"):
        src = open(os.path.join(HERE, f), encoding="utf-8").read()
        assert "evidence.enable_cna_reads()" in src, f


# ── the writer ───────────────────────────────────────────────────────────────────────
def _ctx():
    return run_light.ScanContext(descriptor={}, hostname="commandcompanies.com",
                                 asset_id="commandcompanies.com", scan_run_id="run-1", queue_id="q",
                                 intensity="light")


def _v(cve="CVE-2026-6728", version="6.8.1"):
    import wpvulnerability_client as wpc
    return wpc.WpVulnerability(cve_id=cve, title="Slider Revolution [revslider] < 7.0.10",
                               description=REC_6728["containers"]["cna"]["descriptions"][0]["value"],
                               affected_target="plugin:revslider", affected_version=version,
                               operator_summary="< 7.0.10", source_link=None, uuid=None, unfixed=False)


def test_the_names_a_record_may_use():
    assert run_light._wpvuln_names(_v()) == ["Slider Revolution", "revslider", "revslider"]


def test_the_writer_drops_the_false_alarm_and_notes_the_retraction(monkeypatch):
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", set())
    monkeypatch.setattr(evidence, "_CNA_CACHE", {"CVE-2026-6728": REC_6728})
    ctx = _ctx()
    assert run_light._wpvuln_emit_finding(ctx, _v(version="6.8.1"), wpc) == 0
    assert run_light._wpvuln_emit_finding(ctx, _v(version="6.7.58"), wpc) == 0
    assert ctx.findings == []
    assert [r["check_name"] for r in ctx.cna_retractions] == ["wpvuln-cve-2026-6728"] * 2
    assert ctx.cna_retractions[0]["why"] == WHY and ctx.cna_retractions[0]["version"] == "6.8.1"


def test_inside_the_range_or_no_record_still_writes_it(monkeypatch):
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", set())
    monkeypatch.setattr(evidence, "_CNA_CACHE", {"CVE-2026-6728": REC_6728})
    ctx = _ctx()
    assert run_light._wpvuln_emit_finding(ctx, _v(version="6.7.54"), wpc) == 1   # really affected
    monkeypatch.setattr(evidence, "_CNA_CACHE", {"CVE-2026-6728": None})        # the read failed
    assert run_light._wpvuln_emit_finding(ctx, _v(version="6.8.1"), wpc) == 1
    assert len(ctx.findings) == 2 and ctx.cna_retractions == []


def test_through_a_medium_or_heavy_phase_recorder_the_note_reaches_the_real_context(monkeypatch):
    import phase_contract as pc
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", set())
    monkeypatch.setattr(evidence, "_CNA_CACHE", {"CVE-2026-6728": REC_6728})

    class Real:            # a heavy context: no cna_retractions of its own
        pass
    real = Real()
    rec = pc._LegacyRecorder(real)
    assert run_light._wpvuln_emit_finding(rec, _v(), wpc) == 0
    assert rec.findings == [] and real.cna_retractions[0]["cve_id"] == "CVE-2026-6728"


# ── the retraction ───────────────────────────────────────────────────────────────────
class FakeJson:
    def __init__(self, obj):
        self.obj = obj


class FakeCur:
    def __init__(self, rows):
        self.rows, self.calls = list(rows), []

    def execute(self, sql, params):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None


def test_the_retraction_touches_only_this_writers_open_row_once(monkeypatch):
    ctx = _ctx()
    item = {"check_name": "wpvuln-cve-2026-6728", "cve_id": "CVE-2026-6728", "version": "6.8.1",
            "target": "plugin:revslider", "why": WHY}
    ctx.cna_retractions = [item, dict(item)]                  # matched twice (core + plugin loop)
    cur = FakeCur([{"severity": "MODERATE"}])
    assert run_light.retract_cna_excluded(cur, ctx, FakeJson) == 1
    sqls = [c[0] for c in cur.calls]
    assert len(sqls) == 3, "one UPDATE, one audit row, one history row; the duplicate is skipped"
    assert sqls[0].startswith("UPDATE public.findings SET current_status = 'false_positive'")
    assert "source::text = 'commandsentry_light'" in sqls[0]
    assert "current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in sqls[0]
    assert cur.calls[0][1] == {"finding_id": "commandcompanies.com:light:wpvuln-cve-2026-6728",
                               "asset_id": "commandcompanies.com"}
    assert sqls[1].startswith("INSERT INTO public.admin_audit_log")
    assert cur.calls[1][1]["action"] == "cna_range_retraction"
    assert cur.calls[1][1]["details"].obj["reason"] == WHY
    assert sqls[2].startswith("INSERT INTO public.finding_history")
    assert cur.calls[2][1]["scan_run_id"] == "run-1" and cur.calls[2][1]["severity"] == "MODERATE"


def test_no_open_row_means_no_audit_and_no_history():
    ctx = _ctx()
    ctx.cna_retractions = [{"check_name": "wpvuln-cve-2026-6728", "why": WHY}]
    cur = FakeCur([])                                          # accepted_risk / already closed / absent
    assert run_light.retract_cna_excluded(cur, ctx, FakeJson) == 0
    assert len(cur.calls) == 1


def test_the_writer_retracts_in_its_own_transaction_after_the_upserts():
    import inspect
    src = inspect.getsource(run_light.write_findings_and_artifacts)
    assert src.index("cur.execute(UPSERT_FINDING_SQL, params)") < src.index("retract_cna_excluded(cur, ctx, Json)")
    assert src.index("retract_cna_excluded(cur, ctx, Json)") < src.index("for tool_name, output_format, content_str in ctx.artifacts")
