#!/usr/bin/env python3
"""302 step 3 — published flaws in the JavaScript libraries a site reports.

httpx reports "jQuery UI:1.12.1" on uoltest.unimacgraphics.com (Command). The
light phase library_flaws asks OSV.dev whether that exact version is in the
affected range of a published advisory; each match becomes a version-based
finding. These tests pin: only reviewed libraries, exact versions, one finding
per flaw, the version-based label, nothing sent to the target, and that the
versions reach the phase under cumulative heavy (where artifacts do not).
"""
from __future__ import annotations

import io
import json
import os
import sys
import types
import urllib.error

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import library_flaws as LF  # noqa: E402
import software_inventory as SI  # noqa: E402


def _ghsa(gid, cve, summary, fixed, sev="MODERATE", pkg="jquery-ui", cwe=("CWE-79",), **kw):
    return {"id": gid, "aliases": [cve] if cve else [], "summary": summary,
            "database_specific": {"severity": sev, "cwe_ids": list(cwe)},
            "references": [{"type": "ADVISORY", "url": f"https://github.com/advisories/{gid}"}],
            "affected": [{"package": {"ecosystem": "npm", "name": pkg},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
            **kw}


# What OSV lists for npm jquery-ui 1.12.1 (the four published XSS flaws).
JQUERY_UI_1_12_1 = [
    _ghsa("GHSA-h6gj-6jjq-h8g9", "CVE-2022-31160", "jQuery UI XSS when refreshing a checkboxradio", "1.13.2"),
    _ghsa("GHSA-9gj3-hwp5-pmwc", "CVE-2021-41184", "XSS in the `of` option of the `.position()` util", "1.13.0"),
    _ghsa("GHSA-gpqq-952q-5327", "CVE-2021-41183", "XSS in *Text options of the Datepicker widget", "1.13.0"),
    _ghsa("GHSA-j7qv-pgf6-hvh4", "CVE-2021-41182", "XSS in the `altField` option of the Datepicker", "1.13.0"),
]

OBS = SI.Observation(product="jQuery UI", version="1.12.1", url="https://uoltest.unimacgraphics.com/")


# ── which libraries are looked up ────────────────────────────────────────────

def test_reviewed_list_is_lower_case_names_to_plain_npm_packages():
    for name, pkg in LF.PACKAGES.items():
        assert name == name.lower() and pkg == pkg.lower() and " " not in pkg and "/" not in pkg


def test_only_known_libraries_with_exact_versions_are_looked_up_once():
    obs = SI.observations_from_httpx_rows([{"url": "https://a/", "status_code": 200, "title": "t",
                                            "tech": ["jQuery UI:1.12.1", "jQuery Migrate:3.4.1", "IIS:10.0",
                                                     "Bootstrap", "Microsoft ASP.NET:4.0.30319"]},
                                           {"url": "https://a/b", "status_code": 200, "title": "t",
                                            "tech": ["jQuery UI:1.12.1"]}])
    assert [(o.product, p) for o, p in LF.lookups(obs)] == [("jQuery Migrate", "jquery-migrate"),
                                                            ("jQuery UI", "jquery-ui")]


def test_the_same_library_version_seen_twice_is_looked_up_once():
    twice = [OBS, SI.Observation(product="jquery ui", version="1.12.1", url="https://other/")]
    assert len(LF.lookups(twice)) == 1
    assert len(LF.lookups(twice + [SI.Observation("jQuery UI", "1.13.2", "u")])) == 2


@pytest.mark.parametrize("ver", ["3", "4.1", "1.12.1.0"])
def test_only_full_xyz_versions_are_looked_up(ver):
    """"jQuery 3" would be read by OSV as 3.0.0 and match flaws the site may not have."""
    assert LF.lookups([SI.Observation("jQuery", ver, "u")]) == []


def test_nothing_seen_nothing_looked_up():
    assert LF.lookups([]) == [] and LF.lookups(None) == []


# ── asking OSV ───────────────────────────────────────────────────────────────

def test_query_asks_for_the_exact_npm_package_version():
    sent = []

    def post(url, body):
        sent.append((url, json.loads(json.dumps(body))))
        return {"vulns": JQUERY_UI_1_12_1}
    assert len(LF.query_osv("jquery-ui", "1.12.1", post=post)) == 4
    assert sent == [("https://api.osv.dev/v1/query",
                     {"package": {"name": "jquery-ui", "ecosystem": "npm"}, "version": "1.12.1"})]


def test_query_follows_pages():
    pages = [{"vulns": JQUERY_UI_1_12_1[:2], "next_page_token": "t1"}, {"vulns": JQUERY_UI_1_12_1[2:]}]
    bodies = []

    def post(url, body):
        bodies.append(dict(body))
        return pages[len(bodies) - 1]
    assert len(LF.query_osv("jquery-ui", "1.12.1", post=post)) == 4
    assert "page_token" not in bodies[0] and bodies[1]["page_token"] == "t1"


def test_empty_answer_is_no_flaws():
    assert LF.query_osv("jquery", "3.7.1", post=lambda u, b: {}) == []


@pytest.mark.parametrize("answer", [{"vulns": "x"}, {"vulns": [], "next_page_token": "again"}])
def test_nonsense_answers_fail_the_lookup(answer):
    with pytest.raises(LF.LookupFailed):
        LF.query_osv("jquery", "1.0.0", post=lambda u, b: answer)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(*outcomes):
    calls = []

    def op(req, timeout):
        calls.append(req)
        o = outcomes[len(calls) - 1]
        if isinstance(o, Exception):
            raise o
        return _Resp(o)
    op.calls = calls
    return op


def test_post_sends_json_and_retries_once(monkeypatch):
    monkeypatch.setattr(LF.time, "sleep", lambda s: None)
    op = _opener(urllib.error.HTTPError("u", 503, "x", {}, None), b'{"vulns": []}')
    assert LF._post_json("https://api.osv.dev/v1/query", {"a": 1}, opener=op) == {"vulns": []}
    req = op.calls[0]
    assert req.get_method() == "POST" and json.loads(req.data) == {"a": 1}
    assert req.get_header("Content-type") == "application/json"


def test_post_retries_a_reply_cut_off_mid_body(monkeypatch):
    import http.client
    monkeypatch.setattr(LF.time, "sleep", lambda s: None)
    op = _opener(http.client.IncompleteRead(b'{"vu'), b'{"vulns": []}')
    assert LF._post_json("https://api.osv.dev/v1/query", {}, opener=op) == {"vulns": []}
    with pytest.raises(LF.LookupFailed):
        LF._post_json("https://api.osv.dev/v1/query", {},
                      opener=_opener(http.client.IncompleteRead(b""), http.client.BadStatusLine("x")))


@pytest.mark.parametrize("outcomes", [(urllib.error.HTTPError("u", 400, "x", {}, None),),
                                      (b"[]", b"[]"), (b"nope", b"nope"),
                                      (urllib.error.URLError("down"), urllib.error.URLError("down"))])
def test_post_failures_raise_lookup_failed(monkeypatch, outcomes):
    monkeypatch.setattr(LF.time, "sleep", lambda s: None)
    with pytest.raises(LF.LookupFailed):
        LF._post_json("https://api.osv.dev/v1/query", {}, opener=_opener(*outcomes))


# ── advisories ───────────────────────────────────────────────────────────────

def test_jquery_ui_1_12_1_gives_the_four_flaws_with_their_fixes():
    advs = LF.advisories_from_osv(JQUERY_UI_1_12_1, "jquery-ui", "1.12.1")
    assert [(a.cves, a.fixed, a.severity) for a in advs] == [
        (("CVE-2021-41182",), "1.13.0", "MODERATE"), (("CVE-2021-41183",), "1.13.0", "MODERATE"),
        (("CVE-2021-41184",), "1.13.0", "MODERATE"), (("CVE-2022-31160",), "1.13.2", "MODERATE")]
    assert all(a.cwe == (79,) and a.severity_stated for a in advs)


@pytest.mark.parametrize("bad", [{"id": "GHSA-a", "aliases": "CVE-2020-1111"}, {"id": "GHSA-a", "database_specific": "x"},
                                 {"id": "GHSA-a", "database_specific": {"cwe_ids": "CWE-79"}},
                                 {"id": "GHSA-a", "affected": ["x", {"package": "jquery-ui"}, {"ranges": "x"},
                                                              {"package": {"name": "jquery-ui", "ecosystem": "npm"},
                                                               "ranges": [{"events": ["x", {"fixed": None}]}]}]},
                                 {"id": "GHSA-a", "references": "x"}, {"id": None}])
def test_malformed_records_never_raise(bad):
    LF.advisories_from_osv([bad], "jquery-ui", "1.12.1")


def test_withdrawn_and_non_advisory_records_are_ignored():
    vulns = [_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2020-1111", "s", "2.0.0", withdrawn="2024-01-01T00:00:00Z"),
             {"id": "MAL-2024-1", "summary": "malicious package"},
             {"id": "OSV-2020-1", "aliases": []}, "junk"]
    assert LF.advisories_from_osv(vulns, "jquery-ui", "1.12.1") == []


def test_one_finding_per_flaw_and_the_github_record_wins():
    cve_first = {"id": "CVE-2021-41184", "summary": "dup", "affected": []}
    advs = LF.advisories_from_osv([cve_first, JQUERY_UI_1_12_1[1]], "jquery-ui", "1.12.1")
    assert len(advs) == 1 and advs[0].id == "GHSA-9gj3-hwp5-pmwc"
    advs = LF.advisories_from_osv([JQUERY_UI_1_12_1[1], cve_first], "jquery-ui", "1.12.1")
    assert len(advs) == 1 and advs[0].id == "GHSA-9gj3-hwp5-pmwc"


@pytest.mark.parametrize("raw,ours,stated", [("CRITICAL", "CRITICAL", True), ("HIGH", "HIGH", True),
                                             ("MODERATE", "MODERATE", True), ("MEDIUM", "MODERATE", True),
                                             ("LOW", "LOW", True), ("", "MODERATE", False),
                                             ("UNKNOWN", "MODERATE", False)])
def test_severity_mapping(raw, ours, stated):
    (a,) = LF.advisories_from_osv([_ghsa("GHSA-x", "CVE-2020-1111", "s", "2.0.0", sev=raw)], "jquery-ui", "1.0.0")
    assert (a.severity, a.severity_stated) == (ours, stated)


def test_fixed_is_the_lowest_fix_above_the_version_seen_for_this_package():
    v = _ghsa("GHSA-x", "CVE-2020-1111", "s", "1.0.5")
    v["affected"][0]["ranges"].append({"type": "SEMVER", "events": [{"introduced": "1.1.0"}, {"fixed": "1.2.4"}]})
    v["affected"][0]["ranges"].append({"type": "SEMVER", "events": [{"introduced": "1.3.0"}, {"fixed": "1.3.1"}]})
    v["affected"].append({"package": {"ecosystem": "npm", "name": "other"},
                          "ranges": [{"events": [{"fixed": "1.2.1"}]}]})
    (a,) = LF.advisories_from_osv([v], "jquery-ui", "1.2.0")
    assert a.fixed == "1.2.4"
    (a,) = LF.advisories_from_osv([_ghsa("GHSA-y", "CVE-2020-2222", "s", "garbage")], "jquery-ui", "1.2.0")
    assert a.fixed is None


# ── the finding ──────────────────────────────────────────────────────────────

def test_finding_is_labelled_version_based_and_grouped_per_library():
    (adv,) = [a for a in LF.advisories_from_osv(JQUERY_UI_1_12_1, "jquery-ui", "1.12.1")
              if a.cves == ("CVE-2022-31160",)]
    f = LF.finding_fields(OBS, "jquery-ui", adv, "uoltest.unimacgraphics.com")
    assert f["check_name"] == "libflaw-jquery-ui-ghsa-h6gj-6jjq-h8g9"   # one advisory, one finding
    assert f["normalized_key_override"] == "jslib-jquery-ui"
    assert f["title"] == "jQuery UI 1.12.1: jQuery UI XSS when refreshing a checkboxradio"
    assert f["severity"] == "MODERATE" and f["category"] == "supply_chain" and f["cve"] == ["CVE-2022-31160"]
    assert "Version-based" in f["description"] and "not confirmed by testing" in f["description"]
    assert "fixed in 1.13.2" in f["description"] and "uoltest.unimacgraphics.com" in f["description"]
    assert f["references"][0] == "https://osv.dev/vulnerability/GHSA-h6gj-6jjq-h8g9"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2022-31160" in f["references"]
    assert f["cwe"] == [79] and "version-cve" in f["tags"]


def test_finding_without_cve_or_severity_says_so():
    adv = LF.Advisory(id="GHSA-zzzz-zzzz-zzzz", cves=(), summary="", severity="MODERATE",
                      severity_stated=False, fixed=None, cwe=(), references=())
    f = LF.finding_fields(OBS, "jquery-ui", adv, "h")
    assert f["check_name"] == "libflaw-jquery-ui-ghsa-zzzz-zzzz-zzzz" and f["cve"] == [] and f["cwe"] == [1395]
    assert "no fixed version listed" in f["description"] and "states no severity" in f["description"]
    assert f["title"] == "jQuery UI 1.12.1: in the affected range of GHSA-zzzz-zzzz-zzzz"


def test_finding_fields_build_a_light_finding():
    import run_light as L
    for adv in LF.advisories_from_osv(JQUERY_UI_1_12_1, "jquery-ui", "1.12.1"):
        L.LightFinding(**LF.finding_fields(OBS, "jquery-ui", adv, "h"))


def test_only_osv_is_ever_contacted():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "library_flaws.py")).read()
    urls = {u for u in __import__("re").findall(r"https://[a-z0-9.\-]+", src)}
    assert urls <= {"https://api.osv.dev", "https://osv.dev", "https://nvd.nist.gov"}
    assert LF.OSV_QUERY == "https://api.osv.dev/v1/query"


# ── the light phase ──────────────────────────────────────────────────────────

def _ctx(**kw):
    import run_light as L
    return L.ScanContext(descriptor={}, hostname="uoltest.unimacgraphics.com", asset_id="a", scan_run_id="r",
                         queue_id="q", intensity="light", **kw)


def test_phase_reports_each_flaw(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    asked = []
    monkeypatch.setattr(L.library_flaws, "query_osv", lambda p, v: asked.append((p, v)) or JQUERY_UI_1_12_1)
    ctx = _ctx(tech_versions=[OBS])
    L.check_library_flaws(ctx)
    assert asked == [("jquery-ui", "1.12.1")]
    assert sorted(f.cve[0] for f in ctx.findings) == ["CVE-2021-41182", "CVE-2021-41183",
                                                      "CVE-2021-41184", "CVE-2022-31160"]
    assert len({f.check_name for f in ctx.findings}) == 4
    assert ctx.tools_run == ["library_flaws"] and ctx.tool_status["library_flaws"] == {"ok": True}
    (art,) = [a for a in ctx.artifacts if a[0] == "library_flaws"]
    assert json.loads(art[2])["looked_up"][0]["package"] == "jquery-ui"


def test_phase_without_a_version_list_says_it_did_not_look(monkeypatch):
    """httpx_tech failed or was blocked: 'skipped', never 'looked and found nothing'."""
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    monkeypatch.setattr(L.library_flaws, "query_osv", lambda p, v: pytest.fail("no lookup expected"))
    ctx = _ctx()
    assert ctx.tech_versions is None
    L.check_library_flaws(ctx)
    assert ctx.tool_status["library_flaws"] == {"skipped": "no_version_data"} and ctx.findings == []


@pytest.mark.parametrize("boom", [AttributeError("'str' object has no attribute 'get'"),
                                  __import__("http.client").client.IncompleteRead(b"{"), KeyError("x")])
def test_anything_unexpected_is_contained_never_fails_the_scan(monkeypatch, boom):
    """run_light.run() calls phases directly; an escaping exception would
    discard every finding of the light scan."""
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)

    def q(p, v):
        raise boom
    monkeypatch.setattr(L.library_flaws, "query_osv", q)
    ctx = _ctx(tech_versions=[OBS])
    L.check_library_flaws(ctx)
    assert ctx.tool_status["library_flaws"] == {"degraded": "osv_lookup_failed"}


def test_even_a_broken_helper_is_contained(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    def broken(v):
        raise RuntimeError("helper broke")
    monkeypatch.setattr(L.library_flaws, "lookups", broken)
    ctx = _ctx(tech_versions=[OBS])
    L.check_library_flaws(ctx)
    assert ctx.tool_status["library_flaws"] == {"degraded": "library_flaws_error"}


def test_after_one_failure_the_rest_are_not_tried(monkeypatch):
    """An unreachable OSV costs one timeout, not one per library."""
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    asked = []

    def q(p, v):
        asked.append(p)
        raise LF.LookupFailed("URLError: timed out")
    monkeypatch.setattr(L.library_flaws, "query_osv", q)
    ctx = _ctx(tech_versions=[SI.Observation("jQuery", "3.4.1", "u"), OBS, SI.Observation("Bootstrap", "3.3.7", "u")])
    L.check_library_flaws(ctx)
    assert len(asked) == 1
    (art,) = [a for a in ctx.artifacts if a[0] == "library_flaws"]
    assert len(json.loads(art[2])["failed"]) == 3


def test_phase_with_no_known_library_is_clean_and_asks_nobody(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    monkeypatch.setattr(L.library_flaws, "query_osv", lambda p, v: pytest.fail("no lookup expected"))
    ctx = _ctx(tech_versions=[SI.Observation("IIS", "10.0", "u")])
    L.check_library_flaws(ctx)
    assert ctx.findings == [] and ctx.tool_status["library_flaws"] == {"ok": True}


def test_phase_failed_lookup_is_degraded_never_silently_clean(monkeypatch):
    import run_light as L
    from degradation import classify_cut_reason, CUT_TOOL
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)

    def boom(p, v):
        raise LF.LookupFailed("URLError: down")
    monkeypatch.setattr(L.library_flaws, "query_osv", boom)
    ctx = _ctx(tech_versions=[OBS])
    L.check_library_flaws(ctx)
    assert ctx.findings == [] and ctx.tool_status["library_flaws"] == {"degraded": "osv_lookup_failed"}
    assert classify_cut_reason("osv_lookup_failed") == CUT_TOOL


HTTPX_OUT = json.dumps({"url": "https://uoltest.unimacgraphics.com/", "status_code": 200, "title": "Home",
                        "tech": ["jQuery UI:1.12.1", "IIS:10.0", "jQuery"]})


def test_httpx_tech_hands_over_the_exact_versions(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    monkeypatch.setattr(L, "run_cmd", lambda cmd, timeout=30, input_str=None: (0, HTTPX_OUT + "\n", ""))
    ctx = _ctx()
    L.check_httpx_tech(ctx)
    assert [(o.product, o.version) for o in ctx.tech_versions] == [("IIS", "10.0"), ("jQuery UI", "1.12.1")]


def test_httpx_blocked_leaves_no_version_list(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    blocked = json.dumps({"url": "https://h/", "status_code": 403, "title": "403 Forbidden", "tech": ["jQuery UI:1.12.1"]})
    monkeypatch.setattr(L, "run_cmd", lambda cmd, timeout=30, input_str=None: (0, blocked + "\n", ""))
    ctx = _ctx()
    L.check_httpx_tech(ctx)
    assert ctx.tool_status["httpx_tech"] == {"degraded": "tech_detect_blocked"} and ctx.tech_versions is None


def test_versions_reach_library_flaws_under_cumulative_heavy(monkeypatch):
    """🔴 Under cumulative heavy each legacy phase runs against its own
    recorder, which hides earlier phases' artifacts. ctx.tech_versions is a
    plain attribute, so it reaches the real context and the later phase."""
    import run_light as L
    import phase_contract as pc
    monkeypatch.setattr(L, "flush_progress", lambda ctx: None)
    monkeypatch.setattr(L, "run_cmd", lambda cmd, timeout=30, input_str=None: (0, HTTPX_OUT + "\n", ""))
    monkeypatch.setattr(L.library_flaws, "query_osv", lambda p, v: JQUERY_UI_1_12_1)
    real = types.SimpleNamespace(hostname="uoltest.unimacgraphics.com", asset_id="a", scan_run_id="r",
                                 findings=[], tools_run=[], artifacts=[], tool_status={}, dsn=None)
    rec1 = pc._LegacyRecorder(real)
    L.check_httpx_tech(rec1)
    rec2 = pc._LegacyRecorder(real)
    assert rec2.artifacts == []                     # the trap: no httpx artifact visible here
    L.check_library_flaws(rec2)
    assert len(rec2.findings) == 4 and rec2.tool_status["library_flaws"] == {"ok": True}


def test_registered_after_httpx_tech_in_light_and_heavy():
    import phase_registry  # noqa: F401
    import phase_contract as pc
    from phase_source import LIGHT, HEAVY
    for tier in (LIGHT, HEAVY):
        names = [p.name for p in pc.phases_for_tier(tier)]
        assert names.index("httpx_tech") < names.index("library_flaws"), names
    assert [p.tier for p in pc.REGISTRY if p.name == "library_flaws"] == [LIGHT]


def test_light_runner_calls_it_after_httpx_tech():
    import inspect
    import run_light as L
    src = inspect.getsource(L.run)
    assert src.index("check_httpx_tech(ctx)") < src.index("check_library_flaws(ctx)")


def test_light_writer_keeps_the_cve_and_the_library_group(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(L, "derive_validation_status", lambda *a, **k: "unvalidated")
    (adv,) = LF.advisories_from_osv(JQUERY_UI_1_12_1[:1], "jquery-ui", "1.12.1")
    ctx = types.SimpleNamespace(descriptor={}, asset_id="a", scan_run_id="r", intensity="light", artifacts=[],
                                findings=[L.LightFinding(**LF.finding_fields(OBS, "jquery-ui", adv, "h"))])
    calls = []

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=None):
            calls.append((sql, params))

        def fetchone(self):
            return {"inserted": True}

        def fetchall(self):
            return []

    conn = types.SimpleNamespace(cursor=lambda: Cur(), commit=lambda: None)
    L.write_findings_and_artifacts(conn, ctx, Json=lambda x: x)
    (p,) = [p for s, p in calls if s is L.UPSERT_FINDING_SQL]
    assert p["cve"] == ["CVE-2022-31160"] and p["normalized_key"] == "jslib-jquery-ui"
    assert p["finding_id"] == "a:light:libflaw-jquery-ui-ghsa-h6gj-6jjq-h8g9"


def test_heavy_keeps_the_supply_chain_category():
    """Otherwise the category flips to 'other' on every heavy pass."""
    import inspect
    import run_heavy as H
    assert '"supply_chain",' in inspect.getsource(H.write_event_findings_and_artifacts)
