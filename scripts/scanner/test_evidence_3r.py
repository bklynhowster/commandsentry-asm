"""(KB 12 job 3r, 2026-10-23) Proven, out of date, guess.

Howie, 2026-10-22 15:58: "we don't know. We have no inside information on anything."
16:00: "the only thing that we show on the site is a proven vulnerability." 20:34: "There are
risks and there are things that are known, that's all."

Pinned here: the out-of-date rung (MODERATE, MODERATE-HIGH on CISA's exploited list);
reading an advisory's own stated range, on the live texts of 2026-10-23 (the five Slider
Revolution advisories, SVG Support, Mega Main Menu) — four of five Slider Revolution
advisories leave 6.7.5x out; WordPress advisories dropped when their own text excludes the
version, written MODERATE otherwise, never "vulnerable"; the KEV catalog read once and never
guessed up; the alerter's digest_words agrees with the scanner on every live text.
"""
from __future__ import annotations

import os
import sys

import pytest

import evidence
import run_light

HERE = os.path.dirname(os.path.abspath(__file__))

# The advisories' own words, as stored on Command's open rows 2026-10-23 (findings.description).
LIVE = {
    "CVE-2026-6692": "The Slider Revolution plugin for WordPress is vulnerable to Arbitrary File Upload in "
                     "versions 7.0.0 to 7.0.10 via the '_get_media_url' and '_check_file_path' function.",
    "CVE-2026-7542": "The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information "
                     "Disclosure in versions 7.0 to 7.0.10. This is due to three compounding design flaws.",
    "CVE-2026-9048": "The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information "
                     "Exposure in versions 7.0.0 - 7.0.14, via the 'slider.get.full' AJAX Action.",
    "CVE-2026-57678": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') "
                      "vulnerability in ThemePunch Slider Revolution allows Reflected XSS. This issue affects "
                      "Slider Revolution: from 7.0.0 through 7.0.16.",
    "CVE-2026-6728": "The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information "
                     "Exposure in versions up to, and including, 7.0.9 via the 'get_stream_data()' function. "
                     "This makes it possible for unauthenticated attackers to extract sensitive data.",
    "CVE-2024-10222": "The SVG Support plugin for WordPress is vulnerable to Stored Cross-Site Scripting via "
                      "SVG File uploads in all versions up to, and including, 2.5.10 due to insufficient input "
                      "sanitization.",
    "CVE-2026-48973": "Missing Authorization vulnerability in Benbodhi SVG Support allows Exploiting Incorrectly "
                      "Configured Access Control Security Levels. This issue affects SVG Support: from n/a "
                      "through 2.5.14.",
    "CVE-2023-1575": "The Mega Main Menu plugin for WordPress is vulnerable to Stored Cross-Site Scripting via "
                     "some of its settings parameters in versions up to, and including, 2.2.2 due to insufficient "
                     "input sanitization.",
    # 3r second check (Grok): two ranges in one sentence; the operator says "< 6.7.56"
    "CVE-2026-9050": "The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information Exposure "
                     "in versions 6.0.0-6.7.55 and 7.0.0-7.0.14, via the 'slider.get' AJAX action.",
}


def test_the_out_of_date_rung():
    assert evidence.version_based_severity(False) == "MODERATE"
    assert evidence.version_based_severity(True) == "MODERATE-HIGH"


@pytest.mark.parametrize("cve,version,excluded", [
    ("CVE-2026-6692", "6.7.58", True), ("CVE-2026-6692", "6.7.54", True), ("CVE-2026-6692", "7.0.5", False),
    ("CVE-2026-7542", "6.7.58", True), ("CVE-2026-7542", "7.0.10", False), ("CVE-2026-7542", "7.0.11", True),
    ("CVE-2026-9048", "6.7.55", True), ("CVE-2026-9048", "7.0.14", False),
    ("CVE-2026-57678", "6.7.58", True), ("CVE-2026-57678", "7.0.16", False),
    ("CVE-2026-6728", "6.7.58", False), ("CVE-2026-6728", "6.7.54", False), ("CVE-2026-6728", "7.0.10", True),
    ("CVE-2024-10222", "2.5.9", False), ("CVE-2024-10222", "2.5.11", True),
    ("CVE-2026-48973", "2.5.9", False), ("CVE-2026-48973", "2.5.15", True),
    ("CVE-2023-1575", "2.2.1", False),
    ("CVE-2026-9050", "6.7.58", True), ("CVE-2026-9050", "6.7.50", False), ("CVE-2026-9050", "7.0.5", False),
    ("CVE-2026-9050", "7.0.15", True),
])
def test_the_live_texts_leave_out_exactly_what_they_say(cve, version, excluded):
    assert evidence.range_excludes(version, LIVE[cve]) is excluded


def test_every_range_in_a_sentence_counts():
    assert evidence.stated_ranges(LIVE["CVE-2026-9050"]) == [("6.0.0", "6.7.55", True), ("7.0.0", "7.0.14", True)]
    assert evidence.stated_ranges(LIVE["CVE-2026-48973"]) == [(None, "2.5.14", True)]
    assert evidence.stated_ranges(LIVE["CVE-2026-6728"]) == [(None, "7.0.9", True)]


def test_a_two_ended_operator_is_trusted_over_the_sentence():
    assert evidence.operator_has_both_bounds(">= 7.0.0 and < 7.0.11")
    assert not evidence.operator_has_both_bounds("< 7.0.11") and not evidence.operator_has_both_bounds(None)


def test_four_of_five_slider_revolution_advisories_miss_every_version_command_runs():
    slider = [c for c in LIVE if "Slider Revolution" in LIVE[c] and c != "CVE-2026-9050"]
    for seen in ("6.7.54", "6.7.55", "6.7.56", "6.7.57", "6.7.58"):     # 3r review minor 4
        kept = [c for c in slider if not evidence.range_excludes(seen, LIVE[c])]
        assert kept == ["CVE-2026-6728"], seen


@pytest.mark.parametrize("text", [None, "", "Affects some versions.", "versions 7.x - 8.x",
                                  "A flaw. Fixed in 7.0.11."])
def test_what_cannot_be_read_keeps_the_advisory(text):
    assert evidence.range_excludes("6.7.58", text) is False
    assert evidence.range_excludes(None, LIVE["CVE-2026-6692"]) is False


def test_before_and_prior_to_are_exclusive():
    assert evidence.range_excludes("2.0", "Versions prior to 2.0 are affected.") is True
    assert evidence.range_excludes("1.9.9", "versions before 2.0") is False


def test_the_kev_catalog_is_read_once_and_a_bad_read_is_empty(monkeypatch):
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    calls = []

    def get(url):
        calls.append(url)
        return {"vulnerabilities": [{"cveID": f"CVE-2020-{i}"} for i in range(1500)]}
    assert "CVE-2020-7" in evidence.kev_ids(get)
    assert "CVE-2020-7" in evidence.kev_ids(get) and len(calls) == 1
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    assert evidence.kev_ids(lambda u: {"vulnerabilities": [{"cveID": "CVE-1"}]}) == set(), "short: never trusted"
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)

    def boom(url):
        raise OSError("no route")
    assert evidence.kev_ids(boom) == set()


# ── the WordPress writer ─────────────────────────────────────────────────────────────
def _ctx():
    return run_light.ScanContext(descriptor={}, hostname="commandcompanies.com",
                                 asset_id="commandcompanies.com", scan_run_id="r", queue_id="q",
                                 intensity="light")


def _v(cve, version="6.7.58", title="Slider Revolution [revslider] < 7.0.11", op="< 7.0.11", unfixed=False):
    import wpvulnerability_client as wpc
    return wpc.WpVulnerability(cve_id=cve, title=title, description=LIVE.get(cve, ""), affected_target="plugin:revslider",
                               affected_version=version, operator_summary=op, source_link=None, uuid=None,
                               unfixed=unfixed)


def test_an_advisory_its_own_text_excludes_is_not_written(monkeypatch):
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", set())
    ctx = _ctx()
    added = sum(run_light._wpvuln_emit_finding(ctx, _v(c), wpc) for c in
                ("CVE-2026-6692", "CVE-2026-7542", "CVE-2026-9048", "CVE-2026-57678", "CVE-2026-6728"))
    assert added == 1 and [f.cve for f in ctx.findings] == [["CVE-2026-6728"]]
    (f,) = ctx.findings
    assert f.severity == "MODERATE", "was HIGH by keyword guessing ('unauthenticated')"
    assert "vulnerable" not in f.description.split("\n\n")[0].lower()
    assert "older than the fix for this published flaw" in f.description and "out-of-date" in f.tags


def test_a_kev_listed_wordpress_advisory_is_moderate_high_and_unfixed_says_replace_it(monkeypatch):
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", {"CVE-2026-6728"})
    ctx = _ctx()
    run_light._wpvuln_emit_finding(ctx, _v("CVE-2026-6728"), wpc)
    run_light._wpvuln_emit_finding(ctx, _v("CVE-2023-1575", version="2.2.1", unfixed=True,
                                           title="Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)", op="<= 2.2.2"), wpc)
    assert [f.severity for f in ctx.findings] == ["MODERATE-HIGH", "MODERATE"]
    assert "cisa-kev" in ctx.findings[0].tags
    assert "replace the plugin with a maintained one" in ctx.findings[1].description


def test_a_sentence_that_disagrees_with_a_two_ended_operator_keeps_the_advisory(monkeypatch):
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", set())
    ctx = _ctx()
    v = _v("CVE-2026-6692", version="6.7.58", op=">= 6.0.0 and < 7.0.11")   # operator includes 6.7.58
    assert run_light._wpvuln_emit_finding(ctx, v, wpc) == 1


def test_the_writer_no_longer_guesses_severity_from_keywords():
    import inspect
    src = inspect.getsource(run_light._wpvuln_emit_finding)
    assert "severity_from_cve_metadata(" not in src and "evidence.version_based_severity" in src


# ── one reading of an advisory's words, scanner and alerter ─────────────────────────
def test_the_alerter_reads_the_same_ranges():
    sys.path.insert(0, os.path.join(HERE, "..", "alerter"))
    import digest_words
    extra = ["Versions prior to 2.0 are affected.", "A flaw. Fixed in 7.0.11.", "versions 7.x - 8.x",
             "in versions 7.0 to 7.0.10. This is due to a flaw in version 9.1 - 9.2."]
    for text in list(LIVE.values()) + extra:
        assert digest_words.stated_ranges(text) == evidence.stated_ranges(text), text
    for cve, text in LIVE.items():
        for seen in ("2.2.1", "2.5.9", "2.5.15", "6.7.58", "7.0.5", "7.0.16"):
            a = digest_words.advisory("Slider Revolution [revslider] < 9", f"{text} Detected at version {seen}.")
            if a["applies"] is None:
                continue
            assert a["applies"] is not evidence.range_excludes(seen, text), (cve, seen)


# ── job 3s: the KEV fallback (Kimi's second check of plan 3r: a CISA outage must never
# lower a KEV-listed out-of-date finding back to MODERATE) ─────────────────────────────
def _boom(url):
    raise OSError("cisa.gov unreachable")


def test_a_failed_cisa_read_falls_back_to_the_kev_list_already_held(monkeypatch):
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    monkeypatch.setattr(evidence, "_KEV_FALLBACK", None)
    assert evidence.kev_ids(_boom, fallback=lambda: ["CVE-2026-6728", None, ""]) == {"CVE-2026-6728"}
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    short = lambda u: {"vulnerabilities": [{"cveID": "CVE-1"}]}  # noqa: E731
    assert evidence.kev_ids(short, fallback=lambda: {"CVE-2"}) == {"CVE-2"}, "a short read is a failed read"
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    evidence.set_kev_fallback(lambda: {"CVE-3"})
    assert evidence.kev_ids(_boom) == {"CVE-3"}, "the reader the entry point installed"
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    good = lambda u: {"vulnerabilities": [{"cveID": f"CVE-2020-{i}"} for i in range(1500)]}  # noqa: E731
    assert "CVE-3" not in evidence.kev_ids(good), "a good CISA read is the catalog, not the fallback"


def test_no_fallback_or_a_broken_one_is_empty_and_never_raises(monkeypatch):
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    monkeypatch.setattr(evidence, "_KEV_FALLBACK", None)
    assert evidence.kev_fallback() == set() and evidence.kev_ids(_boom) == set()

    def broken():
        raise RuntimeError("db down")
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    assert evidence.kev_ids(_boom, fallback=broken) == set()
    monkeypatch.setattr(evidence, "_KEV_FALLBACK", broken)
    assert evidence.kev_fallback() == set()


def test_the_db_reader_reads_only_kev_rows_and_connects_lazily():
    import inspect
    src = inspect.getsource(evidence.db_kev_reader)
    assert "SELECT cve_id FROM public.cve_enrichments WHERE kev_listed" in src
    reader = evidence.db_kev_reader("postgresql://unused")       # nothing connects until called
    assert callable(reader)


def test_every_entry_point_that_holds_the_dsn_installs_the_fallback():
    here = os.path.dirname(os.path.abspath(__file__))
    for f in ("run_light.py", "run_medium.py", "run_heavy.py", "advisory_watch.py"):
        src = open(os.path.join(here, f), encoding="utf-8").read()
        assert "evidence.set_kev_fallback(evidence.db_kev_reader(" in src, f


def test_a_light_phase_inside_a_medium_or_heavy_run_keeps_kev_with_cisa_down(monkeypatch):
    """Plan v3 re-check MF1: wpvulnerability runs as a LIGHT phase inside medium/heavy through
    legacy_adapter, whose recorder sets dsn = None. The fallback is installed per process, so
    the phase needs no DSN: a KEV row already in cve_enrichments keeps it MODERATE-HIGH."""
    import pathlib
    import phase_contract as pc
    from phase_source import LIGHT
    import wpvulnerability_client as wpc
    monkeypatch.setattr(evidence, "_KEV_CACHE", None)
    monkeypatch.setattr(evidence.urllib.request, "urlopen", lambda *a, **k: _boom(""))
    monkeypatch.setattr(evidence, "_KEV_FALLBACK", lambda: {"CVE-2026-6728"})
    seen = {}

    def legacy(rec):
        seen["dsn"] = rec.dsn
        run_light._wpvuln_emit_finding(rec, _v("CVE-2026-6728"), wpc)
        seen["sev"] = [f.severity for f in rec.findings]
        rec.tools_run.append("wpvulnerability")
        rec.tool_status["wpvulnerability"] = {"ok": True}
    ctx = _ctx()
    ctx.dsn = "postgresql://the-real-one"
    pc.legacy_adapter(legacy, LIGHT)(ctx, pathlib.Path("/tmp"))
    assert seen == {"dsn": None, "sev": ["MODERATE-HIGH"]}
