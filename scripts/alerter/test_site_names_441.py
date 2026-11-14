"""441 (Howie 2026-11-14 08:28: "Not only do I want you to build it, I want you to fix it"):
a site is named only by its WHOLE name.

What happened: the check that a line names its sites used a substring test, so "staging" counted
as named inside "prosalud-staging". The "no web firewall" item had nine sites; the writer named
six and said "and 3 more", which is right, and the check wanted "and 2 more" and refused it. The
backup's line is word for word the same, so the one-line repair failed the same check and the
whole morning went out as the backup on Nov 11, 12, 13 and 14. The real lines of those four
mornings are replayed here.

The same matcher now serves the check, the backup's own "already names every host" test and the
per-host date clauses, so the three cannot disagree. Every rule is seen refusing as well as
passing.
"""
from __future__ import annotations

import copy
import os
import sys
from datetime import datetime, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_voice as dv  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 11, 14, 12, 2, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Prodex")
NINE = [h + ".prodexlabs.com" for h in ("cooked", "gov", "oidc-test", "prosalud-staging", "prosalud",
                                       "sandbox", "staging", "tour", "www")]

# The still-open line the writer gave on each of the four mornings (digest_pending ids 21-24,
# finalize.voice.draft), each refused with "with 9 hosts, name 6 and say 'and 3 more'".
REAL_LINES = {
    "Nov 11": "Moderate: no web firewall in front of cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox and 3 more.",
    "Nov 12": "Moderate: no web firewall in front of cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox and 3 more. "
              "Our probes walked straight in on all of them.",
    "Nov 13": "Moderate: no web firewall in front of cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox and 3 more. "
              "Our probes walked straight in on all of them.",
    "Nov 14": "[Moderate] No web firewall in front of these sites on cooked, gov, oidc-test, prosalud-staging, prosalud, "
              "sandbox and 3 more. Our harmless probes walked straight in on all of them.",
}


def _facts(hosts=NINE, not_responding=()):
    m = dd.build_model(window_start=NOW.replace(day=13), window_end=NOW, new_findings=[], confirmed=[],
                       regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=[],
                       canary_violations=[], baseline={}, brand=BRAND, not_responding=list(not_responding),
                       unrecognized_pages=[], told={})
    still = [{"kind": "finding", "severity": "MODERATE", "title": "No web firewall in front of these sites",
              "family": "waf-absent", "body": "Our harmless probes walked straight in.",
              "do": "Put a web application firewall in front.", "sites": list(hosts),
              "finding_ids": [h + ":w" for h in hosts], "since": datetime(2026, 10, 22, tzinfo=UTC),
              "recent": False}] if hosts else []
    return dv.facts(m, still_open=still, slack={"changed": [], "nudge": []}, company="Prodex",
                    day="Saturday, November 14")


def _answer(f, line):
    out = copy.deepcopy(dv.fallback(f))
    out["still_open"] = [{"id": "s1", "text": line}]
    return out


def _still_problems(f, line):
    return [p for p in dv.check(_answer(f, line), f) if p.startswith("still_open s1")]


# ── the four mornings ───────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("day", sorted(REAL_LINES))
def test_each_mornings_real_line_now_passes_and_the_writers_draft_is_kept(day):
    f = _facts()
    assert _still_problems(f, REAL_LINES[day]) == [], day
    out, replaced, filled, dropped, wording, problems = dv.settle(_answer(f, REAL_LINES[day]), f)
    assert problems == [] and replaced == [] and out is not None, (day, problems)
    assert out["still_open"][0]["text"] == REAL_LINES[day].replace("—", ",")


def test_the_backup_passes_its_own_check_with_nine_sites():
    f = _facts()
    fb = dv.fallback(f)
    assert "sandbox and 3 more" in fb["still_open"][0]["text"]
    assert dv.blocking(dv.check(fb, f)) == []


# ── the count is still enforced, now correctly ──────────────────────────────────────────────
@pytest.mark.parametrize("line", [
    "[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox and 2 more.",
    "[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox and 4 more.",
    "[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, sandbox and 4 more.",            # five names: prosalud is not named by prosalud-staging
    "[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, sandbox and 3 more.",
    "[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, prosalud and 4 more.",
])
def test_a_wrong_count_or_too_few_whole_names_is_refused(line):
    probs = _still_problems(_facts(), line)
    assert "still_open s1: with 9 hosts, name 6 and say 'and 3 more'" in probs, (line, probs)


def test_naming_all_nine_by_whole_name_passes():
    line = ("[Moderate] No web firewall on cooked, gov, oidc-test, prosalud-staging, prosalud, sandbox, "
            "staging, tour and www.")
    assert _still_problems(_facts(), line) == []


# ── what counts as naming a site ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("hosts,line,missing", [
    (["prosalud.prodexlabs.com", "prosalud-staging.prodexlabs.com"],
     "[Moderate] No web firewall in front of prosalud-staging.", ["prosalud.prodexlabs.com"]),
    (["staging.prodexlabs.com", "prosalud-staging.prodexlabs.com"],
     "[Moderate] No web firewall in front of prosalud-staging.", ["staging.prodexlabs.com"]),
    (["staging.prodexlabs.com", "prosalud-staging.prodexlabs.com"],
     "[Moderate] No web firewall in front of prosalud-staging and staging.", []),
    (["pulse.uat.prodexlabs.com", "www.prodexlabs.com"],
     "[Moderate] No web firewall in front of pulse.uat and www.", []),
    (["pulse.uat.prodexlabs.com", "www.prodexlabs.com"],
     "[Moderate] No web firewall in front of pulse and www.", []),
    (["pulse.uat.prodexlabs.com", "www.prodexlabs.com"],
     "[Moderate] No web firewall in front of pulse.uat.prodexlabs.com and www.prodexlabs.com.", []),
    (["cooked.prodexlabs.com", "tour.prodexlabs.com"],
     "[Moderate] No web firewall in front of cooked's and tour's sites.", []),
    (["cooked.prodexlabs.com", "tour.prodexlabs.com"],
     "[Moderate] No web firewall in front of cooked and tours.", ["tour.prodexlabs.com"]),
    (["cooked.prodexlabs.com", "tour.prodexlabs.com"],
     "[Moderate] No web firewall in front of *cooked* and *tour*.", []),
])
def test_a_site_is_named_only_by_its_whole_name(hosts, line, missing):
    probs = _still_problems(_facts(hosts), line)
    assert probs == [f"still_open s1: does not name {h}" for h in missing], (line, probs)


def test_the_matcher_itself():
    assert dv._name_forms("pulse.uat.prodexlabs.com") == ["pulse.uat.prodexlabs.com", "pulse.uat.prodexlabs",
                                                          "pulse.uat", "pulse"]
    assert dv._name_forms("52.119.65.6") == ["52.119.65.6"]
    assert dv._name_forms("") == []
    yes = [("staging is open", "staging.prodexlabs.com"), ("on staging.", "staging.prodexlabs.com"),
           ("(staging)", "staging.prodexlabs.com"), ("STAGING", "staging.prodexlabs.com"),
           ("see 52.119.65.6.", "52.119.65.6"), ("pulse.uat, then", "pulse.uat.prodexlabs.com")]
    no = [("prosalud-staging", "staging.prodexlabs.com"), ("prosalud-staging", "prosalud.prodexlabs.com"),
          ("staging2", "staging.prodexlabs.com"), ("staging.example.com", "staging.prodexlabs.com"),
          ("x.staging.prodexlabs.com", "staging.prodexlabs.com"), ("52.119.65.61", "52.119.65.6"),
          ("pulse2.uat", "pulse.uat.prodexlabs.com"), ("", "staging.prodexlabs.com")]
    for text, host in yes:
        assert dv._names_host(text, host), (text, host)
    for text, host in no:
        assert not dv._names_host(text, host), (text, host)


def test_the_backups_own_test_agrees_with_the_check():
    # _names_all decides whether the backup adds "on <hosts>": a name inside another name must
    # not stop it from naming the site
    assert dv._names_all("No web firewall on prosalud-staging", ["prosalud-staging.prodexlabs.com"])
    assert not dv._names_all("No web firewall on prosalud-staging", ["staging.prodexlabs.com"])
    assert not dv._names_all("No web firewall on prosalud-staging", ["prosalud.prodexlabs.com"])
    assert dv._names_all("pulse.uat and www", ["pulse.uat.prodexlabs.com", "www.prodexlabs.com"])


def test_per_host_dates_go_to_the_whole_name():
    # two quiet hosts, one name inside the other: each date stays with its own host
    nr = [("staging.prodexlabs.com", datetime(2026, 10, 22, 18, 25, tzinfo=UTC), "name_gone", None,
           datetime(2026, 11, 20, 18, 25, tzinfo=UTC)),
          ("prosalud-staging.prodexlabs.com", datetime(2026, 10, 25, 18, 25, tzinfo=UTC), "name_gone", None,
           datetime(2026, 11, 20, 18, 25, tzinfo=UTC))]
    f = _facts(hosts=(), not_responding=nr)
    item = next(it for it in f["items"] if set(it["hosts"]) == {h for h, *_ in nr} and it.get("detail"))
    good = "prosalud-staging looks down since Oct 25 and staging since Oct 22."
    swapped = "prosalud-staging looks down since Oct 22 and staging since Oct 25."
    where = "email" if item["section"] == "changed" else item["section"]
    ok = [p for p in dv._entry_problems({"text": good}, item, where, "") if "date" in p]
    bad = [p for p in dv._entry_problems({"text": swapped}, item, where, "") if "date" in p]
    assert ok == [], ok
    assert any("is not prosalud-staging.prodexlabs.com's date" in p for p in bad), bad


def test_one_matcher_serves_all_three_places():
    src = open(os.path.join(HERE, "digest_voice.py"), encoding="utf-8").read()
    assert 'missing = [h for h in item["hosts"] if not _names_host(text, h)]' in src
    assert "return all(_names_host(text, h) for h in hosts)" in src
    assert "for form in _name_forms(h):" in src and "masked = _name_re(form).sub(" in src
    assert "_short(h).lower() not in low" not in src and "_short(h).lower() in low" not in src
