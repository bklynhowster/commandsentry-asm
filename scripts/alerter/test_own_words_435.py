"""The daily email and #on-call say a finding's own two sentences (D-077 step 2, 2026-11-12).

advisory_watch.py words a sign-in's out-of-date finding in code (scanner/signin_flaws.py):
"This sign-in shows OAuth2 Proxy 7.15.5. Its maker says release 7.15.6 (Nov 5) fixes 18
published flaws; 6 are described as crash or overload flaws." and "Update OAuth2 Proxy to
7.15.6 or later." Howie approved that wording 16:21, and at 18:40 chose it for the daily
email and Slack over the out-of-date family's stock words ("b").

Pinned here:
  * own_words: only a finding whose three page sections the scanner wrote itself (source
    'scanner', all three filled) has own words; each is one line; a long one is left out;
  * group_problems: a problem whose findings all carry the same own words says them; any
    other keeps the family's words; a WordPress plugin advisory keeps its judged words;
  * build_model hands them to today's new, came-back and reconfirmed findings alike, and the
    email (text and HTML), the Slack post and the voice writer's facts all carry them;
  * found while testing: two different out-of-date products are two cards, never one card
    under the first product's name.
"""
from __future__ import annotations

import inspect
import os
import sys
from datetime import datetime, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_slack as ds  # noqa: E402
import digest_voice as dv  # noqa: E402
import digest_words as dw  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
W0 = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
W1 = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
SEEN = datetime(2026, 11, 12, 10, 23, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Prodex")

HOST = "signin.example.com"
FID = f"{HOST}:advisory_watch:out-of-date:oauth2_proxy:96ac3ff"
TITLE = "Runs OAuth2 Proxy 7.15.5: out of date — 18 published flaws fixed in later versions; update it"
LEAD = ("This sign-in shows OAuth2 Proxy 7.15.5. Its maker says release 7.15.6 (Nov 5) fixes 18 published "
        "flaws; 6 are described as crash or overload flaws.")
FIX = "Update OAuth2 Proxy to 7.15.6 or later."
FLAWS = ("The 6 described as crash or overload flaws: CVE-2026-70001, CVE-2026-70002.\n"
         "Its maker’s notes place all 18 in OAuth2 Proxy or in the Go language and libraries it is built with.\n"
         "None is on CISA’s exploited list.")
DESC = LEAD + "\n\n" + FLAWS + "\n\nFix: " + FIX
STOCK = dw.words(TITLE, 1)
OWN = {FID: (LEAD, FIX)}


def hint(fid=FID, remediation=FIX, description=DESC, cve=("CVE-2026-70001",), what=LEAD, source="scanner",
         flaws=FLAWS):
    """One SQL_FINDING_HINTS row: (finding_id, remediation, description, cve, description_synth,
    description_source, impact)."""
    return (fid, remediation, description, list(cve), what, source, flaws)


def row(fid=FID, host=HOST, title=TITLE, sev="MODERATE", status="open", source="advisory_watch"):
    return (fid, host, title, sev, status, source, SEEN)


def model(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              baseline={}, brand=BRAND)
    kw.update(over)
    return dd.build_model(**kw)


# ── own_words ────────────────────────────────────────────────────────────────

def test_a_finding_the_scanner_worded_itself_has_own_words():
    assert ra.own_words([hint()]) == OWN


@pytest.mark.parametrize("over", [
    {"source": "ai_synthesized"}, {"source": "ai_synthesized_reviewed"}, {"source": "manual"},
    {"source": None}, {"source": "Scanner"}, {"source": ""},
    {"what": None}, {"what": ""}, {"what": "  \n"}, {"what": 7},
    {"flaws": None}, {"flaws": ""}, {"flaws": " "}, {"flaws": 7},
    {"remediation": None}, {"remediation": ""}, {"remediation": "\t"}, {"remediation": 7},
])
def test_any_other_finding_has_none(over):
    """An AI-written, reviewed or hand-edited row, a parser's row (no sections), a rejected row
    (the portal empties its sections) and a half-written row all keep the family's words."""
    assert ra.own_words([hint(**over)]) == {}


def test_a_row_without_the_new_columns_has_none_and_nothing_breaks():
    assert ra.own_words(None) == {} and ra.own_words([]) == {}
    assert ra.own_words([(FID, FIX, DESC, ["CVE-2026-70001"])]) == {}, "the four columns read before this change"
    assert ra.own_words([hint()[:6]]) == {} and ra.own_words([(FID,)]) == {}


def test_only_the_rows_that_qualify_come_back():
    other = hint(fid="b:1", source="ai_synthesized")
    third = hint(fid="c:1", what="Another finding’s lead.", remediation="Do the other thing.")
    assert ra.own_words([hint(), other, third]) == {FID: (LEAD, FIX), "c:1": ("Another finding’s lead.",
                                                                           "Do the other thing.")}


def test_each_is_one_line():
    got = ra.own_words([hint(what="  This sign-in shows X 1.2.\n\nIts maker says so. ", remediation="Update X\nto 1.3. ")])
    assert got == {FID: ("This sign-in shows X 1.2. Its maker says so.", "Update X to 1.3.")}


def test_a_page_of_text_is_not_a_card():
    """Howie 2026-11-12 18:25, on a wall of text: "No one will ever read anything like this."
    A lead or a fix longer than a card carries is left out; the family's stock words stand."""
    assert ra.OWN_WORDS_MAX == (400, 200)
    at_what, at_fix = "w" * 400, "f" * 200
    assert ra.own_words([hint(what=at_what, remediation=at_fix)]) == {FID: (at_what, at_fix)}
    assert ra.own_words([hint(what="w" * 401)]) == {}
    assert ra.own_words([hint(remediation="f" * 201)]) == {}
    assert len(LEAD) < 200 and len(FIX) < 60, "the approved wording is far inside both"


def test_the_read_asks_for_the_three_sections_and_who_wrote_them():
    sql = " ".join(ra.SQL_FINDING_HINTS.split())
    assert sql == ("SELECT finding_id, remediation, description, cve, description_synth, description_source, impact "
                   "FROM public.findings WHERE finding_id = ANY(%s::text[])")
    # the two older readers of these rows are untouched by the longer row
    hints, details = ra.hints_and_details([hint()])
    assert hints == {FID: FIX} and details == {FID: (DESC, ["CVE-2026-70001"])}


def test_main_reads_once_and_hands_the_own_words_to_the_model():
    src = inspect.getsource(ra.main)
    assert 'hint_rows = _soft("remediation hints", SQL_FINDING_HINTS, (hint_ids,)) if hint_ids else []' in src
    assert "hints, details = hints_and_details(hint_rows)" in src and "own = own_words(hint_rows)" in src
    assert src.count("SQL_FINDING_HINTS") == 1, "one read serves the hints, the details and the own words"
    assert src.count("own=own") == 1 and inspect.getsource(ra._digest_model).count("own=own") == 1
    seen = {}
    real = dd.build_model
    try:
        dd.build_model = lambda **kw: seen.update(kw) or {}
        ra._digest_model(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
                         high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
                         baseline={}, brand=BRAND, own=OWN)
    finally:
        dd.build_model = real
    assert seen["own"] is OWN


# ── group_problems ───────────────────────────────────────────────────────────

def one(rows, **kw):
    items = dd.group_problems(rows, {r[1] for r in rows}, **kw)
    assert len(items) == 1, [i["title"] for i in items]
    return items[0]


def test_the_card_says_the_findings_own_two_sentences():
    it = one([row()], own=OWN)
    assert (it["body"], it["do"]) == (LEAD, FIX)
    assert it["do_raw"] is False, "it is the fix, not the scanner's first step"
    assert dd.fix_label(it) == "The fix, for your IT team:"
    # everything else on the card is the family's, as before
    assert (it["title"], it["family"], it["severity"], it["sites"], it["finding_ids"]) == (
        "OAuth2 Proxy is out of date", "out-of-date", "MODERATE", [HOST], [FID])
    assert it["headline"] == f"update OAuth2 Proxy on {HOST}" and it["who"] == "it"


def test_without_own_words_the_card_is_exactly_as_before():
    for kw in ({}, {"own": None}, {"own": {}}, {"own": {"someone-else:1": (LEAD, FIX)}}):
        it = one([row()], **kw)
        assert (it["body"], it["do"], it["do_raw"]) == (STOCK["why"], STOCK["do"], False), kw
    assert STOCK["why"].startswith("Later versions fix published flaws in it.")
    assert STOCK["do"] == "Update OAuth2 Proxy on this site to a current version."


def test_two_sites_with_the_same_own_words_say_them_once():
    b = "b.example.com:advisory_watch:out-of-date:oauth2_proxy:1234567"
    it = one([row(), row(fid=b, host="b.example.com")], own={FID: (LEAD, FIX), b: (LEAD, FIX)})
    assert (it["body"], it["do"]) == (LEAD, FIX) and it["sites"] == ["b.example.com", HOST]


def test_two_sites_that_differ_keep_the_familys_words():
    """One card cannot say two versions' sentences; it says what is true of both."""
    b = "b.example.com:advisory_watch:out-of-date:oauth2_proxy:1234567"
    older = "Runs OAuth2 Proxy 7.14.0: out of date — 30 published flaws fixed in later versions; update it"
    rows = [row(), row(fid=b, host="b.example.com", title=older)]
    stock = dw.words(TITLE, 2)
    for own in ({FID: (LEAD, FIX), b: ("This sign-in shows OAuth2 Proxy 7.14.0.", FIX)},      # different leads
                {FID: (LEAD, FIX), b: (LEAD, "Update OAuth2 Proxy to 7.16.0 or later.")},       # different fixes
                {FID: (LEAD, FIX)},                                                             # one has none
                {b: (LEAD, FIX)}):
        it = one(rows, own=own)
        assert (it["body"], it["do"]) == (stock["why"], stock["do"]), own


def test_a_plugin_advisory_keeps_its_judged_words():
    title = "Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)"
    desc = ("The Mega Main Menu plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions "
            "up to, and including, 2.2.2. This makes it possible for unauthenticated attackers to change the "
            "plugin's settings via a forged request, granted they can trick a site administrator into "
            "clicking a link. Detected at version 2.2.1.")
    assert dw.plugin_of(title), "this test needs a title the plugin reader knows"
    fid = "wp.example.com:wpscan:mega_main_menu:1"
    r = [row(fid=fid, host="wp.example.com", title=title, sev="HIGH", source="wpscan")]
    plain = one(r, details={fid: (desc, [])})
    mine = one(r, details={fid: (desc, [])}, own={fid: (LEAD, FIX)})
    assert plain["body"] and plain["do"], "the advisory applies and has its own words"
    assert (mine["body"], mine["do"], mine["forward"]) == (plain["body"], plain["do"], plain["forward"])
    assert LEAD not in mine["body"] and mine["do"] != FIX


def test_own_words_never_stand_in_for_a_missing_first_step():
    """A family with no fix line still takes the scanner's first step from the hints; own
    words are only ever a finding's own pair, whole."""
    title = "Some check nobody has plain words for"
    fid = "x.example.com:nuclei:some-check:1"
    it = one([row(fid=fid, host="x.example.com", title=title, source="nuclei")],
             hints={fid: "Turn the setting off in the console. Then restart."})
    assert it["do_raw"] is True and it["do"].startswith("Turn the setting off")
    it = one([row(fid=fid, host="x.example.com", title=title, source="nuclei")],
             hints={fid: "Turn the setting off in the console. Then restart."}, own={fid: ("What it is.", "The fix.")})
    assert (it["body"], it["do"], it["do_raw"]) == ("What it is.", "The fix.", False)


# ── two products are two cards ───────────────────────────────────────────────

PHP = "Runs PHP 8.1.2: out of date — 3 published flaws fixed in later versions; update it"


def test_two_out_of_date_products_are_two_cards():
    """Before: one group key for every out-of-date finding, so PHP on one site and OAuth2
    Proxy on another were ONE card, "OAuth2 Proxy is out of date" on both sites."""
    php = "php.example.com:advisory_watch:out-of-date:php:abc1234"
    rows = [row(), row(fid=php, host="php.example.com", title=PHP)]
    items = dd.group_problems(rows, {HOST, "php.example.com"}, own=OWN)
    got = {i["title"]: (i["sites"], i["body"], i["do"]) for i in items}
    assert got == {
        "OAuth2 Proxy is out of date": ([HOST], LEAD, FIX),
        "PHP is out of date": (["php.example.com"], dw.words(PHP, 1)["why"], "Update PHP on this site to a current version."),
    }
    assert dw.family_key(TITLE) == "out-of-date:oauth2 proxy" and dw.family_key(PHP) == "out-of-date:php"


def test_one_product_on_several_sites_is_still_one_card_whatever_the_versions():
    older = "Runs PHP 7.4.33: out of date — 9 published flaws fixed in later versions; update it"
    fw = "Runs Fortinet FortiGate (FortiOS), firmware built Mar 2024: out of date — 2 published since; update it"
    assert dw.family_key(PHP) == dw.family_key(older) == "out-of-date:php"
    assert dw.family_key(fw) == "out-of-date:fortinet fortigate (fortios)"
    it = one([row(fid="a:1", host="a.example.com", title=PHP), row(fid="b:1", host="b.example.com", title=older)])
    assert it["title"] == "PHP is out of date" and it["sites"] == ["a.example.com", "b.example.com"]
    # every other family's key is what it was
    assert dw.family_key("Runs PHP, version not shown") == "version-unknown:php"
    assert dw.family_key("No enforcing WAF in front of live application") == "waf-absent"
    assert dw.words(TITLE, 1)["key"] == "out-of-date", "the family's name on the card is unchanged"


# ── the model, the email, Slack, the voice's facts ───────────────────────────

@pytest.mark.parametrize("kw,bucket,tag", [
    ({"new_findings": [row()]}, "ticket", ""),
    ({"regressed": [row()]}, "ticket", "Came back after being fixed"),
    ({"confirmed": [row()]}, "ticket", "Confirmed by a second scan"),
    ({"new_findings": [row(sev="MODERATE-HIGH")]}, "do", ""),
    ({"regressed": [row(sev="MODERATE-HIGH")]}, "do", "Came back after being fixed"),
])
def test_the_model_carries_them_however_the_finding_arrived(kw, bucket, tag):
    m = model(own=OWN, **kw)
    got = [i for i in m[bucket] if i.get("kind") == "finding"]
    assert len(got) == 1 and (got[0]["body"], got[0]["do"], got[0]["tag"]) == (LEAD, FIX, tag)
    stock = [i for i in model(**kw)[bucket] if i.get("kind") == "finding"]
    assert (stock[0]["body"], stock[0]["do"]) == (STOCK["why"], STOCK["do"]), "and without them, as before"


def test_the_email_says_them_in_text_and_html():
    m = model(new_findings=[row()], own=OWN)
    text = dd.render_text(m, portal_url="https://portal.example", product_name="Prodex Sentry")
    assert f"What it means: {LEAD}" in text and f"The fix, for your IT team: {FIX}" in text
    assert "[Moderate] OAuth2 Proxy is out of date" in text and STOCK["why"] not in text
    html = dd.render_html(m, portal_url="https://portal.example", product_name="Prodex Sentry")
    assert LEAD in html and FIX in html and STOCK["why"].replace("'", "&#x27;") not in html


def test_own_words_are_shown_as_text_never_as_markup():
    m = model(new_findings=[row()], own={FID: ('Shows <b>X</b> & "more".', "Update <i>X</i>.")})
    html = dd.render_html(m, portal_url="https://portal.example", product_name="Prodex Sentry")
    assert "<b>X</b>" not in html and "<i>X</i>" not in html
    assert "Shows &lt;b&gt;X&lt;/b&gt; &amp; &quot;more&quot;." in html and "Update &lt;i&gt;X&lt;/i&gt;." in html


def test_slack_and_the_voices_facts_say_them_too():
    m = model(new_findings=[row()], own=OWN)
    sel = ds.select(m, [], None, W1)
    sheet = dv.facts(m, slack=sel, company="Prodex", day="Thursday, November 12")
    changed = [i for i in sheet["items"] if i["section"] == "changed"]
    posted = [i for i in sheet["items"] if i["section"] == "slack_changed"]
    assert len(changed) == 1 and len(posted) == 1
    for i in changed + posted:
        assert (i["what"], i["why"], i["fix"]) == ("OAuth2 Proxy is out of date", LEAD, FIX)
    out = dv.fallback(sheet)
    post = ds.preview_text(ds.payload(out, sel, product_name="Prodex Sentry", day_label="Thursday, November 12"))
    assert post == ("*What changed since yesterday*\n"
                    f"• [Moderate] OAuth2 Proxy is out of date on *{HOST}*. {LEAD} {FIX}")
