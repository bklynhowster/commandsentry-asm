"""(KB 12 job 3l round 5, 2026-10-27) The daily in Howie's voice: the facts sheet, the check,
the fallback, the rendering.

Howie, 08:37: "I want this to be far more conversational." 09:53: "let's write a model that
totally approximates my voice and adds a certain amount of randomness to it." 10:26 (D-d): the
model writes every sentence, and each is checked against the facts of the one item it is about.
Review (Qwen3.8 Max, M7): the check must see misattribution (a real number on the wrong host),
severity words, spelled-out numbers and the job-talk ruling, and every rule must be SEEN
REFUSING before it is seen passing. So every test here plants the bad case first.
"""
from __future__ import annotations

import copy
import json
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

UTC = timezone.utc
NOW = datetime(2026, 10, 27, 12, 3, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Prodex")


def _model():
    """Today's Prodex daily, as build_model shapes it: one host not responding, four
    'something unrecognized is blocking' tickets, four small things."""
    nr = [("valorep.prodexlabs.com", datetime(2026, 10, 22, 18, 25, tzinfo=UTC), "name_gone", None,
           datetime(2026, 11, 2, 18, 25, tzinfo=UTC))]
    pages = [(f"{h}.prodexlabs.com", None, None, datetime(2026, 10, 27, 2, 0, tzinfo=UTC), ["403", "403", "403"])
             for h in ("l3h-ss", "prod", "l3h-nh", "l3h-ivs")]
    m = dd.build_model(window_start=NOW.replace(day=25), window_end=NOW, new_findings=[], confirmed=[],
                       regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=[],
                       canary_violations=[], baseline={}, brand=BRAND, not_responding=nr,
                       unrecognized_pages=pages, told={})
    m["low"], m["info"] = 3, 1
    return m


def _still():
    return [{"kind": "finding", "severity": "MODERATE-HIGH", "title": "A web firewall is there, but it's only watching",
             "family": "waf-not-blocking", "body": "It is there but only watching.", "do": "Set it to block.",
             "sites": ["bitec.prodexlabs.com", "demo.prodexlabs.com", "highcom.prodexlabs.com"],
             "finding_ids": ["b:w", "d:w", "h:w"], "since": datetime(2026, 10, 22, tzinfo=UTC), "recent": True}]


def _slack():
    return {"changed": [{"kind": "not_responding", "severity": "", "title": "1 host is not responding",
                         "sites": ["valorep.prodexlabs.com"], "lines": ["valorep.prodexlabs.com: no answer since Oct 22, 2:25 PM. Leaves the portal on Nov 2."],
                         "finding_ids": [], "slack_color": ds.RED}],
            "nudge": [{"kind": "finding", "severity": "MODERATE", "title": "Security headers missing: Content-Security-Policy, Strict-Transport-Security",
                       "family": "", "body": "", "do": "", "sites": ["prodexlabs.com", "cooked.prodexlabs.com"],
                       "finding_ids": ["p:csp", "c:hsts"], "since": datetime(2026, 7, 3, tzinfo=UTC)}]}


def _facts():
    return dv.facts(_model(), still_open=_still(), slack=_slack(), company="Prodex", day="Tuesday, October 27")


def _good(f):
    """An answer a careful writer would give: one entry per item, its own facts only."""
    by = {it["section"]: [] for it in f["items"]}
    for it in f["items"]:
        by[it["section"]].append(it)
    c1 = by["changed"][0]
    out = {"subject": "one box went quiet", "headline": "One box went quiet.",
           "opening": "Morning. Short version: one of our boxes went quiet, and that's the only real news today.",
           "email": [], "fixed": [], "still_open": [], "small_line": "4 small things also turned up, none of them need anybody, they're in the portal if you're curious.",
           "slack": {"changed": [], "nudge": [], "closing": "Neither one is urgent. If you own one of those boxes, it's a ten-minute fix when you get a chance."}}
    out["email"].append({"id": c1["id"], "text": "valorep.prodexlabs.com hasn't answered since Oct 22, and its name doesn't resolve on the internet anymore, so it looks like it was taken down for good. If that's right, it drops off the portal on its own on Nov 2."})
    for it in by["changed"][1:]:
        out["email"].append({"id": it["id"], "text": "l3h-ss, prod, l3h-nh and l3h-ivs all turned away Sentry's test traffic, which is a good sign. Something is standing guard in front of them, a firewall or a security device of some kind, and Sentry is still working out which."})
    for it in by["still"]:
        out["still_open"].append({"id": it["id"], "text": "The firewall in front of bitec, demo and highcom is there but it's only watching, not blocking. That's been the case since Oct 22, and it's the most serious thing open right now."})
    for it in by["slack_changed"]:
        out["slack"]["changed"].append({"id": it["id"], "text": "valorep.prodexlabs.com stopped answering on Oct 22 and its name doesn't resolve anymore, so it looks like it was taken down. If somebody expects it to be up, that's worth a look."})
    for it in by["slack_nudge"]:
        out["slack"]["nudge"].append({"id": it["id"], "text": "Two security headers are missing on prodexlabs.com and cooked: they don't send Strict-Transport-Security or Content-Security-Policy. A couple of lines of server config."})
    return out


# ── the facts sheet ──────────────────────────────────────────────────────────────────────
def test_the_sheet_is_closed_and_every_item_has_an_id_hosts_dates_and_numbers():
    f = _facts()
    ids = [it["id"] for it in f["items"]]
    assert len(ids) == len(set(ids)) and ids[0] == "c1"
    c1 = f["items"][0]
    assert c1["kind"] == "not_responding" and c1["hosts"] == ["valorep.prodexlabs.com"]
    assert "Oct 22" in c1["dates"] and "Nov 2" in c1["dates"]
    n1 = [it for it in f["items"] if it["section"] == "slack_nudge"][0]
    assert n1["dates"] == [], "a nudge may carry no date"
    assert f["small_count"] == 4 and f["sentry_only"] == []
    req = dv.required_ids(f)
    assert len(req["email"]) == 2 and req["still_open"] == ["s1"] and req["slack_nudge"] == ["n1"]
    assert c1["detail"] == ["valorep.prodexlabs.com: no answer since Oct 22, 2:25 PM. Its name no longer exists on the internet. Leaves the portal on Nov 2."]


def test_the_same_thing_on_several_hosts_is_one_item_and_a_block_page_is_good_news():
    """Howie 08:38: four near-identical paragraphs become a blur; 08:40: a block page means
    something is standing guard, Sentry is still working out the security stack."""
    f = _facts()
    c2 = f["items"][1]
    assert c2["kind"] == "blockpage" and len(c2["hosts"]) == 4 and c2["hosts"][0] == "l3h-ss.prodexlabs.com"
    assert "standing guard" in c2["what"] and "good news" in c2["why"] and "4" in c2["numbers"]
    assert len(c2["detail"]) == 4 and c2["detail"][1].startswith("prod.prodexlabs.com: On Oct 27")
    assert "Oct 27" in c2["dates"]
    assert "unrecognized" not in c2["what"], "the 3l title ('Something unrecognized is blocking') is not the voice's"
    para = dv._para(c2)
    assert para.startswith("l3h-ss, prod, l3h-nh and l3h-ivs turned away Sentry's test traffic, which is good news")
    assert dv._para(dict(c2, hosts=c2["hosts"][:1])).startswith("l3h-ss.prodexlabs.com turned away Sentry's test traffic, which is good news: something is standing guard in front of it")
    # one block page stays as it was shaped (no merge, its own host in the title)
    m = _model()
    m["ticket"] = [t for t in m["ticket"] if t.get("kind") != "blockpage"][:0] + [t for t in m["ticket"] if t.get("kind") == "blockpage"][:1]
    f1 = dv.facts(m)
    b1 = [i for i in f1["items"] if i["kind"] == "blockpage"]
    assert len(b1) == 1 and b1[0]["hosts"] == ["l3h-ss.prodexlabs.com"]
    # a quiet host's paragraph carries the detail (why, and when it leaves), once
    c1 = f["items"][0]
    p1 = dv._para(c1)
    assert p1.count("Nov 2") == 1 and "Its name no longer exists on the internet." in p1 and "now you know" in p1
    assert p1.count("valorep") == 1 and "checks. No answer since Oct 22, 2:25 PM." in p1, "the host is named once"
    two = dict(c1, hosts=["a.prodexlabs.com", "b.prodexlabs.com"], detail=["a.prodexlabs.com: no answer since Oct 22.", "b.prodexlabs.com: no answer since Oct 23."])
    p2 = dv._para(two)
    assert p2.startswith("a and b have stopped answering Sentry's checks. a.prodexlabs.com: no answer since Oct 22. b.prodexlabs.com: no answer since Oct 23. Any that were taken down")
    # a rating item names its hosts from its lines, so the writer may say them
    m = _model()
    m["ticket"].append({"kind": "rating", "severity": "", "title": "A site got riskier", "body": "x",
                        "lines": ["tour.prodexlabs.com is now High, because of: a thing"], "sites": []})
    fr = dv.facts(m)
    assert [i for i in fr["items"] if i["kind"] == "rating"][0]["hosts"] == ["tour.prodexlabs.com"]


def test_sentrys_own_problems_are_for_howie_only():
    m = _model()
    m["do"].insert(0, {"kind": "coverage", "severity": "", "title": "Sentry lost sight of 2 hosts",
                       "lines": ["a: x", "b: y"], "sites": [], "body": "", "do": "", "tag": ""})
    f = dv.facts(m, sentry_only=[i for i in m["do"] if i.get("kind") == "coverage"])
    assert all(it["kind"] != "coverage" for it in f["items"]) and f["sentry_only"][0]["title"].startswith("Sentry lost sight")


# ── the check: every rule refuses first, then passes ─────────────────────────────────────
def test_a_careful_answer_passes():
    f = _facts()
    assert dv.check(_good(f), f, portal_url="https://prodexsentry.netlify.app") == []


def _refused(mutate, needle):
    f = _facts()
    out = _good(f)
    mutate(out)
    problems = dv.check(out, f, portal_url="https://prodexsentry.netlify.app")
    assert problems and any(needle in p for p in problems), problems
    return problems


def test_the_free_text_fields_cannot_carry_a_number_or_date_that_is_nobodys():
    """The subject, headline, opening and small line are not about one item, so the per-item
    checks never see them (Qwen, code review 11:50: 'Nine small things ... in the portal.')."""
    _refused(lambda o: o.__setitem__("opening", "Nine small things and one info finding are in the portal."), "opening: a number")
    _refused(lambda o: o.__setitem__("headline", "Six boxes went quiet."), "headline: a number")
    _refused(lambda o: o.__setitem__("small_line", "9 small things also turned up, none need anybody."), "small_line: a number")
    _refused(lambda o: o.__setitem__("subject", "3 boxes went quiet"), "subject: a number")
    _refused(lambda o: o.__setitem__("headline", "One box went quiet on Oct 3."), "headline: a date")
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: since Monday one box is quiet."), "opening: a date")
    f = _facts()
    o = _good(f)
    o["opening"] = "Morning. Short version: 2 things since yesterday, 4 small ones in the portal, and it's Tuesday, Oct 22 was the day valorep went quiet."
    o["headline"] = "One box went quiet, one block page, 4 small things."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == [], "the day's own counts, one, the day, and an item's date pass"


def test_a_nudge_may_not_say_how_long_in_any_words():
    """Qwen, code review 12:02: 'Since last week' at the start of a sentence slipped past
    the ' since ' test; 'for weeks nobody has touched it' has no date and no number."""
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "prodexlabs.com is missing a security header, flagged thirty times."}), "a number that is not its own (30)")
    for bad in ("Since last week prodexlabs.com is missing a security header.",
                "prodexlabs.com is missing a security header. For weeks nobody has touched it.",
                "prodexlabs.com has been missing a security header for a while.",
                "prodexlabs.com is missing a security header, open for three months.",
                "prodexlabs.com is missing a security header, flagged ages ago."):
        _refused(lambda o, bad=bad: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": bad}), "a nudge says how long")
    f = _facts()
    o = _good(f)
    o["slack"]["nudge"][0]["text"] = "Two security headers are missing on prodexlabs.com and cooked, Strict-Transport-Security and Content-Security-Policy. A couple of lines of server config."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == []


def test_two_hosts_in_one_item_cannot_have_their_dates_swapped():
    """Qwen, code review 12:02: both hosts and both dates are the item's own, so the old
    rules passed 'a since Oct 25 and b since Oct 22' with the two swapped."""
    m = _model()
    m["do"] = [{"kind": "not_responding", "severity": "", "title": "2 hosts are not responding", "body": dd.NOT_RESPONDING_BODY,
                "lines": ["a.prodexlabs.com: no answer since Oct 22, 2:25 PM. Leaves the portal on Nov 2.",
                          "b.prodexlabs.com: no answer since Oct 25, 9:00 AM. Leaves the portal on Nov 5."], "sites": [], "why": "", "do": "", "tag": ""}]
    m["ticket"] = []
    f = dv.facts(m)
    c1 = f["items"][0]
    assert c1["hosts"] == ["a.prodexlabs.com", "b.prodexlabs.com"] and set(c1["dates"]) >= {"Oct 22", "Oct 25", "Nov 2", "Nov 5"}
    def check(text):
        o = dv.fallback(f); o["email"] = [{"id": "c1", "text": text}]
        return [p for p in dv.check(o, f, portal_url="https://prodexsentry.netlify.app") if p.startswith("email c1")]
    assert check("a.prodexlabs.com has been quiet since Oct 25 and b.prodexlabs.com since Oct 22.") == ["email c1: Oct 25 is not a.prodexlabs.com's date", "email c1: Oct 22 is not b.prodexlabs.com's date"]
    assert check("a.prodexlabs.com has been quiet since Oct 22 and b.prodexlabs.com since Oct 25.") == []
    assert check("a went quiet on Oct 22, b on Oct 25; they leave the portal on Nov 2 and Nov 5.") == []
    assert check("a went quiet on Oct 22, b on Oct 25, and a leaves on Nov 5.") == ["email c1: Nov 5 is not a.prodexlabs.com's date"]
    assert check("a and b went quiet on Oct 22 and Oct 25.") == [], "a clause naming both hosts cannot be told apart, and is left alone"
    assert dv.check(dv.fallback(f), f, portal_url="https://prodexsentry.netlify.app") == [], "the fallback's own two-host paragraph passes"


def test_banned_words_are_whole_words_and_grading_words_are_refused():
    """Qwen, code review 12:02: 'default' tripped 'fault' and 'on users' tripped 'on us'
    (one trip = a fallback day); a Moderate-high item called 'minor' passed."""
    f = _facts()
    o = _good(f)
    o["opening"] = "Morning. Short version: the default settings on users' boxes are fine, a firewall is doing its job, and the most serious thing open is the one below."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == [], "whole words only: default, users, firewall are innocent; 'serious' ranks, it does not grade"
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: HR has the list."), "banned word: 'hr'")
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: this is not anyone's fault."), "banned word: 'fault'")
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: this one is on us."), "banned word: 'on us'")
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: nobody is getting fired over a header."), "banned word: 'fired'")
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "The firewall in front of bitec, demo and highcom is only watching. A minor thing."}), "severity word 'minor'")
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "The firewall in front of bitec, demo and highcom is only watching. Trivial, really."}), "severity word 'trivial'")


def test_the_scanners_raw_titles_are_cleaned_on_the_way_into_the_sheet():
    """Qwen, code review 12:02 (live Prodex SQL): the oldest developer-side nudge is the BREACH
    title with an em dash and 'VULNERABLE' in it; on day one the model echoes it, the check
    refuses the day, and the fallback prints it raw. Every fact is cleaned on the way in."""
    raw = "BREACH attack vulnerability check — potentially VULNERABLE, gzip HTTP compression detected - only supplied '/' tested"
    slack = {"changed": [], "nudge": [{"kind": "finding", "severity": "MODERATE", "title": raw, "family": "", "body": "", "do": "",
                                        "sites": ["bitec.prodexlabs.com", "cooked.prodexlabs.com", "dass.prodexlabs.com"],
                                        "finding_ids": ["b:br", "c:br", "d:br"], "since": datetime(2026, 8, 26, tzinfo=UTC)}]}
    still = [{"kind": "finding", "severity": "MODERATE", "title": "TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA AES256-SHA DES-CBC3-SHA", "family": "",
              "body": "The tool flags the host as VULNERABLE to it.", "do": "", "sites": ["tour.prodexlabs.com"], "finding_ids": ["t:be"], "since": datetime(2026, 7, 10, tzinfo=UTC)},
             {"kind": "finding", "severity": "MODERATE", "title": "Obsolete 3DES/IDEA ciphers offered", "family": "", "body": "", "do": "",
              "sites": ["tour.prodexlabs.com"], "finding_ids": ["t:3d"], "since": datetime(2026, 7, 10, tzinfo=UTC)}]
    m = _model()
    m["ticket"].append({"kind": "finding", "severity": "MODERATE", "title": raw, "family": "", "body": "Nikto says: potentially VULNERABLE — see above.",
                        "do": "", "sites": ["dass.prodexlabs.com"], "finding_ids": ["d:br2"], "tag": ""})
    f = dv.facts(m, still_open=still, slack=slack, company="Prodex", day="Tuesday, October 27")
    whole = " ".join(dv._flatten(it) for it in f["items"])
    assert "—" not in whole and "·" not in whole and "vulnerable" not in whole.lower()
    n1 = [it for it in f["items"] if it["section"] == "slack_nudge"][0]
    assert n1["what"].startswith("Compressed pages could let an attacker read a secret") and "gzip" in n1["why"] and "server config" in n1["fix"]
    s1 = [it for it in f["items"] if it["section"] == "still"]
    assert s1[0]["what"].startswith("Old CBC ciphers") and s1[1]["what"].startswith("Old weak ciphers (3DES)")
    assert s1[0]["why"] == "The tool flags the host as exposed to it."
    c = [it for it in f["items"] if it["section"] == "changed"][-1]
    assert "possibly exposed, see above" in c["why"] and c["what"].startswith("Compressed pages")
    fb = dv.fallback(f)
    assert dv.check(fb, f, portal_url="https://prodexsentry.netlify.app") == [], "the fallback on today's live titles passes its own check"
    html = dv.render_html(fb, f, brand=BRAND, logo_cid=dd.LOGO_CID, local_end=m["local_end"], portal_url="https://prodexsentry.netlify.app", product_name="PRODEXsentry")
    assert "VULNERABLE" not in html and "—" not in html


def test_a_host_that_is_not_the_items_own_is_refused():
    _refused(lambda o: o["email"].__setitem__(0, {"id": "c1", "text": "valorep.prodexlabs.com and staging.prodexlabs.com went quiet on Oct 22, and leave on Nov 2."}),
             "names a host that is not its own")


def test_a_missing_host_is_refused():
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "The firewall in front of bitec and demo is there but only watching since Oct 22."}),
             "does not name highcom")


def test_a_real_date_on_the_wrong_item_is_refused():
    # Nov 2 belongs to c1; attached to the block-page item it is misattribution
    _refused(lambda o: o["email"].__setitem__(1, {"id": "c2", "text": "l3h-ss.prodexlabs.com turned away our test traffic on Nov 2, which is a good sign."}),
             "a date that is not its own")


def test_a_number_that_is_not_the_items_own_is_refused_spelled_out_too():
    _refused(lambda o: o["email"].__setitem__(1, {"id": "c2", "text": "l3h-ss.prodexlabs.com turned away our test traffic 7 times."}),
             "a number that is not its own")
    _refused(lambda o: o["email"].__setitem__(1, {"id": "c2", "text": "l3h-ss.prodexlabs.com turned away our test traffic seven times."}),
             "a number that is not its own")


def test_a_severity_word_that_is_not_the_items_own_is_refused():
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "The firewall in front of bitec, demo and highcom is only watching, which is a High problem."}),
             "severity word 'high'")
    f = _facts()
    out = _good(f)
    out["still_open"][0]["text"] += " Sentry rates it Moderate-high."
    assert dv.check(out, f, portal_url="https://prodexsentry.netlify.app") == [], "its own severity word is fine"


def test_a_nudge_with_a_date_or_a_since_is_refused():
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "Two security headers are missing on prodexlabs.com and cooked since Jul 3."}),
             "date")
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "Two security headers are missing on prodexlabs.com and cooked, open since July."}),
             "a nudge says how long")


def test_job_talk_blame_and_vulnerable_are_refused():
    _refused(lambda o: o["slack"].__setitem__("closing", "Nobody's going to get fired over either one."), "banned word: 'fired'")
    _refused(lambda o: o.__setitem__("opening", "Morning. This one's on us."), "banned word: 'on us'")
    _refused(lambda o: o.__setitem__("opening", "Morning. Nothing for you to do today."), "banned word: 'nothing for you to do'")
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "bitec, demo and highcom are vulnerable behind a watching firewall since Oct 22."}),
             "banned word: 'vulnerable'")


def test_an_em_dash_a_stray_url_and_an_unknown_item_are_refused():
    _refused(lambda o: o.__setitem__("opening", "Morning — short version: quiet."), "em dash")
    _refused(lambda o: o.__setitem__("small_line", "See https://example.com/x for the list."), "a URL that is not the portal")
    _refused(lambda o: o["email"].append({"id": "c99", "text": "x"}), "unknown item id")
    _refused(lambda o: o["email"].pop(), "has no entry")
    _refused(lambda o: o["email"].append(dict(o["email"][0])), "twice")
    _refused(lambda o: o["still_open"].append({"id": "c1", "text": "valorep.prodexlabs.com, Oct 22, Nov 2."}), "belongs to another list")


def test_a_host_in_the_headline_that_is_in_no_item_is_refused_and_small_line_rules():
    _refused(lambda o: o.__setitem__("headline", "demo.prodexlabs.com and evil.example.net went quiet."), "names a host that is in no item")
    f = _facts()
    f["small_count"] = 0
    out = _good(f)
    assert any("small_line" in p for p in dv.check(out, f, portal_url="https://p"))
    out["small_line"] = ""
    assert not any("small_line" in p for p in dv.check(out, f, portal_url="https://p"))


# ── the writer's plumbing (no network) ───────────────────────────────────────────────────
def test_write_uses_one_call_with_the_facts_and_returns_the_json():
    f = _facts()
    calls = []

    def post(url, body, key):
        calls.append((url, body, key))
        return {"content": [{"type": "text", "text": "```json\n" + json.dumps(_good(f)) + "\n```"}]}
    out = dv.write(f, api_key="k", previous_text="yesterday's words", post=post)
    assert len(calls) == 1 and calls[0][0] == dv.API_URL and calls[0][2] == "k"
    body = calls[0][1]
    assert body["model"] == dv.MODEL_ID == "claude-sonnet-4-6" and body["temperature"] == dv.TEMPERATURE
    synth = open(os.path.join(HERE, "..", "backfill", "synthesize_finding_descriptions.py"), encoding="utf-8").read()
    assert 'MODEL_ID = "claude-sonnet-4-6"' in synth, "the writer uses the id this repo already calls daily with the same key"

    assert "yesterday's words" in body["messages"][0]["content"] and '"id": "c1"' in body["messages"][0]["content"]
    assert "never anyone's job" in body["system"].lower() or "being fired" in body["system"].lower()
    assert out["headline"] == "One box went quiet."


def test_write_fails_closed_with_a_short_reason_and_never_the_key():
    f = _facts()
    with pytest.raises(dv.VoiceError) as e:
        dv.write(f, api_key="", post=lambda *a: {})
    assert "no API key" in str(e.value)
    with pytest.raises(dv.VoiceError) as e:
        dv.write(f, api_key="secret-key-value", post=lambda *a: (_ for _ in ()).throw(RuntimeError("boom secret-key-value")))
    assert "secret-key-value" not in str(e.value) and "API call failed" in str(e.value)
    with pytest.raises(dv.VoiceError) as e:
        dv.write(f, api_key="k", post=lambda *a: {"content": [{"type": "text", "text": "not json"}]})
    assert "not JSON" in str(e.value)


# ── the fallback ─────────────────────────────────────────────────────────────────────────
def test_the_fallback_passes_its_own_check_and_is_never_random():
    f = _facts()
    a, b = dv.fallback(f), dv.fallback(f)
    assert a == b
    assert dv.check(a, f, portal_url="https://prodexsentry.netlify.app") == []
    assert "valorep.prodexlabs.com" in a["email"][0]["text"] and "fired" not in json.dumps(a).lower()
    quiet = dv.facts(_model() | {"do": [], "ticket": [], "low": 0, "info": 0})
    q = dv.fallback(quiet)
    assert q["headline"] == "A quiet night." and q["small_line"] == "" and dv.check(q, quiet) == []


# ── rendering ────────────────────────────────────────────────────────────────────────────
def test_the_email_and_the_subject_read_as_howies():
    f = _facts()
    out = _good(f)
    html = dv.render_html(out, f, brand=BRAND, logo_cid="brandlogo", local_end=NOW, portal_url="https://p.example", product_name="PRODEXsentry")
    text = dv.render_text(out, f, brand=BRAND, local_end=NOW, portal_url="https://p.example", product_name="PRODEXsentry")
    assert "One box went quiet." in html and "Still sitting there" in html and "Open the portal" in html
    assert "NEEDS YOU TODAY" not in html and "[ ]" not in text and "Still sitting there:" in text
    assert "Public Sans" in html and "—" not in text
    assert dv.subject(out, f, product_name="PRODEXsentry", local_end=NOW) == "[PRODEXsentry] Tuesday: one box went quiet"
    assert "4 small things" in text


def test_an_api_error_is_reported_in_the_apis_own_words_and_never_the_key():
    import io, urllib.error
    body = json.dumps({"type": "error", "error": {"type": "not_found_error", "message": "model: claude-sonnet-5-5"}}).encode()
    e = urllib.error.HTTPError("https://api.anthropic.com/v1/messages", 404, "Not Found", {}, io.BytesIO(body))
    assert dv.api_error_words(e) == "not_found_error: model: claude-sonnet-5-5"
    e2 = urllib.error.HTTPError("u", 500, "x", {}, io.BytesIO(b"<html>oops</html>"))
    assert dv.api_error_words(e2) == ""
    f = _facts()
    def post(url, b, key):
        raise urllib.error.HTTPError(url, 400, "Bad Request", {}, io.BytesIO(json.dumps({"error": {"type": "invalid_request_error", "message": "max_tokens: too large; sk-ant-SHOULD-NOT-LEAK"}}).encode()))
    try:
        dv.write(f, api_key="sk-ant-THEKEY", post=post)
        assert False, "should raise"
    except dv.VoiceError as ve:
        assert str(ve).startswith("API HTTP 400, invalid_request_error: max_tokens: too large") and "THEKEY" not in str(ve)
