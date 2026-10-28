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
           "opening": "Here's your morning briefing. One of our boxes went quiet, and that's the only real news today.",
           "email": [], "fixed": [], "still_open": [], "small_line": "4 small things also turned up, none of them need anybody, they're in the portal if you're curious.",
           "slack": {"changed": [], "nudge": [], "closing": "Neither one is urgent. If you own one of those boxes, it's a ten-minute fix when you get a chance."}}
    out["email"].append({"id": c1["id"], "text": "valorep.prodexlabs.com looks like it's been down since Oct 22. If it doesn't come back by Nov 2, it drops off the portal on its own and we don't have to talk about it anymore."})
    for it in by["changed"][1:]:
        out["email"].append({"id": it["id"], "text": "Since yesterday, l3h-ss, prod, l3h-nh and l3h-ivs have started blocking our probes. We send every box a few probes to check whether there's some kind of security device sitting in front of it, like a WAF. Something is now standing guard in front of those four, and we're still working out which product it is."})
    for it in by["still"]:
        out["still_open"].append({"id": it["id"], "text": "[Moderate-high] The firewall in front of bitec, demo and highcom is only watching, not blocking, since Oct 22, the most serious thing open."})
    for it in by["slack_changed"]:
        out["slack"]["changed"].append({"id": it["id"], "text": "valorep.prodexlabs.com looks down since Oct 22. If somebody expects it to be up, that's worth a look; otherwise it drops off the portal on Nov 2."})
    for it in by["slack_nudge"]:
        out["slack"]["nudge"].append({"id": it["id"], "text": "[Moderate] Two security headers are missing on prodexlabs.com and cooked: they don't send Strict-Transport-Security or Content-Security-Policy. A couple of lines of server config."})
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
    assert c1["detail"] == ["valorep.prodexlabs.com: looks down since Oct 22. Drops off the portal on Nov 2 if it stays down."], \
        "Howie 18:22: nobody cares that the name does not resolve; the clock time goes too"
    assert "resolve" not in " ".join(c1["detail"]) + c1["why"] and "Sentry" not in c1["why"]


def test_the_same_thing_on_several_hosts_is_one_item_and_a_block_page_is_good_news():
    """Howie 08:38: four near-identical paragraphs become a blur; 08:40: a block page means
    something is standing guard, Sentry is still working out the security stack."""
    f = _facts()
    c2 = f["items"][1]
    assert c2["kind"] == "blockpage" and len(c2["hosts"]) == 4 and c2["hosts"][0] == "l3h-ss.prodexlabs.com"
    assert "standing guard" in c2["what"] and "good news" in c2["why"] and "4" in c2["numbers"]
    assert len(c2["detail"]) == 4 and c2["detail"][1] == "prod.prodexlabs.com: started blocking the probes on Oct 27."
    assert "Oct 27" in c2["dates"]
    assert "unrecognized" not in c2["what"], "the 3l title ('Something unrecognized is blocking') is not the voice's"
    para = dv._para(c2)
    assert para == ("Since yesterday, l3h-ss, prod, l3h-nh and l3h-ivs have started blocking our probes, which is good news. "
                    + dv.THE_PROBE + " Something is now standing guard in front of them, and we're still working out which product it is.")
    assert dv._para(dict(c2, hosts=c2["hosts"][:1])).startswith("Since yesterday, l3h-ss.prodexlabs.com has started blocking our probes, which is good news.")
    assert "in front of it, and we're" in dv._para(dict(c2, hosts=c2["hosts"][:1]))
    assert "new" not in para.replace("news", ""), "Howie 18:33: these boxes are not new, what is new is that they block"
    assert "already in our fleet" in c2["why"]
    assert dv.THE_PROBE in c2["why"] and c2["why"].startswith("These boxes were already in our fleet"), \
        "Howie 18:22: the probes that determine whether there is some type of security device in front, like a WAF; 18:33: not new boxes"
    for word in ("Sentry", "test", "attack", "injection", "vendor", "library"):
        assert word not in c2["why"] and word not in " ".join(c2["detail"]) and word not in c2["what"], word
    assert all(len(sent.split()) <= 30 for sent in para.split(". ")), "short sentences"
    # one block page stays as it was shaped (no merge, its own host in the title)
    m = _model()
    m["ticket"] = [t for t in m["ticket"] if t.get("kind") != "blockpage"][:0] + [t for t in m["ticket"] if t.get("kind") == "blockpage"][:1]
    f1 = dv.facts(m)
    b1 = [i for i in f1["items"] if i["kind"] == "blockpage"]
    assert len(b1) == 1 and b1[0]["hosts"] == ["l3h-ss.prodexlabs.com"]
    # a quiet host's paragraph is Howie's two sentences (18:22), nothing about why
    c1 = f["items"][0]
    p1 = dv._para(c1)
    assert p1 == ("valorep.prodexlabs.com looks like it's been down since Oct 22. If it doesn't come back by Nov 2, "
                  "it drops off the portal on its own and we don't have to talk about it anymore.")
    assert dv._para(dict(c1, detail=["valorep.prodexlabs.com: looks down."])) == (
        "valorep.prodexlabs.com looks like it's been down. If it doesn't come back in the next few days, "
        "it drops off the portal on its own and we don't have to talk about it anymore.")
    two = dict(c1, hosts=["a.prodexlabs.com", "b.prodexlabs.com"],
               detail=["a.prodexlabs.com: looks down since Oct 22.", "b.prodexlabs.com: looks down since Oct 23. Drops off the portal on Nov 3 if it stays down."])
    p2 = dv._para(two)
    assert p2 == ("a since Oct 22 and b since Oct 23 look like they're down. Any that don't come back drop off the portal "
                  "on their own, and we don't have to talk about them anymore.")
    assert dv._plain_quiet("x.prodexlabs.com: no answer from Sentry's checks. Leaves the portal on Nov 9.") == \
        "x.prodexlabs.com: looks down. Drops off the portal on Nov 9 if it stays down."
    assert dv._plain_quiet("something else entirely") == "something else entirely"
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
    _refused(lambda o: o.__setitem__("subject", "8 boxes went quiet"), "subject: a number")
    # the first real morning (2026-10-28 08:03): "five boxes" was true (one down, four guarding) and
    # was refused because the free lines knew only the first item's count. Now any item's count and
    # the day's total of changed boxes pass; the firewall line may count "the hosts above".
    f = _facts()
    ok = _good(f)
    ok["headline"] = "Five boxes: one down, four now guarded."
    ok["still_open"][0]["text"] = "[Moderate-high] The firewall in front of bitec, demo and highcom is only watching, not blocking. The same probes the 4 hosts above block go straight through here."
    assert dv.check(ok, f, portal_url="https://prodexsentry.netlify.app") == []
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "[Moderate-high] The firewall in front of bitec, demo and highcom is only watching, not blocking. The same probes the 6 hosts above block go straight through here."}), "a number that is not its own (6)")
    _refused(lambda o: o.__setitem__("headline", "One box went quiet on Oct 3."), "headline: a date")
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. since Monday one box is quiet."), "opening: a date")
    f = _facts()
    o = _good(f)
    o["opening"] = "Here's your morning briefing. 2 things since yesterday, 4 small ones in the portal, and it's Tuesday, Oct 22 was the day valorep went quiet."
    o["headline"] = "One box went quiet, one block page, 4 small things."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == [], "the day's own counts, one, the day, and an item's date pass"


def test_a_nudge_may_not_say_how_long_in_any_words():
    """Qwen, code review 12:02: 'Since last week' at the start of a sentence slipped past
    the ' since ' test; 'for weeks nobody has touched it' has no date and no number."""
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "[Moderate] prodexlabs.com is missing a security header, flagged thirty times."}), "a number that is not its own (30)")
    for bad in ("[Moderate] Since last week prodexlabs.com is missing a security header.",
                "[Moderate] prodexlabs.com is missing a security header. For weeks nobody has touched it.",
                "[Moderate] prodexlabs.com has been missing a security header for a while.",
                "[Moderate] prodexlabs.com is missing a security header, open for three months.",
                "[Moderate] prodexlabs.com is missing a security header, flagged ages ago."):
        _refused(lambda o, bad=bad: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": bad}), "a nudge says how long")
    f = _facts()
    o = _good(f)
    o["slack"]["nudge"][0]["text"] = "[Moderate] Two security headers are missing on prodexlabs.com and cooked, Strict-Transport-Security and Content-Security-Policy. A couple of lines of server config."
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
    o["opening"] = "Here's your morning briefing. the default settings on users' boxes are fine, a firewall is doing its job, and the most serious thing open is the one below."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == [], "whole words only: default, users, firewall are innocent; 'serious' ranks, it does not grade"
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. HR has the list."), "banned word: 'hr'")
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. this is not anyone's fault."), "banned word: 'fault'")
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. this one is on us."), "banned word: 'on us'")
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. nobody is getting fired over a header."), "banned word: 'fired'")
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "[Moderate-high] The firewall in front of bitec, demo and highcom is only watching. A minor thing."}), "severity word 'minor'")
    _refused(lambda o: o["still_open"].__setitem__(0, {"id": "s1", "text": "[Moderate-high] The firewall in front of bitec, demo and highcom is only watching. Trivial, really."}), "severity word 'trivial'")


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
    assert n1["what"] == "Compressed pages could leak a secret (BREACH)" and "gzip" in n1["why"] and "server config" in n1["fix"]
    s1 = [it for it in f["items"] if it["section"] == "still"]
    assert s1[0]["what"] == "Old CBC ciphers (BEAST) still offered" and s1[1]["what"] == "Old weak ciphers (3DES) still offered"
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
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. This one's on us."), "banned word: 'on us'")
    _refused(lambda o: o.__setitem__("opening", "Here's your morning briefing. Nothing for you to do today."), "banned word: 'nothing for you to do'")
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


def test_two_firewall_stories_say_they_are_opposites_and_say_what_sentry_sent():
    """Howie 15:02: "what was Sentry actually trying to do?" and "how are you differentiating
    [the web firewall] from anything you've mentioned before?" Both items say what was sent;
    the watching-only one says it is the opposite of the hosts above, naming no host of theirs."""
    f = _facts()
    c2 = [it for it in f["items"] if it["kind"] == "blockpage"][0]
    s1 = [it for it in f["items"] if it["section"] == "still"][0]
    assert dv.THE_PROBE in c2["why"] and "block the probes" in c2["why"]
    assert s1["why"] == "The same probes that the hosts above now block go straight through here. This firewall is watching, not blocking.", \
        "Howie 15:32: the probes are explained once; the firewall item refers back"
    assert "WAF" not in s1["why"] and "few probes" not in s1["why"]
    fb = dv.fallback(f)
    still = fb["still_open"][0]["text"]
    assert still == "[Moderate-high] A web firewall is there, but it's only watching on bitec, demo and highcom. " + s1["why"], "a nudge is one line plus the one sentence that relates it"
    assert "<ONE line, under 240 characters" in dv.SYSTEM and "ONCE, the first time it matters" in dv.SYSTEM
    assert "WHO READS IT" in dv.SYSTEM and "never more than 30 words" in dv.SYSTEM and "like a WAF" in dv.SYSTEM
    assert "test requests" not in dv.SYSTEM.split("THE EMAIL HE APPROVED")[1] and "resolve" not in dv.SYSTEM.split("THE EMAIL HE APPROVED")[1]
    import re as _re
    assert not any(_re.search(r"\b" + _re.escape(h.split(".")[0]) + r"\b", s1["why"]) for h in c2["hosts"]), "the other item's hosts are never named (the host rule would refuse it)"
    assert dv.check(dv.fallback(f), f, portal_url="https://prodexsentry.netlify.app") == []
    # no block page on the sheet: no "opposite" line
    f2 = dv.facts(_model() | {"ticket": []}, still_open=_still())
    s1b = [it for it in f2["items"] if it["section"] == "still"][0]
    assert "hosts above" not in s1b["why"] and dv.THE_PROBE in s1b["why"] and "go straight through" in s1b["why"], "alone, the firewall item explains the probes itself"
    assert dv.fallback(f2)["still_open"][0]["text"] == "[Moderate-high] A web firewall is there, but it's only watching on bitec, demo and highcom."
    # the writer's instructions carry his profile's words and the approved morning
    assert "He dictates." in dv.SYSTEM and "Here's your morning briefing." in dv.SYSTEM and "THE EMAIL HE APPROVED" in dv.SYSTEM
    assert 'never "Short version:"' in dv.SYSTEM
    assert "Do not invent folksy idioms" in dv.SYSTEM and "firewalls in opposite states" in dv.SYSTEM


def test_the_second_test_send_refusals_are_allowed_now():
    """Test send 2 (10-27 15:25, run #18): the writer said "two" about the headers item and
    was refused ("a number that is not its own (2)"), and it put the email ids c1, c2 into
    slack.changed. The count of names a title lists is the item's own; the prompt names the
    ids per list."""
    f = _facts()
    n1 = [it for it in f["items"] if it["section"] == "slack_nudge"][0]
    assert n1["what"].startswith("Security headers missing: Content-Security-Policy, Strict-Transport-Security")
    assert "2" in n1["numbers"], "two names after the colon"
    o = _good(f)
    o["slack"]["nudge"][0]["text"] = "[Moderate] Two security headers are missing on prodexlabs.com and cooked, Strict-Transport-Security and Content-Security-Policy. A couple of lines of server config."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == []
    prompt = dv._prompt(f, "")
    assert "WHICH IDS GO IN WHICH LIST" in prompt and "slack.changed: ['k1']" in prompt and "slack.nudge: ['n1']" in prompt and "email: ['c1', 'c2']" in prompt
    # an item with detail lines may count them
    c1 = f["items"][0]
    assert str(len(c1["detail"])) in c1["numbers"]


def test_a_slack_line_says_its_grade():
    """Howie 15:38: "you should identify if it's a medium, informational, or a low." Every
    Slack line about a graded finding carries its own severity word; a quiet host has none."""
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "Two security headers are missing on prodexlabs.com and cooked. A couple of lines of server config."}),
             "does not say its severity (Moderate)")
    _refused(lambda o: o["slack"]["nudge"].__setitem__(0, {"id": "n1", "text": "[Low] Two security headers are missing on prodexlabs.com and cooked."}),
             "severity word 'low' is not its own")
    f = _facts()
    fb = dv.fallback(f)
    assert fb["slack"]["nudge"][0]["text"].startswith("[Moderate] Security headers missing")
    assert fb["slack"]["changed"][0]["text"].startswith("valorep"), "a quiet host carries no grade"
    assert dv.check(fb, f, portal_url="https://prodexsentry.netlify.app") == []
    assert "severity word in brackets" in dv.SYSTEM


def test_the_rules_say_every_host_is_named_even_in_one_sentence():
    """Run #19 (10-27 16:24): told to keep a nudge to one sentence, the writer named one of
    five sites and the check refused the day. The rule is now in so many words."""
    assert "EVERY entry names EVERY host" in dv.SYSTEM and 'never "five of our sites"' in dv.SYSTEM
    assert "MORE than six hosts: name the first six" in dv.SYSTEM


def test_a_nudge_is_one_graded_line_and_a_long_host_list_is_six_and_n_more():
    """Howie 16:32: "way too wordy ... you didn't tell us what level of severity this is";
    16:30: twenty hosts in one breath. A nudge or a still line: '[Grade] what on hosts.',
    under 240 characters; more than six hosts is six names and 'and N more'."""
    f = _facts()
    o = _good(f)
    o["still_open"][0]["text"] = "The firewall in front of bitec, demo and highcom is only watching, not blocking."
    assert any("does not say its severity (Moderate-high)" in p for p in dv.check(o, f, portal_url="https://prodexsentry.netlify.app"))
    o = _good(f)
    o["slack"]["nudge"][0]["text"] = "[Moderate] " + "Two security headers are missing on prodexlabs.com and cooked, " * 4 + "and that is a lot of words."
    assert any("too long" in p for p in dv.check(o, f, portal_url="https://prodexsentry.netlify.app"))
    # twenty hosts: six names and "and 14 more"
    hosts = [f"h{i}.prodexlabs.com" for i in range(20)]
    it = dv._item("n9", "slack_nudge", "nudge", "MODERATE-HIGH", hosts, "Compressed pages could leak a secret (BREACH)", "", "", "", dates_allowed=False)
    assert dv._hosts_words(hosts) == "h0, h1, h2, h3, h4, h5 and 14 more"
    line = dv._para(it)
    assert line == "[Moderate-high] Compressed pages could leak a secret (BREACH) on h0, h1, h2, h3, h4, h5 and 14 more." and len(line) < 240
    assert dv._entry_problems({"id": "n9", "text": line}, it, "slack.nudge", "") == []
    bad = "[Moderate-high] Compressed pages could leak a secret (BREACH) on h0, h1 and 18 more."
    assert any("name 6 and say 'and 14 more'" in p for p in dv._entry_problems({"id": "n9", "text": bad}, it, "slack.nudge", ""))
    bad2 = "[Moderate-high] Compressed pages could leak a secret (BREACH) on h0, h1, h2, h3, h4, h5 and some others."
    assert any("name 6 and say 'and 14 more'" in p for p in dv._entry_problems({"id": "n9", "text": bad2}, it, "slack.nudge", ""))
    assert dv._closing(0) == "" and dv._closing(1).startswith("It isn't urgent.") and dv._closing(2).startswith("Neither one") and dv._closing(3).startswith("None of these is urgent.")


# ── round 5, Howie 17:43 and 17:53: the grade as a pill, a host name in bold, everywhere ──
def test_the_still_rows_carry_the_grade_as_a_pill_from_the_facts_not_the_words():
    f = _facts(); m = _model(); out = _good(f)
    html = dv.render_html(out, f, brand=BRAND, logo_cid=dd.LOGO_CID, local_end=m["local_end"],
                          portal_url="https://prodexsentry.netlify.app", product_name="PRODEXsentry")
    assert "[Moderate-high]" not in html                     # the bracket is gone from the line
    ink, tint = dv.GRADE_COLORS["Moderate-high"]
    assert f'background:{tint}' in html and f'color:{ink}' in html and '>Moderate-high</span>' in html
    assert 'border-radius:999px' in html                     # it is a pill
    assert 'text-transform:uppercase' not in html.split("Still sitting there")[0][-400:]
    # the word on the pill is the item's own, whatever the writer wrote
    assert dv.split_grade("[moderate high] x on a.") == ("Moderate-high", "x on a.")
    assert dv.split_grade("no grade here.") == ("", "no grade here.")
    assert dv.grade_pill("") == ""
    # a quiet host has no grade: its row has no empty pill cell
    assert 'colspan="2"' in dv.grade_row("", "quiet line", first=True)
    assert 'colspan="2"' not in dv.grade_row("Low", "x", first=True)
    assert "border-top:1px solid" not in dv.grade_row("Low", "x", first=True)
    assert "border-top:1px solid" in dv.grade_row("Low", "x", first=False)


def test_a_host_name_is_bold_wherever_it_appears_full_or_short_and_never_inside_a_longer_one():
    f = _facts(); m = _model(); out = _good(f)
    html = dv.render_html(out, f, brand=BRAND, logo_cid=dd.LOGO_CID, local_end=m["local_end"],
                          portal_url="https://prodexsentry.netlify.app", product_name="PRODEXsentry")
    b = '<span style="font-weight:600;">'
    assert b + "valorep.prodexlabs.com</span>" in html        # the opening paragraph, full name
    for short in ("l3h-ss", "prod", "l3h-nh", "l3h-ivs", "bitec", "demo", "highcom"):
        assert b + short + "</span>" in html                    # the block-page and firewall lines, short names
    assert b + "prod</span>.prodexlabs" not in html             # never a short name inside the long one
    assert html.count("<span style=\"font-weight:600;\"><span") == 0
    # a short name that ends a sentence is still bold; 'prod' inside 'production' is not
    hosts = ["prod.prodexlabs.com", "cooked.prodexlabs.com"]
    assert dv.mark_hosts("missing on prod and cooked.", hosts) == f"missing on {b}prod</span> and {b}cooked</span>."
    assert dv.mark_hosts("the production box", hosts) == "the production box"
    assert dv.mark_hosts("Prod.prodexlabs.com is up", hosts) == f"{b}Prod.prodexlabs.com</span> is up"
    assert dv.all_hosts(f) == sorted({h for it in f["items"] for h in it["hosts"]})


# ── Howie 18:15/18:22: plain, how we talk; never the scanner's mechanics; no run-ons ──────
def test_a_run_on_sentence_and_scanner_mechanics_are_refused():
    f = _facts()
    long = ("Sentry sent one plain request and then three attack-shaped ones, a SQL injection, a script injection and a "
            "give-me-a-file-off-your-disk trick, and both hosts turned the attack-shaped ones away with a block page Sentry "
            "doesn't recognize yet.")
    assert len(long.split()) == 36
    _refused(lambda o: o["email"].__setitem__(1, {"id": "c2", "text": "l3h-ss, prod, l3h-nh and l3h-ivs are new. " + long}),
             "a sentence of 36 words")
    _refused(lambda o: o["email"].__setitem__(1, {"id": "c2", "text": "l3h-ss, prod, l3h-nh and l3h-ivs turned away our test traffic, which is good."}),
             "banned word: 'test traffic'")
    _refused(lambda o: o["email"].__setitem__(0, {"id": "c1", "text": "valorep.prodexlabs.com looks down since Oct 22 and its name doesn't resolve anymore. It drops off the portal on Nov 2."}),
             "banned word: 'resolve'")
    _refused(lambda o: o["opening"].__setitem__ if False else o.__setitem__("opening", "Here's your morning briefing. our DNS is fine and one box looks down."),
             "banned word: 'dns'")
    # 32 words is the cap for the writer; the fallback and the careful answer sit well under it
    o = _good(f)
    o["opening"] = dv.OPENER + " " + " ".join(["word"] * 32) + "."
    assert dv.check(o, f, portal_url="https://prodexsentry.netlify.app") == []
    o["opening"] = dv.OPENER + " " + " ".join(["word"] * 33) + "."
    assert any(p.startswith("a sentence of 33 words") for p in dv.check(o, f, portal_url="https://prodexsentry.netlify.app"))
    fb = dv.fallback(f)
    for e in fb["email"] + fb["still_open"] + fb["slack"]["changed"] + fb["slack"]["nudge"]:
        for sent in e["text"].split(". "):
            assert len(sent.split()) <= 30, sent
    assert dv._plain_block("l3h-ss.prodexlabs.com: On Oct 27 it turned away the attack-style test strings with a page no vendor the block-page library knows (no page captured).") == \
        "l3h-ss.prodexlabs.com: started blocking the probes on Oct 27."
    assert dv._plain_block("x.prodexlabs.com: something else") == "x.prodexlabs.com: started blocking the probes."
    # the slack half's quiet-host item carries the same plain lines, and the fallback's line is Howie's
    k1 = [it for it in f["items"] if it["section"] == "slack_changed"][0]
    assert k1["detail"] == ["valorep.prodexlabs.com: looks down since Oct 22. Drops off the portal on Nov 2 if it stays down."]
    assert fb["slack"]["changed"][0]["text"].startswith("valorep.prodexlabs.com looks like it's been down since Oct 22.")


def test_the_email_opens_with_the_morning_briefing_line_and_new_boxes_are_the_only_new_thing():
    """Howie 18:33: "you don't say 'short version.' You can say, 'Here's your morning briefing.'"
    and "Did these boxes not exist before? ... say something like 'There are some new boxes
    that have joined our fleet'" (only for the item that IS new boxes)."""
    f = _facts()
    _refused(lambda o: o.__setitem__("opening", "Morning. Short version: one box looks down."), "banned word: 'short version'")
    _refused(lambda o: o.__setitem__("opening", "Morning. One box looks down."), "opening: does not start with \"Here's your morning briefing.\"")
    for n in (0, 1, 2):
        m = _model()
        m["do"], m["ticket"] = m["do"][:n], ([] if n < 2 else m["ticket"])
        fb = dv.fallback(dv.facts(m))
        assert fb["opening"].startswith("Here's your morning briefing. "), fb["opening"]
        assert "Short version" not in fb["opening"]
    m = _model()
    m["ticket"].append({"kind": "assets", "severity": "", "title": "2 new hosts found", "sites": [], "why": "", "do": "", "tag": "",
                        "lines": ["a.prodexlabs.com: first seen Oct 27, not rated yet", "b.prodexlabs.com: first seen Oct 27, rated moderate"]})
    f2 = dv.facts(m)
    new = [it for it in f2["items"] if it["kind"] == "assets"][0]
    assert new["hosts"] == ["a.prodexlabs.com", "b.prodexlabs.com"] and "joined our fleet" in new["why"]
    assert dv._para(new) == "Some new boxes have joined our fleet: a and b. They get the same checks as everything else from here on."
    assert dv._para(dict(new, hosts=new["hosts"][:1])) == "A new box has joined our fleet: a.prodexlabs.com. It gets the same checks as everything else from here on."
    assert dv.check(dv.fallback(f2), f2, portal_url="https://prodexsentry.netlify.app") == []
    assert '"N new hosts found" is about new boxes' in dv.SYSTEM
