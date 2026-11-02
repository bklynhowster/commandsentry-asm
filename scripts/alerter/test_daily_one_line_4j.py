"""(KB 12 job 4j, 2026-11-02) The daily: one bad line never sinks the morning, and wording never
refuses anything.

Howie, 07:43: "in terms of the daily for Prodex, we went to the backup again on Slack. Something
is wrong." 09:39: "This bit with the language causing the failures is absolutely ridiculous. You
know what these messages are supposed to be."

That morning (digest_pending 10, Prodex) the writer's draft was fine apart from its Slack
sign-off, "Much obliged, everyone, have a good Monday." Any weekday counted as a date; that
problem had no line label, so repair() could not swap it, and the whole email and Slack post went
to the backup, over a sign-off the post would never have shown (digest_slack.payload shows the
closing only under "Still sitting there", and that morning had none).

Each rule is SEEN failing on the old shape before it is seen passing.
"""
from __future__ import annotations

import copy
import inspect
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_slack as ds  # noqa: E402
import digest_voice as dv  # noqa: E402
import run_alerter as ra  # noqa: E402
from test_digest_voice import _good, _model, _slack, _still  # noqa: E402

PORTAL = "https://prodexsentry.netlify.app"
MONDAY = "Monday, November 2"


def _facts(day=MONDAY, nudge=True):
    sl = _slack()
    if not nudge:
        sl = {"changed": sl["changed"], "nudge": []}
    return dv.facts(_model(), still_open=_still(), slack=sl, company="Prodex", day=day)


def _answer(f):
    """_good()'s careful answer; on a day with no nudge, the same answer without one (the
    sheet numbers the other items the same way)."""
    if dv.required_ids(f)["slack_nudge"]:
        return _good(f)
    o = _good(_facts(day=f["day"], nudge=True))
    o["slack"]["nudge"] = []
    return o


def test_the_morning_of_nov_2_now_goes_out_as_the_writer_wrote_it():
    f = _facts(nudge=False)
    o = _answer(f)
    o["slack"]["closing"] = "Much obliged, everyone, have a good Monday."
    # the old shape: a weekday anywhere in the closing refused, with no line label
    assert "slack: a date in the nudge or the closing" not in inspect.getsource(dv)
    out, replaced, filled, dropped, wording, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and replaced == [] and filled == [] and dropped == []
    assert out["slack"]["closing"] == "", "the post never shows a sign-off on a day with no nudge, so it is not kept"
    for k in ("subject", "headline", "opening", "email", "fixed", "still_open"):
        assert out[k] == o[k], k
    assert out["slack"]["changed"] == o["slack"]["changed"]
    p = ds.payload(out, {"changed": [], "nudge": []}, product_name="PRODEXsentry", day_label=MONDAY)
    assert "Much obliged" not in str(p)


def test_the_sign_off_may_name_today_but_not_another_day():
    f = _facts()                                    # a nudge, so the sign-off is shown
    o = _answer(f)
    o["slack"]["closing"] = "Much obliged, everyone, have a good Monday."
    out, replaced, *_rest, refused = dv.settle(o, f, portal_url=PORTAL)
    assert refused == [] and out["slack"]["closing"] == "Much obliged, everyone, have a good Monday."
    o["slack"]["closing"] = "That's it for Nov 2, have a good one."
    assert dv.settle(o, f, portal_url=PORTAL)[-1] == [], "today's date is the day's own too"
    o["slack"]["closing"] = "Talk again Nov 3, have a good one."
    assert dv.settle(o, f, portal_url=PORTAL)[-1] == ["slack.closing: a date that is not today's (Nov 3)"]
    o["slack"]["closing"] = "Much obliged, everyone, have a good Friday."
    probs = dv.check(o, f, portal_url=PORTAL)
    assert "slack.closing: a date that is not today's (Friday)" in probs
    out, replaced, *_rest, refused = dv.settle(o, f, portal_url=PORTAL)
    assert [r[0] for r in replaced] == ["slack.closing"], "the wrong day is a fact: that line alone"
    assert out["slack"]["closing"] == dv.fallback(f)["slack"]["closing"]
    assert out["email"] == o["email"] and out["opening"] == o["opening"], "the rest stays the writer's"
    assert dv.plain_reasons(replaced, f)[0].startswith("The Slack closing: it names a day that is not today.")


def test_wording_is_logged_and_never_refuses_anything():
    f = _facts()
    o = _answer(f)
    o["opening"] = "Short version: one of our boxes went quiet — that's the only real news today."   # no opener, em dash, banned
    o["headline"] = "One box went quiet, and it's on us to keep an eye on it."                           # 'on us'
    long_ = " ".join(["word"] * 50) + "."
    o["email"][0]["text"] += " " + long_                                                                 # a 50-word sentence
    o["still_open"][0]["text"] = o["still_open"][0]["text"] + " " + "x" * 260                           # over 240 characters
    o["slack"]["nudge"][0]["text"] = ("[Moderate] Two security headers are missing on prodexlabs.com and cooked, "
                                      "open for weeks, a couple of lines of server config.")             # a 'how long'
    probs = dv.check(o, f, portal_url=PORTAL)
    assert any("banned word: 'short version'" in p for p in probs) and any("'on us'" in p for p in probs)
    assert any("a sentence of " in p for p in probs) and any("too long" in p for p in probs)
    assert any("a nudge says how long" in p for p in probs)
    assert dv.blocking(probs) == [], dv.blocking(probs)
    out, replaced, filled, dropped, wording, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and replaced == [] and filled == []
    assert out["opening"].startswith(dv.OPENER + " Short version: one of our boxes went quiet, that's"), out["opening"]
    assert "—" not in str(out)
    assert out["headline"] == o["headline"] and out["email"] == o["email"] and out["slack"]["nudge"] == o["slack"]["nudge"]
    assert wording and all(w in probs for w in wording)
    # the briefing line without its period is not added twice (code review minor 4)
    o2 = _answer(f)
    o2["opening"] = "Here's your morning briefing: one of our boxes went quiet."
    out2 = dv.settle(o2, f, portal_url=PORTAL)[0]
    assert out2["opening"] == "Here's your morning briefing: one of our boxes went quiet."


def test_a_date_in_a_nudge_is_a_fact_and_swaps_that_line_alone():
    """Code review 2026-11-02, must-fix 1: the sheet gives a nudge no dates (facts(),
    dates_allowed=False), so a date there is one it cannot vouch for: that line is set aside,
    the rest of the morning stays the writer's. The real path, through settle()."""
    f = _facts()
    assert [it["dates"] for it in f["items"] if it["section"] == "slack_nudge"] == [[]]
    o = _answer(f)
    o["slack"]["nudge"][0]["text"] = ("[Moderate] Two security headers are missing on prodexlabs.com and cooked, "
                                      "open since Oct 22.")
    probs = dv.check(o, f, portal_url=PORTAL)
    assert "a date in a nudge" not in " ".join(probs), "no separate wording rule for it"
    out, replaced, filled, dropped, wording, refused = dv.settle(o, f, portal_url=PORTAL)
    assert refused == ["slack.nudge n1: a date that is not its own (Oct 22)"], refused
    assert wording == ["slack.nudge n1: a nudge says how long"], wording
    assert out is not None and [r[0] for r in replaced] == ["slack.nudge n1"]
    assert out["slack"]["nudge"][0]["text"] == dv.fallback(f)["slack"]["nudge"][0]["text"]
    for k in ("subject", "headline", "opening", "email", "fixed", "still_open"):
        assert out[k] == o[k], k


def test_vulnerable_still_sets_its_line_aside_and_only_its_line():
    f = _facts()
    o = _answer(f)
    o["still_open"][0]["text"] = "[Moderate-high] The firewall in front of bitec, demo and highcom is vulnerable."
    out, replaced, *_rest, refused = dv.settle(o, f, portal_url=PORTAL)
    assert refused == ["still_open s1: banned word: 'vulnerable'"], refused
    assert [r[0] for r in replaced] == ["still_open s1"]
    assert out["still_open"][0]["text"] == dv.fallback(f)["still_open"][0]["text"]
    assert out["email"] == o["email"] and out["headline"] == o["headline"]
    # a wording slip elsewhere in the same answer does not stop the swap (repair() judges the
    # swapped answer on the facts only)
    o["email"][0]["text"] += " " + " ".join(["word"] * 50) + "."
    out, replaced, *_rest, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and [r[0] for r in replaced] == ["still_open s1"] and out["email"] == o["email"]


def test_a_fact_a_line_gets_wrong_sets_aside_that_line_alone():
    f = _facts()
    for mutate, label in (
            (lambda o: o["email"][0].__setitem__("text", o["email"][0]["text"].replace("valorep.prodexlabs.com", "cooked.prodexlabs.com")), "email c1"),
            (lambda o: o["email"][0].__setitem__("text", o["email"][0]["text"] + " Same story on cooked.prodexlabs.com."), "email c1"),
            (lambda o: o["email"][0].__setitem__("text", o["email"][0]["text"].replace("Oct 22", "Oct 12")), "email c1"),
            (lambda o: o.__setitem__("headline", "Nine boxes went quiet."), "headline"),
            (lambda o: o["slack"]["nudge"][0].__setitem__("text", "[High] Two security headers are missing on prodexlabs.com and cooked."), "slack.nudge n1"),
            (lambda o: o["email"][0].__setitem__("text", o["email"][0]["text"] + " See https://evil.example.net/x."), "email c1")):
        o = _answer(f)
        mutate(o)
        out, replaced, *_rest, refused = dv.settle(o, f, portal_url=PORTAL)
        assert refused, label
        assert out is not None and sorted({r[0] for r in replaced}) == [label], (label, replaced)
        assert out["opening"] == o["opening"], "everything else stays the writer's"


def test_a_missing_or_misplaced_entry_never_sinks_the_morning():
    f = _facts()
    base = _answer(f)
    # (a) an entry for an item that does not exist: dropped
    o = copy.deepcopy(base); o["email"].append({"id": "zz", "text": "Something about nothing."})
    assert any("unknown item id" in p for p in dv.check(o, f, portal_url=PORTAL)), "the old shape refused"
    out, replaced, filled, dropped, _w, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and filled == [] and dropped == ["email zz"]
    assert out["email"] == base["email"]
    # (b) an item the writer left out: the backup's line there, the rest the writer's
    o = copy.deepcopy(base); del o["email"][0]
    out, replaced, filled, dropped, _w, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and filled == [("email c1", "missing")]
    assert out["email"][0] == dv.fallback(f)["email"][0] and out["email"][1:] == base["email"][1:]
    assert [e["id"] for e in out["email"]] == dv.required_ids(f)["email"], "the sheet's order"
    # (c) a still item put in the Slack nudge list (10-29 rerun): dropped there, the nudge filled
    o = copy.deepcopy(base); o["slack"]["nudge"] = [{"id": "s1", "text": "x"}]
    out, replaced, filled, dropped, _w, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and dropped == ["slack.nudge s1"]
    assert filled == [("slack.nudge n1", "missing")] and out["still_open"] == base["still_open"]
    # (d) the same item twice: the first one kept
    o = copy.deepcopy(base); o["email"].insert(1, dict(o["email"][0], text="A second take."))
    out, *_r = dv.settle(o, f, portal_url=PORTAL)
    assert out["email"] == base["email"]
    # (e) a list that is not a list, and a free line that is not text
    o = copy.deepcopy(base); o["fixed"] = "nothing"; o["headline"] = ["?"]
    out, replaced, filled, dropped, _w, refused = dv.settle(o, f, portal_url=PORTAL)
    assert out is not None and refused == [] and ("headline", "not text") in filled
    assert out["headline"] == dv.fallback(f)["headline"] and out["opening"] == base["opening"]
    # (f) not an object at all: the whole backup, as before
    assert dv.settle(["?"], f, portal_url=PORTAL)[0] is None


def test_the_backup_says_today_on_the_day_itself():
    f_before = _facts(day="Tuesday, October 27")
    f_day = _facts(day=MONDAY)
    assert dv._today(f_day) == "Nov 2" and dv._today(f_before) == "Oct 27" and dv._today({"day": ""}) == ""
    before = dv.fallback(f_before)["email"][0]["text"]
    day = dv.fallback(f_day)["email"][0]["text"]
    assert "If it doesn't come back by Nov 2," in before
    assert "If it doesn't come back today," in day and "by Nov 2" not in day, day
    for f in (f_before, f_day, _facts(nudge=False)):
        assert dv.blocking(dv.check(dv.fallback(f), f, portal_url=PORTAL)) == [], "the backup passes its own facts"


def test_the_sender_uses_settle_and_judges_the_backup_on_facts_only():
    src = inspect.getsource(ra.main)
    assert "_dv.settle(raw, fct, portal_url=portal_url)" in src
    assert "_dv.check(out, fct, portal_url=portal_url)\n" not in src.replace("_dv.blocking(_dv.check(out, fct, portal_url=portal_url))", "")
    assert '"filled": [lb for lb, _w in filled], "wording": wording[:6]' in src
    rsrc = inspect.getsource(dv.repair)
    assert "blocking(check(out2, f, portal_url=portal_url))" in rsrc
