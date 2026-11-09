"""(KB 12 job 4x, 2026-11-05) The daily tells Command only what is theirs, once.

Howie, 07:26: "I'm really not happy with the email digest that's supposed to go to Command
today." 07:29: "We need to kill this repetitiveness ... we would give a reminder after a
certain amount of time. That has to happen." / "We're not telling people that our own product
isn't working right." 08:25: "Agree, proceed." Plan: KB wrap-up 2026-11-05 0827 (4x).

Pinned here: with an approver, Sentry's own gaps (lost sight, the reachability checks stopped,
the inventory tripwire) go to model["ours"] and the approver's strip only, never the others'
email, its subject or its headline, daily and weekly; without one they stay where they were;
a silent host's record key; the stale line's words (one bracket, a host silent for months says
so); the send path's wiring; and 11-05's own email replayed (test_differ.py's sibling: the
before and after Howie saw).
"""
from __future__ import annotations

import inspect
import os
import sys
from datetime import date, datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import approval as ap  # noqa: E402
import digest_daily as dd  # noqa: E402
import digest_weekly as dw  # noqa: E402
import run_alerter as ra  # noqa: E402
import told as told_rule  # noqa: E402

UTC = timezone.utc
W0 = datetime(2026, 11, 4, 12, 11, tzinfo=UTC)
W1 = datetime(2026, 11, 5, 12, 11, tzinfo=UTC)          # Thursday, 7:11 AM ET
BRAND = dict(dd.DEFAULT_BRAND, short_name="Command")

# 11-05's own inputs (read 07:15-07:40 from digest_pending id 11 and the asset rows)
NS02 = ("ns02.sciimage.com", datetime(2026, 11, 3, 18, 47, tzinfo=UTC), None, 41.0, None,
        True, False, False, "discovery", True, datetime(2026, 7, 24, 20, 27, tzinfo=UTC))
TEST_NAME = ("test.commandcommcentral.com", datetime(2026, 11, 4, 0, 25, tzinfo=UTC), "no_answer",
             datetime(2026, 11, 4, 12, 0, tzinfo=UTC), datetime(2026, 11, 11, 12, 0, tzinfo=UTC))
TEST_ADDR = ("52.119.65.6",) + TEST_NAME[1:]
WHERE = ra.quiet_where_map([
    ("52.119.65.6", None, ["test.commandcommcentral.com"], "Natural Wireless, LLC", "6.65.119.52.naturalwireless.com"),
    ("test.commandcommcentral.com", ["52.119.65.6"], None, None, None),
])
CSP = ("insite.sciimage.com:light:csp-scripts-not-limited", "insite.sciimage.com",
       "Content-Security-Policy does not limit scripts", "MODERATE", "detected", "commandsentry_light", W1)
CANARY = [("www.commandcompanies.com", "MISSING", "MISSING", None)]
STOPPED = (False, datetime(2026, 11, 4, 2, 0, tzinfo=UTC))


def model(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              baseline={}, brand=BRAND, stale_words=ra.stale_row_words, stale_intro=ra.STALE_INTRO,
              stale_note=ra.stale_overdue_note(24, 192))
    kw.update(over)
    return dd.build_model(**kw)


def rendered(m):
    return (dd.subject(m, "COMMANDsentry"), dd.render_html(m, portal_url="https://p.example", product_name="COMMANDsentry"),
            dd.render_text(m, portal_url="https://p.example", product_name="COMMANDsentry"))


# ── Sentry's own gaps: the approver only ──────────────────────────────────────────────
def test_with_an_approver_our_gaps_never_reach_the_others():
    for over in (dict(stale_assets=[NS02]), dict(canary_violations=CANARY), dict(reach_checks=STOPPED),
                 dict(stale_assets=[NS02], canary_violations=CANARY, reach_checks=STOPPED)):
        m = model(gaps_to_approver=True, **over)
        assert m["do"] == [] and m["ours"] and all(i["kind"] == "coverage" for i in m["ours"]), over
        assert m["degraded"] is False and m["headline"].startswith("Nothing new since ")
        subj, html, text = rendered(m)
        assert "(!)" not in subj and "Coverage gap" not in subj
        for out in (html, text):
            assert "lost sight" not in out and "reachability checks" not in out
            assert "gap in our own checking" not in out.lower() and "ns02" not in out and "MISSING" not in out


def test_without_an_approver_nothing_is_lost():
    """No approver (a dry run, a test send, an instance with nobody to approve): as before."""
    m = model(stale_assets=[NS02])
    assert m["ours"] == [] and [i["kind"] for i in m["do"]] == ["coverage"] and m["degraded"] is True
    subj, html, text = rendered(m)
    assert "(!) Coverage gap." in subj and "Sentry lost sight of 1 host" in html and "ns02.sciimage.com" in text


def test_the_approver_sees_them_in_his_strip_and_the_others_copy_is_untouched():
    m = model(gaps_to_approver=True, stale_assets=[NS02], reach_checks=STOPPED)
    notes = ra.ours_notes(m["ours"])
    assert notes[0].startswith("Sentry's own, for you only: Sentry lost sight of 1 host. Sentry looks for every host")
    assert notes[1].startswith("- ns02.sciimage.com: last seen Nov 3")
    assert notes[2].startswith("Overdue means: ")
    assert notes[3].startswith("Sentry's own, for you only: Sentry's reachability checks have stopped. A gap in our own")
    assert len(notes) == 4
    subj, html, text = rendered(m)
    a_subj, a_html, a_text = ap.approver_copy(subj, html, text, url="https://p.example/digest/approve#t",
                                              others=["a@x.example"], kind="daily", notes=notes)
    assert "ns02.sciimage.com" in a_html and "ns02.sciimage.com" in a_text
    assert "ns02.sciimage.com" not in html and "ns02.sciimage.com" not in text      # what the others get
    assert ra.ours_notes([]) == [] and ra.ours_notes(None) == []


# Code review 2026-11-05 10:17, must-fix 1: the whole card reaches the approver, not the title
# and three lines: its explanation, its note, every host, in HTML and text, daily and weekly.
FOUR = [NS02] + [(f"h{i}.sciimage.com",) + NS02[1:] for i in range(3)]
WHOLE = ("Until it closes, they get no new findings.", "Overdue means:", "h2.sciimage.com",
         "Until they run again, no host is marked not responding and none leaves the portal.")


def _approver_and_others(subj, html, text, notes, kind):
    a = ap.approver_copy(subj, html, text, url="https://p.example/digest/approve#t",
                         others=["a@x.example"], kind=kind, notes=notes)
    return a[1], a[2], html, text


def test_the_approvers_strip_carries_the_whole_card_daily():
    m = model(gaps_to_approver=True, stale_assets=FOUR, reach_checks=STOPPED)
    notes = ra.ours_notes(m["ours"])
    assert sum(n.startswith("- ") for n in notes) == 4
    subj, html, text = rendered(m)
    a_html, a_text, o_html, o_text = _approver_and_others(subj, html, text, notes, "daily")
    for words in WHOLE:
        assert words in a_html and words in a_text, words
        assert words not in o_html and words not in o_text, words


def test_the_approvers_strip_carries_the_whole_card_weekly():
    now = datetime(2026, 11, 9, 12, 20, tzinfo=UTC)
    s, e, days = dw.week_window(now, BRAND)
    gated = dw.build_weekly(now=now, window_start=s, window_end=e, days=days, sites=[], opened=[], closed=[],
                            scans=[(date(2026, 11, 3), "heavy", 3)], brand=BRAND, stale_assets=FOUR,
                            canary_violations=CANARY, stale_words=ra.stale_row_words, stale_intro=ra.STALE_INTRO,
                            stale_note=ra.stale_overdue_note(24, 192), gaps_to_approver=True)
    notes = ra.ours_notes(gated["ours"])
    subj = dw.weekly_subject(gated, "COMMANDsentry")
    html = dw.render_weekly_html(gated, portal_url="https://p.example", product_name="COMMANDsentry")
    text = dw.render_weekly_text(gated, portal_url="https://p.example", product_name="COMMANDsentry")
    a_html, a_text, o_html, o_text = _approver_and_others(subj, html, text, notes, "weekly")
    # the weekly has no checks-stopped card (that is the daily's); the tripwire's line instead
    for words in WHOLE[:3] + ("www.commandcompanies.com: expected live and ours",):
        assert words in a_html and words in a_text, words
        assert words not in o_html and words not in o_text, words


def test_the_weekly_too():
    now = datetime(2026, 11, 9, 12, 20, tzinfo=UTC)
    s, e, days = dw.week_window(now, BRAND)
    kw = dict(now=now, window_start=s, window_end=e, days=days, sites=[], opened=[], closed=[],
              scans=[(date(2026, 11, 3), "heavy", 3)], brand=BRAND, stale_assets=[NS02],
              stale_words=ra.stale_row_words, stale_intro=ra.STALE_INTRO, stale_note=ra.stale_overdue_note(24, 192))
    gated = dw.build_weekly(gaps_to_approver=True, **kw)
    assert gated["do"] == [] and gated["ours"] and gated["degraded"] is False
    subj = dw.weekly_subject(gated, "COMMANDsentry")
    html = dw.render_weekly_html(gated, portal_url="https://p.example", product_name="COMMANDsentry")
    text = dw.render_weekly_text(gated, portal_url="https://p.example", product_name="COMMANDsentry")
    assert "(!)" not in subj and "lost sight" not in html and "lost sight" not in text and "ns02" not in html
    plain = dw.build_weekly(**kw)
    assert plain["ours"] == [] and plain["degraded"] is True
    assert "(!) Coverage gap." in dw.weekly_subject(plain, "COMMANDsentry")


# ── the words ────────────────────────────────────────────────────────────────────────
def test_the_stale_line_has_one_bracket_and_says_when_a_host_went_silent_long_ago():
    m = model(stale_assets=[NS02])
    line = m["do"][0]["lines"][0]
    assert line == ("ns02.sciimage.com: last seen Nov 3 (41 hours ago), overdue; Sentry's checks have had no answer from it since Jul 24; "
                    "not given full scans on purpose: it isn't a website")
    assert ") (" not in line
    # silent for less than a month before it was last seen: nothing about it
    recent = NS02[:10] + (datetime(2026, 10, 20, tzinfo=UTC),)
    assert "no answer from it since" not in " ".join(ra.stale_row_words(recent))
    # a month or more: exactly 30 days counts, a minute less does not (code review 10:17, minor 3)
    month = NS02[:10] + (NS02[1] - timedelta(days=30),)
    assert "no answer from it since Oct 4" in " ".join(ra.stale_row_words(month))
    almost = NS02[:10] + (NS02[1] - timedelta(days=30) + timedelta(minutes=1),)
    assert "no answer from it since" not in " ".join(ra.stale_row_words(almost))
    # older row shapes (no column 10) still render
    assert ra.stale_row_words(NS02[:10])[1] == "last seen Nov 3 (41 hours ago)"


def test_the_stale_read_carries_last_alive_at_as_column_10():
    sql = " ".join(ra.SQL_STALE_LIVE_ASSETS.split())
    select = sql.split("SELECT f.asset_id,", 1)[1].split(" FROM f ", 1)[0]
    assert select.strip().endswith("f.seen_via, f.skipped, f.last_alive_at")
    assert "a.last_alive_at," in sql


def test_a_silent_hosts_record_has_its_own_key_and_carries_its_reason():
    assert told_rule.quiet_key("x.example") == "host-quiet:x.example"
    told = {"host-quiet:x.example": {"last_full_at": W0, "last_full_severity": "NO_ANSWER"}}
    assert told_rule.decide_quiet("x.example", "no_answer", told, W1) == ("quiet", None)
    assert told_rule.decide_quiet("x.example", "name_gone", told, W1) == ("full", "changed")
    assert told_rule.decide_quiet("y.example", "no_answer", told, W1) == ("full", "new")
    assert told_rule.decide_quiet("x.example", "no_answer", told, W0 + timedelta(days=30)) == ("full", "due")
    # the closed-marker joins findings, so it can never touch a host's row
    assert "JOIN public.findings" in ra.SQL_TOLD_MARK_CLOSED or "FROM public.findings f" in ra.SQL_TOLD_MARK_CLOSED


# ── the send path ────────────────────────────────────────────────────────────────────
def test_the_send_path_is_wired():
    src = inspect.getsource(ra.main)
    assert "reach_checks=reach_checks, quiet_where=quiet_where, gaps_to_approver=gate," in src
    assert "if gate:\n            notes += ours_notes(sentry_only)" in src
    assert "if not gate:      # gated: already in `notes` above (job 4x)" in src
    assert src.count("ours_notes(sentry_only)") == 2
    assert "gaps_to_approver=gaps_to_approver" in inspect.getsource(ra._digest_model)
    wk = inspect.getsource(ra._run_weekly)
    assert "_weekly_model(conn, now=now, brand=brand, gaps_to_approver=gate)" in wk
    assert "notes=ours_notes(model.get(\"ours\"))" in wk
    assert "gaps_to_approver=gaps_to_approver" in inspect.getsource(ra._weekly_model)


# ── 11-05's own email, replayed ──────────────────────────────────────────────────────
def test_the_email_held_on_nov_5_reads_as_planned():
    """Before: '[COMMANDsentry] (!) Coverage gap. Command, Thursday: 2 for today, 1 this week'
    with ns02 and the test host under Needs you today. After: two things for this week."""
    before = model(new_findings=[CSP], stale_assets=[NS02], not_responding=[TEST_ADDR, TEST_NAME], quiet_where=WHERE)
    assert dd.subject(before, "COMMANDsentry") == "[COMMANDsentry] (!) Coverage gap. Command, Thursday: 1 for today, 2 this week"
    after = model(new_findings=[CSP], stale_assets=[NS02], not_responding=[TEST_ADDR, TEST_NAME], quiet_where=WHERE,
                  gaps_to_approver=True, told={})
    subj, html, text = rendered(after)
    assert subj == "[COMMANDsentry] Command, Thursday: nothing urgent, 2 this week"
    assert after["headline"] == "Nothing urgent today. Two things for this week."
    assert after["do"] == [] and [i["kind"] for i in after["ticket"]] == ["finding", "not_responding"]
    quiet = after["ticket"][1]
    assert quiet["lines"] == ["test.commandcommcentral.com (52.119.65.6): no answer since Nov 3, 7:25 PM. "
                              "Its name still points to an address, but nothing answers there. Leaves the portal on Nov 11."]
    assert "ask your IT team to remove its name" in quiet["body"]
    assert "if it is still in use, ask them to check it" in quiet["body"]     # 11-05: it was not retired
    assert ("host-quiet:test.commandcommcentral.com", "NO_ANSWER", "daily") in after["told_full"]
    assert "ns02" not in html and "lost sight" not in html and "Needs you today" not in html
    # the next morning, the same silent host is not said again
    told = {"host-quiet:test.commandcommcentral.com": {"last_full_at": W1, "last_full_severity": "NO_ANSWER"}}
    nxt = model(window_start=W1, window_end=W1 + timedelta(days=1), not_responding=[TEST_ADDR, TEST_NAME],
                quiet_where=WHERE, gaps_to_approver=True, told=told)
    assert nxt["ticket"] == [] and nxt["headline"].startswith("Nothing new since ")
