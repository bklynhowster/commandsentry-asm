"""(KB 12 job 3t, 2026-10-26) The daily's "not responding" block (D5).

Howie, 2026-10-26 07:16 (D5): "The daily email gets a line when the host stops responding. It
continues for the amount of time that we set for 7 days, and then it's gone."

Pinned here: the rows come from public.v_asset_reachability (migration 20261026a), the view the
portal's banner reads, as a SOFT read on the real send path; the block sits in "Needs you today"
right after our own coverage block; one line per host in plain words (last answer in the brand's
time zone, why, the day it leaves); it is NOT routed through say-once (it repeats every day while
the host is not responding); a not-responding host is not also "lost sight of" or "stopped
answering"; no rows, no block.
"""
from __future__ import annotations

import inspect
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
W0 = datetime(2026, 10, 25, 12, 9, tzinfo=UTC)
W1 = datetime(2026, 10, 26, 12, 9, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Prodex")

# (asset_id, last_answer_at, reason, notice_since, leaves_on) — the SQL_NOT_RESPONDING shape
VALOREP = ("valorep.prodexlabs.com", datetime(2026, 10, 22, 18, 25, tzinfo=UTC), "name_gone",
           datetime(2026, 10, 26, 13, 0, tzinfo=UTC), datetime(2026, 11, 2, 13, 0, tzinfo=UTC))
SILENT = ("mail.commandweb.com", None, "never_answered", None, None)
QUIET = ("fw.example", datetime(2026, 10, 24, 9, 0, tzinfo=UTC), "no_answer", None, None)


def model(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              baseline={}, brand=BRAND)
    kw.update(over)
    return dd.build_model(**kw)


def _block(m):
    got = [i for i in m["do"] if i["kind"] == "not_responding"]
    assert len(got) <= 1
    return got[0] if got else None


def test_the_line_says_when_why_and_when_it_leaves_in_plain_words():
    assert dd.not_responding_line(VALOREP, BRAND) == (
        "valorep.prodexlabs.com: no answer since Oct 22, 2:25 PM. Its name no longer exists on the "
        "internet. Leaves the portal on Nov 2.")
    assert dd.not_responding_line(SILENT, BRAND) == (
        "mail.commandweb.com: no answer from Sentry's checks. Sentry has never had an answer from it.")
    assert dd.not_responding_line(QUIET, BRAND) == (
        "fw.example: no answer since Oct 24, 5:00 AM. Its name still points to an address, but "
        "nothing answers there.")


def test_the_block_is_in_needs_you_today_right_after_our_own_coverage():
    stale = [("lost.example", "a", "b", None, None)]
    m = model(not_responding=[VALOREP, SILENT], stale_assets=stale,
              stale_words=lambda r: (r[0], "last seen Oct 20", "last full scan Oct 1"))
    kinds = [i["kind"] for i in m["do"]]
    assert kinds[:2] == ["coverage", "not_responding"], kinds
    b = _block(m)
    assert b["title"] == "2 hosts are not responding"
    assert b["severity"] == "" and b["lines"][0].startswith("valorep.prodexlabs.com: ")
    assert "7 days" in b["body"] and "unless it answers again" in b["body"]
    assert _block(model(not_responding=[VALOREP]))["title"] == "1 host is not responding"


def test_no_rows_no_block():
    assert _block(model()) is None
    assert _block(model(not_responding=[])) is None
    assert _block(model(not_responding=None)) is None


def test_it_repeats_every_day_and_is_not_said_once():
    """D5 exempts it from say-once: a full told record changes nothing about the block."""
    told = {"f-1": {"finding_id": "f-1", "first_told_at": W0, "last_full_at": W0,
                    "last_full_severity": "HIGH", "last_full_in": "daily", "reminders": 0,
                    "closed_seen_at": None}}
    a, b = _block(model(not_responding=[VALOREP])), _block(model(not_responding=[VALOREP], told=told))
    assert a == b and a is not None
    assert "told_rule" not in inspect.getsource(dd.not_responding_line)


def test_a_not_responding_host_is_not_also_lost_sight_of_or_stopped_answering():
    stale = [("valorep.prodexlabs.com", "a", "b", None, None)]
    dark = [("valorep.prodexlabs.com", "valorep", "prodex", W1, {"last_seen": "Oct 22"})]
    m = model(not_responding=[VALOREP], stale_assets=stale, dark_assets=dark,
              stale_words=lambda r: (r[0], "x", "y"))
    assert [i["kind"] for i in m["do"]] == ["not_responding"]
    assert not any(i["kind"] == "dark" for i in m["ticket"])
    assert m["degraded"] is False, "a host that is down is not a gap in OUR checking"
    # a different host stays where it was
    m2 = model(not_responding=[VALOREP], stale_assets=[("other.example", "a", "b", None, None)],
               stale_words=lambda r: (r[0], "x", "y"))
    assert m2["degraded"] is True and m2["do"][0]["kind"] == "coverage"


def test_the_subject_and_headline_count_it():
    m = model(not_responding=[VALOREP])
    assert m["headline"] == "Today: 1 host is not responding."
    assert dd.subject(m, "PRODEXsentry").endswith(": 1 for today")


def test_both_renderings_carry_it():
    m = model(not_responding=[VALOREP, SILENT])
    html = dd.render_html(m, portal_url="https://portal.example", product_name="PRODEXsentry")
    assert "2 hosts are not responding" in html and "#FCEBEB" in html and "#A32D2D" in html
    assert '<span style="font-weight:700;">valorep.prodexlabs.com</span>: no answer since Oct 22' in html
    text = dd.render_text(m, portal_url="", product_name="PRODEXsentry")
    assert "  [ ] 2 hosts are not responding" in text
    assert "      - valorep.prodexlabs.com: no answer since Oct 22, 2:25 PM." in text


def test_the_send_path_reads_the_view_softly_and_passes_it_on():
    sql = " ".join(ra.SQL_NOT_RESPONDING.split())
    assert sql == ("SELECT r.asset_id, r.last_answer_at, r.reason, r.notice_since, r.leaves_on "
                   "FROM public.v_asset_reachability r WHERE r.not_responding "
                   "ORDER BY r.last_answer_at ASC NULLS FIRST, r.asset_id;")
    src = inspect.getsource(ra.main)
    assert 'not_responding = _soft("not responding", SQL_NOT_RESPONDING)' in src
    assert "details=details, told=told, not_responding=not_responding," in src
    assert "not_responding=not_responding" in inspect.getsource(ra._digest_model)


def test_the_wrappers_pass_it_through():
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              discovery_stale_hours=24, deepscan_stale_hours=192, baseline={},
              product_name="PRODEXsentry", brand=BRAND, not_responding=[VALOREP])
    assert "1 host is not responding" in ra.render_text(**kw)
    assert "1 host is not responding" in ra.render_html(dashboard_url="https://p.example", **kw)


# ── "Sentry itself says when the checks have stopped" (plan v1.2) ─────────────────────
def test_stopped_checks_are_said_as_our_own_gap():
    newest = datetime(2026, 10, 25, 20, 5, tzinfo=UTC)
    m = model(reach_checks=(False, newest))
    item = m["do"][0]
    assert item["kind"] == "coverage" and item["title"] == "Sentry's reachability checks have stopped"
    assert item["body"] == ("A gap in our own checking, not a problem found on any host. The last one ran "
                            "Oct 25, 4:05 PM. Until they run again, no host is marked not responding and "
                            "none leaves the portal.")
    assert m["degraded"] is True and "(!) Coverage gap." in dd.subject(m, "PRODEXsentry")
    assert "They have not run yet." in model(reach_checks=(False, None))["do"][0]["body"]


def test_fresh_unread_or_empty_checks_say_nothing():
    for rc in (None, (True, W1), (None, None), ()):
        m = model(reach_checks=rc)
        assert m["do"] == [] and m["degraded"] is False, rc


def test_the_send_path_reads_the_checks_softly():
    assert " ".join(ra.SQL_REACH_CHECKS.split()) == (
        "SELECT bool_or(r.checks_fresh), max(r.last_check_at) FROM public.v_asset_reachability r;")
    src = inspect.getsource(ra.main)
    assert 'reach_checks = (_soft("reachability checks", SQL_REACH_CHECKS) or [None])[0]' in src
    assert "reach_checks=reach_checks," in src
