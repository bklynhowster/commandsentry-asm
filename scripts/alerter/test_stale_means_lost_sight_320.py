"""320 (2026-10-15) — "stale" in the digest means WE lost sight of a host, and the mail says so
in words.

Howie, reading the 10-15 digests: "What do you mean by stale assets?" and, on the shipped
line `!disc=2026-09-25 12:23 UTC (479.7h)  deep= 2026-10-12 23:44 UTC (60.4h)`: "I, as the
main creator of this with you, am completely confused."

Two things changed:
  1. The discovery leg composes last_observed with last_probe_alive_at (what migration
     20260724a told every freshness consumer to do). A host the liveness probe proved
     alive is not a host we lost sight of. The row says which clock answered (seen_via).
  2. Both renderers print sentences a reader does not have to decode: "last seen Sep 25
     (20 days ago)", "never had a full scan" — no clock names, no column names, no
     decimal hours — under a heading and one plain explanation. The subject says
     "we lost sight of", not "stale".
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
T = lambda *a: datetime(*a, tzinfo=UTC)  # noqa: E731


def _row(aid, lo, ls, hd, hs, disc_stale, never, deep_stale, via="discovery"):
    return (aid, lo, ls, hd, hs, disc_stale, never, deep_stale, via)


def test_320_the_sql_composes_the_two_clocks_and_names_the_winner():
    sql = " ".join(ra.SQL_STALE_LIVE_ASSETS.split())
    assert "GREATEST(a.last_observed, a.last_probe_alive_at) AS seen_at" in sql
    assert "AS seen_via" in sql and "'probe'" in sql and "'discovery'" in sql
    # the stale decision is made on the COMPOSED clock, never on last_observed alone
    assert "c.seen_at IS NULL OR c.seen_at <" in sql
    assert not re.search(r"WHERE[^;]*a\.last_observed <", sql), "a bare last_observed test survived"
    # scope, ownership and status filters stay
    for keep in ("a.ownership = 'owned'", "a.discovery_status = 'confirmed_live'", "a.apex_domain = ANY(%(apexes)s)"):
        assert keep in sql, keep


def test_320_words_for_the_three_shapes():
    aid, d, s = ra.stale_row_words(_row("staging-gpt55.prodexlabs.com", T(2026, 10, 12, 12, 31), T(2026, 10, 12, 23, 44), 72.3, 61.0, True, False, False, "probe"))
    assert d == "last seen Oct 12 (3 days ago)"
    assert s == "last full scan Oct 12 (3 days ago)"
    aid, d, s = ra.stale_row_words(_row("firewall.unimacgraphics.com", None, None, None, None, True, True, False))
    assert d == "never seen by our checks" and s == "never had a full scan"
    aid, d, s = ra.stale_row_words(_row("www.commandcompanies.com", T(2026, 6, 6, 19, 41), T(2026, 10, 14, 0, 33), 3143.0, 42.0, True, False, False))
    assert d == "last seen Jun 6 (131 days ago)"
    assert s == "last full scan Oct 14 (42 hours ago)"


def test_320_no_jargon_reaches_the_reader():
    # Howie: the people reading these mails must not need our vocabulary.
    words = " ".join(ra.stale_row_words(_row("h", T(2026, 10, 1), T(2026, 10, 2), 300.0, 280.0, True, False, True, via))[1] +
                     " " + ra.stale_row_words(_row("h", T(2026, 10, 1), T(2026, 10, 2), 300.0, 280.0, True, False, True, via))[2]
                     for via in ("probe", "discovery"))
    words += " " + ra.STALE_INTRO + " " + ra.stale_overdue_note(9, 168)
    for jargon in ("discovery", "probe", "deep", "pipeline", "clock", "last_observed", "asset_surface"):
        assert jargon not in words.lower(), jargon
    assert ra.stale_overdue_note(9, 168) == "not seen in 9 hours, no full scan in 7 days, or never"


def test_320_the_old_eight_tuple_still_renders():
    aid, d, s = ra.stale_row_words(("x.example.com", T(2026, 10, 1), T(2026, 10, 2), 300.0, 280.0, True, False, True))
    assert d == "last seen Oct 1 (12 days ago)" and s == "last full scan Oct 2 (12 days ago)"


def _render(stale):
    base = {"critical_open": 0, "high_open": 0, "mod_high_open": 0, "moderate_open": 0, "low_open": 0}
    kw = dict(window_start=T(2026, 10, 14, 12), window_end=T(2026, 10, 15, 12), new_findings=[], confirmed=[],
              regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=stale, canary_violations=[],
              discovery_stale_hours=9, deepscan_stale_hours=168, baseline=base, product_name="X")
    return ra.render_html(dashboard_url="https://x.invalid", **kw), ra.render_text(**kw)


def test_320_both_renderers_say_it_in_words():
    stale = [_row("firewall.unimacgraphics.com", None, None, None, None, True, True, False),
             _row("www.commandcompanies.com", T(2026, 6, 6, 19, 41), T(2026, 10, 14, 0, 33), 3143.0, 42.0, True, False, False)]
    html, text = _render(stale)
    for out in (html, " ".join(text.split())):
        assert "lost sight of 2 hosts" in out
        assert "This is a gap in our own checking, not a problem found on the hosts." in out
        assert "never seen by our checks (overdue)" in out and "never had a full scan (overdue)" in out
        assert "last seen Jun 6 (131 days ago) (overdue)" in out
        assert "last full scan Oct 14 (42 hours ago)" in out and "42 hours ago) (overdue)" not in out
        assert "Overdue means: not seen in 9 hours, no full scan in 7 days, or never." in out
        assert "disc=" not in out and "Clock note" not in out and "assets.last_observed" not in out
        assert "PIPELINE DEGRADED" not in out


def test_320_the_subject_says_lost_sight_of():
    import digest_daily as dd
    stale = [_row("firewall.unimacgraphics.com", None, None, None, None, True, True, False)]
    m = ra._digest_model(window_start=T(2026, 10, 15, 12), window_end=T(2026, 10, 16, 12), new_findings=[],
                         confirmed=[], regressed=[], high_risk=[], new_assets=[], dark_assets=[],
                         stale_assets=stale, canary_violations=[], baseline={})
    assert "(!) Coverage gap." in dd.subject(m, "X")
    src = open(ra.__file__, encoding="utf-8").read()
    assert 'f"{n} stale"' not in src