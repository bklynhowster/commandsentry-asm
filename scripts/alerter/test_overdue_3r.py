"""(KB 12 job 3r, 2026-10-23) Overdue: out of date, a known fix, and nobody has acted.

Howie, 07:21: "It doesn't mean that it's not important. It means that nobody's done a damn
thing about it … that doesn't mean it needs to glow and bother people, but it shouldn't be
the same as another moderate." 07:23: "there is a fix. It's just that nobody is pushing to get
it taken care of." 07:25: "drop it to moderate, and then some kind of indication that there is
still some action required here."

Pinned here: which findings are on the out-of-date rung (by identity and title — the heavy
writer stores no tags); the advisory watch's new out-of-date titles in plain words; the
weekly's "Overdue" section (MODERATE, its own calm color, "Known since <first sighting>;
still needs someone to act", never also under "Worth your time"); a plugin with no update
coming reads "Replace it"; the query.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_weekly as dw  # noqa: E402
import digest_words as w  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 26, 12, 5, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Command")
RS_TEXT = ("The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information Exposure in versions "
           "up to, and including, 7.0.9. This makes it possible for unauthenticated attackers to extract sensitive "
           "data. Detected at version 6.7.58.")
RS_7 = ("The Slider Revolution plugin for WordPress is vulnerable to Arbitrary File Upload in versions 7.0.0 to "
        "7.0.10. Detected at version 6.7.58.")
MM_TEXT = ("The Mega Main Menu plugin for WordPress is vulnerable to Stored Cross-Site Scripting in versions up to, "
           "and including, 2.2.2. This makes it possible for authenticated attackers, with administrator-level "
           "permissions and above, to inject arbitrary web scripts. Detected at version 2.2.1.")


def _r(fid, asset, title, first, sev="MODERATE", desc="", cve=()):
    return (fid, asset, title, sev, "detected", "commandsentry_light", first, desc, list(cve))


def test_the_out_of_date_rung_is_known_by_identity_and_title():
    assert w.is_out_of_date("cc.com:light:wpvuln-cve-2026-6728", "Slider Revolution [revslider] < 7.0.10")
    assert w.is_out_of_date("x:light:wpvuln-cve-1", "anything"), "the heavy writer keeps the light identity"
    assert w.is_out_of_date("u.com:light:libflaw-jquery-ui-ghsa-x", "jQuery UI 1.12.1: XSS …")
    assert w.is_out_of_date("cc.com:advisory_watch:out-of-date:php:abc1234", "Runs PHP 8.1.2: out of date — …")
    assert w.is_out_of_date("unimacgraphics.com:manual:F-01", "F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)")
    assert not w.is_out_of_date("cc.com:heavy:waf", "No enforcing WAF in front of live application")
    assert not w.is_out_of_date("cc.com:advisory_watch:advisory:php:abc1234", "Runs PHP, version not shown — 2 advisories")


def test_the_advisory_watchs_out_of_date_rows_read_plainly():
    x = w.words("Runs PHP 8.1.2: out of date — 3 published flaws fixed in later versions; update it")
    assert x["key"] == "out-of-date" and x["title"] == "PHP is out of date"
    assert x["do"] == "Update PHP on this site to a current version." and x["who"] == "it"
    assert "vulnerable" not in (x["why"] + x["do"]).lower()
    fg = w.words("Runs Fortinet FortiGate (FortiOS), firmware built Jan 2024: out of date — 2 published flaws published since; update it")
    assert fg["title"] == "Fortinet FortiGate (FortiOS) is out of date"
    assert not w.is_guess("Runs PHP 8.1.2: out of date — 1 published flaw fixed in later versions; update it")


def _weekly(overdue, open_serious=()):
    s, e, days = dw.week_window(NOW, BRAND)
    return dw.build_weekly(now=NOW, window_start=s, window_end=e, days=days, brand=BRAND, scans=[],
                           opened=[], closed=[], sites=[("commandcompanies.com", "MODERATE", True, "MODERATE")],
                           open_serious=list(open_serious), overdue=overdue)


def test_overdue_is_its_own_section_moderate_with_when_it_was_first_seen():
    rows = [
        _r("cc.com:light:wpvuln-cve-2026-6728", "commandcompanies.com", "Slider Revolution [revslider] < 7.0.10",
           datetime(2026, 6, 9, tzinfo=UTC), desc=RS_TEXT, cve=["CVE-2026-6728"]),
        _r("cmi.com:light:wpvuln-cve-2026-6728", "commandmarketinginnovations.com", "Slider Revolution [revslider] < 7.0.10",
           datetime(2026, 6, 1, tzinfo=UTC), desc=RS_TEXT, cve=["CVE-2026-6728"]),
        _r("cc.com:light:wpvuln-cve-2026-6692", "commandcompanies.com", "Slider Revolution [revslider] < 7.0.11",
           datetime(2026, 6, 9, tzinfo=UTC), desc=RS_7, cve=["CVE-2026-6692"]),
        _r("u.com:manual:F-01", "unimacgraphics.com", "F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)",
           datetime(2026, 5, 23, tzinfo=UTC), desc=MM_TEXT, cve=["CVE-2023-1575"]),
        _r("cc.com:heavy:waf", "commandcompanies.com", "No enforcing WAF in front of live application",
           datetime(2026, 5, 1, tzinfo=UTC)),
    ]
    m = _weekly(rows, open_serious=[rows[3][:3] + ("MODERATE-HIGH",) + rows[3][4:]])
    titles = [i["title"] for i in m["overdue"]]
    assert titles == ["Mega Main Menu, a WordPress plugin, has a published security flaw",
                      "Slider Revolution, a WordPress plugin, has a published security flaw"], "oldest first; WAF not here"
    mm, rs = m["overdue"]
    assert (mm["overdue_since"].month, mm["overdue_since"].day) == (5, 23)
    assert (rs["overdue_since"].month, rs["overdue_since"].day) == (6, 1), "the earliest sighting across its sites"
    assert rs["sites"] == ["commandcompanies.com", "commandmarketinginnovations.com"]
    assert rs["finding_ids"] == ["cc.com:light:wpvuln-cve-2026-6728", "cmi.com:light:wpvuln-cve-2026-6728"], \
        "the advisory whose own range misses 6.7.58 is dropped"
    assert mm["do"] == "Replace Mega Main Menu with a maintained plugin, or remove it. No update is coming."
    assert dd.overdue_words(mm) == "Moderate. Known since May 23; still needs someone to act."
    assert not any(i.get("finding_ids") == ["u.com:manual:F-01"] for i in m["do"]), "never twice"

    html = dw.render_weekly_html(m, portal_url="", product_name="COMMANDsentry")
    assert ">Overdue</h2>" in html and ">Overdue</span>" in html and dd.OVERDUE_FILL in html
    assert "Known since Jun 1; still needs someone to act." in html
    assert "#C2410C" not in html.split(">Overdue</h2>")[1].split("How hard we looked")[0], "no alarm colors in it"
    text = dw.render_weekly_text(m, portal_url="", product_name="COMMANDsentry")
    assert "OVERDUE (known, with a fix, open more than 30 days)" in text
    assert "[ ] [Overdue] Slider Revolution, a WordPress plugin, has a published security flaw" in text


def test_nothing_overdue_means_no_section():
    m = _weekly([])
    assert m["overdue"] == []
    assert ">Overdue</h2>" not in dw.render_weekly_html(m, portal_url="", product_name="X")
    assert "OVERDUE" not in dw.render_weekly_text(m, portal_url="", product_name="X")


def test_the_overdue_query():
    q = " ".join(ra.SQL_OPEN_OUT_OF_DATE.split())
    assert "FROM public.v_fleet_open_reps r CROSS JOIN LATERAL unnest(r.member_finding_ids)" in q
    assert "f.severity::text IN ('MODERATE', 'MODERATE-HIGH')" in q
    assert "f.first_detected_at < now() - interval '30 days'" in q and dd.OVERDUE_DAYS == 30
    assert "f.first_detected_at, f.description, f.cve" in q


def test_each_overdue_item_asks_who_and_says_what_to_do_never_twice_never_forwarded():
    """Howie, 07:58: "inject a little bit of my cynicism and sarcasm into this … that will get the
    IT team's attention." 08:01: "give the reader a little bit more in terms of what they should
    do or who they should contact … is there nobody maintaining the WordPress site, or who
    maintains this?" Never the same line twice in one email; never in the forward box."""
    since = datetime(2026, 6, 1, tzinfo=UTC)
    for who, lines in dd.OVERDUE_NUDGES.items():
        got = [dd.overdue_nudge({"overdue_since": since, "as_of": NOW, "who": who}, k) for k in range(len(lines))]
        assert len(set(got)) == len(got), who
        assert all("?" in g or "below" in g for g in got), "each one asks who, or says the next step"
    wp = [dd.overdue_nudge({"overdue_since": since, "as_of": NOW, "who": "wordpress"}, k) for k in range(5)]
    assert wp[0].startswith("Is anyone actually maintaining this WordPress site? Whoever it is, send them the paragraph")
    assert "maintains this damn site? Forward them the paragraph below." in wp[1]
    assert wp[2].startswith("What are we spending our money on? Send the paragraph below")
    it = dd.overdue_nudge({"overdue_since": since, "as_of": NOW, "who": "it"}, 1)
    assert it == "Is anyone responsible for this server? The fix is below. It's been 4 months."
    rows = [_r("cc.com:light:wpvuln-cve-2026-6728", "commandcompanies.com", "Slider Revolution [revslider] < 7.0.10",
               datetime(2026, 6, 9, tzinfo=UTC), desc=RS_TEXT, cve=["CVE-2026-6728"]),
            _r("u.com:manual:F-01", "unimacgraphics.com", "F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)",
               datetime(2026, 5, 23, tzinfo=UTC), desc=MM_TEXT, cve=["CVE-2023-1575"])]
    m = _weekly(rows)
    assert [i["nudge"] for i in m["overdue"]] == [dd.overdue_nudge(m["overdue"][0], 0), dd.overdue_nudge(m["overdue"][1], 1)]
    assert m["overdue"][0]["nudge"] != m["overdue"][1]["nudge"]
    html = dw.render_weekly_html(m, portal_url="", product_name="X")
    assert "Is anyone actually maintaining this WordPress site?" in html and "maintains this damn site?" in html
    for i in m["overdue"]:
        assert "damn" not in i["forward"] and "money" not in i["forward"], "the vendor gets the polite version"
    assert "Is anyone actually maintaining this WordPress site?" in dw.render_weekly_text(m, portal_url="", product_name="X")
