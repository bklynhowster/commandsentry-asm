"""(KB 12 job 3l, slice 3, 2026-10-22) Plain words for every item, in both emails.

Howie, after the first test sends: "identify it to the best of our knowledge, provide what the
risk is, and provide what the remediation is" — for business owners and the Command/Unimac IT
team, who need "a quick glance". Risk "where it is, not where it might be": a guess ("version
not shown") is counted, never listed. The WordPress sites are run by an outside company, so a
plugin item says so and carries a paragraph ready to forward to them.

Pinned here: the three spellings of a plugin advisory; an advisory judged against its own
affected range (both ends: Slider Revolution 6.7.58 was listed under four advisories that end
at 6.7.37 or start at 7.0); the risk sentence in plain words; one item per plugin, with the
fix and the forward paragraph; where-words for headlines; the certificate's own end date; the
minor line; the guess line; and the queries that feed them.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_words as w  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
RS_A = "Slider Revolution [revslider] < 6.7.38"
RS_B = "revslider 6.7.58 — < 7.0.10 (CVE-2026-6728)"
MM = "Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)"
RS_READ = ("The Slider Revolution plugin for WordPress is vulnerable to Arbitrary File Read in versions "
           "6.7.0 to 6.7.37 via the 'used_svg' parameter. This makes it possible for authenticated "
           "attackers, with Contributor-level access and above, to read the contents of arbitrary files "
           "on the server. Detected at version 6.7.58.")
RS_7 = ("The Slider Revolution plugin for WordPress is vulnerable to Stored Cross-Site Scripting in versions "
        "7.0.0 - 7.0.9. This makes it possible for unauthenticated attackers to inject scripts. "
        "Detected at version 6.7.58.")
MM_DESC = ("The Mega Main Menu plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions "
           "up to, and including, 2.2.2. This makes it possible for unauthenticated attackers to change the "
           "plugin's settings via a forged request, granted they can trick a site administrator into "
           "clicking a link. Detected at version 2.2.1.")


# ── digest_words: what a title is ────────────────────────────────────────────

def test_a_plugin_advisory_is_read_in_all_three_spellings():
    assert w.plugin_of(RS_A) == {"slug": "revslider", "name": "Slider Revolution", "fixed_in": "6.7.38", "seen": None}
    assert w.plugin_of(RS_B) == {"slug": "revslider", "name": "Slider Revolution", "fixed_in": "7.0.10", "seen": "6.7.58"}
    assert w.plugin_of(MM)["fixed_in"] is None, "'<=' and 'unfixed' both mean no fixed version"
    c = w.plugin_of("F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)")
    assert c == {"slug": "mega_main_menu", "name": "Mega Main Menu", "fixed_in": None, "seen": "2.2.1"}
    assert w.plugin_of("No enforcing WAF in front of live application") is None
    assert w.family_key(RS_A) == w.family_key(RS_B) == "plugin:revslider", "one item per plugin"


def test_an_advisory_is_judged_against_both_ends_of_its_own_range():
    above = w.advisory(RS_A, RS_READ)
    assert above["applies"] is False and above["seen"] == "6.7.58", "6.7.58 is past 6.7.37"
    below = w.advisory(RS_B, RS_7)
    assert below["applies"] is False, "6.7.58 is before 7.0.0: the lower end counts too"
    inside = w.advisory(MM, MM_DESC)
    assert inside["applies"] is True and inside["fixed_in"] is None
    assert w.advisory(RS_A, "No range and no version here.")["applies"] is None, "can't tell: say so, don't drop"
    assert w.advisory(RS_B, "")["cves"] == ["CVE-2026-6728"]


def test_the_risk_is_one_plain_sentence_about_who_can_do_what():
    assert w.advisory(MM, MM_DESC)["risk"].startswith(
        "Anyone on the internet, without logging in, can change the plugin's settings")
    assert w.advisory(RS_A, RS_READ)["risk"] == (
        "Anyone with even a basic account on the site can read the contents of arbitrary files on the server.")
    admin = ("This makes it possible for authenticated attackers, with Administrator-level access and above, "
             "to upload files, which makes remote code execution possible. Detected at version 1.0.")
    assert w.advisory(RS_A, admin)["risk"] == (
        "Someone who already has administrator access can upload files, and from there take over the site.")


def test_a_guess_is_known_as_one_and_has_no_job():
    t = "Runs PHP, version not shown — 2 advisories: confirm it’s patched"
    assert w.is_guess(t) and not w.is_guess("No enforcing WAF in front of live application")
    x = w.words(t)
    assert x["title"] == "Runs PHP; we can't see which version" and x["do"] == "" and x["why"] == ""
    assert w.family_key(t) != w.family_key("Runs WordPress, version not shown"), "PHP and WordPress stay apart"


def test_every_family_says_what_it_is_what_it_means_and_the_fix():
    for f in w.FAMILIES:
        if f.get("guess") or f.get("minor"):
            continue
        assert f["title"] and f["why"] and f["who"] in dd.WHO_WORDS, f["key"]
        if f["key"] != "auth-bypass":
            assert f["do"] and f["headline"].count("{where}") == 1, f["key"]
    x = w.words("No enforcing WAF in front of live application", 2)
    assert x["title"] == "No web firewall in front of these sites" and "{" not in x["why"] + x["do"]
    # 351 (2026-10-26): measured at a sign-in, the attacks got as far as the login, no further
    s = w.words("No enforcing WAF in front of the sign-in", 1)
    assert s["title"] == "No web firewall in front of the sign-in on this site"
    assert "walked straight in" not in s["why"] and "login page" in s["why"] and "{" not in s["why"] + s["do"]
    assert w.family_key("No enforcing WAF in front of the sign-in") == "waf-absent-signin"
    assert w.family_key("No enforcing WAF in front of live application") == "waf-absent"


# ── the daily's items ────────────────────────────────────────────────────────

def _row(fid, aid, title, sev="HIGH"):
    return (fid, aid, title, sev, "open", "wpvulnerability", datetime(2026, 10, 22, 12, tzinfo=UTC))


def test_a_plugin_item_drops_what_does_not_apply_and_goes_to_the_wordpress_company():
    rows = [_row("a", "cmi.com", RS_A), _row("b", "cmi.com", RS_B), _row("c", "cmi.com", MM)]
    det = {"a": (RS_READ, []), "b": (RS_7, []), "c": (MM_DESC, ["CVE-2023-1575"])}
    items = dd.group_problems(rows, {"cmi.com"}, details=det)
    assert [i["family"] for i in items] == ["plugin:mega_main_menu"], "both Slider Revolution advisories miss 6.7.58"
    (i,) = items
    assert i["who"] == "wordpress" and dd.WHO_WORDS[i["who"]] == "the company that runs your WordPress sites"
    assert i["body"].startswith("Anyone on the internet, without logging in,")
    assert i["do"] == "Replace Mega Main Menu with a maintained plugin, or remove it. No update is coming."
    assert "Mega Main Menu (version 2.2.1) on cmi.com" in i["forward"] and "CVE-2023-1575" in i["forward"]
    assert "remove the plugin" in i["forward"] and "Please update" not in i["forward"]
    assert i["headline"] == "ask your WordPress company to remove Mega Main Menu on cmi.com"


def test_a_plugin_with_a_fix_names_the_newest_fixed_version():
    det = {"a": ("Vulnerable in versions 6.0 to 6.7.37. Detected at version 6.7.2.", []),
           "b": ("Vulnerable in versions 6.0 to 7.0.9. Detected at version 6.7.2.", [])}
    (i,) = dd.group_problems([_row("a", "x.com", RS_A), _row("b", "x.com", RS_B)], {"x.com"}, details=det)
    assert i["do"] == "Update Slider Revolution to version 7.0.10 or later."
    assert i["forward"].endswith("Please update Slider Revolution to 7.0.10 or later and let us know when it's done.")


def test_where_words_fit_a_headline():
    assert dd.where_words(["pm.u.com"]) == "pm.u.com"
    assert dd.where_words(["bitec.prodexlabs.com", "highcom.prodexlabs.com"]) == "bitec and highcom (prodexlabs.com)"
    assert dd.where_words(["a.x.com", "b.x.com", "c.x.com"]) == "a, b and c (x.com)"
    assert dd.where_words(["x.com", "y.com"]) == "x.com and y.com"
    assert dd.where_words(["a.x.com", "b.x.com", "c.x.com", "d.x.com"]) == "four sites"


def test_a_certificate_ends_when_it_says_not_when_the_day_count_rounds_to():
    seen = datetime(2026, 10, 16, 23, 0, tzinfo=UTC)
    row = ("pm.u.com", "TLS certificate expiring soon — expires < 14 days (9)", seen)
    assert dd.cert_expiry(row) == datetime(2026, 10, 25, 23, 0, tzinfo=UTC), "the old way: a day early"
    assert dd.cert_expiry(row + ("2026-10-26 17:53",)) == datetime(2026, 10, 26, 17, 53, tzinfo=UTC)
    assert dd.cert_expiry(row + (None,)) == dd.cert_expiry(row), "no end date recorded: fall back"
    assert dd.cert_expiry(row + ("not a date",)) == dd.cert_expiry(row)


def test_the_minor_line_names_the_site_and_never_jokes():
    assert dd.minor_words([]) == ""
    one = dd.minor_words([("myorders.u.com", w.words("OCSP stapling not enabled")["title"])])
    assert one == ("Also found today, minor, no action needed: myorders.u.com doesn't staple its certificate "
                   "status (a speed nicety, not a hole).")
    assert dd.minor_words([("a.com", "its domain doesn't limit x")]) == \
        "Also found today, minor, no action needed: a.com's domain doesn't limit x."
    assert "::" not in dd.minor_words([("a.com", "Banner: changed")])
    many = dd.minor_words([(f"s{i}.com", "x") for i in range(4)])
    assert many == "Also found today: 4 minor issues, no action needed. They're listed in the portal."


def test_a_guess_does_not_set_a_sites_level_now_or_a_week_ago():
    """SQL_SITE_RATINGS: a site with an open "version not shown" row is rated by the one rule
    (job 3m) at now() from its other findings; every other site keeps the portal's level.
    Read live 10-22: Command's four FortiWeb sites, CRITICAL in the portal, are MODERATE."""
    import re
    sql = " ".join(ra.SQL_SITE_RATINGS.split())
    pat = ra.GUESS_TITLE_SQL[1:-1]          # the SQL literal without its quotes
    assert sql.count(f"f.title !~* {ra.GUESS_TITLE_SQL}") == 2, "left out of now and of a week ago"
    assert f"g.title ~* {ra.GUESS_TITLE_SQL}" in sql and "ELSE a.current_risk::text END AS rating_now" in sql
    assert "f.first_detected_at <= now()" in sql and "f.first_detected_at <= %(t)s" in sql
    posture = " ".join(ra.SQL_OPEN_POSTURE.split())
    assert f"WHERE title !~* {ra.GUESS_TITLE_SQL} GROUP BY severity" in posture, "the footer counts what is known"
    for t in ("Runs Fortinet FortiWeb, version not shown — 4 advisories on CISA’s exploited list",
              "Runs PHP, version not shown — 2 advisories: confirm it’s patched",
              "No enforcing WAF in front of live application",
              "Slider Revolution [revslider] < 6.7.38"):
        assert bool(re.search(pat, t, re.I)) == w.is_guess(t), t


# ── run_alerter: what feeds the words ────────────────────────────────────────

def test_hints_and_details_split_the_fix_from_what_judges_an_advisory():
    hints, det = ra.hints_and_details([("a", "Update it.", "desc", ["CVE-1"]), ("b", None, None, None)])
    assert hints == {"a": "Update it.", "b": None}
    assert det == {"a": ("desc", ["CVE-1"]), "b": (None, [])}
    assert "description, cve" in ra.SQL_FINDING_HINTS


def test_the_open_list_reads_each_member_of_the_dashboards_set():
    q = ra.SQL_OPEN_SERIOUS
    assert "v_fleet_open_reps" in q and "unnest(r.member_finding_ids)" in q
    assert "v_open_findings_dedup" not in q, "that view keeps closed rows"
    assert "f.description, f.cve" in q, "the weekly judges advisories too"


def test_the_certificate_query_reads_its_end_date_from_the_deep_scan():
    q = ra.SQL_CERTS_EXPIRING
    assert "'cert_notAfter'" in q and "AS not_after" in q and "testssl.sh" in q


def test_the_fixed_line_says_what_was_fixed_and_a_vanished_guess_is_not_news():
    """Howie, 10-22: "one problem fixed. What was fixed? It's a patched version of what?" """
    t = datetime(2026, 10, 22, 12, tzinfo=UTC)
    fixed = [("f1", "a.x.com", "No enforcing WAF in front of live application", "HIGH", "remediated", "h", t),
             ("f2", "b.x.com", "No enforcing WAF in front of live application", "HIGH", "remediated", "h", t),
             ("f3", "c.x.com", "Runs WordPress, version not shown — 1 advisory", "HIGH", "remediated", "a", t),
             ("f4", "d.x.com", "Next.js middleware bypass", "CRITICAL", "remediated", "n", t)]
    html = ra.render_html(window_start=datetime(2026, 10, 21, 12, tzinfo=UTC), window_end=t, new_findings=[],
                          confirmed=[], regressed=[], high_risk=[], new_assets=[], dark_assets=[],
                          stale_assets=[], canary_violations=[], discovery_stale_hours=12,
                          deepscan_stale_hours=48, baseline={}, dashboard_url="https://example.invalid",
                          product_name="COMMANDsentry", fixed=fixed)
    assert "A web firewall is now in place on a.x.com, b.x.com." in html
    assert "Fixed on d.x.com: Next.js middleware bypass." in html
    assert "c.x.com" not in html and "patched version" not in html
