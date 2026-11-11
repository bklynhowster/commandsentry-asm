"""The daily email's redesign (Howie 2026-11-11 07:27: "It is so poorly designed ... make this
entire thing look better"; 07:37, on the mock: "I love it. Let's build this.").

The top: a short headline, the one job named under it with its site as a pill, and the numbers.
Still open: one card per problem (how many sites, the grade, since when, a title, what it is, the
sites, the fix) in place of one grey paragraph each. The words are the email's own; the text
email, the subject, the model's headline and what is recorded as told do not change.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import digest_daily as dd  # noqa: E402
import digest_weekly as dwk  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 11, 11, 12, 11, tzinfo=UTC)            # Wednesday, 7:11 AM in New York
SPF_SITES = ["commandmarketinginnovations.com", "ftp.commandmi.com", "mail.unimacgraphics.com"]


def row(fid, asset, title, sev="MODERATE", source="testssl", first=(2026, 6, 1)):
    return (fid, asset, title, sev, "open", source, NOW - timedelta(days=1), "", [], datetime(*first, tzinfo=UTC))


def model(new=()):
    return ra._digest_model(
        window_start=NOW - timedelta(hours=24), window_end=NOW, new_findings=list(new), confirmed=[],
        regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[], baseline={},
        came_back=[], fixed=[], enforcement_flips=[], unrecognized_pages=[], sites=[], certs=[], prev_deep={}, hints={},
        brand=dict(dd.load_brand(), short_name="Command"), discovery_stale_hours=48, deepscan_stale_hours=720,
        details={}, told={}, not_responding=[], reach_checks=[], quiet_where={}, gaps_to_approver=False)


ROWS = ([row(f"s{i}", a, "DNS missing SPF record", source="commandsentry_light", first=(2026, 5, 31 if i == 0 else 30 - i + 31 - 30))
         for i, a in enumerate(SPF_SITES)]
        + [row("p1", "commandmarketinginnovations.com", "Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)",
               source="wpscan", first=(2026, 5, 4)),
           row("c1", "52.119.65.5", "TLS · cert_extlifeSpan: 12389 days", first=(2026, 7, 21)),
           row("c2", "52.119.65.6", "TLS · cert_extlifeSpan: 12389 days", first=(2026, 7, 22))])
PLAIN = {"s0": "This site's email domain has no sender-authorization setting, which tells other mail servers "
               "which senders are allowed to send email on its behalf. Without it, anyone can try."}
WAF = ("w1", "ftp.commandmi.com", "No enforcing WAF in front of the sign-in", "MODERATE", "detected",
       "commandsentry_heavy", NOW - timedelta(hours=9))


def picks(rows=ROWS):
    return ra._still_open_daily(rows, {r[1] for r in rows}, set(), NOW, {})


def cards(rows=ROWS, plain=PLAIN):
    return {c["card"]["title"]: c["card"] for c in dd.with_still_open(model(), picks(rows), plain)["still_open"]}


# ── the card's facts ──────────────────────────────────────────────────────────
def test_a_card_counts_its_sites_and_says_since_when():
    c = cards()["Nothing stops email that pretends to be from these sites"]
    assert (c["count"], c["unit"]) == (3, "sites") and c["sites"] == sorted(SPF_SITES, key=lambda x: (x.count("."), x))
    assert c["since"] == min(r[9] for r in ROWS if r[2].startswith("DNS missing SPF"))
    assert c["note"] == ""


def test_an_unbooked_jargon_title_gets_the_cards_own_words_one_site_or_several():
    one = cards([ROWS[0]])
    assert list(one) == ["Nothing stops email that pretends to be from this site"]
    dmarc = cards([row("d1", "a.com", "DNS missing DMARC record"), row("d2", "b.com", "DNS missing DMARC record")], {})
    assert list(dmarc) == ["Forged email in these sites' names isn't rejected"]
    # a title with no booked words and no card title keeps its own words
    assert list(cards([row("z1", "a.com", "Some other finding")], {})) == ["Some other finding"]


def test_booked_words_keep_their_own_title_and_the_card_table_never_overrides_them():
    c = cards()
    assert "A certificate good for 34 years" in c
    assert "Mega Main Menu, a WordPress plugin, has a published security flaw" in c


def test_the_card_table_is_only_for_titles_with_no_booked_words():
    booked = {"title": "DNS missing SPF record", "family": "some-family", "sites": ["a.com"], "finding_ids": []}
    assert dd.still_card(booked)["title"] == "DNS missing SPF record"
    assert dd.still_card(dict(booked, family=""))["title"] == "Nothing stops email that pretends to be from this site"


def test_what_it_is_names_no_site_and_is_said_for_each_of_several():
    c = cards()
    spf = c["Nothing stops email that pretends to be from these sites"]["what"]
    assert spf == ("Each site's email domain has no sender-authorization setting, which tells other mail servers "
                   "which senders are allowed to send email on its behalf.")
    assert not any(s in spf for s in SPF_SITES)
    one = cards([ROWS[0]])["Nothing stops email that pretends to be from this site"]["what"]
    assert one.startswith("This site's email domain has no sender-authorization setting")
    # booked words win over the saved sentence
    cert = dd.with_still_open(model(), picks(), {"c1": "This site has a certificate set to last about 33 years."})
    booked = [x["card"] for x in cert["still_open"] if x["card"]["title"].startswith("A certificate good")][0]
    assert booked["what"].startswith("It will outlive the hardware it's on.")
    # neither booked words nor a saved sentence: nothing is made up
    assert cards([row("z1", "a.com", "Some other finding")], {})["Some other finding"]["what"] == ""


def test_bare_addresses_are_called_servers_and_explained():
    c = cards()["A certificate good for 34 years"]
    assert (c["count"], c["unit"], c["note"]) == (2, "servers", "These servers have no name, only an address.")
    one = cards([ROWS[4]])["A certificate good for 34 years"]
    assert (one["unit"], one["note"]) == ("server", "This server has no name, only an address.")
    # IPv6 is an address too (review 428)
    v6 = cards([row("v1", "2001:db8::1", "TLS · cert_extlifeSpan: 12389 days"), ROWS[4]])["A certificate good for 34 years"]
    assert (v6["count"], v6["unit"], v6["note"]) == (2, "servers", "These servers have no name, only an address.")
    mixed = cards([row("m1", "a.com", "TLS · cert_extlifeSpan: 12389 days"), ROWS[4]])["A certificate good for 34 years"]
    assert (mixed["unit"], mixed["note"]) == ("sites", "") and mixed["sites"] == ["a.com", "52.119.65.5"]


def test_the_fix_and_who_does_it_come_from_the_emails_own_words():
    c = cards()
    plugin = c["Mega Main Menu, a WordPress plugin, has a published security flaw"]
    assert plugin["fix_label"] == "The fix, for the company that runs your WordPress sites"
    assert plugin["do"] == "Replace Mega Main Menu with a maintained plugin, or remove it. No update is coming."
    assert c["A certificate good for 34 years"]["fix_label"] == "The fix, for your IT team"
    none = cards([row("z1", "a.com", "Some other finding")], {})["Some other finding"]
    assert (none["do"], none["fix_label"]) == ("", "")


# ── the HTML ──────────────────────────────────────────────────────────────────
def html_for(m):
    return dd.render_html(m, portal_url="https://p.example", product_name="COMMANDsentry")


def test_each_open_problem_is_a_card_and_the_text_email_is_unchanged():
    m = dd.with_still_open(model([WAF]), picks(), PLAIN)
    html, text = html_for(m), dd.render_text(m, portal_url="https://p.example", product_name="COMMANDsentry")
    for title in cards():
        assert f">{title}</div>" in html
    assert html.count("Open since ") == 3 and ">Open since May 4</span>" in html and ">Open since Jul 21</span>" in html
    assert ">3</div>" in html and ">sites</div>" in html and ">servers</div>" in html
    assert "These servers have no name, only an address." in html
    assert ">The fix, for your IT team</div>" in html
    assert "Each one waits on someone to act." in html and "nothing changed since yesterday" in html
    # the one-sentence lines stay in the text email and are still what the model carries
    assert all(l["text"] in text for l in m["still_open"])
    assert not any(l["text"] in html for l in m["still_open"])


def test_a_line_with_no_card_still_shows_its_sentence():
    m = dd.with_still_open(model(), picks(), PLAIN)
    for l in m["still_open"]:
        l.pop("card")
    html = html_for(m)
    assert all(dd.escape(l["text"]) in html for l in m["still_open"])


def test_one_job_the_headline_counts_it_and_the_line_under_names_it_with_its_site_as_a_pill():
    m = dd.with_still_open(model([WAF]), picks(), PLAIN)
    assert m["headline"] == ("Nothing urgent today. This week: put a web firewall in front of the sign-in on "
                             "ftp.commandmi.com.")                      # the model, subject and text: unchanged
    assert dd.hero_words(m) == ("Nothing urgent today. One job for this week.",
                                "Put a web firewall in front of the sign-in on ftp.commandmi.com.", ["ftp.commandmi.com"])
    html = html_for(m)
    assert ">Nothing urgent today. One job for this week.</h1>" in html
    assert "Put a web firewall in front of the sign-in on <span" in html
    # at the top the site is never bare text a mail program can turn into a link (a word joiner
    # follows each dot); the same holds for the pills on the Still open cards
    top = html.split("<body", 1)[1].split(">This week</h2>", 1)[0]
    assert "ftp.commandmi.com" not in top and "ftp.&#8288;commandmi.&#8288;com" in top
    still = html.split(">Still open &nbsp;", 1)[1]
    assert "ftp.commandmi.com" not in still and "ftp.&#8288;commandmi.&#8288;com" in still
    assert f"<title>{dd.escape(m['headline'])}</title>" in html


def test_one_thing_for_today_is_counted_and_named():
    high = ("h1", "shop.example.com", "Obsolete 3DES/IDEA ciphers offered", "HIGH", "detected", "testssl", NOW)
    m = model([high, WAF])
    head, job, _sites = dd.hero_words(m)
    assert head == "One thing for today. Plus one for this week." and job.endswith(".") and job[0].isupper()
    assert f">{head}</h1>" in html_for(m)


def test_a_job_that_starts_with_its_sites_name_keeps_the_name_and_its_pill():
    m = model([WAF])
    m["ticket"][0]["headline"] = "ftp.commandmi.com needs a web firewall"
    m["headline"] = dd.headline(0, 1, m["do"], m["ticket"], since=m.get("since", "yesterday"))
    assert dd.hero_words(m) == ("Nothing urgent today. One job for this week.",
                                "ftp.commandmi.com needs a web firewall.", ["ftp.commandmi.com"])
    top = html_for(m).split("<body", 1)[1].split(">This week</h2>", 1)[0]
    assert "ftp.&#8288;commandmi.&#8288;com</span> needs a web firewall." in top and "Ftp." not in top


def test_other_days_and_a_headline_set_elsewhere_are_left_alone():
    quiet = model()
    assert dd.hero_words(quiet) == (quiet["headline"], "", [])
    two = model([WAF, ("x1", "a.example.com", "DNS missing SPF record", "MODERATE", "detected", "commandsentry_light", NOW)])
    assert dd.hero_words(two) == (two["headline"], "", [])
    own = dict(model([WAF]), headline="Something the voice wrote.")
    assert dd.hero_words(own) == ("Something the voice wrote.", "", [])
    assert ">Something the voice wrote.</h1>" in html_for(own)


def test_the_numbers_under_the_headline():
    m = dd.with_still_open(model([WAF]), picks(), PLAIN)
    html = html_for(m)
    b = m["brand"]
    for n, label in ((0, "urgent today"), (1, "for this week"), (3, "still open, no change")):
        # full: the band's colors reversed; empty: the band's own text color on a shade of the band
        assert f'font-weight:800;color:{b["band_bg"] if n else b["band_text"]};">{n}</div>' in html
        assert f">{label}</div>" in html
    assert f'bgcolor="{b["band_text"]}" style="background:{b["band_text"]};border-radius:12px;"><tr><td class="tile"' in html
    assert dd._mix("#0A4595", "#FFFFFF", 0.09) == "#20569F" and dd._mix("#FFFFFF", "#14161B", 0.09) == "#EAEAEA"
    assert dd._mix("#000000", "#FFFFFF", 0) == "#000000" and dd._mix("#000000", "#FFFFFF", 1) == "#FFFFFF"
    assert "fixed since" not in html
    # on a white band (Prodex's) a full tile is ink with a white number, never white on white
    white = dict(m, brand=dict(b, band_bg="#FFFFFF", band_text="#14161B", band_muted="#56606B"))
    wh = html_for(white)
    assert wh.count('bgcolor="#14161B" style="background:#14161B;border-radius:12px;"><tr><td class="tile"') == 2
    assert 'font-weight:800;color:#FFFFFF;">1</div>' in wh and 'font-weight:800;color:#14161B;">0</div>' in wh
    assert "background:#14161B;color:#FFFFFF;font-weight:800;font-size:15px" in wh       # the site pill under the headline
    # no still-open lines (the voice path): no still-open tile, never a false zero
    assert "still open, no change" not in html_for(model([WAF]))
    # a day with nothing in it: no row of zeros
    assert "urgent today" not in html_for(model())


def test_a_card_has_a_solid_header_in_its_grades_color_and_the_fix_in_a_panel():
    m = model([WAF])
    html = html_for(m)
    fill, on, tint = dd.SEV_STYLE["MODERATE"]
    assert f'bgcolor="{fill}"' in html and f'bgcolor="{tint}"' in html
    assert f"color:{on};text-decoration:none;" in html           # the title, linked to the finding, on the header
    assert ">What it means</div>" in html and ">The fix, for your IT team</div>" in html
    assert 'What it means:</span>' not in html
    # the weekly shares the card
    assert "dd._card(" in __import__("inspect").getsource(dwk.render_weekly_html)


def test_the_button_is_full_width():
    html = html_for(model([WAF]))
    assert 'display:block;padding:16px 18px' in html and ">Open the portal &rarr;</a>" in html
