"""The site a card is about leads the card, in its largest type (push 444).

Howie, 2026-11-17 07:46, on the morning Command email: "the identification of the actual asset
that's being discussed is in too-small letters. It's hard to determine, in the world, which asset
they're talking about." On the mock (08:05, 08:09): one site, its name at the top of the card,
"is perfect"; several sites, one bullet each ("A is fine").

Only where the name sits and how big it is. The words, the text email, the subject, the headline
and what is recorded as told do not change.
"""
from __future__ import annotations

import os
import re
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import digest_daily as dd  # noqa: E402
import test_daily_redesign_1111 as base  # noqa: E402

J = ".&#8288;&#8203;"          # after each dot: no link (word joiner), and a line may end there (zero-width space)


def shown(name: str) -> str:
    return dd.escape(name).replace(".", J)


def still_html(rows, plain=None):
    m = dd.with_still_open(base.model(), base.picks(rows), plain or base.PLAIN)
    return base.html_for(m).split(">Still open &nbsp;", 1)[1]


def one_card(html: str, title: str) -> str:
    """The card that carries this title: from the start of its own row to the end of it."""
    at = html.index(dd.escape(title))
    start = html.rindex('<td class="cnt"', 0, at)
    end = html.find('<td class="cnt"', at)
    return html[start:end if end > 0 else len(html)]


ONE = [base.row("p1", "commandmarketinginnovations.com", "Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)",
                source="wpscan", first=(2026, 5, 4))]


def test_one_site_its_name_is_first_on_the_card_and_the_largest_type_on_it():
    card = one_card(still_html(ONE), "Mega Main Menu")
    name = f'font-size:22px;line-height:1.25;font-weight:800;color:{dd.CHIP_TEXT};'
    assert card.count(">" + shown("commandmarketinginnovations.com") + "</div>") == 1
    assert name in card
    # the order down the card: the name, the grade and since-when, the title, what it is, the fix
    order = [card.index(shown("commandmarketinginnovations.com")), card.index(">Moderate<"), card.index(">Open since May 4<"),
             card.index("Mega Main Menu"), card.index("The fix")]
    assert order == sorted(order)
    # nothing in the words part of the card is set larger than the name
    words = card.split('class="card"', 1)[1]
    assert max(int(n) for n in re.findall(r"font-size:(\d+)px", words)) == 22
    # the title is still there, a size down, and the old small pill is gone
    assert 'font-size:16px;line-height:1.35;font-weight:700' in words
    assert "padding:5px 12px" not in card and "font-size:13px;font-weight:700;color:" not in card


def test_several_sites_one_bullet_each_a_size_down():
    card = one_card(still_html(base.ROWS), "Nothing stops email")
    for site in base.SPF_SITES:
        assert card.count(f">{shown(site)}</td></tr>") == 1
    assert card.count("&bull;") == 3 and "font-size:19px" in card and "font-size:22px" not in card
    assert card.index(shown(base.SPF_SITES[0])) < card.index(">Moderate<") < card.index("Nothing stops email")
    assert ">3</div>" in card and ">sites</div>" in card             # the count block still says how many


def test_five_or_more_sites_a_size_down_again_and_past_twelve_the_rest_are_counted():
    seven = [base.row(f"m{i}", f"site{i}.example.com", "DNS missing DMARC record", source="commandsentry_light")
             for i in range(7)]
    card = one_card(still_html(seven), "Forged email")
    assert card.count("&bull;") == 7 and 'class="s3"' in card and "font-size:19px" not in card
    assert "font-size:16px;line-height:1.4;font-weight:800" in card
    many = [f"s{i:02d}.example.com" for i in range(15)]
    html = dd._site_names(many)
    assert html.count("&bull;") == 12 and ">and 3 more</div>" in html and shown("s12.example.com") not in html


def test_no_sites_no_name_block_and_the_tags_sit_flush():
    assert dd._site_names([]) == ""
    card = dd._still_card({"severity": "MODERATE", "card": {
        "title": "Something", "what": "", "sites": [], "count": 0, "unit": "sites", "note": "", "since": None,
        "do": "", "fix_label": ""}})
    assert "&bull;" not in card and 'class="s1"' not in card and '<div style="padding-top:0px;">' in card


def test_a_name_is_never_bare_text_and_a_long_one_may_only_wrap_after_a_dot_or_as_a_last_resort():
    html = dd._site_names(["zoetislabs.unimacgraphics.com"])
    assert "zoetislabs.unimacgraphics.com" not in html and shown("zoetislabs.unimacgraphics.com") in html
    assert "white-space:nowrap" not in html and "overflow-wrap:anywhere" in html
    two = dd._site_names(["a.example.com", "<b>.example.com"])
    assert "<b>" not in two and "&lt;b&gt;" in two and "overflow-wrap:anywhere" in two


def test_the_cards_at_the_top_name_the_site_in_the_header_and_not_as_a_chip_under_it():
    m = dd.with_still_open(base.model([base.WAF]), base.picks(), base.PLAIN)
    html = base.html_for(m)
    week = html.split(">This week</h2>", 1)[1].split(">Still open &nbsp;", 1)[0]
    head, body = week.split("border-radius:0 0 14px 14px", 1)
    assert shown("ftp.commandmi.com") in head and "ftp." not in body
    assert head.index(shown("ftp.commandmi.com")) < head.index(">Moderate<") < head.index("No web firewall")
    assert "font-size:22px" in head and 'font-size:16px;line-height:1.35;font-weight:700' in head
    assert "border:1px solid #D6DEE8;border-radius:999px" not in week       # the white chip is gone from these cards
    # the name is in the header's own text colour (dark on the yellow of Moderate), never the blue of the open cards
    on = dd.SEV_STYLE["MODERATE"][1]
    assert f'font-weight:800;color:{on};' in head and f'color:{dd.CHIP_TEXT};' not in head


def test_on_a_high_card_the_name_is_in_the_headers_white_like_its_title():
    high = ("h1", "shop.example.com", "Obsolete 3DES/IDEA ciphers offered", "HIGH", "detected", "testssl", base.NOW)
    html = base.html_for(base.model([high]))
    today = html.split(">Needs you today</h2>", 1)[1].split("Open the portal", 1)[0]
    fill, on = dd.SEV_STYLE["HIGH"][0], dd.SEV_STYLE["HIGH"][1]
    assert f'bgcolor="{fill}"' in today
    assert f'font-size:22px;line-height:1.25;font-weight:800;color:{on};' in today
    assert shown("shop.example.com") in today and f'color:{dd.CHIP_TEXT};' not in today.split(shown("shop.example.com"), 1)[0]


def test_a_top_card_with_no_site_keeps_its_large_title():
    card = dd._card({"title": "Sentry could not reach three hosts", "kind": "coverage", "severity": ""}, "")
    assert "font-size:20px;line-height:1.25;font-weight:800" in card and 'class="s1"' not in card


def test_on_a_phone_the_names_step_down_a_size():
    html = base.html_for(base.model())
    assert ".s1{font-size:19px !important}" in html and ".s2{font-size:17px !important}" in html
    assert ".s3{font-size:15px !important}" in html


def test_the_text_email_the_subject_and_the_headline_do_not_change():
    m = dd.with_still_open(base.model([base.WAF]), base.picks(), base.PLAIN)
    text = dd.render_text(m, portal_url="https://p.example", product_name="COMMANDsentry")
    assert "      Sites: ftp.commandmi.com" in text and "STILL OPEN" in text
    assert all(l["text"] in text for l in m["still_open"])
    assert m["headline"].startswith("Nothing urgent today. This week:")
    assert dd.subject(m, "COMMANDsentry").startswith("[COMMANDsentry] Command, Wednesday:")


def test_the_weekly_emails_chips_are_left_as_they_were():
    chips = dd.chips(["a.example.com", "b.example.com"])
    assert chips.count("border-radius:999px") == 2 and "font-size:13px" in chips
