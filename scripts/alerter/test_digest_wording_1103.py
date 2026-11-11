"""(KB 12 job 3l, 2026-11-03) The daily's wording, four fixes Howie ruled one at a time.

From the read of Command's daily of Nov 3 (digest_pending id 9):
- W1 (Howie 12:00, "Yeah, that's fine."): test.commandcommcentral.com and 52.119.65.6 are one
  machine (discovery recorded the name pointing to the address), so the daily says it once,
  name first: "test.commandcommcentral.com (52.119.65.6): no answer since …", and counts 1.
- W2 (12:06, "None of our names here is absolutely fine."): a bare address has no name, so
  not "Its name still points to an address". A lone silent address says what is known: our
  names that point to it, else a real reverse-lookup name, else whose network it is on and
  that none of our names point there.
- W3 (12:07, "Yes, I like it."): "The fix" was the scanner's FIRST step, often preparation.
  Common kinds get one plain fix sentence; a kind without one says "First step", never "The fix".
- W4 (12:11): "Sent at 7:11 AM" was the build time; it says "Sentry's checks as of 7:11 AM."
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
import digest_slack as ds  # noqa: E402
import digest_voice as dv  # noqa: E402
import digest_weekly as dwk  # noqa: E402
import digest_words as dw  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
W0 = datetime(2026, 11, 2, 12, 12, tzinfo=UTC)
W1 = datetime(2026, 11, 3, 12, 11, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Command")
LAST = datetime(2026, 10, 27, 13, 13, tzinfo=UTC)          # 9:13 AM in New York
LEAVES = datetime(2026, 11, 7, 1, 12, tzinfo=UTC)          # Nov 6 in New York

# (asset_id, last_answer_at, reason, notice_since, leaves_on) — SQL_NOT_RESPONDING's shape, as on Nov 3
IP_ROW = ("52.119.65.6", LAST, "no_answer", LAST, LEAVES)
NAME_ROW = ("test.commandcommcentral.com", LAST, "no_answer", LAST, LEAVES)
# SQL_QUIET_WHERE as read live 2026-11-03 (SELECT only), through quiet_where_map
WHERE = ra.quiet_where_map([
    ("52.119.65.6", None, ["test.commandcommcentral.com"], "Natural Wireless, LLC", "6.65.119.52.naturalwireless.com"),
    ("test.commandcommcentral.com", ["52.119.65.6"], None, None, None),
])


def model(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              baseline={}, brand=BRAND)
    kw.update(over)
    return dd.build_model(**kw)


def _block(m):
    # job 4x (2026-11-05): the block moved from Needs you today to This week
    got = [i for i in m["ticket"] if i["kind"] == "not_responding"]
    assert not [i for i in m["do"] if i["kind"] == "not_responding"]
    return got[0] if got else None


# ── W1: one machine, said once ────────────────────────────────────────────────
def test_a_name_and_its_address_are_one_line_name_first():
    b = _block(model(not_responding=[IP_ROW, NAME_ROW], quiet_where=WHERE))
    assert b["title"] == "1 host is not responding"
    assert b["lines"] == ["test.commandcommcentral.com (52.119.65.6): no answer since Oct 27, 9:13 AM. "
                          "Its name still points to an address, but nothing answers there. Leaves the portal on Nov 6."]


def test_the_top_line_counts_the_machine_once():
    m = model(not_responding=[IP_ROW, NAME_ROW], quiet_where=WHERE)
    assert m["headline"] == "Nothing urgent today. This week: 1 host is not responding."     # job 4x
    text = dd.render_text(m, portal_url="", product_name="COMMANDsentry")
    assert "  [ ] 1 host is not responding" in text
    assert "      - test.commandcommcentral.com (52.119.65.6): no answer since Oct 27, 9:13 AM." in text
    assert "      - 52.119.65.6:" not in text


def test_the_html_puts_the_name_in_bold_and_the_address_beside_it():
    html = dd.render_html(model(not_responding=[IP_ROW, NAME_ROW], quiet_where=WHERE),
                          portal_url="https://p.example", product_name="COMMANDsentry")
    assert ('<span style="font-weight:700;">test.commandcommcentral.com</span> (52.119.65.6): '
            'no answer since Oct 27') in html


def test_they_fold_only_when_discovery_recorded_the_name_pointing_there():
    other = ra.quiet_where_map([("test.commandcommcentral.com", ["52.119.65.99"], None, None, None),
                                ("52.119.65.6", None, None, "Natural Wireless, LLC", "6.65.119.52.naturalwireless.com")])
    b = _block(model(not_responding=[IP_ROW, NAME_ROW], quiet_where=other))
    assert b["title"] == "2 hosts are not responding"
    assert b["lines"][1].startswith("test.commandcommcentral.com: no answer")


def test_not_read_folds_nothing_and_claims_nothing():
    b = _block(model(not_responding=[IP_ROW, NAME_ROW]))           # quiet_where None
    assert b["title"] == "2 hosts are not responding"
    assert b["lines"][0] == ("52.119.65.6: no answer since Oct 27, 9:13 AM. Nothing answers at this "
                             "address. Leaves the portal on Nov 6.")
    assert "none of our names" not in " ".join(b["lines"])


def test_a_silent_name_whose_address_still_answers_keeps_its_own_line():
    b = _block(model(not_responding=[NAME_ROW], quiet_where=WHERE))
    assert b["lines"] == ["test.commandcommcentral.com: no answer since Oct 27, 9:13 AM. Its name still "
                          "points to an address, but nothing answers there. Leaves the portal on Nov 6."]


# ── W2: a bare address says what is known ─────────────────────────────────────
def _ip_line(where):
    return _block(model(not_responding=[IP_ROW], quiet_where=ra.quiet_where_map(where)))["lines"][0]


def test_a_lone_address_on_a_stock_name_says_whose_network_and_no_names_of_ours():
    assert _ip_line([("52.119.65.6", None, None, "Natural Wireless, LLC", "6.65.119.52.naturalwireless.com")]) == (
        "52.119.65.6 (on Natural Wireless's network; none of our names point here): no answer since Oct 27, "
        "9:13 AM. Nothing answers at this address. Leaves the portal on Nov 6.")


def test_a_lone_address_with_a_name_of_ours_pointing_to_it_says_so():
    assert _ip_line([("52.119.65.6", None, ["test.commandcommcentral.com"], "Natural Wireless, LLC", None)]
                    ).startswith("52.119.65.6 (test.commandcommcentral.com points here): no answer")
    many = _ip_line([("52.119.65.6", None, ["a.example", "b.example"], None, None)])
    assert many.startswith("52.119.65.6 (a.example, b.example point here): ")


def test_a_lone_address_with_a_real_reverse_name_shows_it():
    line = _block(model(not_responding=[("24.157.51.94", LAST, "no_answer", LAST, LEAVES)],
                        quiet_where=ra.quiet_where_map([("24.157.51.94", None, None, "Cablevision Systems Corp.",
                                                         "mail.commandweb.com")])))["lines"][0]
    assert line.startswith("24.157.51.94 (listed as mail.commandweb.com): no answer since Oct 27")


def test_a_lone_address_with_nothing_recorded_still_says_no_names_of_ours():
    assert _ip_line([]).startswith("52.119.65.6 (none of our names point here): no answer")


def test_a_bare_address_never_gets_the_name_sentence():
    assert dd.not_responding_line(IP_ROW, BRAND) == (
        "52.119.65.6: no answer since Oct 27, 9:13 AM. Nothing answers at this address. Leaves the portal on Nov 6.")
    never = ("10.0.0.9", None, "never_answered", None, None)
    assert dd.not_responding_line(never, BRAND).endswith("Sentry has never had an answer from this address.")
    assert dd.not_responding_line(("2001:db8::5", LAST, "no_answer", None, None), BRAND).endswith(
        "Nothing answers at this address.")


def test_stock_names_and_real_names():
    assert dd.is_stock_name("6.65.119.52.naturalwireless.com", "52.119.65.6")
    assert dd.is_stock_name("189d3346.cst.lightpath.net", "24.157.51.70")
    assert dd.is_stock_name("c-24-157-51-70.hsd1.example.net", "24.157.51.70")
    assert dd.is_stock_name("ec2-3-33-152-147.compute-1.amazonaws.com", "3.33.152.147")
    assert dd.is_stock_name("", "52.119.65.6") and dd.is_stock_name(None, "52.119.65.6")
    assert not dd.is_stock_name("mail.commandweb.com", "24.157.51.94")
    assert not dd.is_stock_name("6.65.119.53.naturalwireless.com", "52.119.65.6")   # someone else's digits


def test_network_names_lose_the_company_suffix():
    assert dd.network_words("Natural Wireless, LLC") == "Natural Wireless"
    assert dd.network_words("Cablevision Systems Corp.") == "Cablevision Systems"
    assert dd.network_words("Microsoft Corporation") == "Microsoft"
    assert dd.network_words("Amazon.com, Inc.") == "Amazon.com"
    assert dd.network_words(None) == ""


# ── W3: the real fix, or an honest "First step" ───────────────────────────────
def test_the_common_kinds_get_a_plain_fix_sentence():
    for title, starts in (
            ("Missing security header: Strict-Transport-Security", "Turn on HSTS for this site"),
            ("Missing security header: Content-Security-Policy", "Add a Content-Security-Policy header"),
            ("Content-Security-Policy does not limit scripts", "Tighten the Content-Security-Policy"),
            ("DNS missing DMARC record", "Publish a DMARC record"),
            ("DMARC policy set to p=none (monitoring only)", "Move the domain's DMARC policy"),
            ("DNS missing SPF record", "Publish an SPF record (a TXT record on the domain) listing the services"),
            ("Missing security header: X-Frame-Options", "Have the web server on this site send X-Frame-Options"),
            ("Missing security header: X-Content-Type-Options", "Have the web server on this site send the header"),
            ("Missing security header: Referrer-Policy", "Have the web server on this site send a Referrer-Policy"),
            ("Missing security header: Permissions-Policy", "Have the web server on this site send a Permissions-Policy"),
            ("Security headers missing or weak", "Add the missing security headers to this site")):
        fix = dw.plain_fix(title, 1)
        assert fix.startswith(starts), (title, fix)
        assert not any(c.isdigit() for c in fix), (title, fix)        # the voice writer's numbers rule
    assert dw.plain_fix("Missing security header: Strict-Transport-Security", 2).startswith("Turn on HSTS for these sites")
    assert dw.plain_fix("Some other finding", 1) == ""


def test_a_plain_fix_changes_only_the_fix_not_the_title_or_the_grouping():
    for title in ("DNS missing SPF record", "Missing security header: Content-Security-Policy"):
        w = dw.words(title, 1)
        assert w["title"] == title and w["key"] == "" and w["do"]
        assert dw.family_key(title) == title.lower()
    assert dw.words("HSTS not enabled")["do"] == ""                    # a minor family: unchanged


def _grouped(title, hint):
    rows = [("pay.commandmi.com:light:x", "pay.commandmi.com", title, "MODERATE", "detected", "commandsentry_light", W1)]
    return dd.group_problems(rows, {"pay.commandmi.com"}, hints={"pay.commandmi.com:light:x": hint})[0]


def test_the_scanner_first_step_is_used_only_when_there_is_no_plain_fix_and_is_labelled_so():
    spf = _grouped("DNS missing SPF record", "1. Inventory all services that send email using the domain.")
    assert spf["do"].startswith("Publish an SPF record") and spf["do_raw"] is False
    assert dd.fix_label(spf) == "The fix, for your IT team:"
    other = _grouped("Some other finding", "1. Identify the web server serving the site. 2. Change it.")
    assert other["do"] == "Identify the web server serving the site." and other["do_raw"] is True
    assert dd.fix_label(other) == "First step, for your IT team:"


def test_both_renderings_and_the_weekly_say_first_step():
    item = dict(_grouped("Some other finding", "Identify the web server serving the site."), severity="MODERATE")
    m = model()
    m["ticket"] = [item]
    text = dd.render_text(m, portal_url="", product_name="COMMANDsentry")
    assert "      First step, for your IT team: Identify the web server serving the site." in text
    assert "The fix, for your IT team: Identify" not in text
    html = dd.render_html(m, portal_url="https://p.example", product_name="COMMANDsentry")
    # 2026-11-11 redesign: the fix sits in its own panel, the label on its own line
    assert ">First step, for your IT team</div>" in html and ">Identify the web server serving the site.</div>" in html
    assert "The fix, for your IT team" not in html
    assert "dd.fix_label(i, kinds=('finding',))" in inspect.getsource(dwk.render_weekly_text)


# ── W4: the time at the bottom ────────────────────────────────────────────────
def test_the_text_says_how_fresh_the_facts_are_not_when_it_was_sent():
    text = dd.render_text(model(), portal_url="", product_name="COMMANDsentry")
    assert "Sentry's checks as of 7:11 AM. Where every site stands" in text
    assert "Sent at" not in text
    src = inspect.getsource(dv)
    assert "Sentry's checks as of {local_end:%-I:%M %p}." in src and "Sent at {local_end" not in src


# ── the voice and the Slack half read the host before the brackets ────────────
FOLDED = ("test.commandcommcentral.com (52.119.65.6): no answer since Oct 27, 9:13 AM. Its name still "
          "points to an address, but nothing answers there. Leaves the portal on Nov 6.")
NOTED = ("52.119.65.6 (on Natural Wireless's network; none of our names point here): no answer since Oct 27, "
         "9:13 AM. Nothing answers at this address. Leaves the portal on Nov 6.")


def test_the_voice_keeps_the_host_and_drops_the_note():
    assert dv._plain_quiet(FOLDED) == ("test.commandcommcentral.com: looks down since Oct 27. "
                                       "Drops off the portal on Nov 6 if it stays down.")
    assert dv._plain_quiet(NOTED).startswith("52.119.65.6: looks down since Oct 27.")
    assert dv._line_host(FOLDED) == "test.commandcommcentral.com" and dv._line_host(NOTED) == "52.119.65.6"
    assert dv._line_host("commandmi.com: first seen Nov 2, rated low") == "commandmi.com"


def test_the_voice_never_shortens_an_address_to_its_first_number():
    assert dv._short("52.119.65.6") == "52.119.65.6" and dv._short("2001:db8::5") == "2001:db8::5"
    assert dv._short("test.commandcommcentral.com") == "test"


def test_slack_matches_the_folded_line_to_its_host():
    item = {"kind": "not_responding", "severity": "", "title": "1 host is not responding", "lines": [FOLDED]}
    got = ds.changed_items({"do": [item]}, quiet_news={"test.commandcommcentral.com"})
    assert got and got[0]["sites"] == ["test.commandcommcentral.com"] and got[0]["lines"] == [FOLDED]
    assert ds.changed_items({"do": [item]}, quiet_news={"other.example"}) == []


# ── the send path ─────────────────────────────────────────────────────────────
def test_the_send_path_reads_where_the_silent_hosts_point_and_passes_it_on():
    src = inspect.getsource(ra.main)
    assert "quiet_where = _read_quiet_where(conn, not_responding)" in src
    assert "reach_checks=reach_checks, quiet_where=quiet_where," in src
    assert "quiet_where=quiet_where" in inspect.getsource(ra._digest_model)
    sql = " ".join(ra.SQL_QUIET_WHERE.split())
    assert "JOIN public.assets a ON a.asset_id = r.name AND a.ownership = 'owned'" in sql
    assert "sub->'dns'->'aaaa'" in sql and "h->>'asn_org'" in sql and "h->>'reverse_dns'" in sql
    # a failed read is None (claim nothing), never [] (which would say "none of our names")
    assert "return None" in inspect.getsource(ra._read_quiet_where)


def test_no_silent_hosts_reads_nothing():
    class Boom:
        def transaction(self):
            raise AssertionError("must not read")
    assert ra._read_quiet_where(Boom(), []) == {}
    assert ra._read_quiet_where(Boom(), None) == {}
