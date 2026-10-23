"""(KB 12 job 3l, slice 1, 2026-10-22) The daily digest as a to-do list.

Howie, 08:50: "This entire email needs to be simplified and redesigned." 14:45: "Let's have it be
colorful … instead of throwing together a bunch of data that is almost impossible to understand."
15:12, on design D: "Happy, I'm thrilled." Plan: KB wrap-up 2026-10-22 1530 (reviewed by GLM-5.3,
no must-fixes; nine minors taken in its Review response). Reworked after Howie read the first
test sends (19:08–19:57): no "ticket", plain words, no risk tally in the daily, guesses left out.

Pinned here: the buckets (every part of the old email has a home), grouping by problem across
sites, www. folded into its site, the health bar (with CRITICAL and MODERATE-HIGH bands and the
honest "not scanned yet" / "all clear" split), the yesterday rebuild's SQL, certificates counted
only while the latest deep scan still sees them, "first deep scan since", the subject, an
email-safe page (tables, inline images by Content-ID, no flex/grid/script), and the mailer's
inline images on both paths with today's MIME shape kept when there are none.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import mailer  # noqa: E402
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
W0 = datetime(2026, 10, 21, 12, 9, tzinfo=UTC)
W1 = datetime(2026, 10, 22, 12, 9, tzinfo=UTC)
FW = "Runs Fortinet FortiWeb, version not shown — 4 advisories on CISA’s exploited list: confirm it’s patched"


def F(fid, asset, title, sev, src="commandsentry_light"):
    return (fid, asset, title, sev, "detected", src, W1)


def model(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              baseline={}, brand=dict(dd.DEFAULT_BRAND, short_name="Command"))
    kw.update(over)
    return dd.build_model(**kw)


# ── sites, folding, the bar ─────────────────────────────────────────────────────────
def test_www_folds_into_its_site_only_when_the_plain_name_is_live():
    names = {"commandcompanies.com", "www.commandcompanies.com", "www.only.example"}
    assert dd.site_of("www.commandcompanies.com", names) == "commandcompanies.com"
    assert dd.site_of("www.only.example", names) == "www.only.example"


def test_a_site_takes_the_worst_of_its_hosts_and_the_bands_split_not_rated_honestly():
    rows = [("a.example", "MODERATE", True, "MODERATE"), ("www.a.example", "CRITICAL", True, "MODERATE"),
            ("ns01.b.example", "UNKNOWN", True, None), ("new.c.example", "UNKNOWN", False, None),
            ("d.example", "MODERATE-HIGH", True, "MODERATE"), ("e.example", "INFO", True, None)]
    now, then = dd.site_bands(rows)
    assert now == {"a.example": "critical", "ns01.b.example": "clear", "new.c.example": "unscanned",
                   "d.example": "modhigh", "e.example": "low"}
    assert then["a.example"] == "moderate"
    c = dd.band_counts(now)
    assert c["critical"] == 1 and c["modhigh"] == 1 and c["clear"] == 1 and c["unscanned"] == 1
    assert dd.counts_words(c) == "1 critical, 1 moderate-high, 1 low, 1 all clear, 1 not scanned yet"


def test_change_words_say_which_way_each_site_went():
    """Howie, 10-22: "What the hell does up or down actually mean?" — riskier / safer, by site,
    with the levels; a site rated for the first time is not a move."""
    same = {"critical": 0, "high": 2, "modhigh": 0, "moderate": 5, "low": 1, "clear": 1, "unscanned": 0}
    assert dd.change_words(same, dict(same, clear=0, unscanned=1)) == "No site's risk level changed since yesterday."
    now = {"a": "critical", "b": "critical", "c": "moderate", "d": "low"}
    then = {"a": "moderate", "b": "moderate", "c": "high", "d": "unscanned"}
    assert dd.change_words({}, {}, now, then) == \
        "Since yesterday, two sites got riskier (Moderate to Critical); c got safer (High to Moderate)."


def test_the_daily_leads_with_the_job_and_carries_no_risk_tally():
    """Howie, 10-22, on the risk boxes above "One thing for today": "What do I have to do with
    this risk level? This needs to be completely redone." The daily says what to do; where every
    site stands is the weekly's (its labeled boxes are pinned here)."""
    m = model(sites=[("a.example", "CRITICAL", True, "MODERATE"), ("b.example", "MODERATE", True, "MODERATE")],
              new_findings=[F("h", "a.example", "Exposed panel", "HIGH")])
    html = dd.render_html(m, portal_url="https://p.example", product_name="X")
    assert "by risk level" not in html and "Open across" not in html
    assert html.index("<h1") < html.index("Needs you today") < html.index("Sent by")
    t = dd.tally({"critical": 1, "moderate": 1}, {"critical": 0, "moderate": 2}, "x")
    assert ">Critical<" in t and ">Moderate<" in t and "was 0" in t and "was 2" in t
    assert t.index("#8B1A4A") < t.index("#FFD43B"), "worst level first"


def test_the_yesterday_rebuild_uses_the_one_rule_and_the_dedup_views_closed_set():
    sql = " ".join(ra.SQL_SITE_RATINGS.split())
    assert "a.ownership = 'owned' AND a.discovery_status = 'confirmed_live'" in sql, "D2's gate (minor 6)"
    for st in ("false_positive", "wont_fix", "accepted_risk", "closed_reclassified", "detector_retired"):
        assert f"'{st}'" in sql, st
    assert "f.first_detected_at <= %(t)s" in sql and "f.remediated_at > %(t)s" in sql
    assert "f.severity::text <> 'INFO'" in sql
    assert "a.current_risk::text" in sql and "ever_found" in sql


# ── buckets ─────────────────────────────────────────────────────────────────────────
def test_every_part_of_the_old_email_has_a_home():
    """The 15 parts of the old email (plan Review response 1): each lands in a bucket or the
    header/footer; nothing that needs Howie lands below Do today."""
    now = W1
    stale = [("lost.example", None, None, None, None, True, True, False, "discovery", False)]
    canary = [("www.c.example", "ct_ghost", "owned", None)]
    hot = F("h", "a.example", "Exposed admin panel", "HIGH")
    mod = F("m", "b.example", "Missing CSP", "MODERATE")
    reg = F("r", "c.example", "Old cipher", "MODERATE-HIGH")
    conf = F("c", "d.example", "Weak TLS", "MODERATE")
    low = F("l", "e.example", "Header missing", "LOW")
    info = F("i", "e.example", "Tech seen", "INFO")
    fixed = F("x", "f.example", "Was broken", "HIGH")
    hi = [("g.example", "g", "o", "HIGH", "1 open; top: Something", now)]
    new_a = [("n.example", "n", "o", now, "MODERATE")]
    dark = [("k.example", "k", "o", now, {"last_seen": "2026-10-20"})]
    back = [("bk.example", "bk", "o", now, now - timedelta(days=3))]
    stop = ("s.example", "s", "o", now, False, True, now - timedelta(days=7), [])
    start = ("t.example", "t", "o", now, True, False, now - timedelta(days=7), [])
    unrec = [("u.example", "u", "o", now, [{"status": 403}])]
    certs = [("z.example", "TLS certificate expiring soon — expires < 30 days (5)", now - timedelta(days=1))]
    m = model(new_findings=[hot, mod, low, info], regressed=[reg], confirmed=[conf], fixed=[fixed],
              high_risk=hi, new_assets=new_a, dark_assets=dark, came_back=back,
              enforcement_flips=[stop, start], unrecognized_pages=unrec, stale_assets=stale,
              canary_violations=canary, certs=certs, baseline={"high_open": 1},
              stale_words=ra.stale_row_words)
    kinds = lambda b: [i["kind"] for i in m[b]]  # noqa: E731
    assert kinds("do") == ["coverage", "finding", "finding", "enforcement", "cert"]
    assert [i["title"] for i in m["do"] if i["kind"] == "finding"] == ["Old cipher", "Exposed admin panel"]
    assert [i["tag"] for i in m["do"] if i["kind"] == "finding"] == ["Came back after being fixed", ""]
    assert [i["tag"] for i in m["ticket"] if i["kind"] == "finding"] == ["", "Confirmed by a second scan"]
    assert kinds("ticket") == ["finding", "finding", "rating", "blockpage", "assets", "dark"]
    assert kinds("done") == ["fixed", "back", "blocking"]
    assert m["low"] == 1 and m["info"] == 1
    assert m["degraded"] and m["headline"] == "Five things for today, six for this week."
    assert m["minor"] == [("e.example", "Header missing")]


WAF = "No enforcing WAF in front of live application"


def test_findings_group_by_problem_across_sites_worst_first_in_plain_words():
    rows = [F(f"w{i}", h, WAF, "CRITICAL", "commandsentry_heavy") for i, h in
            enumerate(["api.x.com", "www.x.com", "x.com", "e2.y.com"])] + [F("a", "q.com", "Exposed panel", "HIGH")]
    items = dd.group_problems(rows, {"api.x.com", "www.x.com", "x.com", "e2.y.com", "q.com"})
    assert [i["title"] for i in items] == ["No web firewall in front of these sites", "Exposed panel"]
    assert items[0]["sites"] == ["api.x.com", "e2.y.com", "x.com"], "www. folded, sorted, once"
    assert items[0]["body"].startswith("Our harmless test attacks walked straight in")
    assert items[0]["do"].startswith("Put a web application firewall in front of these sites")
    assert items[0]["who"] == "it" and items[0]["headline"] == "put a web firewall in front of api.x.com, e2.y.com and x.com"


def test_a_guess_is_not_listed_counted_or_mentioned():
    """Howie, 10-22: "There are risks and there are things that are known, that's all."
    "Version not shown" is neither. The site's level comes from SQL_SITE_RATINGS, which
    leaves guesses out (api.x.com: Moderate, not the portal's Critical)."""
    m = model(new_findings=[F("fw", "api.x.com", FW, "CRITICAL", "advisory_watch")],
              high_risk=[("api.x.com", "a", "o", "CRITICAL", f"1 open; top: {FW}", W1)],
              fixed=[F("wp", "b.x.com", "Runs WordPress, version not shown", "HIGH", "advisory_watch")],
              sites=[("api.x.com", "MODERATE", True, "MODERATE")])
    assert m["do"] == [] and m["ticket"] == [] and m["done"] == []
    assert "guesses" not in m and m["change"] == "No site's risk level changed since yesterday."
    html = dd.render_html(m, portal_url="", product_name="X")
    text = dd.render_text(m, portal_url="", product_name="X")
    for out in (html, text):
        assert "FortiWeb" not in out and "WordPress" not in out
        assert "guess" not in out.lower() and "version" not in out.lower()
    assert m["headline"] == "Nothing needs you today."


def test_first_deep_scan_since_and_first_ever_and_unknown_says_nothing():
    rows = [F("1", "insite.s.com", "Old IIS page", "MODERATE", "commandsentry_heavy")]
    names = {"insite.s.com"}
    old = {"insite.s.com": datetime(2026, 7, 23, tzinfo=UTC)}
    assert dd.group_problems(rows, names, old, window_start=W0)[0]["why"] == \
        "New because this was its first deep scan since Jul 23; it may have been there a while."
    assert dd.group_problems(rows, names, {"insite.s.com": None}, window_start=W0)[0]["why"] == \
        "New because this was its first deep scan ever."
    recent = {"insite.s.com": W0 - timedelta(days=7)}
    assert dd.group_problems(rows, names, recent, window_start=W0)[0]["why"] == ""
    assert dd.group_problems(rows, names, {}, window_start=W0)[0]["why"] == ""


def test_the_do_line_is_the_first_step_and_only_for_a_one_site_problem():
    hint = {"a": "1. Identify the WAF product and its mode (monitor vs. prevention) — check the console. 2. Switch it.",
            "b": "1. Log in to the admin on one.example and record the version."}
    one = dd.group_problems([F("a", "one.example", "WAF not blocking", "HIGH")], {"one.example"}, hints=hint)
    assert one[0]["do"] == "Identify the WAF product and its mode (monitor vs. prevention) — check the console."
    two = dd.group_problems([F("b", "one.example", "P", "HIGH"), F("c", "two.example", "P", "HIGH")],
                            {"one.example", "two.example"}, hints=hint)
    assert two[0]["do"] == "", "a step written for one host is not advice for two"
    assert dd.first_step("") == "" and len(dd.first_step("1. " + "word " * 100)) <= 200


def test_ratings_that_went_up_skip_sites_today_already_explains():
    hot = F("h", "a.example", "Exposed panel", "HIGH")
    hi = [("a.example", "a", "o", "HIGH", "1 open; top: Exposed panel", W1),
          ("www.b.example", "b", "o", "HIGH", "2 open; top: Other thing", W1)]
    m = model(new_findings=[hot], high_risk=hi, sites=[("b.example", "HIGH", True, "MODERATE"),
                                                        ("www.b.example", "HIGH", True, "MODERATE")])
    (rating,) = [i for i in m["ticket"] if i["kind"] == "rating"]
    assert rating["lines"] == ["b.example is now High, because of: Other thing"]


# ── certificates ────────────────────────────────────────────────────────────────────
def test_cert_days_left_counts_from_the_last_check():
    row = ("ftp.u.com", "TLS certificate expiring soon — expires < 30 days (11)", datetime(2026, 10, 14, 20, 42, tzinfo=UTC))
    assert dd.cert_days_left(row, datetime(2026, 10, 22, 20, 0, tzinfo=UTC)) == 3   # expires Oct 25 20:42
    assert dd.cert_days_left(row, datetime(2026, 10, 23, 21, 0, tzinfo=UTC)) == 1
    assert dd.cert_days_left(("x", "no number", W1), W1) is None


def test_a_cert_counts_only_inside_14_days_and_reads_the_day_it_expires():
    mk = lambda n: ("h.example", f"TLS certificate expiring soon — expires < 60 days ({n})", W1)  # noqa: E731
    assert [i for i in model(certs=[mk(15)])["do"] if i["kind"] == "cert"] == []
    (c,) = [i for i in model(certs=[mk(3)])["do"] if i["kind"] == "cert"]
    assert c["title"] == "Renew the certificate on h.example" and c["severity"] == "HIGH"
    assert c["body"].startswith("It expires Sunday, Oct 25 (3 days).")
    assert c["who"] == "it" and c["do"].startswith("Install a renewed certificate")
    (e,) = [i for i in model(certs=[("h.example", "TLS certificate expiring soon — expires < 30 days (2)",
                                     W1 - timedelta(days=5))])["do"] if i["kind"] == "cert"]
    assert e["body"].startswith("It expired ")


def test_a_cert_warning_a_later_deep_scan_did_not_repeat_is_not_read():
    """⛔ The first render called commandcompanies.com's certificate expired: its warning was last
    seen 2026-09-22 and four deep scans since never repeated it (renewed; the row stayed open)."""
    sql = " ".join(ra.SQL_CERTS_EXPIRING.split())
    assert "NOT EXISTS ( SELECT 1 FROM public.scan_run r" in sql
    assert "r.intensity::text = 'heavy'" in sql and "r.status::text IN ('complete', 'degraded')" in sql
    assert "r.completed_at > f.last_observed_at + interval '10 minutes'" in sql
    assert "position('TLS certificate expiring soon' in f.title) = 1" in sql
    assert ra.SQL_CERTS_EXPIRING.count("%") == 0, "read without parameters: no percent signs"


# ── headline and subject ────────────────────────────────────────────────────────────
def test_headline_words():
    """Never "ticket" (Howie, 10-22: "We don't have any tickets"); one item names the job."""
    assert dd.headline(2, 1) == "Two things for today, one for this week."
    assert dd.headline(1, 0) == "One thing for today."
    assert dd.headline(0, 3) == "Nothing urgent today. Three things for this week."
    assert dd.headline(0, 1) == "Nothing urgent today. One thing for this week."
    assert dd.headline(0, 0) == "Nothing needs you today."
    assert dd.headline(12, 0) == "12 things for today."
    job = [{"title": "Renew the certificate on pm.u.com", "headline": ""}]
    assert dd.headline(1, 0, job) == "Today: renew the certificate on pm.u.com."
    assert dd.headline(1, 2, job) == "Today: renew the certificate on pm.u.com. Plus two for this week."
    assert dd.headline(0, 1, [], [{"title": "X", "headline": "switch the web firewall on a.com to block mode"}]) == \
        "Nothing urgent today. This week: switch the web firewall on a.com to block mode."


def test_subject_keeps_the_filter_prefix_and_says_what_you_will_do():
    hot = F("h", "a.example", "Exposed panel", "HIGH")
    mod = F("m", "b.example", "Missing CSP", "MODERATE")
    assert dd.subject(model(new_findings=[hot, mod]), "COMMANDsentry") == \
        "[COMMANDsentry] Command, Thursday: 1 for today, 1 this week"
    assert dd.subject(model(), "COMMANDsentry") == "[COMMANDsentry] Command, Thursday: nothing needs you"
    stale = [("lost.example", None, None, None, None, True, True, False)]
    assert dd.subject(model(stale_assets=stale), "P").startswith("[P] (!) Coverage gap. Command, Thursday: 1 for today")


def test_the_date_is_local_time_from_the_brand():
    m = model(brand=dict(dd.DEFAULT_BRAND, short_name="Command", tz="America/New_York"))
    assert m["local_end"].hour == 8 and dd._clock(m["local_end"]) == "8:09 AM"


# ── the page is email-safe ──────────────────────────────────────────────────────────
def _page(**over):
    brand = dd.load_brand()
    hot = F("h", "a.example", "Exposed panel", "HIGH")
    return dd.render_html(model(new_findings=[hot], brand=brand, **over),
                          portal_url="https://p.example", product_name="X"), brand


def test_the_page_is_tables_inline_styles_and_one_style_block():
    html, _ = _page()
    styles = " ".join(re.findall(r'style="([^"]*)"', html))
    assert "display:flex" not in styles and "display:grid" not in styles
    assert "<script" not in html and "<form" not in html
    assert html.count("<style>") == 1 and "prefers-reduced-motion" in html
    assert 'role="presentation"' in html and "max-width:640px" in html and 'width="680"' not in html
    assert "fonts.googleapis.com/css2?family=Bricolage+Grotesque" in html


def test_every_image_is_an_inline_cid_and_the_logo_rides_along():
    html, brand = _page()
    srcs = re.findall(r'<img[^>]+src="([^"]+)"', html)
    assert srcs == ["cid:brandlogo"]
    imgs = dd.inline_images(brand)
    assert len(imgs) == 1 and imgs[0][0] == "brandlogo" and imgs[0][2] == "image/png"
    assert imgs[0][1][:8] == b"\x89PNG\r\n\x1a\n"


def test_a_missing_brand_file_still_sends_with_a_name_and_no_image(tmp_path):
    b = dd.load_brand(str(tmp_path))
    assert b["logo_bytes"] == b"" and dd.inline_images(b) == []
    html = dd.render_html(model(brand=b), portal_url="", product_name="X")
    assert "<img" not in html and b["short_name"] in html


def test_this_repos_brand_file_is_complete():
    with open(os.path.join(dd.BRAND_DIR, "brand.json"), encoding="utf-8") as f:
        b = json.load(f)
    for k in ("short_name", "logo_file", "logo_alt", "band_bg", "band_text", "band_muted", "button", "tz"):
        assert b.get(k), k
    assert b["short_name"] in ("Command", "Prodex")
    assert os.path.isfile(os.path.join(dd.BRAND_DIR, b["logo_file"]))


# ── wiring in run_alerter.main ──────────────────────────────────────────────────────
def test_main_reads_the_four_new_things_softly_and_sends_the_logo():
    src = open(ra.__file__, encoding="utf-8").read()
    assert "with conn.transaction():" in src, "each new read in its own savepoint"
    assert 'sites = _soft("site ratings", SQL_SITE_RATINGS, {"t": window_start})' in src
    assert 'certs = _soft("expiring certificates", SQL_CERTS_EXPIRING)' in src
    assert "SQL_PREV_DEEP_SCANS, (window_start, listed)" in src
    assert "SQL_FINDING_HINTS, (hint_ids,)" in src
    assert "inline_images=_dd.inline_images(brand)" in src
    assert "inline_images=inline_images" in src


def test_html_and_text_come_from_one_model():
    src = open(ra.__file__, encoding="utf-8").read()
    assert "html = _dd.render_html(model, portal_url=portal_url, product_name=from_name)" in src
    assert "text = _dd.render_text(model, portal_url=portal_url, product_name=from_name)" in src


# ── mailer: inline images on both paths, today's shape without ──────────────────────
PNG = b"\x89PNG\r\n\x1a\nfake"


def _smtp(images):
    return mailer.build_smtp_message(["a@x.example"], "S", '<img src="cid:brandlogo">', "T",
                                     "f@x.example", "F", {}, images)


def test_smtp_without_images_is_todays_multipart_alternative():
    for images in (None, []):
        m = _smtp(images)
        assert m.get_content_type() == "multipart/alternative"
        assert [p.get_content_type() for p in m.get_payload()] == ["text/plain", "text/html"]


def test_smtp_with_an_image_makes_the_html_part_related_with_the_content_id():
    m = _smtp([("brandlogo", PNG, "image/png")])
    plain, rel = m.get_payload()
    assert rel.get_content_type() == "multipart/related"
    html, img = rel.get_payload()
    assert html.get_content_type() == "text/html" and img.get_content_type() == "image/png"
    assert img["Content-ID"] == "<brandlogo>" and img.get_content_disposition() == "inline"
    assert img.get_payload(decode=True) == PNG


def test_sendgrid_without_images_has_no_attachments_and_with_one_inlines_it():
    args = (["a@x.example"], "S", "<p>h</p>", "T", "f@x.example", "F", {})
    assert "attachments" not in mailer.build_sendgrid_payload(*args)
    assert "attachments" not in mailer.build_sendgrid_payload(*args, [])
    p = mailer.build_sendgrid_payload(*args, [("brandlogo", PNG, "image/png")])
    (a,) = p["attachments"]
    assert a["disposition"] == "inline" and a["content_id"] == "brandlogo" and a["type"] == "image/png"
    import base64
    assert base64.b64decode(a["content"]) == PNG


def test_a_malformed_image_entry_is_skipped_not_fatal():
    assert mailer._image_parts([("x",), None, ("cid", b"", "image/png"), ("ok", b"1", "image/png")]) == \
        [("ok", b"1", "image", "png")]
