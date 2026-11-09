"""test_command_daily_still_open.py — the Command daily (Howie 2026-11-09 08:23; KB 13 - Digests,
Command daily 1-4).

  1. A true headline: never "Nothing needs you" while problems are open; the window is said as it
     is ("since Friday" after mornings that were not sent), never "since yesterday" when it is not.
  3. Every day, the two or three worst open problems that are not today's news, one sentence each,
     naming the sites, in the saved plain words where a finding has them; once named, not again for
     7 days; only what a scan confirmed (no hand-entered rows; nothing no scan has seen in 30 days);
     not the web firewall items (their own 30/90-day cadence in the weekly).
  4. No nudge in the daily (the weekly's 30-day Overdue is the nudge): nothing here says "told".
  Also: no blanket "Every scan since yesterday came back with nothing that needs anyone", and on a
  Monday the weekly is "today's".
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
for d in ("..", "../common", "../scanner", "../db", "../normalize"):
    sys.path.insert(0, os.path.join(HERE, d))
sys.path.insert(0, HERE)

import digest_daily as dd  # noqa: E402
import run_alerter as ra  # noqa: E402
import told  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 11, 9, 12, 12, tzinfo=UTC)            # a Monday, 7:12 AM in New York
BRAND = {"tz": "America/New_York", "short_name": "Command"}


def row(fid, asset, title, sev="MODERATE", source="testssl", seen_days=1, first_days=60):
    """SQL_OPEN_PROBLEMS's ten columns."""
    return (fid, asset, title, sev, "open", source, NOW - timedelta(days=seen_days), "", [],
            NOW - timedelta(days=first_days))


# ── 1. the window, the headline, the subject, the weekly line ───────────────────────────────
def test_since_words_say_the_window_as_it_is():
    assert dd.since_words(NOW - timedelta(hours=24), NOW, BRAND) == "yesterday"
    assert dd.since_words(NOW - timedelta(hours=30), NOW, BRAND) == "yesterday"
    assert dd.since_words(datetime(2026, 11, 6, 12, 11, tzinfo=UTC), NOW, BRAND) == "Friday"
    assert dd.since_words(datetime(2026, 11, 1, 12, 0, tzinfo=UTC), NOW, BRAND) == "Nov 1"
    assert dd.since_words(None, NOW, BRAND) == "yesterday"


def test_the_headline_is_never_nothing_needs_you():
    three = [{"text": "a"}, {"text": "b"}, {"text": "c"}]
    assert dd.headline(0, 0, [], [], still=three, since="Friday") == "Nothing new since Friday. Three things still open, below."
    assert dd.headline(0, 0, [], [], still=three[:1], since="yesterday") == "Nothing new since yesterday. One thing still open, below."
    assert dd.headline(0, 0, since="Friday") == "Nothing new since Friday."
    for n_do, n_t in ((0, 0), (1, 0), (0, 1), (2, 3)):
        assert "Nothing needs you" not in dd.headline(n_do, n_t, still=three)


def test_the_weekly_is_todays_on_monday():
    assert "today's weekly review" in dd.weekly_words(dd.local_time(NOW, BRAND))
    tue = dd.local_time(NOW + timedelta(days=1), BRAND)
    assert dd.weekly_words(tue).endswith("comes in the weekly review on Monday.")


# ── 3. the picks ────────────────────────────────────────────────────────────────────────────
def _pick(rows, told_rows=None, changed=frozenset(), quiet=frozenset()):
    return ra._still_open_daily(rows, {r[1] for r in rows}, set(changed), NOW, told_rows or {}, set(quiet))


def test_only_what_a_scan_confirmed_lately():
    rows = [row("hand", "ftp.s.com", "F-01: Incomplete TLS Certificate Chain", "HIGH", "manual_named"),
            row("stale", "cmi.com", "WordPress upgrade page exposed: /wp-admin/upgrade.php", "MODERATE", "other", seen_days=170),
            row("fresh", "a.com", "Missing security header: Strict-Transport-Security", "MODERATE", "commandsentry_light")]
    got = _pick(rows)
    assert [i["finding_ids"] for i in got] == [["fresh"]]


def test_not_today_s_news_not_a_quiet_host_not_low():
    rows = [row("news", "a.com", "Security headers missing or weak"),
            row("gone", "valorep.p.com", "Obsolete 3DES/IDEA ciphers offered"),
            row("low", "b.com", "No OCSP stapling", "LOW"),
            row("ok", "c.com", "DNS missing DMARC record", source="commandsentry_light")]
    got = _pick(rows, changed={"news"}, quiet={"valorep.p.com"})
    assert [i["finding_ids"] for i in got] == [["ok"]]


def test_the_web_firewall_items_keep_their_own_cadence():
    rows = [row("x.com:commandsentry_heavy:waf-absent-differential:1", "x.com", "No enforcing WAF in front of live application",
                source="commandsentry_heavy"),
            row("y.com:commandsentry_heavy:waf-absent-exposed:2", "y.com",
                "Out-of-date component with no enforcing WAF in front (4 open)", "MODERATE-HIGH", "commandsentry_heavy"),
            row("z", "z.com", "DNS missing SPF record", source="commandsentry_light")]
    assert [i["finding_ids"] for i in _pick(rows)] == [["z"]]


def test_worst_then_oldest_and_at_most_three():
    rows = [row("m-new", "a.com", "DNS missing SPF record", first_days=5, source="commandsentry_light"),
            row("m-old", "b.com", "DNS missing DMARC record", first_days=200, source="commandsentry_light"),
            row("mh", "c.com", "Accessible path: /admin (HTTP 200)", "MODERATE-HIGH", "commandsentry_medium", first_days=1),
            row("m-mid", "d.com", "Obsolete 3DES/IDEA ciphers offered", first_days=50),
            row("m-mid2", "e.com", "API documentation publicly exposed: /swagger (HTTP 301)", first_days=40,
                source="commandsentry_medium")]
    got = _pick(rows)
    assert [i["finding_ids"] for i in got] == [["mh"], ["m-old"], ["m-mid"]]
    assert dd.STILL_OPEN_MAX == 3


def test_named_once_then_not_for_seven_days():
    rows = [row("a1", "a.com", "DNS missing SPF record", source="commandsentry_light"),
            row("b1", "b.com", "DNS missing DMARC record", source="commandsentry_light")]
    lately = {told.still_key("a1"): {"last_full_at": NOW - timedelta(days=6, hours=23)}}
    assert [i["finding_ids"] for i in _pick(rows, lately)] == [["b1"]]
    a_week = {told.still_key("a1"): {"last_full_at": NOW - timedelta(days=7)}}
    assert {i["finding_ids"][0] for i in _pick(rows, a_week)} == {"a1", "b1"}
    # the weekly's own row for the same finding does not count as a still-open mention
    weekly = {"a1": {"last_full_at": NOW - timedelta(days=1)}}
    assert {i["finding_ids"][0] for i in _pick(rows, weekly)} == {"a1", "b1"}
    assert told.STILL_GAP_DAYS == 7 and told.still_key("x") == "still-open:x"


def test_one_problem_on_many_sites_is_one_line():
    rows = [row(f"h{k}", f"s{k}.x.com", "Missing security header: Strict-Transport-Security", source="commandsentry_light")
            for k in range(6)]
    got = _pick(rows)
    assert len(got) == 1 and len(got[0]["finding_ids"]) == 6


# ── 3. the words ────────────────────────────────────────────────────────────────────────────
def test_the_sites_are_named():
    assert dd.still_who(["pm.u.com"]) == ("pm.u.com", 1)
    who, n = dd.still_who(["b.x.com", "x.com", "1.2.3.4", "a.x.com", "y.com"])
    assert n == 5 and who == "x.com, y.com, a.x.com and two other sites"


def test_the_saved_plain_words_lead():
    it = {"finding_ids": ["f1", "f2"], "sites": ["a.com", "b.com"], "title": "Missing security header: Strict-Transport-Security"}
    plain = {"f1": "This site is missing a setting that tells browsers to always use an encrypted connection. Without it ..."}
    assert dd.still_line(it, plain) == "a.com and b.com are missing a setting that tells browsers to always use an encrypted connection."
    one = dict(it, sites=["a.com"])
    assert dd.still_line(one, plain) == "a.com is missing a setting that tells browsers to always use an encrypted connection."
    poss = {"f2": "This site's web server reveals its version number. That helps an attacker."}
    assert dd.still_line(one, poss) == "a.com's web server reveals its version number."
    assert dd.still_line(it, poss) == "On a.com and b.com, the web server reveals its version number."
    other = {"f1": "The security certificate on this site does not match its name."}
    assert dd.still_line(one, other) == "The security certificate on a.com does not match its name."
    # several sites (review, push-424): never "this site" with a list after it
    assert dd.still_line(it, other) == "The security certificate on each of these sites does not match its name (a.com and b.com)."
    starts = {"f1": "This site does not send a sender policy. More text."}
    assert dd.still_line(one, starts) == "a.com does not send a sender policy."
    assert dd.still_line(it, starts) == "Each of these sites does not send a sender policy (a.com and b.com)."
    mid = {"f1": "Anyone can read this site's file list."}
    assert dd.still_line(one, mid) == "Anyone can read a.com's file list."
    assert dd.still_line(it, mid) == "Anyone can read each site's file list (a.com and b.com)."
    many = dict(it, sites=["a.com", "b.com", "c.com", "d.com", "e.com"])
    assert dd.still_line(many, other) == ("The security certificate on each of these sites does not match its name "
                                          "(a.com, b.com, c.com and two other sites).")
    neutral = {"f1": "A login page is open to anyone."}
    assert dd.still_line(it, neutral) == "A login page is open to anyone (on a.com and b.com)."
    assert "this site" not in dd.still_line(it, {"f1": "Websites like this site often leak."}).lower()
    # a site-first sentence is preferred over another member's
    both = {"f1": "The scanner found that the page answered.", "f2": "This site has no sender policy."}
    assert dd.still_line(it, both) == "a.com and b.com have no sender policy."


def test_without_plain_words_the_title_is_used():
    it = {"finding_ids": ["f"], "sites": ["a.com"], "title": "API documentation publicly exposed: /swagger (HTTP 301)"}
    assert dd.still_line(it, {}) == "API documentation publicly exposed: /swagger (HTTP 301) (on a.com)."


# ── the model, the email, the record ────────────────────────────────────────────────────────
def _model():
    return ra._digest_model(
        window_start=datetime(2026, 11, 6, 12, 11, tzinfo=UTC), window_end=NOW, new_findings=[], confirmed=[],
        regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[], baseline={},
        came_back=[], fixed=[], enforcement_flips=[], unrecognized_pages=[], sites=[], certs=[], prev_deep={}, hints={},
        brand=dict(dd.load_brand(), short_name="Command"), discovery_stale_hours=48, deepscan_stale_hours=720,
        details={}, told={}, not_responding=[], reach_checks=[], quiet_where={}, gaps_to_approver=False)


def test_the_email_carries_the_lines_and_records_them_for_the_gap():
    rows = [row("a1", "a.com", "DNS missing SPF record", source="commandsentry_light"),
            row("b1", "b.com", "Obsolete 3DES/IDEA ciphers offered"), row("b2", "c.com", "Obsolete 3DES/IDEA ciphers offered")]
    picks = _pick(rows)
    m = dd.with_still_open(_model(), picks, {"a1": "This site has no email sender policy published."})
    assert m["headline"] == "Nothing new since Friday. Two things still open, below."
    assert dd.subject(m, "COMMANDsentry") == "[COMMANDsentry] Command, Monday: nothing new, 2 still open"
    html = dd.render_html(m, portal_url="https://p.example", product_name="COMMANDsentry")
    text = dd.render_text(m, portal_url="https://p.example", product_name="COMMANDsentry")
    assert ">Still open<" in html and "STILL OPEN" in text
    assert "a.com has no email sender policy published." in html and "a.com has no email sender policy published." in text
    assert "today's weekly review" in html and "today's weekly review" in text
    for out in (html, text):
        assert "Nothing needs you" not in out and "came back with nothing that needs anyone" not in out
        assert "since yesterday" not in out.lower() and " told " not in out.lower()
    rec = [r for r in m["told_full"] if r[0].startswith(told.STILL_PREFIX)]
    assert sorted(rec) == sorted([("still-open:a1", "MODERATE", "daily"),
                                  ("still-open:b1", "MODERATE", "daily"),
                                  ("still-open:b2", "MODERATE", "daily")])


def test_every_told_record_fits_the_tables_own_rule():
    """digest_told.last_full_in is CHECKed to 'daily' or 'weekly' (20261023c): one record outside
    that fails the whole told write after a send, and every card would be told again next time."""
    import re
    mig = os.path.join(HERE, "..", "db", "migrations", "20261023c_digest_told.sql")
    with open(mig, encoding="utf-8") as fh:
        sql = fh.read()
    allowed = set(re.findall(r"'([a-z]+)'", re.search(r"last_full_in[^\n]*CHECK \(last_full_in IN \(([^)]*)\)\)", sql).group(1)))
    assert allowed == {"daily", "weekly"}
    rows = [row("a1", "a.com", "DNS missing SPF record", source="commandsentry_light")]
    m = dd.with_still_open(_model(), _pick(rows), {})
    assert m["told_full"] and all(where in allowed for _f, _sev, where in m["told_full"])
    assert all(len(r) == 3 for r in m["told_full"])


def test_a_quiet_morning_with_nothing_open_says_only_that():
    m = dd.with_still_open(_model(), [], {})
    assert m["headline"] == "Nothing new since Friday." and m["still_open"] == []
    assert dd.subject(m, "C").endswith(": nothing new")
    assert "Still open" not in dd.render_html(m, portal_url="", product_name="C")


def test_the_alerter_wires_it_for_the_voice_off_daily_only():
    with open(ra.__file__, encoding="utf-8") as fh:
        src = fh.read()
    i = src.index("# KB 12, the Command daily: its own \"still open\" lines")
    block = src[i:src.index("subject = _dd.subject(model, from_name)", i)]
    assert "if not _voice_on():" in block
    assert "_still_open_daily(rows_, names_, changed_, window_end, told, quiet_hosts)" in block
    assert "_dd.with_still_open(model, picks, plain)" in block
    assert "SQL_PLAIN_WHAT" in block
    assert "plain_rejected_at IS NULL" in ra.SQL_PLAIN_WHAT
    # the told rows are written only after a send that worked (job 3s), from finalize's told_full
    assert "_told_record(conn, [tuple(r) for r in (finalize.get(\"told_full\") or [])])" in src
    # the voice path (Prodex) keeps its own picks
    assert "still = _still_open_picks(open_items, changed_ids, window_end, told) if voice_on else []" in src
