"""(KB 12 job 3s, 2026-10-23) Say it once, then remind on a timer.

Howie, 2026-10-22 19:59-20:02: "us constantly reminding Sean or Kianu or the people over at
Unimac or Command might get sick of hearing it" ... "We leave them alone, and after a certain
amount of time, we remind them again." "Agreed." 2026-10-23 07:25: Overdue the same, every 30
days. 13:50 (D1): the company is the whole fleet. D2: other serious problems every 30 days.
08:26: the daily's "Open today's report" opens the portal's front page, "That's misleading."

Pinned: the rule (new / worse / came back, twice / due / quiet; the cadence by kind; the
firewall case); the weekly (one grouping, a mixed family printed once, nothing twice, the cap
and "Also this week" not recorded, Overdue due vs quiet, "Still open, no change" worst first
with since); the daily (no record = today's email; told and unchanged = not repeated; a
regressed event is a came-back); recording only after a send that worked, never on a test send
or dry run; the queries; the button; the Monday order.
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_weekly as dw  # noqa: E402
import run_alerter as ra  # noqa: E402
import told as T  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 26, 12, 5, tzinfo=UTC)
OCT26 = datetime(2026, 10, 26, 12, 5, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Command")
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

RS_TEXT = ("The Slider Revolution plugin for WordPress is vulnerable to Sensitive Information Exposure in versions "
           "up to, and including, 7.0.9. Detected at version 6.7.58.")


def _row(at, sev="MODERATE-HIGH", told_in="weekly", closed=None, first=None):
    return {"first_told_at": first or at, "last_full_at": at, "last_full_severity": sev,
            "last_full_in": told_in, "reminders": 0, "closed_seen_at": closed}


def _item(*fids, sev="MODERATE-HIGH", family="", title="x"):
    return {"finding_ids": list(fids), "severity": sev, "family": family, "title": title, "sites": ["a.com"]}


# ── the rule ─────────────────────────────────────────────────────────────────────────
def test_new_worse_back_due_and_quiet():
    it = _item("f1", "f2")
    sev = {"f1": "MODERATE-HIGH", "f2": "MODERATE-HIGH"}
    t0 = NOW - timedelta(days=3)
    both = {"f1": _row(t0), "f2": _row(t0)}
    assert T.decide(it, {}, NOW, sev) == ("full", "new")
    assert T.decide(it, {"f1": _row(t0)}, NOW, sev) == ("full", "new"), "any member new"
    assert T.decide(it, both, NOW, sev) == ("quiet", None)
    assert T.decide(it, both, NOW, dict(sev, f2="HIGH")) == ("full", "worse")
    assert T.decide(it, both, NOW, dict(sev, f2="MODERATE")) == ("quiet", None), "better is not news"
    back = dict(both, f1=_row(t0, closed=t0 + timedelta(hours=5)))
    assert T.decide(it, back, NOW, sev) == ("full", "back")
    seen_before = dict(both, f1=_row(t0, closed=t0 - timedelta(days=1)))
    assert T.decide(it, seen_before, NOW, sev) == ("quiet", None), "closed before it was told is not a return"
    old = {"f1": _row(NOW - timedelta(days=30)), "f2": _row(NOW - timedelta(days=31))}
    assert T.decide(it, old, NOW, sev) == ("full", "due"), "due from the LATEST full telling"
    assert T.decide(it, {"f1": _row(NOW - timedelta(days=31)), "f2": _row(NOW - timedelta(days=29))},
                    NOW, sev) == ("quiet", None)


def test_two_returns_in_a_row_each_produce_a_card():
    it, sev = _item("f1"), {"f1": "HIGH"}
    t0 = NOW - timedelta(days=20)
    told = {"f1": _row(t0, sev="HIGH", closed=t0 + timedelta(days=1))}   # closed, then back
    assert T.decide(it, told, NOW, sev) == ("full", "back")
    t2 = t0 + timedelta(days=2)                                          # told in full again
    told = {"f1": _row(t2, sev="HIGH", first=t0, closed=t0 + timedelta(days=1))}
    assert T.decide(it, told, NOW, sev) == ("quiet", None)
    told["f1"]["closed_seen_at"] = t2 + timedelta(days=1)                # closed, back again
    assert T.decide(it, told, NOW, sev) == ("full", "back")
    mark = " ".join(ra.SQL_TOLD_MARK_CLOSED.split())
    assert "(t.closed_seen_at IS NULL OR t.closed_seen_at <= t.last_full_at)" in mark, \
        "a second close after a second telling is marked again"


def test_the_cadence_by_kind_and_the_firewall_case():
    assert T.CADENCE == {"firewall-1": 30, "firewall-2": 90, "overdue": 30, "serious": 30}
    gap = _item("a.com:commandsentry_heavy:waf-absent-differential:x", family="waf-absent")
    assert T.kind_of(gap, set(), True) == "firewall-1"
    assert T.kind_of(gap, set(), False) == "firewall-2", "no firewall anywhere: a budget decision"
    for fam, fid in (("waf-not-blocking", "a.com:commandsentry_heavy:waf-present-not-enforcing:x"),
                     ("", "a.com:commandsentry_heavy:waf-partial-coverage:x")):
        assert T.kind_of(_item(fid, family=fam), set(), False) == "firewall-1", "a firewall is there"
    assert T.kind_of(_item("a.com:light:wpvuln-cve-1", "b"), {"a.com:light:wpvuln-cve-1"}) == "overdue", \
        "an out-of-date member 30+ days old makes the item Overdue (plan v3 Design 5)"
    assert T.kind_of(_item("a.com:heavy:tls"), set()) == "serious"
    t = NOW - timedelta(days=60)
    told = {gap["finding_ids"][0]: _row(t)}
    sev = {gap["finding_ids"][0]: "MODERATE-HIGH"}
    assert T.decide(gap, told, NOW, sev, "firewall-1") == ("full", "due")
    assert T.decide(gap, told, NOW, sev, "firewall-2") == ("quiet", None)


def test_the_tags_say_why_it_is_here_again():
    told = {"f1": _row(NOW - timedelta(days=31), first=OCT26 - timedelta(days=31))}
    it = _item("f1")
    assert T.tag_for("new", it, told, "serious", dd._day) == ""
    assert T.tag_for("due", it, told, "firewall-2", dd._day) == "Reminder, every 90 days — first told Sep 25; nothing has changed"
    assert T.tag_for("back", it, told, "serious", dd._day) == "Came back after it was fixed (first told Sep 25)"
    assert T.tag_for("due", it, {}, "serious", dd._day) == "Reminder, every 30 days; nothing has changed"
    assert T.tag_for("worse", it, told, "serious", dd._day).startswith("Got worse since we told you")
    assert T.records([_item("f1", "f2"), _item("f2", "f3")], {"f1": "HIGH"}, "weekly") == \
        [("f1", "HIGH", "weekly"), ("f2", "MODERATE-HIGH", "weekly"), ("f3", "MODERATE-HIGH", "weekly")]


# ── the weekly ───────────────────────────────────────────────────────────────────────
def _s(fid, asset, title, sev="MODERATE-HIGH", first=None, desc=""):
    """A SQL_OPEN_SERIOUS / SQL_OPEN_FIREWALL_GAPS row (10 columns, first_detected_at last)."""
    return (fid, asset, title, sev, "detected", "commandsentry_heavy", NOW, desc, [],
            first or NOW - timedelta(days=3))


def _o(fid, asset, title, first, sev="MODERATE", desc="", cve=()):
    """A SQL_OPEN_OUT_OF_DATE row (first_detected_at at index 6)."""
    return (fid, asset, title, sev, "detected", "commandsentry_light", first, desc, list(cve))


def _weekly(**kw):
    s, e, days = dw.week_window(NOW, BRAND)
    kw.setdefault("open_serious", [])
    return dw.build_weekly(now=NOW, window_start=s, window_end=e, days=days, brand=BRAND, scans=[],
                           opened=[], closed=[], sites=[("a.com", "MODERATE-HIGH", True, "MODERATE-HIGH")], **kw)


def _ids(items):
    return [f for i in items for f in i.get("finding_ids", [])]


def _gaps(n):
    """n firewall gaps on n sites: ONE item (group_problems groups a family across sites)."""
    return [_s(f"s{i}.com:commandsentry_heavy:waf-absent-differential:x", f"s{i}.com",
               "No enforcing WAF in front of live application", sev="MODERATE") for i in range(n)]


def _distinct(n):
    """n serious problems that do not group: n items."""
    return [_s(f"p{i}.com:heavy:check-{i}", f"p{i}.com", f"Distinct problem number {i}", sev="HIGH")
            for i in range(n)]


def test_one_family_with_a_young_serious_member_and_an_old_out_of_date_one_prints_once():
    young = _s("b.com:light:wpvuln-cve-2026-6728", "b.com", "Slider Revolution [revslider] < 7.0.10",
               desc=RS_TEXT)
    old = _o("a.com:light:wpvuln-cve-2026-6728", "a.com", "Slider Revolution [revslider] < 7.0.10",
             datetime(2026, 6, 1, tzinfo=UTC), desc=RS_TEXT, cve=["CVE-2026-6728"])
    m = _weekly(open_serious=[young], overdue=[old], told={})
    every = _ids(m["do"]) + _ids(m["overdue"]) + _ids(m["also"]) + _ids(m["quiet"])
    assert sorted(every) == sorted([young[0], old[0]]) and len(every) == 2, "one item, printed once"
    (item,) = m["overdue"]
    assert sorted(item["finding_ids"]) == sorted([young[0], old[0]]) and item["sites"] == ["a.com", "b.com"]
    assert (item["overdue_since"].month, item["overdue_since"].day) == (6, 1)


def test_nothing_twice_the_cap_and_also_this_week_is_not_recorded():
    m = _weekly(open_serious=_distinct(8), told={}, fleet_has_waf=True)
    problems = [i for i in m["do"] if i.get("finding_ids")]
    assert len(problems) == 6 == dw.DO_MAX and len(m["also"]) == 2 and m["more"] == 2
    ids = _ids(problems) + _ids(m["also"])
    assert len(ids) == len(set(ids)) == 8, "every gap once, by item"
    rec = {f for f, _s, _w in m["told_full"]}
    assert rec == set(_ids(problems)) and not rec & set(_ids(m["also"])), \
        "past the cap: listed one line, NOT recorded, so it gets its full card next week"
    assert all(w == "weekly" for _f, _s, w in m["told_full"])
    html = dw.render_weekly_html(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    text = dw.render_weekly_text(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    assert "Also this week:" in html and "Each gets its full card next week." in html
    assert text.count("  Also this week: ") == 2 and "waiting patiently" not in html


def test_told_and_unchanged_is_one_quiet_line_worst_first_with_since():
    gaps = _gaps(2)
    high = _s("c.com:heavy:tls-expired", "c.com", "TLS certificate expired", sev="HIGH",
              first=datetime(2026, 10, 15, tzinfo=UTC))
    t = NOW - timedelta(days=5)
    told = {g[0]: _row(t, sev="MODERATE") for g in gaps}
    told[high[0]] = _row(t, sev="HIGH")
    m = _weekly(open_serious=[high], gaps=gaps, told=told)
    assert not [i for i in m["do"] if i.get("finding_ids")] and m["told_full"] == []
    assert [i["severity"] for i in m["quiet"]][0] == "HIGH", "worst first"
    line = dw.quiet_line(m["quiet"][0])
    assert line.endswith("(since Oct 15)") and "c.com" in line
    html = dw.render_weekly_html(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    text = dw.render_weekly_text(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    assert "Still open, no change" in html and "STILL OPEN, NO CHANGE" in text
    assert text.count("\n  - ") == 2, "the two gaps are one item: one line"
    worse = dict(told)
    worse[high[0]] = _row(t, sev="MODERATE-HIGH")
    m2 = _weekly(open_serious=[high], gaps=gaps, told=worse)
    (card,) = [i for i in m2["do"] if i.get("finding_ids")]
    assert card["tag"].startswith("Got worse since we told you") and len(m2["quiet"]) == 1


def test_overdue_due_is_a_full_reminder_and_otherwise_quiet():
    old = _o("a.com:light:wpvuln-cve-2026-6728", "a.com", "Slider Revolution [revslider] < 7.0.10",
             datetime(2026, 6, 1, tzinfo=UTC), desc=RS_TEXT, cve=["CVE-2026-6728"])
    m = _weekly(overdue=[old], told={old[0]: _row(NOW - timedelta(days=10), sev="MODERATE")})
    assert m["overdue"] == [] and len(m["quiet"]) == 1
    assert dw.quiet_line(m["quiet"][0]).startswith("Overdue: ") and "(since Jun 1)" in dw.quiet_line(m["quiet"][0])
    m = _weekly(overdue=[old], told={old[0]: _row(NOW - timedelta(days=30), sev="MODERATE")})
    (item,) = m["overdue"]
    assert item["tag"].startswith("Reminder, every 30 days") and item.get("nudge")
    assert m["told_full"] == [(old[0], "MODERATE", "weekly")]


def test_no_record_yet_tells_everything_as_new():
    m = _weekly(gaps=_gaps(2), open_serious=_distinct(1), told=None)
    assert len([i for i in m["do"] if i.get("finding_ids")]) == 2 and m["quiet"] == []
    assert len(m["told_full"]) == 3


# ── the daily ────────────────────────────────────────────────────────────────────────
def _daily(told, new=(), regressed=(), confirmed=()):
    s = NOW - timedelta(days=1)
    return dd.build_model(window_start=s, window_end=NOW, new_findings=list(new), confirmed=list(confirmed),
                          regressed=list(regressed), high_risk=[], new_assets=[], dark_assets=[],
                          stale_assets=[], canary_violations=[], baseline={}, brand=BRAND, told=told)


def _d(fid, asset="a.com", title=None, sev="HIGH"):
    return (fid, asset, title or f"Distinct daily problem on {asset}", sev, "detected", "commandsentry_heavy", NOW)


def test_the_daily_without_a_record_is_todays_email():
    m = _daily(None, new=[_d("a.com:heavy:tls")], confirmed=[_d("b.com:heavy:tls", "b.com")])
    assert sorted(_ids(m["do"] + m["ticket"])) == ["a.com:heavy:tls", "b.com:heavy:tls"]


def test_the_daily_tells_new_worse_and_back_and_never_repeats_or_reminds():
    t = NOW - timedelta(days=40)
    told = {"b.com:heavy:tls": _row(t, sev="HIGH"), "c.com:heavy:tls": _row(t, sev="MODERATE-HIGH"),
            "d.com:heavy:tls": _row(t, sev="HIGH")}
    m = _daily(told, new=[_d("a.com:heavy:tls")],
               confirmed=[_d("b.com:heavy:tls", "b.com"), _d("c.com:heavy:tls", "c.com")],
               regressed=[_d("d.com:heavy:tls", "d.com")])
    shown = _ids(m["do"] + m["ticket"])
    assert "b.com:heavy:tls" not in shown, "told, unchanged and due: the weekly reminds, not the daily"
    assert {"a.com:heavy:tls", "c.com:heavy:tls", "d.com:heavy:tls"} <= set(shown)
    tags = {i["finding_ids"][0]: i.get("tag") for i in m["do"] + m["ticket"] if i.get("finding_ids")}
    assert tags["d.com:heavy:tls"] == "Came back after being fixed", "a REGRESSED event is a came-back"
    assert tags["c.com:heavy:tls"].startswith("Got worse since we told you")
    assert {f for f, _s, w in m["told_full"]} == set(shown) and all(w == "daily" for *_x, w in m["told_full"])


def test_the_daily_button_says_the_portal():
    m = _daily(None, new=[_d("a.com:heavy:tls")])
    html = dd.render_html(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    text = dd.render_text(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    assert ">Open the portal</a>" in html and "Open the portal: https://portal.example" in text
    assert "today's report" not in html + text


# ── run_alerter: what is read, when it is written ─────────────────────────────────────
def test_the_queries():
    ser = " ".join(ra.SQL_OPEN_SERIOUS.split())
    assert "f.description, f.cve, f.first_detected_at FROM public.v_fleet_open_reps" in ser
    gaps = " ".join(ra.SQL_OPEN_FIREWALL_GAPS.split())
    assert "position(':commandsentry_heavy:waf-' in f.finding_id) > 0" in gaps
    assert "('CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE')" in gaps and "unnest(r.member_finding_ids)" in gaps
    assert gaps.split(" FROM ")[0] == ser.split(" FROM ")[0], "the same ten columns"
    waf = " ".join(ra.SQL_FLEET_HAS_WAF.split())
    assert "device_class::text = 'waf' AND device_class_confidence::text = 'confirmed'" in waf
    mark = " ".join(ra.SQL_TOLD_MARK_CLOSED.split())
    assert "NOT IN ('detected', 'confirmed', 'open', 'regressed')" in mark and set(T.OPEN_STATUSES) == \
        {"detected", "confirmed", "open", "regressed"}
    rec = " ".join(ra.SQL_TOLD_RECORD.split())
    assert "ON CONFLICT (finding_id) DO UPDATE" in rec and "first_told_at = " not in rec.split("DO UPDATE")[1]


class _Cur:
    def __init__(self, log, rows=(), boom=False):
        self.log, self.rows, self.boom, self.rowcount = log, rows, boom, 3

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        if self.boom:
            raise RuntimeError('relation "public.digest_told" does not exist')
        self.log.append(("execute", " ".join(sql.split())[:30], params))

    def executemany(self, sql, seq):
        if self.boom:
            raise RuntimeError('relation "public.digest_told" does not exist')
        self.log.append(("executemany", " ".join(sql.split())[:30], list(seq)))

    def fetchall(self):
        return list(self.rows)


class _Tx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    def __init__(self, rows=(), boom=False):
        self.log, self.rows, self.boom, self.commits = [], rows, boom, 0

    def transaction(self):
        return _Tx()

    def cursor(self):
        return _Cur(self.log, self.rows, self.boom)

    def commit(self):
        self.commits += 1


def test_a_missing_table_reads_as_no_record_and_writes_fail_soft():
    assert ra._read_told(_Conn(boom=True)) is None
    assert ra._told_mark_closed(_Conn(boom=True)) == 0
    assert ra._told_record(_Conn(boom=True), [("f", "HIGH", "daily")]) == 0
    t = NOW
    got = ra._read_told(_Conn(rows=[("f1", t, t, "HIGH", "weekly", 0, None)]))
    assert got == {"f1": {"finding_id": "f1", "first_told_at": t, "last_full_at": t, "last_full_severity": "HIGH",
                          "last_full_in": "weekly", "reminders": 0, "closed_seen_at": None}}
    c = _Conn()
    assert ra._told_record(c, [("f1", "HIGH", "weekly"), ("f2", "", "weekly")]) == 2 and c.commits == 1
    assert c.log[0][0] == "executemany" and c.log[0][2] == [("f1", "HIGH", "weekly"), ("f2", "", "weekly")]
    assert ra._told_record(_Conn(), []) == 0


def test_recording_only_after_a_send_that_worked_and_never_on_a_test_send_or_dry_run():
    src = open(os.path.join(HERE, "run_alerter.py"), encoding="utf-8").read()
    calls = [m.start() for m in re.finditer(r"_told_record\(conn, model", src)]
    assert len(calls) == 2, "the daily and the weekly, nowhere else"
    for at in calls:
        assert src[:at].rstrip().endswith("if record and sent:") or \
            src[:at].rsplit("\n", 2)[-2].strip().startswith("if record and sent:"), "guarded by record AND sent"
    assert "record       = not (args.dry_run or args.preview)" in src
    marks = [m.start() for m in re.finditer(r"(?<=\n) +_told_mark_closed\(conn\)", src)]
    assert len(marks) == 2
    for at in marks:
        assert "if record:" in src[:at].rsplit("\n", 3)[-3] + src[:at].rsplit("\n", 2)[-2]
    daily = src.split("def _run_weekly")[0].split("def main")[1]
    assert daily.index("_told_mark_closed(conn)") < daily.index("told = _read_told(conn)") < daily.index("_digest_model(")
    assert daily.index("if args.dry_run:") < daily.index("_told_record(conn")


def test_monday_the_daily_finishes_before_the_weekly_reads():
    wf = open(os.path.join(REPO, ".github", "workflows", "alerter.yml"), encoding="utf-8").read()
    assert "concurrency:\n  group: alerter-test-send-${{ github.event.inputs.preview == 'true' }}\n" \
           "  cancel-in-progress: false\n" in wf
    assert '- cron: "0 12 * * *"' in wf and '- cron: "5 12 * * 1"' in wf
