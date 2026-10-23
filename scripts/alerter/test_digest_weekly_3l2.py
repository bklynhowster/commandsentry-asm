"""KB 12 job 3l slice 2 (2026-10-22) — the Monday weekly and the test send.

Howie, 14:51: "There's a weekly ... that has more detail." 14:59: "the weekly should
definitely be Monday." 16:54: "generate a daily and a weekly to send to me and the other
recipients of the Prodex side. You send only me the Command side." These pins keep: the
week as seven whole local days; sites grouped by registered domain, alphabetical, www.
folded; every rating move explained by a finding or said to be unexplained; the open
serious list read from the dashboard's own view; a test send that writes nothing and can
only narrow the recipients.
"""
import inspect
import pathlib
import re
from datetime import date, datetime, timezone

import digest_daily as dd
import digest_weekly as dw
import run_alerter as ra

UTC = timezone.utc
NOW = datetime(2026, 10, 22, 21, 30, tzinfo=UTC)          # Thursday, 5:30 PM ET
BRAND = dict(dd.DEFAULT_BRAND, short_name="Command")
WAF = "No enforcing WAF in front of live application"
FW = "Runs Fortinet FortiWeb, version not shown"


def T(s):
    return datetime.fromisoformat(s)


def _f(fid, aid, title, sev, ts, status="detected", src="commandsentry_heavy"):
    return (fid, aid, title, sev, status, src, T(ts))


# ── the week ─────────────────────────────────────────────────────────────────

def test_the_week_is_the_seven_whole_local_days_before_today():
    s, e, days = dw.week_window(NOW, BRAND)
    assert days[0] == date(2026, 10, 15) and days[-1] == date(2026, 10, 21) and len(days) == 7
    assert s == datetime(2026, 10, 15, 4, tzinfo=UTC), "local midnight, EDT"
    assert e == datetime(2026, 10, 22, 4, tzinfo=UTC)


def test_a_week_across_the_clock_change_is_still_seven_calendar_days():
    s, e, days = dw.week_window(datetime(2026, 11, 3, 12, 0, tzinfo=UTC), BRAND)  # Tue after Nov 1
    assert days[0] == date(2026, 10, 27) and days[-1] == date(2026, 11, 2)
    assert s == datetime(2026, 10, 27, 4, tzinfo=UTC) and e == datetime(2026, 11, 3, 5, tzinfo=UTC)


def test_monday_8am_covers_monday_to_sunday():
    _s, _e, days = dw.week_window(datetime(2026, 10, 26, 12, 5, tzinfo=UTC), BRAND)
    assert days[0].strftime("%a") == "Mon" and days[-1].strftime("%a") == "Sun"


# ── sites, grouped ───────────────────────────────────────────────────────────

def test_registered_domain_not_apex_domain():
    assert dw.registered_domain("portal-test.unimacgraphics.com") == "unimacgraphics.com"
    assert dw.registered_domain("unimacgraphics.com") == "unimacgraphics.com"
    assert dw.registered_domain("commandsentry-portal.netlify.app") == "commandsentry-portal.netlify.app"
    assert dw.registered_domain("52.119.65.5") is None
    assert dw.registered_domain("ip-range:24.157.51.64/27") is None


def test_groups_are_alphabetical_with_the_site_first_and_addresses_last_in_number_order():
    now = {"b.example.com": "high", "example.com": "moderate", "a.example.com": "low",
           "zeta.org": "moderate", "24.157.51.70": "low", "24.38.70.14": "moderate"}
    then = dict(now, **{"b.example.com": "moderate"})
    g = dw.site_groups(now, then)
    assert [x["name"] for x in g] == ["example.com", "zeta.org", dw.NO_NAME]
    assert [t["label"] for t in g[0]["tiles"]] == ["site", "a", "b"]
    assert [t["changed"] for t in g[0]["tiles"]] == [False, False, True]
    assert [t["site"] for t in g[2]["tiles"]] == ["24.38.70.14", "24.157.51.70"], "numeric, not string, order"


def test_www_is_folded_into_its_site_before_the_tiles():
    rows = [("example.com", "MODERATE", True, "MODERATE"), ("www.example.com", "HIGH", True, "MODERATE")]
    now, then = dd.site_bands(rows)
    g = dw.site_groups(now, then)
    assert len(g[0]["tiles"]) == 1 and g[0]["tiles"][0]["band"] == "high" and g[0]["tiles"][0]["changed"]


# ── why ratings moved ────────────────────────────────────────────────────────

def test_each_move_is_explained_by_the_worst_finding_opened_or_closed_on_that_site():
    now = {"a.x.com": "high", "b.x.com": "high", "c.x.com": "moderate", "d.x.com": "high"}
    then = {"a.x.com": "moderate", "b.x.com": "moderate", "c.x.com": "high", "d.x.com": "moderate"}
    opened = [_f("1", "a.x.com", WAF, "HIGH", "2026-10-16T12:00:00+00:00"),
              _f("2", "a.x.com", "Missing header", "LOW", "2026-10-16T12:00:00+00:00"),
              _f("3", "b.x.com", WAF, "HIGH", "2026-10-17T12:00:00+00:00")]
    closed = [_f("4", "c.x.com", WAF, "HIGH", "2026-10-18T12:00:00+00:00", "remediated")]
    mv = dw.moves(now, then, opened, closed, set(now))
    assert mv["n_up"] == 3 and mv["n_down"] == 1
    assert mv["up"][0] == {"title": WAF, "severity": "HIGH", "sites": ["a.x.com", "b.x.com"]}
    assert mv["up"][-1]["sites"] == ["d.x.com"] and "no finding opened" in mv["up"][-1]["title"], \
        "a move nothing explains says so; it is never guessed"
    assert mv["down"][0]["sites"] == ["c.x.com"] and mv["down"][0]["title"] == WAF


def test_a_site_that_went_from_unrated_to_rated_is_not_a_move():
    mv = dw.moves({"n.x.com": "moderate"}, {"n.x.com": "unscanned"}, [], [], {"n.x.com"})
    assert mv["n_up"] == 0 and mv["n_down"] == 0


# ── the week, day by day ─────────────────────────────────────────────────────

def test_scans_by_day_deep_is_heavy_and_quick_is_light_or_medium():
    _s, _e, days = dw.week_window(NOW, BRAND)
    rows = [(date(2026, 10, 15), "heavy", 5), (date(2026, 10, 15), "light", 8),
            (date(2026, 10, 16), "medium", 2), (date(2026, 10, 22), "heavy", 9)]
    cols = dw.scans_by_day(rows, days)
    assert cols[0] == (5, 8) and cols[1] == (0, 2) and sum(a + b for a, b in cols) == 15, "today is outside the week"


def test_what_changed_is_grouped_by_reason_not_by_where_each_site_landed():
    """Howie, 10-22: "7 sites got safer … 1 site got safer. Why isn't it 8 sites got safer?" —
    one card per reason; a site that landed elsewhere is said inside it."""
    names = {"a.p.com", "b.p.com", "bitec.p.com", "s.p.com", "h.p.com"}
    then = {"a.p.com": "high", "b.p.com": "high", "bitec.p.com": "high", "s.p.com": "moderate", "h.p.com": "moderate"}
    now = {"a.p.com": "moderate", "b.p.com": "moderate", "bitec.p.com": "modhigh", "s.p.com": "high", "h.p.com": "modhigh"}
    closed = [_f(f"c{x}", x, WAF, "HIGH", "2026-10-18T12:00:00+00:00", "remediated") for x in ("a.p.com", "b.p.com", "bitec.p.com")]
    opened = [_f("o1", "bitec.p.com", "WAF detected but not blocking attacks", "MODERATE-HIGH", "2026-10-21T12:00:00+00:00"),
              _f("o2", "s.p.com", WAF, "HIGH", "2026-10-19T12:00:00+00:00"),
              _f("o3", "h.p.com", "WAF detected but not blocking attacks", "MODERATE-HIGH", "2026-10-20T12:00:00+00:00")]
    ch = dw.changes(now, then, opened, closed, names)
    safer = [g for g in ch if not g["riskier"]]
    assert len(safer) == 1 and safer[0]["sites"] == ["a.p.com", "b.p.com", "bitec.p.com"]
    assert (safer[0]["was"], safer[0]["now"]) == ("high", "moderate")
    assert safer[0]["reason"] == "A web firewall is now in place."
    assert safer[0]["asides"] == ["On bitec.p.com, though, the firewall only watches so far: our test attacks "
                                  "still get through, so it's Moderate-high, not Moderate."]
    riskier = [g for g in ch if g["riskier"]]
    assert len(riskier) == 1 and riskier[0]["was"] is None, "two single sites, one card"
    assert riskier[0]["asides"] == [
        "h.p.com (Moderate to Moderate-high): new problem: a web firewall is there, but it's only watching.",
        "s.p.com (Moderate to High): new problem: no web firewall in front of it."]


def test_a_guess_is_not_listed_counted_or_mentioned():
    """Howie, 10-22: "I'm really not into admitting a guess. There are risks and there are
    things that are known, that's all." SQL_SITE_RATINGS rates api.x.com by its known findings
    (Moderate, unchanged), so the guess moves nothing and is said nowhere."""
    s, e, days = dw.week_window(NOW, BRAND)
    m = dw.build_weekly(now=NOW, window_start=s, window_end=e, days=days, brand=BRAND, scans=[],
                        closed=[_f("c", "w.x.com", "Runs PHP, version not shown", "MODERATE", "2026-10-19T12:00:00+00:00", "remediated")],
                        sites=[("api.x.com", "MODERATE", True, "MODERATE"), ("w.x.com", "HIGH", True, "MODERATE")],
                        opened=[_f("g", "api.x.com", FW + ", 4 advisories", "CRITICAL", "2026-10-20T12:00:00+00:00"),
                                _f("w", "w.x.com", WAF, "HIGH", "2026-10-20T12:00:00+00:00")],
                        open_serious=[_f("g", "api.x.com", FW + ", 4 advisories", "CRITICAL", "2026-10-20T12:00:00+00:00"),
                                      _f("w", "w.x.com", WAF, "HIGH", "2026-10-20T12:00:00+00:00")])
    assert m["moves"]["n_up"] == 1 and m["headline"] == "w.x.com got riskier this week."
    assert [i["title"] for i in m["do"]] == ["No web firewall in front of this site"]
    (r,) = m["changes"]
    assert dw.change_title(r) == "1 site got riskier" and r["sites"] == ["w.x.com"]
    assert m["n_opened"] == 1 and m["n_closed"] == 0, "a guess opening or closing is not counted"
    assert "guesses" not in m
    html = dw.render_weekly_html(m, portal_url="", product_name="X")
    text = dw.render_weekly_text(m, portal_url="", product_name="X")
    for out in (html, text):
        assert "FortiWeb" not in out and "PHP" not in out
        assert "guess" not in out.lower() and "version" not in out.lower()


# ── the model, the words ─────────────────────────────────────────────────────

def _model(**over):
    s, e, days = dw.week_window(NOW, BRAND)
    kw = dict(now=NOW, window_start=s, window_end=e, days=days,
              sites=[("a.x.com", "HIGH", True, "MODERATE"), ("b.x.com", "MODERATE", True, "MODERATE")],
              opened=[_f("1", "a.x.com", WAF, "HIGH", "2026-10-16T12:00:00+00:00"),
                      _f("9", "b.x.com", FW, "CRITICAL", "2026-10-22T19:00:00+00:00")],   # today: explains, not counted
              closed=[], scans=[(date(2026, 10, 15), "heavy", 3)], brand=BRAND,
              baseline={"critical_open": 1, "high_open": 2, "mod_high_open": 0, "moderate_open": 3, "low_open": 4})
    kw.update(over)
    return dw.build_weekly(**kw)


def test_the_counts_are_the_seven_days_but_moves_may_be_explained_by_today():
    m = _model()
    assert m["n_opened"] == 1, "the finding opened today is outside the week's count"
    assert m["moves"]["n_up"] == 1 and m["moves"]["up"][0]["title"] == WAF


def test_this_week_do_lists_certificates_then_serious_problems_capped():
    certs = [("ftp.x.com", "TLS certificate expiring soon — expires < 30 days (11)", T("2026-10-14T20:42:31+00:00")),
             ("far.x.com", "TLS certificate expiring soon — expires < 60 days (51)", T("2026-10-20T21:00:00+00:00"))]
    serious = [_f(f"s{i}", f"h{i}.x.com", f"Problem {i}", "HIGH", "2026-10-20T00:00:00+00:00") for i in range(9)]
    m = _model(certs=certs, open_serious=serious)
    assert m["do"][0]["kind"] == "cert" and m["do"][0]["title"] == "Renew the certificate on ftp.x.com"
    assert m["do"][0]["who"] == "it"
    assert m["n_certs"] == 1, "51 days out is not this week's job"
    assert len([i for i in m["do"] if i["kind"] == "finding"]) == dw.DO_MAX and m["more"] == 9 - dw.DO_MAX


def test_headline_leads_with_the_bigger_move():
    m = _model()
    m["moves"] = {"up": [{"sites": ["a"], "severity": "HIGH", "title": WAF}], "down": [{}] * 1,
                  "n_up": 2, "n_down": 8}
    assert dw.weekly_headline(m) == "Eight sites got safer this week. Two got riskier."
    m["moves"].update(n_up=0, n_down=0)
    m["n_closed"] = 0
    assert dw.weekly_headline(m) == "A quiet week. No site changed risk level. We checked."


def test_subject_names_the_week_and_the_bigger_move_first():
    m = _model()
    assert dw.weekly_subject(m, "COMMANDsentry") == "[COMMANDsentry] Command, your week: 1 site riskier"
    m["moves"].update(n_up=2, n_down=8)
    m["n_closed"], m["n_certs"] = 8, 1
    assert dw.weekly_subject(m, "P") == "[P] Command, your week: 8 sites safer, 2 riskier, 8 problems fixed, 1 certificate to renew"
    m["degraded"] = True
    assert dw.weekly_subject(m, "P").startswith("[P] (!) Coverage gap. ")


def test_open_words_shows_moderate_high_only_when_there_is_one():
    assert dw.open_words({"critical_open": 4, "high_open": 16, "moderate_open": 187, "low_open": 406}) == \
        "4 critical, 16 high, 187 moderate, 406 low"
    assert "2 moderate-high" in dw.open_words({"high_open": 8, "mod_high_open": 2})


def test_html_is_email_safe_and_shows_every_site():
    m = _model()
    html = dw.render_weekly_html(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    assert not re.search(r"display\s*:\s*(flex|grid)", html)
    assert "<script" not in html.lower() and "<form" not in html.lower()
    assert all(src.startswith("cid:") for src in re.findall(r'<img[^>]+src="([^"]+)"', html))
    assert "Every site, by risk level" in html and ">a<" in html and ">b<" in html
    assert "What changed" in html
    assert "was 0" in html, "each box says what it was last week"
    assert "ticket" not in html.lower()
    assert 'href="https://portal.example"' in html and "prefers-reduced-motion" in html
    text = dw.render_weekly_text(m, portal_url="https://portal.example", product_name="COMMANDsentry")
    assert "EVERY SITE, BY RISK LEVEL" in text and "x.com: a high *, b moderate" in text


# ── run_alerter: the test send ───────────────────────────────────────────────

def test_a_test_send_may_narrow_the_recipients_and_never_add_one():
    to = ["Howie@prodexlabs.com", "sean@prodexlabs.com"]
    assert ra.preview_recipients(to, "") == (to, "")
    assert ra.preview_recipients(to, " howie@prodexlabs.com ") == (["howie@prodexlabs.com"], "")
    who, why = ra.preview_recipients(to, "howie@prodexlabs.com, someone@else.com")
    assert who == [] and "someone@else.com" in why and "never add" in why


def test_a_test_send_says_so_first_in_the_subject():
    assert ra.preview_subject("[P] Prodex, Thursday: nothing") == "Preview: [P] Prodex, Thursday: nothing"


def test_a_test_send_and_a_dry_run_write_nothing():
    src = inspect.getsource(ra.main)
    assert "record       = not (args.dry_run or args.preview)" in src
    assert "if record:\n                cur.execute(SQL_INSERT_RUN_START" in src
    assert "if run_id is not None:" in src, "no run row, nothing to finalize"
    assert "window_start = window_end - timedelta(hours=PREVIEW_HOURS)" in src
    assert src.index("preview_recipients(") < src.index("refusing to send the digest")
    wk = inspect.getsource(ra._run_weekly)
    assert "if record:" in wk and "if run_id is not None:" in wk and "preview_subject(subject)" in wk


def test_the_weekly_keeps_its_own_runs_rows():
    src = inspect.getsource(ra.main)
    assert '_env("ALERTER_WEEKLY_NAME", default=WEEKLY_NAME_DEFAULT)' in src
    assert ra.WEEKLY_NAME_DEFAULT == "weekly_digest"
    assert src.index("if args.weekly:\n            return _run_weekly(") < src.index("SQL_LAST_WINDOW_END"), \
        "the weekly never reads or moves the daily's window"


def test_open_serious_reads_the_dashboards_view_not_the_dedup_view():
    sql = " ".join(ra.SQL_OPEN_SERIOUS.split())
    assert "FROM public.v_fleet_open_reps r" in sql
    assert "v_open_findings_dedup" not in sql, "that view keeps false positives and fixed rows"
    for c in (ra.SQL_WEEK_SCANS, ra.SQL_OPEN_SERIOUS):
        assert re.sub(r"%\(\w+\)s|%s", "", c).count("%") == 0


class _Cur:
    def __init__(self, log, answers):
        self.log, self.answers, self.rows = log, answers, []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=None):
        self.log.append((sql, params))
        self.rows = self.answers.get(sql, [])
    def fetchall(self): return list(self.rows)
    def fetchone(self): return self.rows[0] if self.rows else None


class _Conn:
    def __init__(self, answers):
        self.log, self.answers = [], answers
    def cursor(self): return _Cur(self.log, self.answers)
    def transaction(self):
        return _Cur(self.log, {})


def test_weekly_model_reads_the_week_and_explains_up_to_now():
    answers = {ra.SQL_SITE_RATINGS: [("a.x.com", "HIGH", True, "MODERATE")],
               ra.SQL_NEW_FINDINGS_IN_WINDOW: [_f("1", "a.x.com", WAF, "HIGH", "2026-10-16T12:00:00+00:00")],
               ra.SQL_WEEK_SCANS: [(date(2026, 10, 19), "heavy", 7)]}
    conn = _Conn(answers)
    m = ra._weekly_model(conn, now=NOW, brand=BRAND)
    calls = dict((sql, p) for sql, p in conn.log)
    s = datetime(2026, 10, 15, 4, tzinfo=UTC)
    assert calls[ra.SQL_NEW_FINDINGS_IN_WINDOW] == (s, NOW) and calls[ra.SQL_FIXED_IN_WINDOW] == (s, NOW)
    assert calls[ra.SQL_SITE_RATINGS] == {"t": s}
    assert calls[ra.SQL_WEEK_SCANS] == {"tz": "America/New_York", "s": s, "e": datetime(2026, 10, 22, 4, tzinfo=UTC)}
    assert m["moves"]["n_up"] == 1 and m["n_scans"] == 7


# ── the job file ─────────────────────────────────────────────────────────────

def test_the_job_sends_the_weekly_on_monday_and_reads_inputs_as_variables():
    wf = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "alerter.yml"
    t = "\n".join(ln for ln in wf.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))
    assert 'cron: "0 12 * * *"' in t and 'cron: "5 12 * * 1"' in t
    assert '"$EVENT_SCHEDULE" = "5 12 * * 1"' in t, "the weekly's cron and its test agree"
    run = t[t.index("        run: |\n          args=()"):]
    assert "${{" not in run, "inputs reach the shell as variables, never pasted into it"
    for k in ("kind:", "preview:", "preview_to:", "dry_run:"):
        assert k in t
    assert "ALERTER_PREVIEW_TO:  ${{ github.event.inputs.preview_to }}" in t


def test_a_logo_entry_that_is_not_bytes_is_skipped_not_fatal():
    """Checker minor (3l code review): the bytes() conversion now sits inside the guard."""
    import mailer
    assert mailer._image_parts([("a", "text", "image/png"), ("b", 5, "image/png"),
                                ("ok", bytearray(b"1"), "image/png")]) == [("ok", b"1", "image", "png")]
