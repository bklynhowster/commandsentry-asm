"""(note 307 Part 2b, 2026-10-13) The digest counts like the dashboard.

Before push-307c the "currently open" block counted finding ROWS on owned+confirmed_live
assets (HIGH 23 while the dashboard said 6: apex + www rows, one row per advisory, and
findings no scan had seen in weeks). The headline counted INFO inventory as findings, and
its "status change(s)" counter read a view the scanners never write to (0 on the day a
CRITICAL was fixed). These pins keep each of those from coming back. Execution against
real PostgreSQL is in the push-307c evidence (v_fleet_open_reps vs the portal's own code).
"""
import inspect
import re
from datetime import datetime, timezone

import run_alerter as ra

W0 = datetime(2026, 10, 12, 12, 9, tzinfo=timezone.utc)
W1 = datetime(2026, 10, 13, 12, 8, tzinfo=timezone.utc)
HIGH = ("F-H", "ftp.sciimage.com", "F-01: Incomplete TLS Certificate Chain", "HIGH", "detected", "manual_named", W1)
LOW = ("F-L", "a.example", "Missing security header", "LOW", "detected", "commandsentry_light", W1)
INFO = ("F-I", "a.example", "Detected technologies: nginx", "INFO", "detected", "commandsentry_light", W1)
FIXED = ("F-X", "commandsentry-portal.netlify.app", "Next.js Middleware Bypass (CVE-2025-29927)",
         "CRITICAL", "remediated", "nuclei", W1)

ROWS = [("HIGH", 11, 4), ("MODERATE", 181, 49), ("LOW", 482, 226), ("INFO", 653, 312)]


def _sql(c):
    return " ".join(re.sub(r"--.*$", "", c, flags=re.M).split())


def _render(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              discovery_stale_hours=9, deepscan_stale_hours=168,
              baseline=ra.posture_from_rows(ROWS), product_name="COMMANDsentry")
    kw.update(over)
    return ra.render_html(dashboard_url="https://portal.example", **kw), ra.render_text(**kw)


# ── the open-posture query ──────────────────────────────────────────────────

def test_open_posture_reads_the_dashboards_rule_not_finding_rows():
    sql = _sql(ra.SQL_OPEN_POSTURE)
    assert "FROM public.v_fleet_open_reps" in sql
    assert "FROM findings" not in sql and "JOIN assets" not in sql, "row counting is what was wrong"
    assert "GROUP BY severity" in sql


def test_open_posture_says_how_many_problems_are_stale():
    sql = _sql(ra.SQL_OPEN_POSTURE)
    assert "last_observed_at < now() - interval '30 days'" in sql


def test_the_row_count_baseline_is_gone():
    assert not hasattr(ra, "SQL_OPEN_BASELINE")


def test_posture_dict_has_every_key_even_on_a_quiet_fleet():
    b = ra.posture_from_rows([])
    for k in ("critical_open", "high_open", "mod_high_open", "moderate_open", "low_open", "info_open",
              "problems_open", "problems_stale_30d", "info_stale_30d"):
        assert b[k] == 0
    b = ra.posture_from_rows(ROWS)
    assert b["high_open"] == 11 and b["moderate_open"] == 181 and b["low_open"] == 482
    assert b["info_open"] == 653, "INFO is carried, on its own"
    assert b["problems_open"] == 11 + 181 + 482, "problems exclude INFO"
    assert b["problems_stale_30d"] == 4 + 49 + 226 and b["info_stale_30d"] == 312


# ── fixed this window ───────────────────────────────────────────────────────

def test_fixed_reads_remediated_at_inside_the_window_on_owned_assets():
    sql = _sql(ra.SQL_FIXED_IN_WINDOW)
    assert "f.remediated_at > %s AND f.remediated_at <= %s" in sql
    assert "f.current_status IN ('remediated', 'validated_remediated')" in sql
    assert "a.ownership = 'owned'" in sql
    assert "v_alerter_changes" not in sql, "the transition view is what printed 0; do not read it"


def test_fixed_is_queried_in_main_with_the_window():
    src = inspect.getsource(ra.main)
    assert "cur.execute(SQL_FIXED_IN_WINDOW, (window_start, window_end))" in src
    assert "fixed=fixed" in src


# ── what the email says ─────────────────────────────────────────────────────

def test_problems_and_inventory_are_split_by_severity():
    p, i = ra.split_problems_inventory([HIGH, LOW, INFO])
    assert p == [HIGH, LOW] and i == [INFO]
    assert ra.split_problems_inventory([]) == ([], [])


def test_headline_counts_problems_not_inventory_and_names_fixed():
    html, text = _render(new_findings=[HIGH, LOW, INFO], fixed=[FIXED])
    assert "<strong>2</strong> new problem(s)" in html
    assert "<strong>1</strong> new inventory item(s)" in html
    assert "<strong>1</strong> fixed" in html
    assert "status change(s)" not in html
    assert "2 new problem(s), 1 new inventory item(s), 1 fixed" in text


def test_a_window_with_only_a_fix_is_not_no_changes():
    html, text = _render(fixed=[FIXED])
    assert "No changes" not in html and "No changes since last run" not in text
    assert "Marked fixed in this window" in html and "MARKED FIXED IN THIS WINDOW (1)" in text
    assert "Next.js Middleware Bypass" in html and "Next.js Middleware Bypass" in text


def test_open_block_shows_portal_counts_inventory_and_stale_separately():
    html, text = _render()
    assert "HIGH: <strong>11</strong>" in html and "MODERATE: <strong>181</strong>" in html
    assert "LOW: <strong>482</strong>" in html
    assert "<strong>674</strong> open problem(s)" in html
    assert "<strong>653</strong> informational" in html
    assert "<strong>279</strong> of the open problems" in html and "30+ days" in html
    assert "MOD-HIGH" not in html, "a zero legacy severity is not shown"
    assert "HIGH=11  MODERATE=181  LOW=482  = 674 open problem(s)" in text
    assert "+ 653 informational" in text
    assert "279 of the open problems have not been seen by any scan in 30+ days" in text


def test_mod_high_shows_only_when_non_zero_and_stale_line_only_when_non_zero():
    b = ra.posture_from_rows([("MODERATE-HIGH", 2, 0), ("LOW", 1, 0)])
    html, text = _render(baseline=b)
    assert "MOD-HIGH: <strong>2</strong>" in html and "MOD-HIGH=2" in text
    assert "30+ days" not in html and "30+ days" not in text


def test_old_five_key_baseline_still_renders():
    """The renderers must not KeyError on a baseline from an older caller/test."""
    b = {"critical_open": 0, "high_open": 1, "mod_high_open": 0, "moderate_open": 2, "low_open": 3}
    html, text = _render(baseline=b)
    assert "<strong>6</strong> open problem(s)" in html and "= 6 open problem(s)" in text


def test_links_and_footer_go_to_the_portal():
    html, _ = _render(new_findings=[HIGH, INFO])
    assert 'href="https://portal.example/findings/F-H"' in html
    # the collapsed INFO line links to the asset page; /findings has no asset= filter
    assert 'href="https://portal.example/assets/a.example"' in html
    assert "findings?asset=" not in html
    assert "Open the COMMANDsentry portal" in html
    assert "Supabase" not in html
    src = inspect.getsource(ra.main)
    assert '_env("ALERTER_PORTAL_URL"' in src, "the portal URL must be READ from the env, not just mentioned"
    assert "dashboard_url=portal_url" in src


def test_fixed_rows_are_labelled_fixed_not_new_and_scanner_sources_read_as_tiers():
    html, _ = _render(fixed=[FIXED])
    assert "1 fixed</span>" in html and "1 new</span>" not in html
    assert ra.scan_tier_label("commandsentry_medium") == "medium scan"
    assert ra.scan_tier_label("commandsentry_light") == "light scan"
    assert ra.scan_tier_label("commandsentry_heavy") == "deep scan"
    assert ra.scan_tier_label("some_new_producer") == "some_new_producer"


def test_the_device_class_line_is_gone_from_both_renderers():
    classes = {"a.example": {"device_class": "unknown", "confidence": "unknown", "vendor_product": {}}}
    html, text = _render(new_findings=[LOW], device_classes=classes)
    assert "dry-run classification" not in html and "dry-run classification" not in text
    assert "unknown/unknown" not in html and "unknown/unknown" not in text


def test_subject_names_problems_inventory_fixed_regressed():
    src = inspect.getsource(ra.main)
    for part in ('f"{n} new problem', 'f"{n} new info"', 'f"{n} fixed"', 'f"{n} regressed"'):
        assert part in src, part
    assert '{n} new find' not in src and '{n} chng' not in src


def test_no_percent_sign_in_the_new_sql_except_placeholders():
    for c in (ra.SQL_OPEN_POSTURE, ra.SQL_FIXED_IN_WINDOW):
        assert re.sub(r"%s", "", c).count("%") == 0
