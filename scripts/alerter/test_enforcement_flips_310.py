"""(Obsidian 310, 2026-10-13) "Security device enforcement" — the email says when a device
in front of a host starts (or stops) blocking attack payloads.

uat.prodexlabs.com: 10-12 20:10Z the differential probe measured every payload class passing
through; 10-13 18:39Z all blocked. The scanner saw it; the email did not say it. Read live on
2026-10-13 with a September-onward window, SQL_ENFORCEMENT_FLIPS_IN_WINDOW returns exactly two
rows: uat (false -> true, 10-13) and staging (first measurement, true, 10-12). These pins keep
the definition from drifting.
"""
import re
from datetime import datetime, timezone

import run_alerter as ra

W0 = datetime(2026, 10, 13, 12, 9, tzinfo=timezone.utc)
W1 = datetime(2026, 10, 14, 12, 8, tzinfo=timezone.utc)
UAT = ("uat.prodexlabs.com", "uat.prodexlabs.com", "prodex",
       datetime(2026, 10, 13, 18, 39, tzinfo=timezone.utc), True, False,
       datetime(2026, 10, 12, 20, 10, tzinfo=timezone.utc), ["lfi", "sqli", "xss"])
STAGING_FIRST = ("staging.prodexlabs.com", "staging.prodexlabs.com", "prodex",
                 datetime(2026, 10, 12, 17, 0, tzinfo=timezone.utc), True, None, None, ["lfi", "sqli", "xss"])
REVERSE = ("uat.prodexlabs.com", "uat.prodexlabs.com", "prodex",
           datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc), False, True,
           datetime(2026, 10, 13, 18, 39, tzinfo=timezone.utc), [])
BASE = {"critical_open": 0, "high_open": 0, "mod_high_open": 0, "moderate_open": 0, "low_open": 0}


def _sql():
    return " ".join(re.sub(r"--.*$", "", ra.SQL_ENFORCEMENT_FLIPS_IN_WINDOW, flags=re.M).split())


def _render(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              discovery_stale_hours=9, deepscan_stale_hours=168, baseline=BASE,
              product_name="PRODEXsentry")
    kw.update(over)
    return ra.render_html(dashboard_url="https://x.invalid", **kw), ra.render_text(**kw)


def test_a_measurement_is_a_non_null_verdict_on_a_complete_run():
    sql = _sql()
    assert "a.tool_name = 'stack_id_waf_differential'" in sql
    assert "a.content_jsonb->>'waf_present_differential' IS NOT NULL" in sql, "null = did not fire"
    assert "r.status::text = 'complete'" in sql


def test_a_flip_is_a_change_against_the_previous_measurement_per_asset():
    sql = _sql()
    assert "lag(m.blocked) OVER (PARTITION BY m.asset_id ORDER BY m.measured_at)" in sql
    assert "o.prev_blocked IS DISTINCT FROM o.blocked" in sql


def test_a_first_block_is_reported_and_a_first_pass_through_is_not():
    """The HIGH 'No enforcing WAF' finding already reports a first pass-through."""
    assert "(o.blocked OR o.prev_blocked IS NOT NULL)" in _sql()


def test_reported_once_in_the_window_holding_the_measurement_with_the_30_minute_shift():
    sql = _sql()
    assert "o.measured_at > %s - interval '30 minutes'" in sql
    assert "o.measured_at <= %s - interval '30 minutes'" in sql
    assert ra.SQL_ENFORCEMENT_FLIPS_IN_WINDOW.count("%s") == 2


def test_same_gate_as_dark_and_back():
    sql = _sql()
    assert "a.ownership = 'owned'" in sql and "a.discovery_status = 'confirmed_live'" in sql


def test_no_percent_sign_in_the_sql_except_placeholders():
    assert ra.SQL_ENFORCEMENT_FLIPS_IN_WINDOW.replace("%s", "").count("%") == 0


def test_the_words_are_the_probes_words_and_name_no_product():
    assert ra.enforcement_words(True, False) == ("NOW BLOCKED", "#1a7f37")
    assert ra.enforcement_words(True, None) == ("BLOCKED", "#1a7f37")
    assert ra.enforcement_words(False, True) == ("NOW PASSING THROUGH", "#b42318")


def test_rendered_in_both_bodies_with_the_measurement_and_the_previous_test():
    html, text = _render(enforcement_flips=[UAT, STAGING_FIRST])
    assert "Security device enforcement" in html
    assert "uat.prodexlabs.com" in html and "NOW BLOCKED" in html
    assert "2026-10-13 18:39 UTC" in html and "previous test 2026-10-12 20:10 UTC: passed through" in html
    assert "staging.prodexlabs.com" in html and "first test" in html
    assert "names no product" in html
    assert "SECURITY DEVICE ENFORCEMENT (2):" in text
    assert "uat.prodexlabs.com" in text and "attack payloads NOW BLOCKED (measured 2026-10-13 18:39 UTC; previous test 2026-10-12 20:10 UTC: passed through)" in text
    for body in (html, text):
        assert "Cloud Armor" not in body and "Google" not in body, "presence-only, like the probe"


def test_the_reverse_flip_reads_as_passing_through():
    html, text = _render(enforcement_flips=[REVERSE])
    assert "NOW PASSING THROUGH" in html and "previous test 2026-10-13 18:39 UTC: blocked" in html
    assert "attack payloads NOW PASSING THROUGH" in text


def test_a_window_with_only_a_flip_is_not_no_changes():
    html, text = _render(enforcement_flips=[UAT])
    assert "No changes" not in html and "No changes" not in text
    assert "1</strong> security device change(s)" in html
    assert "1 security device change(s)." in text


def test_nothing_flipped_changes_nothing():
    a = _render()
    b = _render(enforcement_flips=[])
    assert a == b
    assert "Security device enforcement" not in a[0] and "SECURITY DEVICE ENFORCEMENT" not in a[1]


def test_subject_counts_flips():
    src = open(ra.__file__, encoding="utf-8").read()
    assert 'subject_parts.append(f"{n} security device")' in src
    assert "cur.execute(SQL_ENFORCEMENT_FLIPS_IN_WINDOW, (window_start, window_end))" in src
