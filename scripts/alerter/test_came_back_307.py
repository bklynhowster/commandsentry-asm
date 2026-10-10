"""(note 307, 2026-10-10) "Assets back online" — the other half of "went dark".

pm.unimacgraphics.com was reported dark on 10-05 and appeared with new findings on 10-10; the
digest never said it had come back. The executed behaviour is proven against real PostgreSQL in
the push-307 evidence; these pins keep the definition from drifting.
"""
import re
from datetime import datetime, timezone

import run_alerter as ra

W0 = datetime(2026, 10, 9, 12, 9, tzinfo=timezone.utc)
W1 = datetime(2026, 10, 10, 12, 8, tzinfo=timezone.utc)
ROW = ("pm.unimacgraphics.com", "pm.unimacgraphics.com", "unimac",
       datetime(2026, 10, 9, 19, 12, tzinfo=timezone.utc),
       datetime(2026, 10, 5, 1, 37, tzinfo=timezone.utc))
BASE = {"critical_open": 0, "high_open": 0, "mod_high_open": 0, "moderate_open": 0, "low_open": 0}


def _sql():
    return " ".join(re.sub(r"--.*$", "", ra.SQL_CAME_BACK_IN_WINDOW, flags=re.M).split())


def _render(**over):
    kw = dict(window_start=W0, window_end=W1, new_findings=[], confirmed=[], regressed=[],
              high_risk=[], new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
              discovery_stale_hours=9, deepscan_stale_hours=168, baseline=BASE,
              product_name="COMMANDsentry")
    kw.update(over)
    return ra.render_html(dashboard_url="https://x.invalid", **kw), ra.render_text(**kw)


def test_back_means_the_first_answer_after_the_latest_dark_event():
    sql = _sql()
    assert "event_type = 'asset_went_dark'" in sql
    assert "DISTINCT ON (e.asset_id)" in sql and "ORDER BY e.asset_id, e.observed_at DESC" in sql
    assert "min(v.probed_at)" in sql and "v.any_port_responded" in sql
    assert "v.probed_at > d.dark_at" in sql


def test_back_is_reported_once_in_the_window_that_holds_the_first_answer():
    sql = _sql()
    assert ("b.back_at > %s - interval '30 minutes' AND b.back_at <= %s - interval '30 minutes'"
            in sql), "both edges shifted by the SAME lag, so windows still tile"


def test_back_uses_the_same_gate_as_dark():
    sql = _sql()
    assert "a.ownership = 'owned'" in sql and "a.discovery_status = 'confirmed_live'" in sql


def test_any_route_counts_no_probe_source_filter():
    assert "probe_source" not in _sql()


def test_no_percent_sign_in_the_sql_except_placeholders():
    """psycopg reads a bare percent sign anywhere in the string as a parameter marker."""
    assert re.sub(r"%s", "", ra.SQL_CAME_BACK_IN_WINDOW).count("%") == 0


def test_rendered_in_both_bodies_with_both_times():
    html, text = _render(came_back=[ROW])
    assert "Assets back online" in html and "<strong>1</strong> back online" in html
    assert "2026-10-05 01:37 UTC" in html and "2026-10-09 19:12 UTC" in html
    assert "ASSETS BACK ONLINE (1):" in text
    assert "reported dark 2026-10-05 01:37 UTC, answered again 2026-10-09 19:12 UTC" in text


def test_a_window_with_only_a_comeback_is_not_no_changes():
    html, text = _render(came_back=[ROW])
    assert "No changes" not in html and "No changes since last run" not in text


def test_nothing_back_changes_nothing():
    html, text = _render()
    assert "back online" not in html and "BACK ONLINE" not in text


def test_subject_counts_comebacks():
    import inspect
    assert 'subject_parts.append(f"{n} back")' in inspect.getsource(ra.main)
