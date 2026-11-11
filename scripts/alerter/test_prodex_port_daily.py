from datetime import datetime, timedelta, timezone
import digest_daily as dd
import run_alerter as ra


def _model(notices):
    end = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
    return dd.build_model(window_start=end - timedelta(days=1), window_end=end,
        new_findings=[], confirmed=[], regressed=[], high_risk=[], new_assets=[], dark_assets=[],
        stale_assets=[], canary_violations=[], baseline={}, port_notices=notices)


def test_new_proven_nonweb_service_gets_one_line_in_both_renderings():
    notice = ("finding-1", "prod.prodexlabs.com", 22, "ssh", "2026-11-10T10:00:00Z")
    model = _model([notice])
    expected = "New service answering on prod.prodexlabs.com: 22/tcp (ssh)."
    assert dd.render_text(model).count(expected) == 1
    assert dd.render_html(model).count(expected) == 1
    assert model["port_notices"][0]["kind"] == "ssh"


def test_no_notice_means_no_new_service_line():
    model = _model([])
    assert "New service answering" not in dd.render_text(model)
    assert "New service answering" not in dd.render_html(model)


def test_daily_query_is_new_info_proven_nonweb_only():
    sql = ra.SQL_NEW_PROVEN_NONWEB_PORTS
    assert "f.first_detected_at > %s" in sql
    assert "f.severity='INFO'" in sql
    assert "f.params->>'port_sweep'='prodex_all_tcp'" in sql
    assert "NOT IN ('http','https')" in sql
    assert "a.ownership='owned'" in sql and "a.discovery_status='confirmed_live'" in sql
