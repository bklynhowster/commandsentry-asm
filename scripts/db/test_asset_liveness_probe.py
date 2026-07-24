"""Tests for the liveness probe worker's pure cores (Obsidian 161 step 2).

probe_asset is exercised with the network primitives (resolve_host/probe_port) monkeypatched, so
no sockets are opened. sweep_ok is the 4.7-Q7 egress fail-safe.
"""
import asset_liveness_probe as w


# ── sweep-health egress fail-safe (4.7 Q7) ────────────────────────────────────────
def test_sweep_ok_aborts_when_fleet_mostly_silent():
    verdicts = [{"any_port_responded": False}] * 95 + [{"any_port_responded": True}] * 5
    ok, reason = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is False and "egress" in reason               # 5% < 10% floor -> our egress, abort


def test_sweep_ok_passes_with_healthy_response_rate():
    verdicts = [{"any_port_responded": True}] * 20 + [{"any_port_responded": False}] * 80
    ok, reason = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is True and "20/100" in reason


def test_sweep_ok_small_fleet_has_no_floor():
    # a tiny fleet can legitimately be mostly quiet — never abort on it
    ok, reason = w.sweep_ok([{"any_port_responded": False}] * 4, fleet_size=4)
    assert ok is True and "small_fleet" in reason


def test_sweep_ok_none_verdicts_dont_count_as_responded():
    # skipped assets (resolver hiccup -> None) must not inflate the responded fraction
    verdicts = [None] * 95 + [{"any_port_responded": True}] * 5
    ok, _ = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is False


# ── probe_asset (primitives patched) ──────────────────────────────────────────────
def test_probe_asset_nxdomain_is_not_responded(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: (None, "nxdomain"))
    v = w.probe_asset("gone.example.com", [443, 80, 22])
    assert v == {"any_port_responded": False, "any_port_open": False,
                 "per_port_results": {"_dns": "nxdomain"}}


def test_probe_asset_resolver_hiccup_skips(monkeypatch):
    # EAI_AGAIN etc. -> inconclusive -> None (don't record a wrong verdict)
    monkeypatch.setattr(w, "resolve_host", lambda h: (None, "inconclusive"))
    assert w.probe_asset("flaky.example.com", [443]) is None


def test_probe_asset_rst_only_responded_not_open(monkeypatch):
    # the ftp.unimacgraphics.com shape: host answers with RST on every probed port
    monkeypatch.setattr(w, "resolve_host", lambda h: ("208.199.0.160", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "refused")
    v = w.probe_asset("ftp.unimacgraphics.com", [22, 443, 990, 21])
    assert v["any_port_responded"] is True                  # host answered -> digest SUPPRESSES
    assert v["any_port_open"] is False                      # no open service -> demotion may act
    assert set(v["per_port_results"]) == {"22", "443", "990", "21"}


def test_probe_asset_open_service_is_open(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: ("1.2.3.4", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "open" if p == 443 else "noresponse")
    v = w.probe_asset("web.example.com", [443, 80])
    assert v["any_port_responded"] is True and v["any_port_open"] is True


def test_probe_asset_all_timeout_is_dark(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: ("1.2.3.4", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "noresponse")
    v = w.probe_asset("dead.example.com", [443, 80, 22])
    assert v["any_port_responded"] is False and v["any_port_open"] is False   # genuinely dark
