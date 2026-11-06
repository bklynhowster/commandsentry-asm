"""KB 12 job 5c (2026-11-06) — a missing Content-Security-Policy and a static CSP nonce are LOW.

Howie, 11:40, on the missing policy (Command 36 open, Prodex 6): "Yes, recategorize them as low for
the emails, please."; by 11:44, on the static-nonce findings (Command 9): "Yes, include them". The
same reasoning as job 4v: each is a policy that stops nothing; by itself it lets nothing in.
Pinned here:
  - the quick scan's header table: Content-Security-Policy LOW, every other header unchanged
    (Strict-Transport-Security stays MODERATE);
  - the header check writes the missing-policy finding LOW;
  - both static-nonce checks write LOW, and still say nothing when the nonce changes.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_light  # noqa: E402


def _ctx():
    class _Ctx:
        hostname = "geisinger.commandcommcentral.com"

        def __init__(self):
            self.tools_run, self.findings, self.artifacts, self.tool_status = [], [], [], {}
    return _Ctx()


def test_the_header_table():
    assert {h: s for h, s, _ in run_light.SECURITY_HEADERS} == {
        "Strict-Transport-Security": "MODERATE",
        "Content-Security-Policy": "LOW",
        "X-Frame-Options": "LOW",
        "X-Content-Type-Options": "LOW",
        "Referrer-Policy": "LOW",
        "Permissions-Policy": "LOW",
        "X-Permitted-Cross-Domain-Policies": "INFO",
    }


def test_the_header_check_writes_a_missing_policy_low(monkeypatch):
    rec = {"status_code": 200, "header": {"strict_transport_security": "max-age=1"}}
    ctx = _ctx()
    monkeypatch.setattr(run_light, "run_cmd", lambda *a, **k: (0, json.dumps(rec) + "\n", ""))
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_ok", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_degraded", lambda *a, **k: None)
    run_light.check_headers(ctx)
    got = {f.check_name: f.severity for f in ctx.findings}
    assert got["missing-header-content-security-policy"] == "LOW"
    assert "missing-header-strict-transport-security" not in got
    assert got["missing-header-x-frame-options"] == "LOW"


def _curl_answers(monkeypatch, policies):
    it = iter(policies)

    def fake(*a, **k):
        return 0, f"HTTP/2 200\r\ncontent-security-policy: {next(it)}\r\n", ""
    monkeypatch.setattr(run_light, "run_cmd", fake)


def test_a_static_script_nonce_is_low(monkeypatch):
    ctx = _ctx()
    _curl_answers(monkeypatch, ["script-src 'nonce-abc123' 'self'"] * 5)
    run_light.check_csp_nonce(ctx)
    assert [(f.check_name, f.severity) for f in ctx.findings] == [("csp-static-nonce", "LOW")]
    ctx = _ctx()
    _curl_answers(monkeypatch, [f"script-src 'nonce-n{i}' 'self'" for i in range(5)])
    run_light.check_csp_nonce(ctx)
    assert ctx.findings == [], "a nonce that changes is not a finding"


def test_a_static_nonce_per_directive_is_low(monkeypatch):
    ctx = _ctx()
    pol = [f"script-src 'nonce-s{i}'; style-src 'nonce-CSS_10001' 'nonce-CSS_10002'" for i in range(5)]
    _curl_answers(monkeypatch, pol)
    run_light.probe_static_csp_nonces_per_directive(ctx)
    assert [(f.check_name, f.severity) for f in ctx.findings] == [("csp-static-nonce-style_src", "LOW")]
    ctx = _ctx()
    _curl_answers(monkeypatch, [f"script-src 'nonce-s{i}'; style-src 'nonce-t{i}'" for i in range(5)])
    run_light.probe_static_csp_nonces_per_directive(ctx)
    assert ctx.findings == []


def test_no_moderate_left_in_the_two_nonce_checks():
    import inspect
    for fn in (run_light.check_csp_nonce, run_light.probe_static_csp_nonces_per_directive):
        src = inspect.getsource(fn)
        assert 'severity="MODERATE"' not in src and 'severity="LOW"' in src, fn.__name__
