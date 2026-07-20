"""Unit tests for the fwbbot_check active probe (Phase B, 4.7 Q3/Q7).
Pure detector + the dry-run default. The DB opt-in gate, audit write, and live
firing are validated end-to-end in the Phase C 7-day soak (they need a live DB)."""
import run_heavy as h


def test_dry_run_is_the_default():
    # env ACTIVE_PROBE_LIVE unset -> module ships DRY-RUN (fires nothing). The whole
    # safety posture rests on this default.
    assert h._ACTIVE_PROBE_LIVE is False


def test_redirect_to_challenge_is_observed_and_corroborated():
    hdrs = "HTTP/1.1 302 Found\r\nLocation: https://host/fwbbot_check?csrftoken=abc\r\n"
    observed, corroborated, d = h._detect_fwbbot_from_headers(hdrs)
    assert observed is True and corroborated is True
    assert "fwbbot_check" in d["location"]


def test_path_mention_without_redirect_is_observed_not_corroborated():
    # 4.7 Q7: /fwbbot_check seen but NOT as a redirect-to-challenge -> candidate only,
    # must NOT corroborate (stops honeypot / coincidental-collision vendor assertions).
    hdrs = "HTTP/1.1 200 OK\r\nX-Note: docs at /fwbbot_check\r\n"
    observed, corroborated, _ = h._detect_fwbbot_from_headers(hdrs)
    assert observed is True and corroborated is False


def test_absent_is_neither():
    hdrs = "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: cookiesession1=x\r\n"
    observed, corroborated, _ = h._detect_fwbbot_from_headers(hdrs)
    assert observed is False and corroborated is False


def test_empty_headers_safe():
    assert h._detect_fwbbot_from_headers("") == (False, False, {"location": "", "request_class": "head_browser_ua"})


# ── egress A/B toggle (Howie 2026-07-20): VPN vs direct datacenter vantage ───
def test_egress_direct_with_interface_binds_it():
    args = h._probe_curl_args("host.example", "direct", "eth0")
    assert "--interface" in args and args[args.index("--interface") + 1] == "eth0"
    assert args[-1] == "https://host.example/"


def test_egress_vpn_never_binds_interface():
    args = h._probe_curl_args("host.example", "vpn", "eth0")
    assert "--interface" not in args


def test_egress_direct_without_interface_falls_back_to_default():
    # 'direct' requested but no interface configured -> no faked bypass; default egress.
    args = h._probe_curl_args("host.example", "direct", "")
    assert "--interface" not in args


def test_egress_default_is_vpn():
    assert h._ACTIVE_PROBE_EGRESS == "vpn"


# ── regression: DB helpers must get psycopg via _import_deps() (no module-level
# psycopg — the NameError that silently killed the auth read + audit write) ──────
import types


def _fake_deps(fetch_row, calls):
    class _Cur:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, sql, params=None): calls.append((sql, params))
        def fetchone(self): return fetch_row
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def cursor(self, **kw): return _Cur()
    psy = types.SimpleNamespace(connect=lambda *a, **k: _Conn())
    return lambda: (psy, dict, None)


def test_read_authorized_reaches_db_via_import_deps(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "_import_deps", _fake_deps({"active_probe_authorized": True}, calls))
    ctx = types.SimpleNamespace(dsn="x", asset_id="ccc")
    assert h._read_active_probe_authorized(ctx) is True     # False before the fix (NameError swallowed)
    assert calls and "active_probe_authorized" in calls[0][0]


def test_audit_write_reaches_insert_via_import_deps(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "_import_deps", _fake_deps(None, calls))
    ctx = types.SimpleNamespace(dsn="x", asset_id="ccc", egress_ip_initial=None, scan_run_id="s")
    v = {"probe_class": "fwbbot_check_elicit", "authorized": False, "dry_run": True,
         "observed": None, "corroborated": None, "details": {}}
    h._write_active_probe_audit(ctx, v)
    assert calls and "insert into public.active_probe_audit" in calls[0][0]   # execute reached (no NameError)


def test_read_no_dsn_is_false():
    assert h._read_active_probe_authorized(types.SimpleNamespace(dsn=None, asset_id="x")) is False
