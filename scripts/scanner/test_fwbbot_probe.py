"""Unit tests for the fwbbot_check active probe (Phase B guardrails + Phase D shape).
Pure classifier + bot-shape argv + the dry-run default + the per-asset policy read.
The DB opt-in gate and live firing are validated end-to-end on a live scan; here we
pin the pure logic: response classification (4.7 Q4), the bot-shaped request (4.7 Q2),
and that the policy read reaches the DB via _import_deps (the psycopg-scope regression)."""
import run_heavy as h


def test_dry_run_is_the_default():
    # env ACTIVE_PROBE_LIVE unset -> module ships DRY-RUN (fires nothing). The whole
    # safety posture rests on this default.
    assert h._ACTIVE_PROBE_LIVE is False


# ── 4.7 Q4: the response classifier — 4 outcomes, corroboration only on redirect ──
def test_redirect_to_challenge_is_observed_and_corroborated():
    hdrs = "HTTP/1.1 302 Found\r\nLocation: https://host/fwbbot_check?csrftoken=abc\r\n"
    observed, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert observed is True and corroborated is True
    assert d["result"] == "challenge_elicited" and d["status"] == 302
    assert "fwbbot_check" in d["location"]


def test_banned_is_neither_even_if_path_echoed():
    # 4.7 Q4: a WAF block (403/429) is NOT corroboration, even if the block page path
    # echoes /fwbbot_check in a header. Signal must stay dormant.
    hdrs = "HTTP/1.1 403 Forbidden\r\nServer: FortiWeb\r\nX-Blocked: /fwbbot_check\r\n"
    observed, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert corroborated is False and d["result"] == "banned" and d["status"] == 403


def test_path_mention_without_redirect_is_observed_not_corroborated():
    # /fwbbot_check seen but NOT as a redirect target -> candidate only, must NOT
    # corroborate (stops honeypot / coincidental-collision vendor assertions).
    hdrs = "HTTP/1.1 200 OK\r\nX-Note: docs at /fwbbot_check\r\n"
    observed, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert observed is True and corroborated is False
    assert d["result"] == "path_mentioned_not_redirect"


def test_normal_response_is_no_challenge():
    hdrs = "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: cookiesession1=x\r\n"
    observed, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert observed is False and corroborated is False and d["result"] == "no_challenge"


def test_generic_302_not_to_challenge_is_not_corroborated():
    # a redirect that is NOT to /fwbbot_check must never corroborate.
    hdrs = "HTTP/1.1 302 Found\r\nLocation: https://host/login\r\n"
    observed, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert corroborated is False and d["result"] == "no_challenge"


def test_empty_headers_safe():
    observed, corroborated, d = h._classify_fwbbot_response("")
    assert observed is False and corroborated is False
    assert d == {"result": "no_challenge", "status": 0, "location": ""}


# ── 4.7 Q2/Q3: the fixed bot-shaped request (L7 only; uTLS deferred) ─────────────
def test_bot_shape_is_get_with_nonbrowser_ua_and_no_accept():
    args = h._probe_curl_args("host.example", "vpn", "")
    assert "-I" not in args                                   # GET, not HEAD
    assert "-L" not in args                                   # never follow the redirect
    assert args[args.index("-A") + 1] == "curl/7.81.0"        # known non-browser UA
    assert args[args.index("-o") + 1] == "/dev/null"          # body discarded
    assert "-D" in args                                       # headers dumped (read Location)
    # Accept / Accept-Language / Accept-Encoding stripped (bot-shape tell)
    hdr_vals = [args[i + 1] for i, a in enumerate(args) if a == "-H"]
    assert "Accept:" in hdr_vals and "Accept-Language:" in hdr_vals and "Accept-Encoding:" in hdr_vals
    assert args[-1] == "https://host.example/"


def test_bot_ua_is_fixed_not_randomized():
    assert h._PROBE_BOT_UA == "curl/7.81.0"
    a1 = h._probe_curl_args("a", "vpn", "")
    a2 = h._probe_curl_args("b", "vpn", "")
    assert a1[a1.index("-A") + 1] == a2[a2.index("-A") + 1]


# ── egress A/B toggle: VPN vs direct datacenter vantage (per-asset, 4.7 Q1) ──────
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


# ── regression: policy read must reach the DB via _import_deps() (the psycopg-scope
# NameError that silently killed the auth read + audit write) + return per-asset egress ─
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


def test_policy_read_reaches_db_and_returns_egress(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "_import_deps",
                        _fake_deps({"active_probe_authorized": True,
                                    "active_probe_egress": "direct",
                                    "active_probe_egress_reason": "Mullvad ban observed"}, calls))
    ctx = types.SimpleNamespace(dsn="x", asset_id="ccc")
    authorized, egress, reason = h._read_active_probe_policy(ctx)   # False before the fix (NameError swallowed)
    assert authorized is True and egress == "direct" and "Mullvad" in reason
    assert calls and "active_probe_authorized" in calls[0][0] and "active_probe_egress" in calls[0][0]


def test_policy_read_defaults_egress_to_vpn_when_unset(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "_import_deps",
                        _fake_deps({"active_probe_authorized": True}, calls))   # no egress column value
    ctx = types.SimpleNamespace(dsn="x", asset_id="ccc")
    authorized, egress, reason = h._read_active_probe_policy(ctx)
    assert authorized is True and egress == "vpn" and reason == ""


def test_audit_write_reaches_insert_via_import_deps(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "_import_deps", _fake_deps(None, calls))
    ctx = types.SimpleNamespace(dsn="x", asset_id="ccc", egress_ip_initial=None, scan_run_id="s")
    v = {"probe_class": "fwbbot_check_elicit", "authorized": False, "dry_run": True,
         "observed": None, "corroborated": None, "details": {}}
    h._write_active_probe_audit(ctx, v)
    assert calls and "insert into public.active_probe_audit" in calls[0][0]   # execute reached (no NameError)


def test_policy_read_no_dsn_is_false():
    authorized, egress, reason = h._read_active_probe_policy(types.SimpleNamespace(dsn=None, asset_id="x"))
    assert authorized is False and egress == "vpn"
