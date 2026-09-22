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
    # (relay 430) THIS TEST ENCODED THE BUG. Empty headers = NO HTTP RESPONSE,
    # which is a network reset, not a quiet "no challenge" — and on the one host
    # we know enforces, that misreading is what the live positive-control fire
    # exposed. Uncorroborated it still claims NOTHING (the safety the old
    # assertion was really protecting), which is what this now pins.
    observed, corroborated, d = h._classify_fwbbot_response("")
    assert corroborated is False, "an empty response must never corroborate the vendor"
    assert d["result"] == "network_reset"
    assert d["status"] == 0 and d["location"] == ""
    assert d["enforcement_corroborated"] is False, (
        "with no same-run reachability, a no-response proves nothing")
    assert observed is True, "we did observe the edge giving us nothing"


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


# ── relay 430: the NETWORK RESET outcome, and the two-claims separation ──────
# The live positive-control fire (Scanner #3652, commandcommcentral.com,
# 2026-09-22) returned status 0 / empty headers — FortiWeb rate-banned the
# Mullvad exit mid-heavy-scan. The old classifier had no branch for it and
# logged a FALSE no_challenge on the one host we KNOW enforces.

def test_the_LIVE_positive_control_capture_reads_network_reset():
    # The exact shape 4.7 measured: no response at all.
    observed, corroborated, d = h._classify_fwbbot_response(
        "", reachable_earlier=True, curl_rc=35)
    assert d["result"] == "network_reset", d
    assert observed is True, "a reset IS an observation — we watched the edge cut us off"
    assert d["enforcement_corroborated"] is True
    assert d["curl_rc"] == 35 and d["reachable_earlier_this_run"] is True


def test_a_reset_is_NOT_corroboration_of_the_fortiweb_challenge_endpoint():
    # ⛔ THE SEPARATION THAT MUST NOT COLLAPSE. `corroborated` is
    # VENDOR-IDENTIFYING — device_class_runner feeds it to the
    # fortiweb_challenge_endpoint_fwbbot_check fingerprint. Any edge can drop a
    # connection, so a reset names NO vendor and must never set it. Enforcement
    # evidence rides the separate field.
    _o, corroborated, d = h._classify_fwbbot_response("", reachable_earlier=True)
    assert corroborated is False, (
        "a network reset set the FortiWeb VENDOR fingerprint — it proves a ban, "
        "not that this edge is FortiWeb")
    assert d["enforcement_corroborated"] is True


def test_an_UNCORROBORATED_reset_claims_nothing():
    # The 407 discipline applied to resets: with no proof the host was ever up
    # from this egress, "no response" cannot be told from "never answered".
    _o, corroborated, d = h._classify_fwbbot_response("", reachable_earlier=False)
    assert d["result"] == "network_reset"
    assert corroborated is False
    assert d["enforcement_corroborated"] is False, (
        "a bare status-0 with no same-run reachability was read as enforcement")


def test_a_challenge_sets_BOTH_claims():
    hdrs = "HTTP/1.1 302 Found\r\nLocation: https://host/fwbbot_check?t=1\r\n"
    _o, corroborated, d = h._classify_fwbbot_response(hdrs)
    assert corroborated is True and d["enforcement_corroborated"] is True


def test_a_REAL_response_is_never_a_reset():
    # ⛔ Gated on BOTH status==0 AND empty headers, so a malformed-but-present
    # response cannot be mistaken for a ban.
    for hdrs in ("HTTP/1.1 200 OK\r\n", "garbage but present\r\n", "   \r\n\r\nx"):
        _o, _c, d = h._classify_fwbbot_response(hdrs, reachable_earlier=True)
        assert d["result"] != "network_reset", (hdrs, d)
    # and a plain 200 still reads no_challenge, unchanged
    _o, _c, d = h._classify_fwbbot_response("HTTP/1.1 200 OK\r\n", reachable_earlier=True)
    assert d["result"] == "no_challenge" and d["enforcement_corroborated"] is False


# ── the corroborator itself ──────────────────────────────────────────────────

def test_passive_stack_answered_reads_a_real_same_run_answer():
    import json as _json
    for sig in ({"cert": {"subject": "CN=x"}}, {"headers": "server: nginx"},
                {"set_cookie_names": ["cookiesession1"]}):
        arts = [("stack_id_passive", "json", _json.dumps(sig))]
        assert h.passive_stack_answered(arts) is True, sig


def test_passive_stack_answered_is_false_without_a_real_answer():
    import json as _json
    assert h.passive_stack_answered([]) is False
    assert h.passive_stack_answered(None) is False
    # the phase ran but collected nothing = the host did NOT answer
    assert h.passive_stack_answered(
        [("stack_id_passive", "json", _json.dumps({}))]) is False
    # a different artifact must not be mistaken for reachability
    assert h.passive_stack_answered(
        [("stack_id_wafw00f", "json", _json.dumps({"headers": "x"}))]) is False
    # unparseable payloads fail closed
    assert h.passive_stack_answered([("stack_id_passive", "json", "{not json")]) is False


def test_the_corroborator_does_NOT_key_on_waf_differential():
    """⛔ THE SILENT-NO-OP GUARD (relay 430).

    run_heavy calls run_fwbbot_check_probe_phase BEFORE
    run_waf_differential_probe_phase, so at fwbbot time the differential
    artifact does NOT exist. Keying the corroborator on it — the obvious choice,
    and the one 430's write-up reasoned from — would make it ALWAYS False and
    the whole network_reset branch dead on arrival. Pin the ordering so a later
    refactor cannot quietly reintroduce that.
    """
    import inspect as _inspect
    import json as _json
    # ⛔ ASSERT THE PROPERTY, NOT THE PROSE. A source-text scan reds on this
    # function's own docstring, which names waf_differential precisely in order
    # to explain why it is NOT used — the prose-contains-the-token trap this
    # codebase has now hit six times. So: feed it a differential artifact and
    # require that it counts for nothing.
    for name in ("stack_id_waf_differential", "waf_differential"):
        assert h.passive_stack_answered(
            [(name, "json", _json.dumps({"headers": "server: nginx"}))]) is False, (
            f"{name} was accepted as same-run reachability, but it does not exist "
            f"yet when the fwbbot phase runs — the corroborator would be a no-op")
    run_src = _inspect.getsource(h)
    i_fwbbot = run_src.index("run_fwbbot_check_probe_phase(ctx, work_dir)")
    i_diff = run_src.index("run_waf_differential_probe_phase(ctx, work_dir)")
    assert i_fwbbot < i_diff, (
        "phase order changed — the differential now runs FIRST, so it could be a "
        "valid corroborator and this constraint should be revisited deliberately")
