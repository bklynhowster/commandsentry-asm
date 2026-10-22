"""KB 12 job 3c — stack_fingerprint.py: the VPN-gateway checks the light tier sends.

Pins: the exact requests (the three reviewed nuclei templates' requests, nothing
else — no credentials, no POST, no exploit path), the matchers, the ASA version
spelling NVD uses, the FortiGate ETag build date and its sanity bounds, null for
"no answer" vs a real negative, the port list, and the run_light / registry wiring.
"""
import ast
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stack_fingerprint as sf  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ASA_HELLO_REPLY = ('<?xml version="1.0" encoding="UTF-8"?>\n<config-auth client="vpn" type="hello" '
                   'aggregate-auth-version="2"><version who="sg">9.16(4)48</version>'
                   '<auth id="main"><title>Login</title></auth></config-auth>')
ASA_LOGON_PAGE = '<html><link rel="stylesheet" href="/+CSCOU+/portal.css"><title>SSL VPN Service</title>'
FGT_LANDING = '<html><script>top.location="/remote/login";</script></html>'
FGT_ETAG = '"5f2-65d4c0a1"'          # 0x65d4c0a1 = 1708441761 = 2024-02-20


class Fake:
    """fetch() double: records every request; answers by (port, path)."""

    def __init__(self, answers=None, default=(404, "", None)):
        self.answers = answers or {}
        self.default = default
        self.sent = []

    def __call__(self, port, path, headers, body):
        self.sent.append((port, path, dict(headers or {}), body))
        return self.answers.get((port, path), self.default)


# ── the requests ─────────────────────────────────────────────────────────────
def test_sends_exactly_the_three_template_requests_on_443():
    f = Fake()
    sf.run_checks("vpn.example.com", set(), f, now=NOW)
    assert f.sent == [
        (443, "/", {"X-Aggregate-Auth": "1"}, "TESTME"),   # cisco-asa-detect
        (443, "/+CSCOE+/logon.html", {}, None),             # cisco-asa-panel
        (443, "/", {}, None),                               # fortinet-fortigate-panel
    ]


def test_no_credential_or_exploit_shaped_request_ever():
    f = Fake()
    sf.run_checks("vpn.example.com", {4443, 8443, 10443}, f, now=NOW)
    for port, path, headers, body in f.sent:
        low = (path + json.dumps(headers) + str(body)).lower()
        for bad in ("password", "username", "authorization", "cookie", "../", "%2e", "select ",
                    "<script", "/remote/logincheck", "/api/v2/", "cmdb"):
            assert bad not in low, (port, path)
        assert body in (None, "TESTME")


def test_alt_ports_only_when_open_and_stop_at_first_fortigate():
    f = Fake({(8443, "/"): (200, FGT_LANDING, FGT_ETAG)})
    _, portal, sent = sf.run_checks("h", {22, 8443, 10443}, f, now=NOW)
    assert [(p, path) for p, path, _, _ in f.sent][2:] == [(443, "/"), (8443, "/")]
    assert sent == 4
    assert portal["fortigate_sslvpn"]["matched"] is True and portal["fortigate_sslvpn"]["port"] == 8443
    f2 = Fake()
    sf.run_checks("h", {22, 80}, f2, now=NOW)
    assert len(f2.sent) == 3


# ── Cisco ASA ────────────────────────────────────────────────────────────────
def test_asa_hello_matched_with_version_in_nvd_spelling():
    r = sf.parse_asa_hello(200, ASA_HELLO_REPLY)
    assert r == {"matched": True, "status": 200, "version_raw": "9.16(4)48", "version": "9.16.4.48"}


def test_asa_hello_needs_status_200_and_the_config_auth_document():
    assert sf.parse_asa_hello(302, ASA_HELLO_REPLY)["matched"] is False
    assert sf.parse_asa_hello(200, "<html>Cisco ASA login</html>")["matched"] is False
    assert sf.parse_asa_hello(200, "<html>Cisco ASA login</html>")["version"] is None


def test_asa_version_spellings():
    assert sf.asa_version_dotted("9.16(4)48") == "9.16.4.48"
    assert sf.asa_version_dotted("9.8(4)") == "9.8.4"
    assert sf.asa_version_dotted("9.18") == "9.18"
    for bad in ("9.16(4)48.1", "nine", "", None, "9.16(4)48 interim", "9.x"):
        assert sf.asa_version_dotted(bad) is None


def test_asa_logon_page_matchers():
    assert sf.parse_asa_logon(200, ASA_LOGON_PAGE)["matched"] is True
    assert sf.parse_asa_logon(200, "<title>SSL VPN Service</title>")["matched"] is True
    assert sf.parse_asa_logon(404, ASA_LOGON_PAGE)["matched"] is False
    assert sf.parse_asa_logon(200, "<html>welcome</html>")["matched"] is False


# ── FortiGate ────────────────────────────────────────────────────────────────
def test_fortigate_build_date_from_etag():
    assert sf.fortigate_build_date(FGT_ETAG, NOW) == "2024-02-20"
    assert sf.fortigate_build_date('W/"5f2-65d4c0a1"', NOW) == "2024-02-20"


def test_fortigate_build_date_refuses_nonsense():
    assert sf.fortigate_build_date('"5f2-00000001"', NOW) is None       # 1970
    assert sf.fortigate_build_date('"5f2-7fffffff"', NOW) is None       # 2038, future
    assert sf.fortigate_build_date('"no-dash"', NOW) is None
    assert sf.fortigate_build_date(None, NOW) is None


def test_fortigate_landing_needs_200_and_the_redirect_script():
    assert sf.parse_fortigate_landing(200, FGT_LANDING, FGT_ETAG, NOW) == {
        "matched": True, "status": 200, "release_date": "2024-02-20"}
    assert sf.parse_fortigate_landing(200, "<html>FortiGate</html>", FGT_ETAG, NOW)["matched"] is False
    assert sf.parse_fortigate_landing(302, FGT_LANDING, FGT_ETAG, NOW)["matched"] is False
    assert sf.parse_fortigate_landing(200, "<html/>", FGT_ETAG, NOW)["release_date"] is None
    # a page that merely links the login path is not the SSL-VPN's own redirect script
    assert sf.parse_fortigate_landing(200, '<a href="/remote/login">VPN</a>', FGT_ETAG, NOW)["matched"] is False


# ── null = no answer; a real negative is a dict ─────────────────────────────
def test_no_answer_is_null_not_a_negative():
    hello, portal, _ = sf.run_checks("h", set(), Fake(default=(0, "", None)), now=NOW)
    assert hello["asa_hello"] is None
    assert portal["asa_logon"] is None and portal["fortigate_sslvpn"] is None


def test_an_answer_that_is_not_the_device_is_a_real_negative():
    hello, portal, _ = sf.run_checks("h", set(), Fake(default=(200, "<html>shop</html>", None)), now=NOW)
    assert hello["asa_hello"]["matched"] is False
    assert portal["asa_logon"]["matched"] is False
    assert portal["fortigate_sslvpn"]["matched"] is False


def test_a_full_asa():
    f = Fake({(443, "/"): (200, ASA_HELLO_REPLY, None),
              (443, "/+CSCOE+/logon.html"): (200, ASA_LOGON_PAGE, None)})
    # the hello and the plain landing share (443, "/"): the fake answers the
    # hello's document to both; the FortiGate matcher must not fire on it.
    hello, portal, _ = sf.run_checks("vpn.sciimage.com", set(), f, now=NOW)
    assert hello["asa_hello"]["version"] == "9.16.4.48"
    assert portal["asa_logon"]["matched"] is True
    assert portal["fortigate_sslvpn"]["matched"] is False
    assert sf.identified(hello, portal) == ["Cisco ASA 9.16(4)48 (VPN hello)",
                                            "Cisco ASA (WebVPN login page)"]
    json.dumps(hello), json.dumps(portal)        # artifacts are plain JSON


def test_artifact_names_are_the_ones_the_classifier_reads():
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "db"))
    src = open(os.path.join(os.path.dirname(HERE), "db", "device_class_runner.py"), encoding="utf-8").read()
    assert f'_ART_VPN_HELLO   = "{sf.HELLO_ARTIFACT}"' in src
    assert f'_ART_VPN_PORTAL  = "{sf.PORTAL_ARTIFACT}"' in src


# ── wiring ───────────────────────────────────────────────────────────────────
def _src(name):
    return open(os.path.join(HERE, name), encoding="utf-8").read()


def test_run_light_calls_it_inside_the_https_suite_after_library_flaws():
    s = _src("run_light.py")
    i_lib = s.index("            check_library_flaws(ctx)\n")
    i_fp = s.index("            check_stack_fingerprint(ctx)\n")
    i_beh = s.index("            check_behavioral_probes(ctx)\n")
    assert i_lib < i_fp < i_beh


def test_run_light_function_credits_one_tool_and_writes_both_artifacts():
    tree = ast.parse(_src("run_light.py"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "check_stack_fingerprint")
    body = ast.unparse(fn)
    assert "ctx.tools_run.append(tool)" in body
    assert "stack_fingerprint.HELLO_ARTIFACT" in body and "stack_fingerprint.PORTAL_ARTIFACT" in body
    assert "mark_tool_ok(ctx, tool)" in body and "mark_tool_degraded(ctx, tool" in body


def test_registered_as_a_light_phase_after_library_flaws():
    s = _src("phase_registry.py")
    assert s.index('_register("library_flaws"') < s.index(
        '_register("stack_fingerprint", LIGHT, _light.check_stack_fingerprint, ORDER_LIGHT)')
