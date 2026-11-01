"""KB 12 job 4f — plain_http.py: does a site's http:// address send visitors to https?

Pins: what is sent (GET on port 80 to our own name; at most 3; only plain-http redirects inside
the same domain are followed), every verdict, the rating (LOW by default; MODERATE for a password
box, a login prompt, a personal-details form, or no working HSTS; never High), the words, the
artifact, and the run_light / registry / daily wiring (the HSTS hand-off from check_headers is
tested through the real check_headers).
"""
import http.client
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "alerter"))
import plain_http as ph  # noqa: E402
import run_light  # noqa: E402

HSTS_YEAR = "max-age=31536000"            # commandcompanies.com's, read 2026-10-31
HSTS_PRELOAD = "max-age=31536000; includeSubDomains; preload"

# WordPress-style home page with only the theme's search box (role=search, name=s).
WP_SEARCH_ONLY = ('<html><body><form role="search" method="get" class="search-form" '
                  'action="https://commandcompanies.com/"><input type="search" name="s"></form>'
                  '<h1>Command Companies</h1></body></html>')
# Contact Form 7 markup (the plugin's own field names).
WP_CONTACT = ('<html><form action="/#wpcf7-f5-o1" method="post" class="wpcf7-form">'
              '<input type="text" name="your-name"><input type="email" name="your-email">'
              '<textarea name="your-message"></textarea><input type="submit"></form></html>')
WP_LOGIN = ('<form name="loginform" id="loginform" action="http://x/wp-login.php" method="post">'
            '<input type="text" name="log" id="user_login"><input type="password" name="pwd" '
            'id="user_pass"></form>')


class Fake:
    """fetch(host, path) double: records every request; answers by full URL."""

    def __init__(self, answers=None, default=(0, {}, "")):
        self.answers = answers or {}
        self.default = default
        self.sent = []

    def __call__(self, host, path):
        url = "http://%s%s" % (host, path)
        self.sent.append(url)
        return self.answers.get(url, self.default)


def R(status, location=None, body="", **extra):
    h = dict(extra)
    if location is not None:
        h["location"] = location
    return (status, h, body)


# ── what is sent ─────────────────────────────────────────────────────────────────────────
def test_first_request_is_get_slash_on_the_sites_own_name():
    f = Fake()
    ph.follow("www.commandcompanies.com", f)
    assert f.sent == ["http://www.commandcompanies.com/"]


def test_http_get_is_one_plain_get_on_port_80_with_no_credentials(monkeypatch):
    seen = {}

    class Conn:
        def __init__(self, host, port, timeout=None):
            seen.update(host=host, port=port, timeout=timeout)

        def request(self, method, path, body=None, headers=None):
            seen.update(method=method, path=path, body=body, headers=dict(headers or {}))

        def getresponse(self):
            class Resp:
                status = 301

                def read(self, n):
                    seen["read_cap"] = n
                    return b""

                def getheaders(self):
                    return [("Location", "https://x.example.com/"), ("Server", "nginx")]
            return Resp()

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(http.client, "HTTPConnection", Conn)
    st, headers, body = ph.http_get("x.example.com", "/", user_agent="UA/1")
    assert (st, headers["location"], body) == (301, "https://x.example.com/", "")
    assert seen["port"] == 80 and seen["method"] == "GET" and seen["path"] == "/" and seen["body"] is None
    assert seen["headers"]["User-Agent"] == "UA/1" and seen["closed"] and seen["read_cap"] == ph.MAX_BODY
    low = json.dumps(seen["headers"]).lower()
    for bad in ("authorization", "cookie", "password"):
        assert bad not in low


def test_http_get_turns_any_transport_failure_into_no_answer(monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            raise OSError("connection refused")
    monkeypatch.setattr(http.client, "HTTPConnection", Boom)
    assert ph.http_get("x.example.com", "/") == (0, {}, "")


def test_never_more_than_three_requests():
    f = Fake({"http://a.example.com/": R(301, "http://b.a.example.com/"),
              "http://b.a.example.com/": R(301, "http://c.a.example.com/"),
              "http://c.a.example.com/": R(301, "http://d.a.example.com/"),
              "http://d.a.example.com/": R(200, body="page")})
    res = ph.follow("a.example.com", f)
    assert len(f.sent) == 3 and res["outcome"] == "too_many_redirects"
    assert ph.finding_fields("a.example.com", res, HSTS_YEAR) is None


def test_nothing_is_requested_after_a_redirect_to_https():
    f = Fake({"http://commandcompanies.com/": R(301, "http://www.commandcompanies.com/"),
              "http://www.commandcompanies.com/": R(301, "https://www.commandcompanies.com/")})
    res = ph.follow("commandcompanies.com", f)
    assert res["outcome"] == "sent_to_https" and res["target"] == "https://www.commandcompanies.com/"
    assert f.sent == ["http://commandcompanies.com/", "http://www.commandcompanies.com/"]


def test_a_redirect_off_the_domain_or_port_is_not_followed():
    for loc in ("http://evil.example.net/", "http://commandcompanies.com.evil.net/",
                "http://www.commandcompanies.com:8080/", "ftp://commandcompanies.com/"):
        f = Fake({"http://commandcompanies.com/": R(302, loc)})
        res = ph.follow("commandcompanies.com", f)
        assert res["outcome"] == "left_over_http", loc
        assert len(f.sent) == 1, loc
        assert ph.finding_fields("commandcompanies.com", res, "") is None


def test_a_redirect_loop_stops():
    f = Fake({"http://x.prodexlabs.com/": R(301, "/")})
    res = ph.follow("x.prodexlabs.com", f)
    assert res["outcome"] == "redirect_loop" and len(f.sent) == 1


def test_an_ip_address_is_its_own_domain():
    f = Fake({"http://24.157.51.70/": R(302, "/remote/login"),
              "http://24.157.51.70/remote/login": R(200, body="<input type=password name=p>")})
    res = ph.follow("24.157.51.70", f)
    assert res["outcome"] == "serves_page" and res["signals"] == ["password"]
    f = Fake({"http://24.157.51.70/": R(302, "http://24.157.51.71/")})
    assert ph.follow("24.157.51.70", f)["outcome"] == "left_over_http"


# ── the verdicts ─────────────────────────────────────────────────────────────────────────
def test_a_redirect_to_https_is_fine_whatever_the_status():
    for st in (301, 302, 307, 308):
        res = ph.follow("docs.prodexlabs.com", Fake({"http://docs.prodexlabs.com/": R(st, "https://docs.prodexlabs.com/")}))
        assert res["outcome"] == "sent_to_https"
        assert ph.finding_fields("docs.prodexlabs.com", res, "") is None


def test_no_answer_error_pages_and_odd_redirects_are_not_findings():
    cases = {
        "no_answer": R(0),
        "error_status": R(403, body="403.4 SSL required"),
        "redirect_without_location": R(302),
    }
    for outcome, ans in cases.items():
        res = ph.follow("x.example.com", Fake({"http://x.example.com/": ans}))
        assert res["outcome"] == outcome
        assert ph.finding_fields("x.example.com", res, "") is None
    for st in (400, 404, 500, 503):
        res = ph.follow("x.example.com", Fake({"http://x.example.com/": R(st)}))
        assert ph.finding_fields("x.example.com", res, "") is None, st
    res = ph.follow("x.example.com", Fake({"http://x.example.com/": R(401)}))
    assert res["outcome"] == "error_status", "a 401 with no login prompt asks for nothing"


def test_a_page_over_plain_http_is_a_finding():
    f = Fake({"http://www.commandcompanies.com/": R(200, body=WP_SEARCH_ONLY)})
    res = ph.follow("www.commandcompanies.com", f)
    assert res["outcome"] == "serves_page" and res["signals"] == []
    e = ph.finding_fields("www.commandcompanies.com", res, HSTS_YEAR)
    assert (e["check_name"], e["title"], e["severity"]) == (
        "http-not-sent-to-https", "Plain http:// does not send visitors to https", "LOW")


def test_a_login_prompt_over_plain_http_is_a_moderate_finding():
    res = ph.follow("x.example.com", Fake({"http://x.example.com/": R(401, **{"www-authenticate": 'Basic realm="x"'})}))
    assert res["outcome"] == "login_prompt"
    e = ph.finding_fields("x.example.com", res, HSTS_PRELOAD)
    assert e["severity"] == "MODERATE" and "login-over-http" in e["tags"]
    assert "user name and password without encryption" in e["description"]


# ── the rating ───────────────────────────────────────────────────────────────────────────
def _page(body, hsts):
    res = ph.follow("x.prodexlabs.com", Fake({"http://x.prodexlabs.com/": R(200, body=body)}))
    return ph.finding_fields("x.prodexlabs.com", res, hsts)


def test_low_when_hsts_works_and_the_page_collects_nothing():
    e = _page(WP_SEARCH_ONLY, HSTS_YEAR)
    assert e["severity"] == "LOW" and "no-hsts" not in e["tags"]
    assert "sends returning visitors straight to https" in e["description"]


def test_moderate_when_the_https_site_has_no_working_hsts():
    for hsts in ("", "max-age=0", "includeSubDomains", ["max-age=0"]):
        e = _page(WP_SEARCH_ONLY, hsts)
        assert e["severity"] == "MODERATE" and "no-hsts" in e["tags"], hsts
        assert "no working Strict-Transport-Security" in e["description"]


def test_unknown_hsts_stays_low_and_says_so():
    e = _page(WP_SEARCH_ONLY, None)
    assert e["severity"] == "LOW" and "no-hsts" not in e["tags"]
    assert "is unknown" in e["description"]


def test_moderate_for_a_password_box_or_a_personal_details_form():
    e = _page(WP_LOGIN, HSTS_YEAR)
    assert e["severity"] == "MODERATE" and "password-over-http" in e["tags"]
    e = _page(WP_CONTACT, HSTS_YEAR)
    assert e["severity"] == "MODERATE" and "form-over-http" in e["tags"]
    assert "collects personal details" in e["description"]


def test_page_signals():
    assert ph.page_signals(WP_SEARCH_ONLY) == []
    assert ph.page_signals(WP_LOGIN) == ["password"]
    assert ph.page_signals(WP_CONTACT) == ["personal_form"]
    assert ph.page_signals('<FORM><INPUT TYPE=TEL NAME=x></FORM>') == ["personal_form"]
    assert ph.page_signals('<form><input name="billing_email"></form>') == ["personal_form"]
    assert ph.page_signals('<input type="email">') == [], "an email box outside any form submits nothing"
    assert ph.page_signals("") == [] and ph.page_signals(None) == []


def test_never_high():
    for body in ("", WP_SEARCH_ONLY, WP_LOGIN, WP_CONTACT, WP_LOGIN + WP_CONTACT):
        for hsts in (None, "", "max-age=0", HSTS_YEAR):
            e = _page(body, hsts)
            assert e["severity"] in ("LOW", "MODERATE")
    res = ph.follow("x.example.com", Fake({"http://x.example.com/": R(401, **{"www-authenticate": "Basic"})}))
    assert ph.finding_fields("x.example.com", res, "")["severity"] == "MODERATE"


def test_hsts_state():
    assert ph.hsts_state(None) is None
    assert ph.hsts_state("") is False and ph.hsts_state("max-age=0") is False
    assert ph.hsts_state(HSTS_PRELOAD) is True and ph.hsts_state('max-age="600"') is True
    assert ph.hsts_state(["max-age=31536000"]) is True


# ── the words and the record ────────────────────────────────────────────────────────────
def test_the_description_names_the_redirects_that_stayed_on_http():
    f = Fake({"http://commandcompanies.com/": R(301, "http://www.commandcompanies.com/"),
              "http://www.commandcompanies.com/": R(200, body=WP_SEARCH_ONLY)})
    res = ph.follow("commandcompanies.com", f)
    e = ph.finding_fields("commandcompanies.com", res, HSTS_YEAR)
    assert "Asking for http://commandcompanies.com/ got the page itself (HTTP 200 after 1 redirect " \
           "that stayed on plain http at http://www.commandcompanies.com/)" in e["description"]
    assert e["description"].endswith("redirect to the same address on https://.")
    assert json.loads(e["raw_excerpt"])["hops"][0]["location"] == "http://www.commandcompanies.com/"
    for word in ("vulnerable", "exploit", "attack succeeded"):
        assert word not in e["description"].lower()


def test_the_artifact_is_written_for_every_verdict():
    res = ph.follow("docs.prodexlabs.com", Fake({"http://docs.prodexlabs.com/": R(308, "https://docs.prodexlabs.com/")}))
    a = ph.artifact("docs.prodexlabs.com", res)
    assert a == {"schema": 1, "hostname": "docs.prodexlabs.com", "outcome": "sent_to_https",
                 "hops": [{"url": "http://docs.prodexlabs.com/", "status": 308,
                           "location": "https://docs.prodexlabs.com/"}],
                 "signals": [], "target": "https://docs.prodexlabs.com/"}


def test_known_ports_reads_both_tiers_shapes():
    assert ph.known_ports({80, 443}) == {80, 443}
    assert ph.known_ports([{"port": 80, "proto": "tcp"}, {"port": "443"}]) == {80, 443}
    assert ph.known_ports(None) == set() and ph.known_ports([{"x": 1}, "junk"]) == set()


# ── the shipped quick-scan check ────────────────────────────────────────────────────────
class _Ctx:
    hostname = "www.commandcompanies.com"

    def __init__(self, open_ports=None, https_hsts=None):
        self.tools_run, self.findings, self.artifacts, self.tool_status = [], [], [], {}
        self.open_ports = open_ports if open_ports is not None else {80, 443}
        self.https_hsts = https_hsts


def _wire(monkeypatch, answers):
    calls, marks = [], []

    def fake_get(host, path, timeout=None, user_agent=None):
        calls.append(("http://%s%s" % (host, path), user_agent))
        return answers.get("http://%s%s" % (host, path), (0, {}, ""))
    monkeypatch.setattr(ph, "http_get", fake_get)
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_ok", lambda c, t: marks.append(("ok", t)))
    monkeypatch.setattr(run_light, "mark_tool_skipped", lambda c, t, r: marks.append(("skipped", t, r)))
    monkeypatch.setattr(run_light, "mark_tool_degraded", lambda c, t, r: marks.append(("degraded", t, r)))
    return calls, marks


def test_check_plain_http_emits_one_finding_and_the_artifact(monkeypatch):
    calls, marks = _wire(monkeypatch, {"http://www.commandcompanies.com/": R(200, body=WP_SEARCH_ONLY)})
    ctx = _Ctx(https_hsts=HSTS_YEAR)
    run_light.check_plain_http(ctx)
    assert calls == [("http://www.commandcompanies.com/", run_light.LIGHT_UA)]
    assert [(f.check_name, f.severity, f.category, f.cwe) for f in ctx.findings] == [
        ("http-not-sent-to-https", "LOW", "tls", [319])]
    assert ctx.tools_run == ["plain_http"] and marks == [("ok", "plain_http")]
    (name, fmt, body), = ctx.artifacts
    assert (name, fmt, json.loads(body)["outcome"]) == ("plain_http", "json", "serves_page")


def test_check_plain_http_writes_the_artifact_and_no_finding_when_it_redirects(monkeypatch):
    calls, marks = _wire(monkeypatch, {"http://www.commandcompanies.com/": R(301, "https://www.commandcompanies.com/")})
    ctx = _Ctx(https_hsts="")
    run_light.check_plain_http(ctx)
    assert not ctx.findings and marks == [("ok", "plain_http")]
    assert json.loads(ctx.artifacts[0][2])["outcome"] == "sent_to_https"


def test_check_plain_http_asks_nothing_when_port_80_is_known_closed(monkeypatch):
    for ports in ({443}, [{"port": 443, "proto": "tcp"}]):
        calls, marks = _wire(monkeypatch, {})
        ctx = _Ctx(open_ports=ports)
        run_light.check_plain_http(ctx)
        assert calls == [] and not ctx.findings and not ctx.artifacts
        assert marks == [("skipped", "plain_http", "port_80_closed")]


def test_check_plain_http_asks_when_ports_are_unknown_or_heavy_shaped(monkeypatch):
    for ports in (set(), [{"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"}]):
        calls, marks = _wire(monkeypatch, {"http://www.commandcompanies.com/": R(200, body="x")})
        ctx = _Ctx(open_ports=ports, https_hsts="")
        run_light.check_plain_http(ctx)
        assert len(calls) == 1 and ctx.findings[0].severity == "MODERATE", ports


def test_a_strange_answer_never_sinks_the_scan(monkeypatch):
    calls, marks = _wire(monkeypatch, {})

    def boom(*a, **k):
        raise ValueError("odd")
    monkeypatch.setattr(ph, "follow", boom)
    ctx = _Ctx()
    run_light.check_plain_http(ctx)
    assert not ctx.findings and marks == [("degraded", "plain_http", "exception:ValueError")]


def test_check_headers_hands_the_hsts_value_over(monkeypatch):
    """Through the real check_headers: the value it read reaches ctx.https_hsts; '' when the
    https answer had none."""
    for header, want in (({"strict_transport_security": HSTS_PRELOAD}, HSTS_PRELOAD), ({}, "")):
        rec = {"status_code": 200, "header": header}

        class C:
            hostname = "x.prodexlabs.com"

            def __init__(self):
                self.tools_run, self.findings, self.artifacts, self.tool_status = [], [], [], {}
        ctx = C()
        monkeypatch.setattr(run_light, "run_cmd", lambda *a, **k: (0, json.dumps(rec) + "\n", ""))
        monkeypatch.setattr(run_light, "log", lambda *a, **k: None)
        monkeypatch.setattr(run_light, "mark_tool_ok", lambda c, t: None)
        monkeypatch.setattr(run_light, "mark_tool_degraded", lambda *a, **k: None)
        run_light.check_headers(ctx)
        assert ctx.https_hsts == want


def test_scan_context_starts_with_hsts_unknown():
    ctx = run_light.ScanContext(descriptor={}, hostname="h", asset_id="a", scan_run_id="s",
                                queue_id="q", intensity="light")
    assert ctx.https_hsts is None


def _src(name):
    with open(os.path.join(HERE, name)) as fh:
        return fh.read()


def test_run_light_calls_it_right_after_check_headers_and_plans_it():
    s = _src("run_light.py")
    i = s.index("    check_headers(ctx)\n            log(\"  → check_plain_http")
    assert s.index("check_plain_http(ctx)\n", i) < s.index("probe_refusal_signature(ctx)", i)
    ctx = run_light.ScanContext(descriptor={}, hostname="h", asset_id="a", scan_run_id="s",
                                queue_id="q", intensity="light", open_ports={80, 443})
    plan = run_light.build_light_planned_steps(ctx)
    assert plan.index("headers_check") + 1 == plan.index("plain_http")
    assert '"headers_check", "plain_http",' in s.split("ctx.planned_steps = [", 1)[1][:200]


def test_registered_as_a_light_phase_right_after_headers_check():
    s = _src("phase_registry.py")
    a = s.index('_register("headers_check", LIGHT, _light.check_headers, ORDER_LIGHT)')
    b = s.index('_register("plain_http", LIGHT, _light.check_plain_http, ORDER_LIGHT)')
    c = s.index('_register("common_paths"')
    assert a < b < c


# ── the daily ───────────────────────────────────────────────────────────────────────────
def test_the_slack_post_puts_it_on_the_developer_side():
    import digest_slack as ds
    assert ds.is_developer(ph.TITLE, "")
    assert ds.merge_key(ph.TITLE, "") != ds.merge_key("Missing security header: Strict-Transport-Security", ""), \
        "a missing redirect and a missing HSTS header are different fixes: not merged"
