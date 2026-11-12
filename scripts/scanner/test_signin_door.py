#!/usr/bin/env python3
"""D-077 (Howie, 2026-11-12): the deep scan names a sign-in and reads its version with at
most two look-only page loads. These tests pin every limit in plan-name-the-sign-in:

  * no qualifying redirect -> nothing is sent;
  * SIGNIN_DOOR_LIVE off -> nothing is sent;
  * the site's attack-test switch off, or unreadable -> request 2 is not sent;
  * a version already on request 1, a development build's included -> request 2 is not sent;
  * curl reads no .curlrc (--disable first), so nothing can ride along;
  * neither request carries a cookie, a credential, a body, or follows a redirect;
  * a cookie name alone is "looks like": no product named, no version;
  * a custom footer and a non-release version are not a version;
  * a version elsewhere on the page (another product's, or a link's) is never taken;
  * a request with no answer is "no answer", never anything else;
  * no cookie value and nothing after a "?" reaches the artifact;
  * the phase is wired into run() exactly once, after httpx, and cannot fail the scan;
  * the workflow arms it by default on Prodex only.

The pages below are written from OAuth2 Proxy's PUBLIC templates
(pkg/app/pagewriter/sign_in.html and error.html), not from any real site.
Byte-identical in both scanner repos.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_heavy as h  # noqa: E402
import signin_door as d  # noqa: E402

HOST = "door.example.test"
WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scanner.yml"
RUNNER = Path(__file__).resolve().parent / "run_heavy.py"
MODULE = Path(__file__).resolve().parent / "signin_door.py"

FOOTER = ('<footer class="footer has-text-grey has-background-light is-size-7">'
          '<div class="content has-text-centered"><p>Secured with '
          '<a href="https://github.com/oauth2-proxy/oauth2-proxy#oauth2_proxy" '
          'class="has-text-grey">OAuth2 Proxy</a> version v{v}</p></div></footer>')
ERROR_PAGE = ('<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body>'
              '<div class="status-code">500</div><h1>Internal Server Error</h1>'
              '<form method="GET" action="/oauth2/sign_in"><input type="hidden" name="rd" value="/">'
              '</form>' + FOOTER.format(v="7.15.5") + '</body></html>')
SIGN_IN_PAGE = ('<html><head><title>Sign In</title></head><body><form method="GET" '
                'action="/oauth2/start"><button>Sign in with Google</button></form>'
                + FOOTER.format(v="7.6.0") + '</body></html>')
REDIRECT_HEADERS = ("HTTP/2 302 \r\ncontent-type: text/html; charset=utf-8\r\n"
                    "location: https://accounts.google.com/o/oauth2/auth?client_id=abc&state=SECRETSTATE\r\n"
                    "set-cookie: _oauth2_proxy_csrf=SECRETCOOKIEVALUE; Path=/; HttpOnly\r\n\r\n")
REDIRECT_BODY = '<a href="https://accounts.google.com/o/oauth2/auth?client_id=abc&state=SECRETSTATE">Found</a>.'
HOME = ("httpx_tech", "json", json.dumps({
    "url": f"https://{HOST}", "path": "/", "status_code": 302,
    "location": f"https://{HOST}/oauth2/start?rd=%2F"}))


# ── which sites qualify ───────────────────────────────────────────────────────────────
def test_only_this_hosts_own_oauth2_start_with_rd_qualifies():
    assert d.qualifies(f"https://{HOST}/oauth2/start?rd=%2F", HOST)
    assert d.qualifies("/oauth2/start?rd=/admin", HOST)
    assert d.qualifies(f"https://{HOST.upper()}:443/oauth2/start?rd=", HOST)
    for bad in (
        f"https://evil.example.test/oauth2/start?rd=%2F",      # another host
        f"https://{HOST}.evil.test/oauth2/start?rd=%2F",       # a look-alike host
        f"http://{HOST}/oauth2/start?rd=%2F",                  # not HTTPS
        f"https://{HOST}:8443/oauth2/start?rd=%2F",            # another port
        f"https://{HOST}/oauth2/start",                        # no rd
        f"https://{HOST}/oauth2/start?next=%2F",               # another parameter
        f"https://{HOST}/auth/start?rd=%2F",                   # another prefix
        f"https://{HOST}/oauth2/start/x?rd=%2F",
        "//evil.example.test/oauth2/start?rd=%2F",             # scheme-relative
        "oauth2/start?rd=%2F", "https://accounts.google.com/o/oauth2/v2/auth?x=1", "", None,
    ):
        assert not d.qualifies(bad, HOST), bad
    assert not d.qualifies(f"https://{HOST}/oauth2/start?rd=%2F", "")


def test_home_location_reads_what_the_scan_already_holds():
    assert d.home_location([HOME]) == f"https://{HOST}/oauth2/start?rd=%2F"
    methods = ("methods_check", "json", json.dumps(
        {"raw": f"HTTP/2 302 \ndate: x\nlocation: https://{HOST}/oauth2/start?rd=%2F\n\n"}))
    assert d.home_location([methods]) == f"https://{HOST}/oauth2/start?rd=%2F"
    ok_page = ("httpx_tech", "json", json.dumps({"path": "/", "status_code": 200,
                                                 "location": "https://x/oauth2/start?rd=1"}))
    other_path = ("httpx_tech", "json", json.dumps({"path": "/x", "status_code": 302,
                                                    "location": f"https://{HOST}/oauth2/start?rd=1"}))
    assert d.home_location([ok_page, other_path, ("gau", "json", "[]"), ("x",), None]) is None
    assert d.home_location([]) is None and d.home_location(None) is None
    assert d.home_location([("httpx", "json", "not json")]) is None


# ── the request itself ────────────────────────────────────────────────────────────────
def test_the_request_is_a_plain_get_with_nothing_attached():
    allowed = {"--disable": 0, "--silent": 0, "--show-error": 0, "--max-time": 1, "--max-redirs": 1,
               "--max-filesize": 1, "--proto": 1, "--proto-redir": 1, "--user-agent": 1,
               "--output": 1, "--dump-header": 1}
    for path in (d.SIGN_IN, d.CALLBACK):
        args = d.curl_args(HOST, path, "/tmp/x.body", "UA/1")
        assert args[0] == "curl" and args[-1] == f"https://{HOST}{path}"
        assert args[1] == "--disable"      # must be FIRST, or curl still reads a .curlrc
        assert "?" not in args[-1] and "@" not in args[-1]
        # EXACT allowlist: every option is one of these, each at most once, and nothing
        # else is on the line. So no --location, --cookie, --cookie-jar, --data, --request,
        # --user, --header, --insecure, --form, --referer or --upload-file can ride along.
        seen, rest = [], args[1:-1]
        k = 0
        while k < len(rest):
            opt = rest[k]
            assert opt in allowed, (opt, args)
            seen.append(opt)
            k += 1 + allowed[opt]
        assert sorted(seen) == sorted(allowed), seen
        assert args[args.index("--max-redirs") + 1] == "0"
        assert args[args.index("--proto") + 1] == "=https"
        assert args[args.index("--proto-redir") + 1] == "=https"
        assert args[args.index("--dump-header") + 1] == "-"
        assert args[args.index("--user-agent") + 1] == "UA/1"


def test_it_sends_only_its_two_paths():
    for path in ("/", "/oauth2/start", "/oauth2/callback?code=x", "/oauth2/auth", "/admin",
                 "/oauth2/sign_in/", "/oauth2/callback/../x"):
        try:
            d.curl_args(HOST, path, "/tmp/x", "UA")
        except ValueError:
            continue
        raise AssertionError(f"{path} must be refused")


# ── what a page says, and how sure that is ────────────────────────────────────────────
def test_the_footer_names_the_product_and_gives_the_version():
    r = d.looked_at(d.CALLBACK, 0, "HTTP/2 500 \r\ncontent-type: text/html\r\n\r\n", ERROR_PAGE)
    assert r["grade"] == d.GRADE_SAYS and r["version"] == "7.15.5" and r["status"] == 500
    assert r["evidence"] == ["footer"] and r["version_raw"] is None
    assert r["footer_line"] == "OAuth2 Proxy</a> version v7.15.5"
    r = d.looked_at(d.SIGN_IN, 0, "HTTP/1.1 200 OK\r\n\r\n", SIGN_IN_PAGE.encode())
    assert r["grade"] == d.GRADE_SAYS and r["version"] == "7.6.0"
    split = ERROR_PAGE.replace("OAuth2 Proxy</a> version", "OAuth2 Proxy</a>\n\t version")
    assert d.read_page(split)["version"] == "7.15.5"
    assert d.read_page("<p>Secured with OAuth2 Proxy version 7.4.0</p>")["version"] == "7.4.0"


def test_a_cookie_name_alone_only_looks_like_it():
    r = d.looked_at(d.SIGN_IN, 0, REDIRECT_HEADERS, REDIRECT_BODY)
    assert r["grade"] == d.GRADE_LOOKS_LIKE and r["evidence"] == ["cookie_name"]
    assert r["version"] is None and r["footer_line"] is None
    assert r["hands_off_to"] == "accounts.google.com" and r["status"] == 302
    rec = d.build_record(HOST, "2026-11-12T00:00:00Z", True, True, r, None, "site_not_switched_on")
    assert rec["grade"] == d.GRADE_LOOKS_LIKE
    assert rec["product"] is None and rec["product_key"] is None and rec["version"] is None
    upper = REDIRECT_HEADERS.replace("set-cookie:", "SET-COOKIE:")
    assert d.looked_at(d.SIGN_IN, 0, upper, "")["grade"] == d.GRADE_LOOKS_LIKE
    other = REDIRECT_HEADERS.replace("_oauth2_proxy_csrf", "session_oauth2_proxy")
    assert d.looked_at(d.SIGN_IN, 0, other, "")["grade"] == d.GRADE_NONE


def test_a_version_elsewhere_on_the_page_is_never_taken():
    for page in (
        "<body>Sign-in by OAuth2 Proxy.<hr><center>nginx version 1.25.3</center></body>",
        '<p>Secured with <a href="https://oauth2-proxy.github.io/oauth2-proxy/#v7.6.0">OAuth2 Proxy</a></p>',
        "<p>OAuth2 Proxy version of our portal. Build 2.4.1</p>",
        "<p>OAuth2 Proxy version undefined</p>",
        "<p>version v9.9.9</p><p>OAuth2 Proxy</p>",
    ):
        got = d.looked_at(d.CALLBACK, 0, "HTTP/2 403 \r\n\r\n", page)
        assert got["version"] is None and got["version_raw"] is None, page
        assert got["grade"] == d.GRADE_LOOKS_LIKE and got["evidence"] == ["page_mention"], page
    plain = d.looked_at(d.CALLBACK, 0, "HTTP/2 500 \r\n\r\n", "<center>nginx</center>")
    assert plain["grade"] == d.GRADE_NONE and plain["evidence"] == []


def test_a_build_that_is_not_a_release_is_shown_but_is_not_a_version():
    for token in ("v7.15.5-3-gabc1234", "7.15.5+dirty", "7.15", "7.15.5.1", "v7.x.y"):
        page = FOOTER.replace("v{v}", token)
        got = d.read_page(page)
        assert got["version"] is None, token
        if token[0].isdigit() or token[1:2].isdigit():
            assert got["version_raw"] and got["footer_line"], token
    rec = d.build_record(HOST, "t", True, True, d.looked_at(
        d.CALLBACK, 0, "HTTP/2 500 \r\n\r\n", FOOTER.replace("v{v}", "v7.15.5-3-gabc1234")))
    assert rec["grade"] == d.GRADE_SAYS and rec["product"] == d.PRODUCT
    assert rec["version"] is None and rec["version_raw"] == "v7.15.5-3-gabc1234"


def test_no_answer_is_no_answer():
    for rc, raw in ((28, ""), (6, ""), (60, ""), (7, None), (0, "garbage with no status line")):
        r = d.looked_at(d.SIGN_IN, rc, raw, ERROR_PAGE)        # a stale body must not count
        assert r["answered"] is False and r["status"] is None and r["grade"] == d.GRADE_NONE
        assert r["version"] is None and r["curl_rc"] == rc
        assert d.wants_second(r) is False
    rec = d.build_record(HOST, "t", True, True, d.looked_at(d.SIGN_IN, 28, "", ""), None,
                         "first_request_no_answer")
    text = json.dumps(rec).lower()
    assert "block" not in text and "ban" not in text


def test_nothing_secret_reaches_the_record():
    first = d.looked_at(d.SIGN_IN, 0, REDIRECT_HEADERS, REDIRECT_BODY)
    nasty = ("HTTP/2 500 \r\nset-cookie: _oauth2_proxy=SECRETCOOKIEVALUE\r\n"
             "x-internal-token: SECRETTOKEN\r\nlocation: https://idp.example.test/a?state=SECRETSTATE\r\n\r\n")
    body = ('<a href="https://idp.example.test/a?client_id=abc\n&state=SECRETSTATE\t&x=SECRETTOKEN">x</a>'
            + FOOTER.format(v="7.15.5") + "\x1b[31m\x07")
    second = d.looked_at(d.CALLBACK, 0, nasty, body)
    rec = d.build_record(HOST, "2026-11-12T00:00:00Z", True, True, first, second, "sent")
    text = json.dumps(rec)
    assert "SECRET" not in text and "?" not in text and "\\u001b" not in text and "\x1b" not in text
    assert rec["version"] == "7.15.5" and rec["hands_off_to"] == "accounts.google.com"
    assert set(rec) == {"schema", "hostname", "checked_at", "live_flag", "qualifying_redirect",
                        "product", "product_key", "grade", "evidence", "version", "version_raw",
                        "version_from", "hands_off_to", "footer_line", "requests", "second_request"}
    assert all(set(q) == {"path", "answered", "status", "curl_rc"} for q in rec["requests"])
    assert d.clean("a\x1b[2J\tb\nc https://x.test/p?q=SECRET&r=1 d", 80) == "a[2J b c https://x.test/p?<cut>"
    assert len(d.flatten(b"x" * (d.MAX_BODY_BYTES * 3))) == d.MAX_BODY_BYTES
    assert len(d.flatten("x" * (d.MAX_BODY_BYTES * 3))) == d.MAX_BODY_BYTES
    # the cookie VALUE never leaves the header parser, kept or not
    assert d.parse_headers(REDIRECT_HEADERS)["cookie_names"] == ["_oauth2_proxy_csrf"]
    assert d.parse_headers(nasty) == {"status": 500, "cookie_names": ["_oauth2_proxy"],
                                      "location_host": "idp.example.test"}
    assert "SECRET" not in json.dumps([first, second])


def test_a_redirect_back_to_this_site_is_not_a_hand_off():
    own = REDIRECT_HEADERS.replace("https://accounts.google.com/o/oauth2/auth", f"https://{HOST}/oauth2/start")
    rec = d.build_record(HOST, "t", True, True, d.looked_at(d.SIGN_IN, 0, own, ""))
    assert rec["hands_off_to"] is None


# ── request 2: when, and only when ────────────────────────────────────────────────────
def test_request_two_is_decided_fail_closed():
    looks = d.looked_at(d.SIGN_IN, 0, REDIRECT_HEADERS, REDIRECT_BODY)
    assert d.second_decision(looks, True, "") == (True, "sent")
    assert d.second_decision(looks, False, "") == (False, "site_not_switched_on")
    assert d.second_decision(looks, True, "__unreadable__") == (False, "policy_unreadable")
    assert d.second_decision(looks, False, "__unreadable__") == (False, "policy_unreadable")
    shown = d.looked_at(d.SIGN_IN, 0, "HTTP/2 200 \r\n\r\n", SIGN_IN_PAGE)
    assert d.second_decision(shown, True, "") == (False, "version_already_shown")
    nothing = d.looked_at(d.SIGN_IN, 0, "HTTP/2 404 \r\n\r\n", "<h1>Not found</h1>")
    assert d.second_decision(nothing, True, "") == (False, "first_request_named_nothing")
    silent = d.looked_at(d.SIGN_IN, 28, "", "")
    assert d.second_decision(silent, True, "") == (False, "first_request_no_answer")
    assert d.second_decision(None, True, "") == (False, "first_request_no_answer")
    # D-077: "without showing a version". A development build's version IS a version shown.
    dev = d.looked_at(d.SIGN_IN, 0, "HTTP/2 200 \r\n\r\n", FOOTER.replace("v{v}", "v7.15.5-dirty"))
    assert dev["version"] is None and dev["version_raw"] == "v7.15.5-dirty"
    assert d.second_decision(dev, True, "") == (False, "version_already_shown")


# ── the phase in run_heavy: what is actually sent ─────────────────────────────────────
def _ctx(artifacts=None):
    c = h.HeavyScanContext(descriptor={}, hostname=HOST, asset_id=HOST, scan_run_id="scan-1",
                           queue_id="queue-1", intensity="heavy")
    c.artifacts = list([HOME] if artifacts is None else artifacts)
    return c


def _wire(monkeypatch, tmp_path, answers, live=True, policy=(True, "vpn", "")):
    """answers: {path: (rc, raw_headers, body)}. Returns the list of argv run_cmd got."""
    calls, audits, slept = [], [], []

    def fake_run_cmd(cmd, timeout=30):
        calls.append(cmd)
        path = cmd[-1].split(HOST, 1)[1]
        rc, raw, body = answers[path]
        Path(cmd[cmd.index("--output") + 1]).write_text(body, encoding="utf-8")
        return rc, raw, ""

    monkeypatch.setattr(h, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(h, "_SIGNIN_DOOR_LIVE", live)
    monkeypatch.setattr(h, "_read_active_probe_policy", lambda ctx: policy)
    monkeypatch.setattr(h, "_write_active_probe_audit", lambda ctx, v: audits.append(v))
    return calls, audits, slept


def _record(ctx):
    got = [json.loads(p) for n, _k, p in ctx.artifacts if n == "signin_door"]
    assert len(got) <= 1
    return got[0] if got else None


ANSWERS = {d.SIGN_IN: (0, REDIRECT_HEADERS, REDIRECT_BODY),
           d.CALLBACK: (0, "HTTP/2 500 \r\ncontent-type: text/html\r\n\r\n", ERROR_PAGE)}


def test_phase_two_requests_in_order_and_the_version_is_read(monkeypatch, tmp_path):
    calls, audits, slept = _wire(monkeypatch, tmp_path, ANSWERS)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=slept.append)
    assert [c[-1] for c in calls] == [f"https://{HOST}/oauth2/sign_in", f"https://{HOST}/oauth2/callback"]
    assert slept == [d.PACING_S]
    rec = _record(ctx)
    assert rec["grade"] == "says" and rec["product"] == "OAuth2 Proxy" and rec["version"] == "7.15.5"
    assert rec["version_from"] == "error_page" and rec["hands_off_to"] == "accounts.google.com"
    assert rec["second_request"] == "sent" and rec["live_flag"] is True
    assert [q["status"] for q in rec["requests"]] == [302, 500]
    assert "SECRET" not in json.dumps(rec)
    assert len(audits) == 1 and audits[0]["probe_class"] == "signin_door_version"
    assert audits[0]["authorized"] is True and audits[0]["dry_run"] is False and audits[0]["observed"] is True
    assert list(tmp_path.iterdir()) == []                       # the page is not left behind
    assert ctx.findings == [] and ctx.tools_run == [] and ctx.tool_status == {}


def test_phase_sends_nothing_without_the_redirect(monkeypatch, tmp_path):
    for arts in ([], [("httpx_tech", "json", json.dumps({"path": "/", "status_code": 200}))],
                 [("httpx_tech", "json", json.dumps({"path": "/", "status_code": 302,
                   "location": "https://accounts.google.com/o/oauth2/v2/auth?client_id=1"}))],
                 [("httpx_tech", "json", json.dumps({"path": "/", "status_code": 302,
                   "location": "https://other.example.test/oauth2/start?rd=%2F"}))]):
        calls, audits, _ = _wire(monkeypatch, tmp_path, ANSWERS)
        ctx = _ctx(arts)
        h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
        assert calls == [] and audits == [] and _record(ctx) is None


def test_phase_sends_nothing_when_switched_off(monkeypatch, tmp_path):
    calls, audits, _ = _wire(monkeypatch, tmp_path, ANSWERS, live=False)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
    rec = _record(ctx)
    assert calls == [] and audits == []
    assert rec["live_flag"] is False and rec["requests"] == [] and rec["grade"] == "none"
    assert rec["second_request"] == "switched_off" and rec["qualifying_redirect"] is True


def test_phase_site_switch_off_stops_request_two(monkeypatch, tmp_path):
    for policy, why in (((False, "vpn", ""), "site_not_switched_on"),
                        ((False, "vpn", "__unreadable__"), "policy_unreadable")):
        calls, audits, slept = _wire(monkeypatch, tmp_path, ANSWERS, policy=policy)
        ctx = _ctx()
        h.run_signin_door_phase(ctx, tmp_path, sleep=slept.append)
        rec = _record(ctx)
        assert [c[-1] for c in calls] == [f"https://{HOST}/oauth2/sign_in"] and slept == []
        assert rec["grade"] == "looks_like" and rec["product"] is None and rec["version"] is None
        assert rec["second_request"] == why
        assert len(audits) == 1 and audits[0]["dry_run"] is True and audits[0]["observed"] is None
        assert audits[0]["authorized"] is False


def test_phase_version_on_request_one_means_no_request_two(monkeypatch, tmp_path):
    answers = dict(ANSWERS)
    answers[d.SIGN_IN] = (0, "HTTP/2 200 \r\n\r\n", SIGN_IN_PAGE)
    calls, audits, _ = _wire(monkeypatch, tmp_path, answers)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
    rec = _record(ctx)
    assert len(calls) == 1 and audits == []
    assert rec["version"] == "7.6.0" and rec["version_from"] == "sign_in"
    assert rec["second_request"] == "version_already_shown"


def test_phase_dev_version_on_request_one_means_no_request_two(monkeypatch, tmp_path):
    answers = dict(ANSWERS)
    answers[d.SIGN_IN] = (0, "HTTP/2 200 \r\n\r\n", FOOTER.replace("v{v}", "v7.15.5-3-gabc1234"))
    calls, audits, _ = _wire(monkeypatch, tmp_path, answers)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
    rec = _record(ctx)
    assert len(calls) == 1 and audits == []
    assert rec["grade"] == "says" and rec["version"] is None
    assert rec["version_raw"] == "v7.15.5-3-gabc1234" and rec["version_from"] == "sign_in"
    assert rec["second_request"] == "version_already_shown"


def test_phase_named_nothing_or_silent_means_no_request_two(monkeypatch, tmp_path):
    for first, why in (((0, "HTTP/2 404 \r\n\r\n", "<h1>404</h1>"), "first_request_named_nothing"),
                       ((28, "", ""), "first_request_no_answer")):
        answers = dict(ANSWERS)
        answers[d.SIGN_IN] = first
        calls, audits, _ = _wire(monkeypatch, tmp_path, answers)
        ctx = _ctx()
        h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
        rec = _record(ctx)
        assert len(calls) == 1 and audits == []
        assert rec["grade"] == "none" and rec["second_request"] == why and rec["version"] is None


def test_phase_request_two_that_shows_nothing_claims_nothing(monkeypatch, tmp_path):
    answers = dict(ANSWERS)
    answers[d.CALLBACK] = (0, "HTTP/2 403 \r\n\r\n", "<h1>Forbidden</h1>")     # footer turned off
    calls, audits, _ = _wire(monkeypatch, tmp_path, answers)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)
    rec = _record(ctx)
    assert len(calls) == 2 and rec["grade"] == "looks_like" and rec["product"] is None
    assert rec["version"] is None and audits[0]["observed"] is False


def test_phase_cannot_fail_the_scan(monkeypatch, tmp_path):
    def boom(cmd, timeout=30):
        raise RuntimeError("curl is not installed")
    monkeypatch.setattr(h, "run_cmd", boom)
    monkeypatch.setattr(h, "_SIGNIN_DOOR_LIVE", True)
    ctx = _ctx()
    h.run_signin_door_phase(ctx, tmp_path, sleep=lambda s: None)      # must not raise
    assert _record(ctx) is None


# ── wiring ────────────────────────────────────────────────────────────────────────────
def test_off_is_the_default_in_code():
    # Unset env -> nothing is sent. The workflow, not the code, arms an instance.
    assert h._SIGNIN_DOOR_LIVE is False
    assert h._env_flag_armed("true") and not h._env_flag_armed("false") and not h._env_flag_armed("")


def test_run_calls_the_phase_once_after_httpx():
    src = RUNNER.read_text(encoding="utf-8")
    assert src.count("run_signin_door_phase(ctx, work_dir)") == 1
    assert src.index("        run_httpx_phase(ctx, work_dir)\n") < src.index("        run_signin_door_phase(ctx, work_dir)\n")
    assert src.count("def run_signin_door_phase(") == 1 and src.count("def _signin_door_look(") == 1


def test_the_pure_half_does_no_io():
    src = MODULE.read_text(encoding="utf-8")
    for banned in ("import subprocess", "import socket", "import urllib.request", "import requests",
                   "import http.client", "import psycopg", "open(", "os.environ"):
        assert banned not in src, banned


def test_the_workflow_arms_prodex_only_and_has_a_kill_switch():
    text = WORKFLOW.read_text(encoding="utf-8")
    lines = re.findall(r"^\s+SIGNIN_DOOR_LIVE:\s*(.+)$", text, re.M)
    assert len(lines) == 1, lines
    m = re.fullmatch(r"\$\{\{ vars\.SIGNIN_DOOR_LIVE \|\| '(true|false)' \}\}", lines[0].strip())
    assert m, lines[0]
    repo = Path(__file__).resolve().parents[2].name
    assert m.group(1) == ("true" if repo == "prodexsentry-asm" else "false"), (repo, m.group(1))
    assert "inputs.signin_door" not in text          # no dispatch input: see the workflow comment
    # it is passed to the same step that runs the heavy tier
    block = text[text.index("ACTIVE_PROBE_LIVE: ${{"):]
    assert block.index("SIGNIN_DOOR_LIVE:") < block.index("CUMULATIVE_WALL_CLOCK_S:")
