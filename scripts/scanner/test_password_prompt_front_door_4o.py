"""(KB 12 job 4o, 2026-11-02) A password prompt is a front door, and it can be tested.

Howie, 17:00, on ftp.unimacgraphics.com's page ("Couldn't test ... HTTP 401"): "I want to be
able to get a firewall and identify it and all that good stuff. I want it to be properly
represented on the screen because it's misleading". 18:43: D1 "Do we count a password prompt
as a front door? Absolutely yes." D2 (keep the probe's own name): "There's no reason to hide
who we are." D3 (publish the absence finding when measured): "I agree."

Pins here:
  * the collector keeps a 401's WWW-Authenticate value as `challenge` (and only on a 401);
  * a baseline that is a password prompt (401 + a challenge) measures the front door:
    front_door 'signin', door_kind 'password_prompt', the classes that got the same prompt
    (reached_signin), the challenge; a 401 without a challenge stays 311's "not served";
  * the real EFT shape (ftp.unimacgraphics.com / ftp.commandmi.com, 2026-11-02: benign, sqli,
    xss, lfi all 401 / 102 B, Basic realm="<host>") reads: none blocked, 3 at the prompt;
  * two refused classes at a prompt are a block; one is ambiguous; a different challenge
    is not "the same prompt";
  * 351's redirect door is unchanged (door_kind 'redirect');
  * a measured absence at a prompt emits 3b's MODERATE "No enforcing WAF in front of the
    sign-in", worded for the prompt;
  * the probe still says who it is (D2: the bot User-Agent, no browser headers);
  * wafw00f's generic reason is kept, structured, and only on a generic verdict.
"""
import json
import types

import run_heavy as h
import run_medium as m
import waf_differential as wd

PROMPT = 'Basic realm="ftp.unimacgraphics.com"'
BODY_401 = "<html><head><title>Unauthorized</title></head><body><H1>HTTP/1.1 401 Unauthorized</H1></body></html>\n"


def _probe(code, size, extra_headers="", body=""):
    hdrs = f"HTTP/1.1 {code} X\n{extra_headers}Content-Length: {size}\n"
    return h._parse_waf_probe(f"{hdrs}CS_STATUS:{code} CS_SIZE:{size}", body, capture=True)


def _prompt(challenge=PROMPT):
    return _probe(401, 102, f"WWW-Authenticate: {challenge}\n", BODY_401)


def _shape(baseline, responses):
    payloads = []
    for cls, resp in responses.items():
        resp = dict(resp)
        resp["cls"] = cls
        payloads.append(resp)
    return baseline, payloads


EFT = _shape(_prompt(), {c: _prompt() for c in ("sqli", "xss", "lfi")})
EDGE_403 = _probe(403, 134, "", "<html><body><h1>403 Forbidden</h1></body></html>")
BLOCKED_AT_PROMPT = _shape(_prompt(), {"sqli": EDGE_403, "xss": EDGE_403, "lfi": _prompt()})
ONE_REFUSED = _shape(_prompt(), {"sqli": EDGE_403, "xss": _prompt(), "lfi": _prompt()})


# ── the collector ──────────────────────────────────────────────────────────────────────
def test_the_collector_keeps_the_challenge_on_a_401():
    r = _prompt()
    assert r["status"] == 401 and r["challenge"] == PROMPT


def test_the_challenge_is_read_case_insensitively_and_capped():
    r = _probe(401, 10, "www-authenticate: Digest realm=\"x\", nonce=\"" + "a" * 400 + "\"\n")
    assert r["challenge"].startswith('Digest realm="x"') and len(r["challenge"]) == 200


def test_no_challenge_key_on_other_statuses():
    assert "challenge" not in _probe(200, 500, "WWW-Authenticate: Basic realm=\"x\"\n")
    assert "challenge" not in _probe(302, 0, "Location: /login\n")


def test_a_401_without_a_challenge_has_an_empty_one():
    assert _probe(401, 102)["challenge"] == ""


# ── the classifier ─────────────────────────────────────────────────────────────────────
def test_password_prompt_predicate():
    assert wd.password_prompt({"status": 401, "challenge": PROMPT})
    assert not wd.password_prompt({"status": 401, "challenge": ""})
    assert not wd.password_prompt({"status": 401})
    assert not wd.password_prompt({"status": 403, "challenge": PROMPT})
    assert not wd.password_prompt(None)


def test_the_real_eft_shape_measures_the_front_door():
    v = wd.classify_waf_differential(*EFT)
    assert v["waf_present"] is False
    assert v["front_door"] == wd.FRONT_DOOR_SIGNIN and v["door_kind"] == wd.DOOR_PASSWORD_PROMPT
    assert v["reached_signin"] == ["lfi", "sqli", "xss"] and v["blocked"] == []
    assert v["challenge"] == PROMPT and v["redirect_to"] is None
    assert "password prompt" in v["reason"] and "undefined" not in v


def test_two_refused_at_the_prompt_is_a_block():
    v = wd.classify_waf_differential(*BLOCKED_AT_PROMPT)
    assert v["waf_present"] is True and v["blocked"] == ["sqli", "xss"]
    assert v["reached_signin"] == ["lfi"] and v["door_kind"] == wd.DOOR_PASSWORD_PROMPT


def test_one_refused_at_the_prompt_is_ambiguous():
    v = wd.classify_waf_differential(*ONE_REFUSED)
    assert v["waf_present"] is False and v["blocked"] == ["sqli"]
    assert not h._no_waf_proven(ONE_REFUSED[0], v)


def test_a_different_challenge_is_not_the_same_prompt():
    b, p = _shape(_prompt(), {"sqli": _prompt('Basic realm="elsewhere"'), "xss": _prompt(), "lfi": _prompt()})
    v = wd.classify_waf_differential(b, p)
    assert "sqli" not in v["reached_signin"]


def test_a_401_without_a_challenge_stays_not_served():
    b, p = _shape(_probe(401, 102), {c: _probe(401, 102) for c in ("sqli", "xss", "lfi")})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is None and v["undefined"] == wd.UNDEFINED_NOT_SERVED
    assert "front_door" not in v


def test_351_redirect_door_is_unchanged_and_says_so():
    loc = "https://atlantis-gcp.prodexlabs.com/oauth2/start?rd=x"
    base = _probe(302, 138, f"Location: {loc}\n")
    b, p = _shape(base, {c: _probe(302, 138, f"Location: {loc}{c}\n") for c in ("sqli", "xss", "lfi")})
    v = wd.classify_waf_differential(b, p)
    assert v["front_door"] == wd.FRONT_DOOR_SIGNIN and v["door_kind"] == wd.DOOR_REDIRECT
    assert v["waf_present"] is False and v["reached_signin"] == ["lfi", "sqli", "xss"]
    assert "challenge" not in v and v["redirect_to"] == "https://atlantis-gcp.prodexlabs.com/oauth2/start"


# ── the finding (3b, D3) ───────────────────────────────────────────────────────────────
def _ctx():
    c = h.HeavyScanContext.__new__(h.HeavyScanContext)
    c.asset_id = c.hostname = "ftp.unimacgraphics.com"
    c.scan_run_id = "00000000-0000-0000-0000-000000000000"
    c.findings = []
    c.waf_absence_emitted = None
    return c


def test_a_measured_absence_at_a_prompt_emits_the_sign_in_finding(monkeypatch):
    monkeypatch.setattr(h, "_waf_finding_applies", lambda ctx: True)
    monkeypatch.setattr(h, "_waf_confirmed_present", lambda ctx: False)
    ctx = _ctx()
    v = wd.classify_waf_differential(*EFT)
    assert h._no_waf_proven(EFT[0], v)
    h._maybe_emit_no_waf_finding(ctx, EFT[0], v)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.title == "No enforcing WAF in front of the sign-in" and f.severity == "MODERATE"
    assert "password prompt (HTTP 401, Basic challenge)" in f.description
    assert "3 got the same password prompt" in f.description and "redirect" not in f.description.split(" — ")[0]


def test_the_description_for_a_redirect_door_is_unchanged():
    v = {"front_door": wd.FRONT_DOOR_SIGNIN, "door_kind": wd.DOOR_REDIRECT, "redirect_to": "/login",
         "reached_signin": ["sqli"]}
    d = h._no_waf_description({"status": 302}, v)
    assert d.startswith("Differential probe: an ordinary request was redirected (HTTP 302) to this host's sign-in (/login)")


# ── D2: the probe still says who it is ─────────────────────────────────────────────────
def test_the_probe_keeps_its_own_name():
    args = h._waf_probe_curl_args("ftp.unimacgraphics.com", "q1", "x", False, "/dev/null", "vpn", "")
    assert args[args.index("-A") + 1] == h._PROBE_BOT_UA
    for blank in ("Accept:", "Accept-Language:", "Accept-Encoding:"):
        assert blank in args


# ── wafw00f's generic reason ───────────────────────────────────────────────────────────
EFT_WAFW00F = ("[*] Checking https://ftp.unimacgraphics.com/\n"
               "[+] Generic Detection results:\n"
               "[*] The site https://ftp.unimacgraphics.com/ seems to be behind a WAF or some sort of security solution\n"
               "[~] Reason: The response was different when the request wasn't made from a browser. \n"
               "Normal response code is \"200\", while the response code to a modified request is \"401\"\n"
               "[~] Number of requests: 4\n")
ATTACK_WAFW00F = ("[+] Generic Detection results:\n"
                  "[*] The site https://x.example/ seems to be behind a WAF or some sort of security solution\n"
                  "[~] Reason: The server returns a different response code when an attack string is used.\n"
                  "Normal response code is \"200\", while the response code to cross-site scripting attack is \"403\"\n"
                  "[~] Number of requests: 5\n")


def test_the_generic_reason_is_parsed():
    r = m._wafw00f_generic_reason(EFT_WAFW00F)
    assert r["non_browser"] is True and r["normal_code"] == 200 and r["modified_code"] == 401
    a = m._wafw00f_generic_reason(ATTACK_WAFW00F)
    assert a["non_browser"] is False and a["modified_code"] == 403
    assert m._wafw00f_generic_reason("[-] No WAF detected by the generic detection") is None


def test_the_reason_rides_on_a_generic_verdict_only():
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, waf_generic_reason=None, artifacts=[])
    m._classify_wafw00f_output(ctx, EFT_WAFW00F, 0)
    assert ctx.waf_kind == "generic" and ctx.waf_generic_reason["modified_code"] == 401
    m.persist_stack_id_wafw00f(ctx)
    d = json.loads(ctx.artifacts[0][2])
    assert d["wafw00f_generic_reason"]["non_browser"] is True
    named = types.SimpleNamespace(waf_detected=True, waf_kind="fortiweb", waf_generic_reason={"text": "x"}, artifacts=[])
    m.persist_stack_id_wafw00f(named)
    assert "wafw00f_generic_reason" not in json.loads(named.artifacts[0][2])


# ── the review (Qwen 3.8 Max, 2026-11-02 19:45): D1 and D2 ────────────────────────────
# D1: a door where no attack got the same answer and none was refused measured nothing.
# D2: a request with no answer at all (curl status 000: a reset or a timeout) is ours as
# likely as theirs, and counts neither way.
def _dead():
    return h._parse_waf_probe("\nCS_STATUS:000 CS_SIZE:0 CS_TIME:15.0 CS_CONNECT:0.0", "", capture=True)


SIGNIN_LOC = "https://atlantis-gcp.prodexlabs.com/oauth2/start"


def _redirect(loc=SIGNIN_LOC):
    return _probe(302, 138, f"Location: {loc}?rd=x\n")


def test_review_d1_no_attack_reached_the_prompt_is_not_a_measurement(monkeypatch):
    monkeypatch.setattr(h, "_waf_finding_applies", lambda ctx: True)
    monkeypatch.setattr(h, "_waf_confirmed_present", lambda ctx: False)
    b, p = _shape(_prompt(), {c: _prompt('Basic realm="Restricted"') for c in ("sqli", "xss", "lfi")})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is None and v["undefined"] == wd.UNDEFINED_DOOR_NOT_MEASURED
    assert "front_door" not in v and v["blocked"] == []
    assert not h._no_waf_proven(b, v)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, b, v)
    assert ctx.findings == []


def test_review_d1_the_same_rule_at_a_redirect_door():
    b, p = _shape(_redirect(), {c: _redirect("/blocked.html") for c in ("sqli", "xss", "lfi")})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is None and v["undefined"] == wd.UNDEFINED_DOOR_NOT_MEASURED
    assert "front_door" not in v and v["redirect_to"] == SIGNIN_LOC


def test_review_d1_one_class_explained_is_not_enough():
    b, p = _shape(_prompt(), {"sqli": _prompt(), "xss": _prompt('Basic realm="Restricted"'),
                              "lfi": _prompt('Basic realm="Restricted"')})
    assert wd.classify_waf_differential(b, p)["waf_present"] is None


def test_review_d1_a_digest_nonce_does_not_break_the_same_prompt():
    dig = lambda n: _prompt(f'Digest realm="ftp.example", qop="auth", nonce="{n}", opaque="o{n}"')
    b, p = _shape(dig("aaa"), {"sqli": dig("bbb"), "xss": dig("ccc"), "lfi": dig("ddd")})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is False and v["reached_signin"] == ["lfi", "sqli", "xss"]
    assert wd._challenge_key('Digest realm="x", nonce="a1"') == ("digest", "x")
    assert wd._challenge_key("Basic realm=host") == ("basic", "host")
    assert wd._challenge_key('Basic realm="a"') != wd._challenge_key('Bearer realm="a"')


def test_review_d2_dead_requests_are_neither_reached_nor_refused():
    b, p = _shape(_prompt(), {"sqli": _dead(), "xss": _dead(), "lfi": _prompt()})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is None and v["undefined"] == wd.UNDEFINED_DOOR_NOT_MEASURED
    assert v["unanswered"] == ["sqli", "xss"] and v["blocked"] == []


def test_review_d2_the_same_rule_at_a_redirect_door():
    b, p = _shape(_redirect(), {"sqli": _dead(), "xss": _dead(), "lfi": _redirect()})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is None and v["unanswered"] == ["sqli", "xss"]


def test_review_d2_one_dead_two_at_the_prompt_says_so(monkeypatch):
    monkeypatch.setattr(h, "_waf_finding_applies", lambda ctx: True)
    monkeypatch.setattr(h, "_waf_confirmed_present", lambda ctx: False)
    b, p = _shape(_prompt(), {"sqli": _dead(), "xss": _prompt(), "lfi": _prompt()})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is False and v["blocked"] == [] and v["unanswered"] == ["sqli"]
    assert v["reached_signin"] == ["lfi", "xss"] and h._no_waf_proven(b, v)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, b, v)
    assert "2 got the same password prompt as the ordinary request, and 1 got no answer at all" in ctx.findings[0].description


def test_review_d2_one_dead_one_refused_one_at_the_prompt_is_ambiguous():
    b, p = _shape(_prompt(), {"sqli": _dead(), "xss": EDGE_403, "lfi": _prompt()})
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is False and v["blocked"] == ["xss"] and not h._no_waf_proven(b, v)
