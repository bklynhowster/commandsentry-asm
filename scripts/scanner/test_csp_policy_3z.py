"""KB 12 job 3z (2026-10-31) — does the Content-Security-Policy actually limit scripts?

Howie's ZAP trials (10-30, 10-31) showed docs.prodexlabs.com and uat.prodexlabs.com sending a
policy that lets injected scripts run, while Sentry only checked that the header was there.
Howie, 10:24: "Yes" (build it). The rule and its reasons: csp_policy.py.

Pins:
  * every policy the two fleets sent on 2026-10-31 (read only from each database's newest
    headers_check artifact) gets the verdict the rule says: 22 ProDex app sites + docs weak,
    link.prodexlabs.com tight; on Command 5 weak (insite, 24.157.51.70, 24.157.51.84, vpn, vpn2),
    the nonce / strict-dynamic / 'self' policies tight;
  * ZAP's false positive is not repeated: 'unsafe-inline' next to a nonce, a hash or
    'strict-dynamic' is ignored by browsers, so it is not a finding;
  * the quick scan's SHIPPED check_headers emits one finding, from the fetch it already made,
    and a strange header never costs the header check;
  * the daily's Slack post puts the new titles on the developer side, like the header rows.

Job 4v (2026-11-06, Howie 08:03 "yes"): both findings are LOW. The verdict now names the check
that fires ('weakness'); the rating lives only in finding_fields. test_two_checks_low_4v.py pins
the change.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "alerter"))

import csp_policy as cp  # noqa: E402
import run_light  # noqa: E402

# ── the fleets' own policies, verbatim (2026-10-31) ─────────────────────────────────────
PRODEX_APP = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' "
              "'unsafe-inline'; img-src 'self' data: https: blob:; font-src 'self' data:; connect-src "
              "'self' wss: https:; worker-src 'self' blob:; frame-src 'self' blob:;")
PRODEX_APP_SITES = ("bitec", "dass", "demo", "gov", "highcom", "l3h-ivs", "l3h-nh", "l3h-ss",
                    "littleleaffarms", "oidc-test", "panthalassa", "ph-test", "prod", "prosalud-staging",
                    "prosalud", "sandbox", "staging", "time", "tour", "trial", "uat", "valorep")
DOCS = ("worker-src 'self' blob:; object-src 'none'; base-uri 'self'; upgrade-insecure-requests; "
        "frame-ancestors 'self' https://dashboard.mintlify.com https://app.mintlify.com; form-action 'self'; "
        "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' "
        "'unsafe-inline' https:; img-src 'self' data: blob: https:; font-src 'self' data: https:; media-src "
        "'self' data: blob: https:; frame-src 'self' blob: https:; connect-src 'self' data: https: wss:;")
LINK = ("default-src 'self'; style-src 'self' https://fonts.googleapis.com "
        "'sha256-qu/DA/rYdnX+6KBfIuR3TOhptBOBZW5dbmK89Ckd3gM=' "
        "'sha256-zqiMqGYP1YZ5gW2psQKxjVB3CQGC7gzqZUrTnc1LAxQ='; font-src 'self' https://fonts.gstatic.com; "
        "frame-ancestors 'self'; form-action 'self'; script-src "
        "'sha256-qu/DA/rYdnX+6KBfIuR3TOhptBOBZW5dbmK89Ckd3gM='; img-src 'self' https://www.smtp2go.com;")
CCC = ("default-src 'self'; script-src 'self' cdnjs.cloudflare.com www.googletagmanager.com "
       "'nonce-WdQI75dHpcDvcYkGCtvAgbZwQDh0lKanj3qSNpf-K9I' 'strict-dynamic'; style-src 'self' "
       "cdnjs.cloudflare.com fonts.googleapis.com 'nonce-CSS_10001' 'nonce-CSS_10002'; font-src 'self' "
       "fonts.gstatic.com fonts.googleapis.com data:; img-src 'self' data: www.w3.org; connect-src 'self'; "
       "frame-src 'self' app.powerbi.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self';")
EDELIVERY = ("default-src 'self'; frame-src 'self'; base-uri 'self'; script-src 'self'; font-src 'self' "
             "fonts.gstatic.com ; connect-src 'self'; img-src 'self';style-src 'self' 'nonce-CSS_10001' "
             "'nonce-CSS_10002' fonts.googleapis.com; frame-ancestors 'self'; form-action 'self';")
FTP_SCIIMAGE = ("base-uri 'self'; object-src 'none'; script-src 'self' "
                "'nonce-DDCF32D72D65F431ADC3ABCAEBC46502CD4A7619103D8CE4C77BCEBCF84AD40E'; style-src 'self' "
                "'nonce-DDCF32D72D65F431ADC3ABCAEBC46502CD4A7619103D8CE4C77BCEBCF84AD40E'; default-src 'self';")
GEISINGER = ("default-src 'self'; frame-src 'self'; base-uri 'self'; script-src 'self' 'nonce-JS_10001' "
             "'nonce-JS_10002'; font-src 'self' fonts.gstatic.com ; connect-src 'self'; img-src 'self';"
             "style-src 'self' 'nonce-CSS_10001' 'nonce-CSS_10002' fonts.googleapis.com; "
             "frame-ancestors 'self'; form-action 'self';")
PRINERGY = ("default-src 'self' https://www.google.com/recaptcha/; img-src 'self' */PrinergyWeb/ */Site/ "
            "https://localhost:6001/SRData/ data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ "
            "'unsafe-inline' 'unsafe-eval'; connect-src 'self' wss:; object-src 'none'; frame-ancestors 'self'")
SCIIMAGE_VPN = ("default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'self'; "
                "base-uri 'self'; block-all-mixed-content")


def _sev(v):
    return cp.script_weakness(v)["weakness"] if cp.script_weakness(v) else None


# ── the fleets, 2026-10-31 ──────────────────────────────────────────────────────────────
def test_the_prodex_fleet_22_app_sites_and_docs_are_weak_link_is_tight():
    app = cp.script_weakness(PRODEX_APP)
    assert app["weakness"] == cp.CHECK_NOT_LIMITED and app["rule"] == "script-src" and app["eval"]
    assert app["reasons"] == ["scripts written straight into the page ('unsafe-inline')"]
    assert len(PRODEX_APP_SITES) == 22
    docs = cp.script_weakness(DOCS)
    assert docs["weakness"] == cp.CHECK_NOT_LIMITED and docs["eval"]
    assert docs["reasons"] == ["scripts written straight into the page ('unsafe-inline')",
                               "scripts from any https website ('https:')"]
    assert cp.script_weakness(LINK) is None, "a hash-only script rule is tight"


def test_the_command_fleet_five_weak_the_nonce_and_self_policies_tight():
    for name, pol in (("commandcommcentral family (nonce + strict-dynamic + hosts)", CCC),
                      ("edelivery / enrollment2 ('self')", EDELIVERY),
                      ("ftp.sciimage.com (nonce)", FTP_SCIIMAGE), ("geisinger (nonces)", GEISINGER)):
        assert cp.script_weakness(pol) is None, name
    prin = cp.script_weakness(PRINERGY)       # insite.sciimage.com and 24.157.51.70
    assert prin["weakness"] == cp.CHECK_NOT_LIMITED and prin["rule"] == "script-src" and prin["eval"]
    vpn = cp.script_weakness(SCIIMAGE_VPN)     # vpn, vpn2.sciimage.com and 24.157.51.84
    assert vpn["rule"] == "default-src", "no script-src: default-src governs (the F-04 case)"
    assert vpn["reasons"] == ["scripts written straight into the page ('unsafe-inline')",
                              "scripts carried inside data: links ('data:')"] and vpn["eval"]


# ── the rule ────────────────────────────────────────────────────────────────────────────
def test_unsafe_inline_next_to_a_nonce_a_hash_or_strict_dynamic_is_not_a_finding():
    """CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present (often left in for
    old browsers); ZAP flags it anyway. Not repeated here."""
    for pol in ("script-src 'self' 'unsafe-inline' 'nonce-abc123'",
                "script-src 'self' 'unsafe-inline' 'sha256-AAAA='",
                "script-src 'unsafe-inline' 'strict-dynamic' 'nonce-x' https: http:",
                "default-src 'self' 'unsafe-inline' 'sha384-BBBB='"):
        assert cp.script_weakness(pol) is None, pol


def test_any_site_is_not_a_limit_unless_strict_dynamic_drops_the_list():
    for src, why in (("*", "('*')"), ("https:", "('https:')"), ("http:", "('http:')"),
                     ("https://*", "('https://*')"), ("data:", "('data:')")):
        v = cp.script_weakness(f"script-src 'self' {src}")
        assert v["weakness"] == cp.CHECK_NOT_LIMITED and why in v["reasons"][0], src
    assert cp.script_weakness("script-src 'self' https: 'strict-dynamic' 'nonce-q'") is None
    assert cp.script_weakness("script-src 'self' *.example.com https://cdn.example.com") is None, \
        "a named host or a subdomain wildcard is a limit"


def test_no_rule_for_scripts_is_a_finding_and_script_src_wins_over_default_src():
    v = cp.script_weakness("frame-ancestors 'self'; object-src 'none'")
    assert v["weakness"] == cp.CHECK_NOT_LIMITED and v["rule"] is None and "no rule for scripts" in v["reasons"][0]
    assert cp.script_weakness("default-src *; script-src 'self'") is None, "script-src governs scripts"
    assert cp.script_weakness("script-src 'self'; script-src *") is None, "the first directive wins"


def test_eval_alone_is_its_own_check_and_case_and_spacing_do_not_matter():
    v = cp.script_weakness("script-src 'self' 'unsafe-eval'")
    assert v["weakness"] == cp.CHECK_EVAL_ONLY and v["reasons"] == [] and v["eval"]
    assert _sev("SCRIPT-SRC 'SELF' 'UNSAFE-INLINE'") == cp.CHECK_NOT_LIMITED
    assert _sev("  script-src   'self'  ;;  ") is None


def test_several_policies_the_tightest_wins_and_odd_shapes_are_safe():
    assert cp.script_weakness(PRODEX_APP + ", script-src 'self'") is None, "both apply: the tight one wins"
    assert _sev("script-src * , script-src 'self' 'unsafe-eval'") == cp.CHECK_EVAL_ONLY
    assert _sev([PRODEX_APP, "script-src 'self'"]) is None, "a repeated header, listed"
    for v in (None, "", " , ,"):
        assert cp.script_weakness(v) is None, repr(v)


def test_the_finding_words():
    f = cp.finding_fields("uat.prodexlabs.com", PRODEX_APP)
    assert f["check_name"] == "csp-scripts-not-limited" and f["severity"] == "LOW"
    assert f["title"] == "Content-Security-Policy does not limit scripts"
    assert f["description"].startswith("The Content-Security-Policy header from uat.prodexlabs.com allows "
                                       "scripts written straight into the page ('unsafe-inline') and "
                                       "turning text into code with eval() ('unsafe-eval').")
    assert "script-src 'self' 'unsafe-inline' 'unsafe-eval'" in f["description"]
    e = cp.finding_fields("x.prodexlabs.com", "default-src 'self' 'unsafe-eval'")
    assert e["check_name"] == "csp-allows-eval" and e["severity"] == "LOW"
    assert e["title"] == "Content-Security-Policy allows eval()"
    assert cp.finding_fields("x", LINK) is None and cp.finding_fields("x", None) is None


# ── the shipped quick-scan check ────────────────────────────────────────────────────────
def _run_headers(monkeypatch, header):
    rec = {"status_code": 200, "header": dict({"strict_transport_security": "max-age=1"}, **header)}

    class _Ctx:
        hostname = "uat.prodexlabs.com"

        def __init__(self):
            self.tools_run, self.findings, self.artifacts, self.tool_status = [], [], [], {}

    ctx, calls, ok = _Ctx(), [], []
    monkeypatch.setattr(run_light, "run_cmd", lambda *a, **k: calls.append(a) or (0, json.dumps(rec) + "\n", ""))
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_ok", lambda c, t: ok.append(t))
    monkeypatch.setattr(run_light, "mark_tool_degraded", lambda *a, **k: None)
    run_light.check_headers(ctx)
    return ctx, calls, ok


def test_check_headers_emits_one_finding_from_the_fetch_it_already_made(monkeypatch):
    ctx, calls, ok = _run_headers(monkeypatch, {"content_security_policy": PRODEX_APP})
    weak = [f for f in ctx.findings if f.check_name.startswith("csp-")]
    assert len(calls) == 1, "no new request"
    assert [(f.check_name, f.severity, f.category) for f in weak] == [
        ("csp-scripts-not-limited", "LOW", "headers")]
    assert "missing-header-content-security-policy" not in {f.check_name for f in ctx.findings}
    assert ok == ["headers_check"]


def test_check_headers_says_nothing_new_for_a_tight_policy_or_a_missing_one(monkeypatch):
    ctx, _, _ = _run_headers(monkeypatch, {"content_security_policy": CCC})
    assert not [f for f in ctx.findings if f.check_name.startswith("csp-")]
    ctx, _, _ = _run_headers(monkeypatch, {})
    names = {f.check_name for f in ctx.findings}
    assert "missing-header-content-security-policy" in names and not any(n.startswith("csp-") for n in names)


def test_a_strange_header_never_costs_the_header_check(monkeypatch):
    def boom(*a, **k):
        raise ValueError("odd header")
    monkeypatch.setattr(cp, "finding_fields", boom)
    ctx, _, ok = _run_headers(monkeypatch, {"content_security_policy": PRODEX_APP})
    assert ok == ["headers_check"] and not [f for f in ctx.findings if f.check_name.startswith("csp-")]
    assert "missing-header-x-frame-options" in {f.check_name for f in ctx.findings}


# ── the daily ───────────────────────────────────────────────────────────────────────────
def test_the_slack_post_puts_both_titles_on_the_developer_side():
    import digest_slack as ds
    assert ds.is_developer(cp.TITLE_NOT_LIMITED, "") and ds.is_developer(cp.TITLE_EVAL_ONLY, "")
    assert ds.merge_key(cp.TITLE_NOT_LIMITED, "") != ds.merge_key("Missing security header: Content-Security-Policy", ""), \
        "a loose policy and a missing one are different fixes: not merged"
