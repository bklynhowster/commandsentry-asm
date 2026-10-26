"""(KB 12 job 351, 2026-10-26) A sign-in is the front door, and it can be tested.

Howie, 16:01, on atlantis-gcp.prodexlabs.com (every request 302s to its own Google sign-in,
/oauth2/start): "Why does authentication redirect negate the WAF scan?" 16:05: "I think you
should test. You should say what the test actually measured."

Pins here:
  * a baseline that redirects to a SIGN-IN (an identity provider's host, or a login path)
    measures the front door: waf_present True/False, front_door 'signin', with the classes
    that got the same redirect as the ordinary request (reached_signin);
  * an attack request that got the same redirect reached the login: not blocked, whatever
    its size (pm.unimacgraphics.com's sizes differ on every request);
  * every other redirect is 311's, unchanged: UNDEFINED, no finding (www -> apex, /mail/);
  * the sign-in rule is the portal's (protection-panel.mjs redirectKind), on the same real
    targets read 2026-10-26 from both fleets;
  * a measured absence at a sign-in emits the MODERATE absence finding (3b), worded for
    the door: "No enforcing WAF in front of the sign-in"; one refused class is ambiguous
    and emits nothing; two refused is a block;
  * a row 311 retracted is reopened at this run's severity, only when 311's retraction is
    its latest audit entry; the step runs on the clean path, after 3b's settle and before
    finding_history.
"""
import ast
import json
import os
import re

import run_heavy as h
import waf_differential as wd
from cs_parsers.common import stable_finding_id

HERE = os.path.dirname(os.path.abspath(__file__))

# ── the real targets, read 2026-10-26 (both fleets' newest live captures) ─────────────
SIGNIN = [
    "https://atlantis-gcp.prodexlabs.com/oauth2/start",            # Prodex, 302/138 x4
    "/login",                                                       # commandsentry-portal.netlify.app, 307/0 x4
    "https://login.microsoftonline.com/b3096ec4-7bba-4e2f-9c92-818dea8094e1/oauth2/v2.0/authorize",  # myordersauth(-test)
    "/qtmsLogin.aspx",                                              # pm.unimacgraphics.com, 302/216-264
]
NOT_SIGNIN = [
    "https://commandcompanies.com/",                                # www.commandcompanies.com, 301 (311's case)
    "https://email.commandcompanies.com/mail/",                     # same site, not a login
    "/PortalSite/",                                                 # insite.sciimage.com, 24.157.51.70
    "https://prodexlabs.com/",                                      # www.prodexlabs.com
    "",
]


def _probe(code, size, location, body=""):
    hdrs = f"HTTP/2 {code} \ncontent-length: {size}\n" + (f"location: {location}\n" if location else "")
    return h._parse_waf_probe(f"{hdrs}CS_STATUS:{code} CS_SIZE:{size}", body, capture=True)


def _shape(baseline, responses):
    payloads = []
    for cls, (code, size, loc, body) in responses.items():
        p = _probe(code, size, loc, body)
        p["cls"] = cls
        payloads.append(p)
    return baseline, payloads


ATL_LOC = "https://atlantis-gcp.prodexlabs.com/oauth2/start?rd=%2F%3Fq1a2b3c%3D"
ATLANTIS = _shape(_probe(302, 138, ATL_LOC + "benign"),
                  {c: (302, 138, ATL_LOC + "X" * n, "") for c, n in (("sqli", 9), ("xss", 11), ("lfi", 7))})

PM_LOC = "/qtmsLogin.aspx?ReturnUrl=%2f%3fq1a2b3c%3d"
PM = _shape(_probe(302, 216, PM_LOC + "benign"),
            {c: (302, s, PM_LOC + "X" * n, "") for c, s, n in (("sqli", 238, 23), ("xss", 264, 49), ("lfi", 246, 31))})

MS_LOC = ("https://login.microsoftonline.com/b3096ec4-7bba-4e2f-9c92-818dea8094e1/oauth2/v2.0/authorize"
          "?client_id=abc&state=")
MYORDERS = _shape(_probe(302, 0, MS_LOC + "1"), {c: (302, 0, MS_LOC + str(i), "") for i, c in enumerate(("sqli", "xss", "lfi"))})

EDGE_403 = (403, 134, "", "<html><body><h1>403 Forbidden</h1></body></html>")
BLOCKED_AT_DOOR = _shape(_probe(302, 138, ATL_LOC + "benign"),
                         {"sqli": EDGE_403, "xss": EDGE_403, "lfi": (302, 138, ATL_LOC + "X", "")})
ONE_REFUSED = _shape(_probe(302, 138, ATL_LOC + "benign"),
                     {"sqli": EDGE_403, "xss": (302, 138, ATL_LOC + "X", ""), "lfi": (302, 138, ATL_LOC + "Y", "")})

WWW = _shape(_probe(301, 162, "https://commandcompanies.com/?q1a2b3c=benign"),
             {c: (301, 162, "https://commandcompanies.com/?q1a2b3c=X", "") for c in ("sqli", "xss", "lfi")})
MAIL = _shape(_probe(302, 150, "https://email.commandcompanies.com/mail/"),
              {c: (302, 150, "https://email.commandcompanies.com/mail/", "") for c in ("sqli", "xss", "lfi")})


# ── which redirects are a sign-in ─────────────────────────────────────────────────
def test_the_real_sign_in_targets_are_sign_ins_and_the_rest_are_not():
    for t in SIGNIN:
        assert wd.redirect_is_signin(t), t
    for t in NOT_SIGNIN:
        assert not wd.redirect_is_signin(t), t
    assert not wd.redirect_is_signin(None)


def test_the_patterns_are_the_portals():
    # protection-panel.mjs, redirectKind (push-350): the same two patterns, character for character
    assert wd._SIGNIN_PATH.pattern == r"oauth|log-?in|sign-?in|sso|saml|authorize|/auth(/|$)"
    assert wd._SIGNIN_HOSTS.pattern == (r"(^|\.)(login\.microsoftonline\.com|accounts\.google\.com|login\.live\.com"
                                        r"|okta\.com|auth0\.com|onelogin\.com)$")
    assert wd._SIGNIN_PATH.flags & re.I and wd._SIGNIN_HOSTS.flags & re.I


# ── the measurement ───────────────────────────────────────────────────────────────
def test_atlantis_measures_the_front_door_and_nothing_refused():
    v = wd.classify_waf_differential(*ATLANTIS)
    assert v["waf_present"] is False and v["front_door"] == "signin" and v["blocked"] == []
    assert v["reached_signin"] == ["lfi", "sqli", "xss"]
    assert v["redirect_to"] == "https://atlantis-gcp.prodexlabs.com/oauth2/start"
    assert "undefined" not in v
    assert "Nothing behind the sign-in was reached" in v["reason"]


def test_the_same_redirect_is_not_a_block_whatever_its_size():
    v = wd.classify_waf_differential(*PM)
    assert v["waf_present"] is False and v["blocked"] == [] and v["reached_signin"] == ["lfi", "sqli", "xss"]
    v = wd.classify_waf_differential(*MYORDERS)
    assert v["waf_present"] is False and v["blocked"] == [] and v["reached_signin"] == ["lfi", "sqli", "xss"]


def test_two_refused_before_the_sign_in_is_a_block():
    v = wd.classify_waf_differential(*BLOCKED_AT_DOOR)
    assert v["waf_present"] is True and v["blocked"] == ["sqli", "xss"] and v["reached_signin"] == ["lfi"]
    assert v["front_door"] == "signin" and "refused before it" in v["reason"]


def test_one_refused_is_ambiguous_and_proves_nothing():
    b, p = ONE_REFUSED
    v = wd.classify_waf_differential(b, p)
    assert v["waf_present"] is False and v["blocked"] == ["sqli"]
    assert h._no_waf_proven(b, v) is False


def test_every_other_redirect_is_still_311s():
    for shape in (WWW, MAIL):
        v = wd.classify_waf_differential(*shape)
        assert v["waf_present"] is None and v["undefined"] == wd.UNDEFINED_REDIRECT and "front_door" not in v
        assert h._no_waf_proven(shape[0], v) is False


def test_a_measured_sign_in_absence_is_proven_absence():
    b, p = ATLANTIS
    assert h._no_waf_proven(b, wd.classify_waf_differential(b, p)) is True


# ── the phase: artifact, context, finding ─────────────────────────────────────────
def _ctx(host="atlantis-gcp.prodexlabs.com"):
    return h.HeavyScanContext(descriptor={}, hostname=host, asset_id=host,
                              scan_run_id="7f0a3c2e-1d6b-4d2c-9a47-2b7a4f0b3d11", queue_id="q", intensity="heavy")


def _run_phase(monkeypatch, tmp_path, shape):
    monkeypatch.setattr(h, "_read_active_probe_policy", lambda ctx: (True, "vpn", ""))
    monkeypatch.setattr(h, "_ACTIVE_PROBE_LIVE", True)
    monkeypatch.setattr(h, "_write_active_probe_audit", lambda ctx, v: None)
    baseline, payloads = shape
    fired = [{"cls": "benign", "status": baseline["status"], "size": baseline["size"]}] + [
        {"cls": p["cls"], "status": p["status"], "size": p["size"]} for p in payloads]
    monkeypatch.setattr(h, "_fire_waf_differential_probe",
                        lambda ctx, wdir, egress: (baseline, payloads, {"param": "q1a2b3c", "egress_mode": egress, "fired": fired}))
    ctx = _ctx()
    h.run_waf_differential_probe_phase(ctx, tmp_path)
    return ctx


def _artifact(ctx):
    return json.loads(dict((n, p) for n, _, p in ctx.artifacts)["stack_id_waf_differential"])


def test_the_phase_records_the_front_door_and_emits_the_moderate_sign_in_finding(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, ATLANTIS)
    art = _artifact(ctx)
    assert art["waf_present_differential"] is False
    d = art["details"]
    assert d["front_door"] == "signin" and d["reached_signin"] == ["lfi", "sqli", "xss"]
    assert d["baseline_redirect_to"] == "https://atlantis-gcp.prodexlabs.com/oauth2/start"
    assert "undefined" not in d and d["baseline_status"] == 302
    assert ctx.waf_signin_measured is True and ctx.waf_baseline_redirect is None
    assert ctx.waf_absence_measured is not None and ctx.waf_absence_emitted == "absent"
    fs = [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id]
    assert len(fs) == 1
    f = fs[0]
    assert f.severity == "MODERATE" and f.title == "No enforcing WAF in front of the sign-in"
    assert f.finding_id == stable_finding_id(ctx.asset_id, "commandsentry_heavy", h.WAF_ABSENT_CHECK_ID, ctx.hostname)
    assert "redirected (HTTP 302) to this host's sign-in (https://atlantis-gcp.prodexlabs.com/oauth2/start)" in f.description
    assert "None of the 3 independent attack-payload classes" in f.description
    assert "3 got the same redirect to the sign-in" in f.description
    assert "nothing behind the sign-in was tested" in f.description
    assert "live application" not in f.title
    for word in ("Cloud Armor", "Google Cloud", "Okta", "Microsoft"):
        assert word not in f.title and word not in f.description, "presence-only: no product named"


def test_a_block_at_the_door_is_a_measured_block(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, BLOCKED_AT_DOOR)
    assert _artifact(ctx)["waf_present_differential"] is True
    assert ctx.waf_block_measured is not None and ctx.waf_block_measured["blocked"] == ["sqli", "xss"]
    assert ctx.waf_block_measured["passed"] == [], "a redirect to the login is not the application"
    assert not [f for f in ctx.findings if "waf-" in f.finding_id]


def test_the_other_redirects_still_record_311s_shape(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, WWW)
    d = _artifact(ctx)["details"]
    assert d["undefined"] == "baseline_redirect" and "front_door" not in d
    assert ctx.waf_signin_measured is False and ctx.waf_baseline_redirect is not None
    assert not ctx.findings


# ── reopening what 311 retracted ──────────────────────────────────────────────────
class _Cur:
    def __init__(self, hit):
        self.hit, self.calls = hit, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return {"finding_id": "x", "severity": "MODERATE"} if self.hit else None


class _Conn:
    def __init__(self, hit):
        self.cur = _Cur(hit)

    def cursor(self):
        return self.cur


def _json(x):
    return x


def test_the_reopen_sql_only_touches_a_row_311_retracted_last():
    s = " ".join(h.REOPEN_311_RETRACTED_SQL.split())
    assert "SET current_status = 'detected', severity = %(severity)s::severity_t" in s
    assert "f.current_status::text = 'false_positive'" in s and "f.source::text = 'commandsentry_heavy'" in s
    assert ("(SELECT l.action FROM public.admin_audit_log l WHERE l.after_state->>'finding_id' = f.finding_id "
            "ORDER BY l.created_at DESC LIMIT 1) = %(retraction_action)s") in s
    assert h.REDIRECT_RETRACTION_ACTION == "redirect_retraction"


def test_a_measured_sign_in_reopens_the_retracted_row_at_this_runs_severity(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, ATLANTIS)
    conn = _Conn(hit=True)
    assert h.reopen_signin_rows_retracted_by_311(conn, ctx, _json) == 1
    upd, audit = conn.cur.calls
    fid = stable_finding_id(ctx.asset_id, "commandsentry_heavy", h.WAF_ABSENT_CHECK_ID, ctx.hostname)
    assert upd[0].startswith("UPDATE public.findings f")
    assert upd[1] == {"finding_id": fid, "asset_id": ctx.asset_id, "severity": "MODERATE",
                      "retraction_action": "redirect_retraction"}
    assert audit[0].startswith("INSERT INTO public.admin_audit_log")
    assert audit[1]["action"] == "signin_front_door_reopened"
    assert audit[1]["details"]["rule"] == "note_351_signin_front_door_reopens_311_retraction"
    assert audit[1]["after"] == {"finding_id": fid, "current_status": "detected", "severity": "MODERATE"}
    assert not any("finding_history" in c[0] for c in conn.cur.calls), "the history writer records it, once"


def test_nothing_reopens_without_a_sign_in_measurement_or_a_retracted_row(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, WWW)
    conn = _Conn(hit=True)
    assert h.reopen_signin_rows_retracted_by_311(conn, ctx, _json) == 0 and conn.cur.calls == []
    ctx = _run_phase(monkeypatch, tmp_path, ATLANTIS)
    miss = _Conn(hit=False)
    assert h.reopen_signin_rows_retracted_by_311(miss, ctx, _json) == 0
    assert len(miss.cur.calls) == 1, "the UPDATE matched nothing, so no audit row"
    blocked = _run_phase(monkeypatch, tmp_path, BLOCKED_AT_DOOR)
    conn = _Conn(hit=True)
    assert h.reopen_signin_rows_retracted_by_311(conn, blocked, _json) == 0 and conn.cur.calls == [], \
        "a block emits no absence finding, so there is nothing to reopen"


def test_the_reopen_runs_on_the_clean_path_after_the_settle_and_before_history():
    src = open(os.path.join(HERE, "run_heavy.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, main)
    try_block = body[:body.rindex("except DegradedRunError as dre")]
    i = [try_block.index(s) for s in (
        "retract_waf_absent_on_redirect(conn, ctx, Json)",
        "settle_waf_absence_family(conn, ctx, Json)",
        "reopen_signin_rows_retracted_by_311(conn, ctx, Json)",
        "write_finding_history_for_scan_run(",
    )]
    assert i == sorted(i)
    assert "reopen_signin_rows_retracted_by_311" not in body[body.rindex("except DegradedRunError as dre"):]
