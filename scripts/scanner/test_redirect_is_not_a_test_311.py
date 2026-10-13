"""(Obsidian 311, 2026-10-13) A REDIRECT IS NOT A TEST.

www.commandcompanies.com, 22:05Z, the first live differential on Command after the probe
was armed: the benign baseline answered HTTP 301 (nginx "301 Moved Permanently", 162 B,
Location: https://commandcompanies.com/?q6a3eca=benign) and so did every attack payload —
four byte-identical bounces. Gate 1 read `< 400`; the tally said "0 of 3 blocked"; the
collector published a HIGH "No enforcing WAF in front of live application" about an
address that serves no application. The portal, whose copy of the rule was tightened to
2xx on 2026-09-28, rendered "ATTACK TEST NOT RUN" two inches above that finding.

Pins (the DB round trip is in push/s311/realdb_311.py):
  * a 3xx baseline is UNDEFINED (None), kind 'baseline_redirect', with the Location
    target minus our query string; 0/4xx/5xx is UNDEFINED kind 'baseline_not_served';
  * None is never a measurement: no finding, no waf_block_measured, artifact verdict null;
  * the collector records the redirect on the context ONLY for a 3xx baseline;
  * the retraction targets exactly one finding, marks it false_positive (remediated_at
    untouched), writes the audit + history rows, and runs on the clean path only, right
    after the 310 closure and before the history writer;
  * one definition of 'served': run_heavy's gate IS the classifier's.
"""
import ast
import os
import re

import run_heavy as h
import waf_differential as wd

HERE = os.path.dirname(os.path.abspath(__file__))

# The real capture, 2026-10-13 22:05:47Z (query string shortened; it carried our probe value).
WWW_301_HEADERS = ("HTTP/2 301 \nserver: nginx\ndate: Tue, 13 Oct 2026 22:05:47 GMT\n"
                   "content-type: text/html\ncontent-length: 162\n"
                   "location: https://commandcompanies.com/?q6a3eca=benign\n"
                   "strict-transport-security: max-age=31536000\n"
                   "x-ac: 29.mdw _atomic_dca MISS\nalt-svc: clear\n"
                   "server-timing: a8c-cdn, dc;desc=mdw, cache;desc=MISS;dur=19.0\n")
WWW_301_BODY = ("<html>\n<head><title>301 Moved Permanently</title></head>\n<body>\n"
                "<center><h1>301 Moved Permanently</h1></center>\n<hr><center>nginx</center>\n"
                "</body>\n</html>\n")


def _ctx():
    return h.HeavyScanContext(descriptor={}, hostname="www.commandcompanies.com",
                              asset_id="www.commandcompanies.com",
                              scan_run_id="12dc1d95-0076-46cf-8aa4-f574af103540", queue_id="q", intensity="heavy")


def _run_phase(monkeypatch, tmp_path, *, baseline_status=301, payload_status=301):
    """Drive the REAL phase with the probe's network call replaced by the recorded bytes."""
    monkeypatch.setattr(h, "_read_active_probe_policy", lambda ctx: (True, "vpn", ""))
    monkeypatch.setattr(h, "_ACTIVE_PROBE_LIVE", True)
    monkeypatch.setattr(h, "_write_active_probe_audit", lambda ctx, v: None)

    def fake_fire(ctx, work_dir, egress):
        hdr = WWW_301_HEADERS if baseline_status == 301 else ""
        baseline = h._parse_waf_probe(f"{hdr}CS_STATUS:{baseline_status} CS_SIZE:162 CS_TIME:0.59 CS_CONNECT:0.19",
                                      WWW_301_BODY)
        payloads = []
        for cls in h.INDEPENDENT_CLASSES:
            r = h._parse_waf_probe(f"{WWW_301_HEADERS}CS_STATUS:{payload_status} CS_SIZE:162", WWW_301_BODY, capture=True)
            r["cls"] = cls
            payloads.append(r)
        return baseline, payloads, {"param": "q6a3eca", "egress_mode": egress, "fired": []}

    monkeypatch.setattr(h, "_fire_waf_differential_probe", fake_fire)
    ctx = _ctx()
    h.run_waf_differential_probe_phase(ctx, tmp_path)
    return ctx


# ── the classifier: one definition of served, two kinds of undefined ─────────
def test_served_is_2xx_only_and_shared_with_the_collector():
    assert wd.baseline_served(200) and wd.baseline_served(204)
    for s in (0, 301, 302, 307, 403, 404, 500, 504, None, "x"):
        assert not wd.baseline_served(s), s
    assert h.baseline_served is wd.baseline_served, "run_heavy must use the classifier's gate, not a copy"


def test_a_301_baseline_is_undefined_with_the_redirect_target():
    base = {"status": 301, "size": 162, "tokens": set(), "headers": set(),
            "redirect_to": "https://commandcompanies.com/"}
    payloads = [{"cls": c, "status": 301, "size": 162, "tokens": set(), "headers": set()}
                for c in wd.INDEPENDENT_CLASSES]
    res = wd.classify_waf_differential(base, payloads)
    assert res["waf_present"] is None
    assert res["undefined"] == wd.UNDEFINED_REDIRECT == "baseline_redirect"
    assert res["redirect_to"] == "https://commandcompanies.com/"
    assert res["blocked"] == []
    assert "redirected" in res["reason"] and "commandcompanies.com" in res["reason"]
    assert "not a measurement" in res["reason"]


def test_a_dead_origin_is_undefined_but_not_a_redirect():
    for status in (0, 500, 502, 504):
        res = wd.classify_waf_differential({"status": status, "size": 0, "tokens": set(), "headers": set()}, [])
        assert res["waf_present"] is None and res["undefined"] == wd.UNDEFINED_NOT_SERVED, status
        assert res["redirect_to"] is None


def test_a_served_baseline_with_nothing_blocked_is_still_a_measured_false():
    base = {"status": 200, "size": 3245, "tokens": {"t:uat"}, "headers": set()}
    payloads = [{"cls": c, "status": 200, "size": 3245, "tokens": {"t:uat"}, "headers": set()}
                for c in wd.INDEPENDENT_CLASSES]
    res = wd.classify_waf_differential(base, payloads)
    assert res["waf_present"] is False and "undefined" not in res


# ── the collector: the Location target, minus our query string ───────────────
def test_the_redirect_target_drops_our_probe_value():
    assert h._waf_redirect_target(WWW_301_HEADERS) == "https://commandcompanies.com/"
    assert h._waf_redirect_target("HTTP/2 302 \nLocation: /login?next=%2F%3Fq%3D1\n") == "/login"
    assert h._waf_redirect_target("HTTP/2 200 \nserver: nginx\n") == ""


def test_parse_records_redirect_to_only_on_3xx():
    r = h._parse_waf_probe(f"{WWW_301_HEADERS}CS_STATUS:301 CS_SIZE:162", WWW_301_BODY)
    assert r["redirect_to"] == "https://commandcompanies.com/"
    ok = h._parse_waf_probe("CS_STATUS:200 CS_SIZE:3245", "<title>UAT</title>")
    assert "redirect_to" not in ok


# ── the phase: undefined verdict, no finding, redirect on the context ─────────
def test_the_www_bounce_emits_no_finding_and_records_the_redirect(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path)
    assert not [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id], "a redirect is not a pass-through"
    assert ctx.waf_block_measured is None
    r = ctx.waf_baseline_redirect
    assert r is not None and r["baseline_status"] == 301 and r["redirect_to"] == "https://commandcompanies.com/"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", r["measured_at"])
    art = dict((n, p) for n, _, p in ctx.artifacts)["stack_id_waf_differential"]
    assert '"waf_present_differential": null' in art, "undefined, never false"
    assert '"undefined": "baseline_redirect"' in art
    assert '"baseline_redirect_to": "https://commandcompanies.com/"' in art
    assert ctx.waf_detected is False


def test_a_dead_origin_records_nothing_to_retract(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, baseline_status=504, payload_status=504)
    assert ctx.waf_baseline_redirect is None and ctx.waf_block_measured is None
    assert not [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id]
    art = dict((n, p) for n, _, p in ctx.artifacts)["stack_id_waf_differential"]
    assert '"waf_present_differential": null' in art and '"undefined": "baseline_not_served"' in art


def test_no_waf_proven_requires_a_served_baseline_and_a_measured_false():
    none_verdict = {"waf_present": None, "blocked": []}
    false_verdict = {"waf_present": False, "blocked": []}
    assert not h._no_waf_proven({"status": 301}, false_verdict), "the old < 400 gate"
    assert not h._no_waf_proven({"status": 200}, none_verdict), "undefined never proves absence"
    assert h._no_waf_proven({"status": 200}, false_verdict)


# ── the retraction: one finding, false_positive, audit + history ─────────────
def test_the_retract_sql_targets_one_finding_and_leaves_remediated_at_alone():
    s = " ".join(h.RETRACT_WAF_ABSENT_ON_REDIRECT_SQL.split())
    assert "UPDATE public.findings" in s
    assert "SET current_status = 'false_positive', updated_at = now()" in s
    assert "remediated_at" not in s, "not a remediation (note 126)"
    assert "finding_id = %(finding_id)s" in s and "asset_id = %(asset_id)s" in s
    assert "source::text = 'commandsentry_heavy'" in s
    assert "current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in s
    assert "RETURNING" in s and "LIKE" not in s


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
        return {"finding_id": "x", "severity": "HIGH", "first_detected_at": None, "last_observed_at": None} if self.hit else None


class _Conn:
    def __init__(self, hit):
        self.cur = _Cur(hit)

    def cursor(self):
        return self.cur


def _json(x):
    return x


def test_nothing_recorded_touches_nothing():
    conn = _Conn(hit=True)
    assert h.retract_waf_absent_on_redirect(conn, _ctx(), _json) == 0
    assert conn.cur.calls == []


def test_a_miss_writes_no_audit_and_no_history():
    ctx = _ctx()
    ctx.waf_baseline_redirect = {"baseline_status": 301, "redirect_to": "https://commandcompanies.com/",
                                 "measured_at": "2026-10-13T22:05:47Z", "egress_mode": "vpn"}
    conn = _Conn(hit=False)
    assert h.retract_waf_absent_on_redirect(conn, ctx, _json) == 0
    assert len(conn.cur.calls) == 1 and conn.cur.calls[0][0].startswith("UPDATE public.findings")


def test_a_hit_writes_the_update_the_audit_and_the_history_in_that_order():
    ctx = _ctx()
    ctx.waf_baseline_redirect = {"baseline_status": 301, "redirect_to": "https://commandcompanies.com/",
                                 "measured_at": "2026-10-13T22:05:47Z", "egress_mode": "vpn"}
    conn = _Conn(hit=True)
    assert h.retract_waf_absent_on_redirect(conn, ctx, _json) == 1
    sqls = [c[0] for c in conn.cur.calls]
    assert sqls[0].startswith("UPDATE public.findings")
    assert sqls[1].startswith("INSERT INTO public.admin_audit_log")
    assert sqls[2].startswith("INSERT INTO public.finding_history")
    audit = conn.cur.calls[1][1]
    assert audit["action"] == h.REDIRECT_RETRACTION_ACTION == "redirect_retraction"
    assert audit["details"]["rule"] == h.REDIRECT_RETRACTION_RULE
    assert audit["details"]["scan_run_id"] == ctx.scan_run_id
    assert audit["details"]["redirect_to"] == "https://commandcompanies.com/"
    assert audit["details"]["baseline_status"] == 301
    assert audit["after"]["current_status"] == "false_positive"
    hist = conn.cur.calls[2][1]
    assert hist["scan_run_id"] == ctx.scan_run_id and hist["severity"] == "HIGH"
    assert "'false_positive'::history_status_t" in sqls[2]
    assert "commandcompanies.com" in hist["notes"]


# ── placement: clean path only, after the 310 closure, before history ────────
def test_the_retraction_runs_on_the_clean_path_after_the_closure_and_before_history():
    src = open(os.path.join(HERE, "run_heavy.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, main)
    try_block = body[:body.rindex("except DegradedRunError as dre")]
    i_regress = try_block.index("regress_observed_for_scan_run(%s, %s)")
    i_close = try_block.index("close_waf_absent_on_measured_block(conn, ctx, Json)")
    i_retract = try_block.index("retract_waf_absent_on_redirect(conn, ctx, Json)")
    i_hist = try_block.index("write_finding_history_for_scan_run(")
    assert i_regress < i_close < i_retract < i_hist
    degraded = body[body.rindex("except DegradedRunError as dre"):]
    assert "retract_waf_absent_on_redirect" not in degraded, "never on the degraded path"
