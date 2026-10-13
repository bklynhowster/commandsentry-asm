"""(Obsidian 310, 2026-10-13) A MEASURED block closes the "No enforcing WAF" finding.

uat.prodexlabs.com: 2026-10-12 19:58Z the differential probe measured 0 of 3 payload
classes blocked -> HIGH 'No enforcing WAF in front of live application'. 2026-10-13
18:39Z the same probe measured all 3 blocked behind Google's 134-byte 403 page. The
finding stayed open as the page's top risk, two inches from the chip reading "attack
blocked": the heavy tier runs no delta-close by design, and no rule said a measured
block closes this one finding.

Pins here (the DB round trip with the production functions is in the push evidence,
push/s310/realdb_310.py: emit -> block closes -> pass-through re-emits -> production
regress flips remediated -> regressed -> block closes again):

  * the phase records the measurement on the context ONLY when the probe FIRED and the
    classifier returned waf_present; dry-run, unauthorized, and pass-through leave it None;
  * the closure targets exactly one finding — by stable id, asset, source, open family —
    and sets the remediated pair (note 126 invariant); nothing else is written on a miss;
  * the audit row carries the rule, the scan and the blocked classes; the history row is
    bound to THIS scan with status remediated;
  * the closure runs on the CLEAN path only, after the regress loop, before the history
    writer.
"""
import ast
import os
import re

import run_heavy as h

HERE = os.path.dirname(os.path.abspath(__file__))
UAT_403_BODY = ('<!doctype html><meta charset="utf-8"><meta name=viewport content="width=device-width, '
                'initial-scale=1"><title>403</title>403 Forbidden')
UAT_403_HEADERS = ("HTTP/2 403 \ncontent-type: text/html; charset=UTF-8\ncontent-length: 134\n"
                   "via: 1.1 google\ndate: Tue, 13 Oct 2026 18:39:26 GMT\n")


def _ctx():
    return h.HeavyScanContext(descriptor={}, hostname="uat.prodexlabs.com", asset_id="uat.prodexlabs.com",
                              scan_run_id="0181f867-ee9e-405e-96ac-8cc4ef728664", queue_id="q", intensity="heavy")


def _run_phase(monkeypatch, tmp_path, *, authorized=True, live=True, blocked_statuses=(403, 403, 403)):
    """Drive the REAL phase with the probe's network call replaced by recorded UAT bytes."""
    monkeypatch.setattr(h, "_read_active_probe_policy", lambda ctx: (authorized, "vpn", ""))
    monkeypatch.setattr(h, "_ACTIVE_PROBE_LIVE", live)
    monkeypatch.setattr(h, "_write_active_probe_audit", lambda ctx, v: None)

    def fake_fire(ctx, work_dir, egress):
        baseline = h._parse_waf_probe("CS_STATUS:200 CS_SIZE:3245 CS_TIME:0.14 CS_CONNECT:0.08", "<title>UAT</title>")
        payloads = []
        for cls, code in zip(h.INDEPENDENT_CLASSES, blocked_statuses):
            body = UAT_403_BODY if code == 403 else "<title>UAT</title>"
            size = 134 if code == 403 else 3245
            r = h._parse_waf_probe(f"{UAT_403_HEADERS if code == 403 else ''}CS_STATUS:{code} CS_SIZE:{size}", body, capture=True)
            r["cls"] = cls
            payloads.append(r)
        return baseline, payloads, {"param": "q508787", "egress_mode": egress, "fired": []}

    monkeypatch.setattr(h, "_fire_waf_differential_probe", fake_fire)
    ctx = _ctx()
    h.run_waf_differential_probe_phase(ctx, tmp_path)
    return ctx


# ── the context records the measurement only on a FIRED, POSITIVE verdict ────
def test_the_uat_block_is_recorded_on_the_context_and_emits_no_finding(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path)
    m = ctx.waf_block_measured
    assert m is not None and {"lfi", "sqli", "xss"} <= set(m["blocked"])
    assert m["baseline_status"] == 200 and m["egress_mode"] == "vpn"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", m["measured_at"])
    assert ctx.waf_detected is True
    assert not [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id], "a block emits no 'no WAF' finding"
    art = dict((n, p) for n, _, p in ctx.artifacts)["stack_id_waf_differential"]
    assert '"waf_present_differential": true' in art


def test_a_pass_through_records_nothing_and_emits_the_finding(monkeypatch, tmp_path):
    ctx = _run_phase(monkeypatch, tmp_path, blocked_statuses=(200, 200, 200))
    assert ctx.waf_block_measured is None
    assert [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id], "the 10-12 shape still emits"


def test_a_single_class_block_is_not_a_measured_block(monkeypatch, tmp_path):
    """One class denied = an app input-validator, not a WAF (4.7 Q2). Neither closes nor emits."""
    ctx = _run_phase(monkeypatch, tmp_path, blocked_statuses=(403, 200, 200))
    assert ctx.waf_block_measured is None
    assert not [f for f in ctx.findings if h.WAF_ABSENT_CHECK_ID in f.finding_id]


def test_dry_run_and_unauthorized_record_nothing(monkeypatch, tmp_path):
    assert _run_phase(monkeypatch, tmp_path, live=False).waf_block_measured is None
    assert _run_phase(monkeypatch, tmp_path, authorized=False).waf_block_measured is None


# ── the closure: one finding, by id, open family only, remediated pair ───────
def test_the_close_sql_targets_one_finding_by_id_asset_source_and_open_family():
    s = " ".join(h.CLOSE_WAF_ABSENT_ON_MEASURED_BLOCK_SQL.split())
    assert "UPDATE public.findings" in s
    assert "finding_id = %(finding_id)s" in s and "asset_id = %(asset_id)s" in s
    assert "source::text = 'commandsentry_heavy'" in s
    assert "current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in s
    assert "SET current_status = 'remediated', remediated_at = now(), updated_at = now()" in s
    assert "RETURNING" in s
    assert "LIKE" not in s and "~" not in s, "exact id, never a pattern"


def test_the_finding_id_the_closure_uses_is_the_one_the_emitter_mints():
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, {"status": 200, "size": 1}, {"waf_present": False, "blocked": []})
    emitted = ctx.findings[0].finding_id
    from cs_parsers.common import stable_finding_id
    assert emitted == stable_finding_id(ctx.asset_id, "commandsentry_heavy", h.WAF_ABSENT_CHECK_ID, ctx.hostname)
    assert h.WAF_ABSENT_CHECK_ID == "waf-absent-differential"


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


def test_nothing_measured_touches_nothing():
    conn = _Conn(hit=True)
    assert h.close_waf_absent_on_measured_block(conn, _ctx(), _json) == 0
    assert conn.cur.calls == []


def test_a_miss_writes_no_audit_and_no_history():
    ctx = _ctx()
    ctx.waf_block_measured = {"blocked": ["lfi", "sqli", "xss"], "reason": "r", "baseline_status": 200,
                              "measured_at": "2026-10-13T18:39:00Z", "egress_mode": "vpn"}
    conn = _Conn(hit=False)
    assert h.close_waf_absent_on_measured_block(conn, ctx, _json) == 0
    assert len(conn.cur.calls) == 1 and conn.cur.calls[0][0].startswith("UPDATE public.findings")


def test_a_hit_writes_the_update_the_audit_and_the_history_in_that_order():
    ctx = _ctx()
    ctx.waf_block_measured = {"blocked": ["lfi", "sqli", "xss"], "reason": "3 independent payload classes blocked",
                              "baseline_status": 200, "measured_at": "2026-10-13T18:39:00Z", "egress_mode": "vpn"}
    conn = _Conn(hit=True)
    assert h.close_waf_absent_on_measured_block(conn, ctx, _json) == 1
    sqls = [c[0] for c in conn.cur.calls]
    assert sqls[0].startswith("UPDATE public.findings")
    assert sqls[1].startswith("INSERT INTO public.admin_audit_log")
    assert sqls[2].startswith("INSERT INTO public.finding_history")
    audit = conn.cur.calls[1][1]
    assert audit["action"] == h.MEASURED_REMEDIATION_ACTION == "measured_remediation"
    assert audit["details"]["rule"] == h.MEASURED_REMEDIATION_RULE
    assert audit["details"]["scan_run_id"] == ctx.scan_run_id
    assert audit["details"]["blocked"] == ["lfi", "sqli", "xss"]
    assert audit["after"]["current_status"] == "remediated"
    hist = conn.cur.calls[2][1]
    assert hist["scan_run_id"] == ctx.scan_run_id and hist["severity"] == "HIGH"
    assert "'remediated'::history_status_t" in sqls[2]


# ── placement: clean path only, after regress, before history ────────────────
def test_the_closure_runs_on_the_clean_path_after_regress_and_before_history():
    src = open(os.path.join(HERE, "run_heavy.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, main)
    try_block = body[:body.rindex("except DegradedRunError as dre")]
    i_regress = try_block.index("regress_observed_for_scan_run(%s, %s)")
    i_close = try_block.index("close_waf_absent_on_measured_block(conn, ctx, Json)")
    i_hist = try_block.index("write_finding_history_for_scan_run(")
    assert i_regress < i_close < i_hist
    degraded = body[body.rindex("except DegradedRunError as dre"):]
    assert "close_waf_absent_on_measured_block" not in degraded, "never on the degraded path"
