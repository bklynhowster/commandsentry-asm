"""(KB 12 job 3b, 2026-10-21) How Sentry rates missing protection — Howie's rulings.

  * a proven absence is MODERATE, not HIGH (a missing control, not a hole);
  * a CONFIRMED waf that blocked nothing is its own MODERATE-HIGH finding; a SUSPECTED waf
    class is NOT presence (note 266: the GFE "Cloud Armor" false positive) -> plain absence;
  * absence + open CVE-listed findings (MODERATE or worse) -> its own 'exposed' finding,
    emitted through ctx.findings so the normal upsert writes and reopens it; a failed read
    emits nothing and closes nothing; HIGH only behind a HIGH/CRITICAL (proven) finding,
    MODERATE-HIGH behind out-of-date ones (3r, 2026-10-23 - test_waf_exposure_3r.py);
  * not a WAF candidate (mail / ftp kind, CONFIRMED edge_firewall) -> no finding at all;
  * the close-out settles the family: block closes, redirect retracts, kinds supersede each
    other and reopen themselves, exposed closes only on a successful read.
"""
import run_heavy as h
from cs_parsers.common import stable_finding_id

ABSENT = {"waf_present": False, "blocked": []}
SERVED = {"status": 200, "size": 1}


def _ctx(asset=None, dsn=None):
    c = h.HeavyScanContext(descriptor={"asset": asset or {}}, hostname="app.example.com",
                           asset_id="app.example.com", scan_run_id="run-1", queue_id="q",
                           intensity="heavy")
    c.dsn = dsn
    return c


def _fid(ctx, check_id):
    return stable_finding_id(ctx.asset_id, "commandsentry_heavy", check_id, ctx.hostname)


def _no_exposure(monkeypatch, ok=True, rows=()):
    monkeypatch.setattr(h, "_read_waf_exposure", lambda ctx: (ok, list(rows)))


# ── emit ────────────────────────────────────────────────────────────────────────────
def test_a_proven_absence_is_moderate_not_high(monkeypatch):
    _no_exposure(monkeypatch)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    assert [(f.finding_id, f.severity) for f in ctx.findings] == [(_fid(ctx, h.WAF_ABSENT_CHECK_ID), "MODERATE")]
    assert ctx.findings[0].title == "No enforcing WAF in front of live application"
    assert ctx.waf_absence_emitted == "absent"


def test_nothing_is_emitted_unless_absence_is_proven(monkeypatch):
    _no_exposure(monkeypatch)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, SERVED, {"waf_present": False, "blocked": ["xss"]})
    h._maybe_emit_no_waf_finding(ctx, {"status": 301, "size": 1}, ABSENT)
    h._maybe_emit_no_waf_finding(ctx, SERVED, {"waf_present": None, "blocked": []})
    assert ctx.findings == [] and ctx.waf_absence_emitted is None


def test_a_confirmed_waf_that_blocked_nothing_is_its_own_moderate_high(monkeypatch):
    _no_exposure(monkeypatch)
    ctx = _ctx({"device_class": "waf", "device_class_confidence": "confirmed"})
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    (f,) = ctx.findings
    assert f.finding_id == _fid(ctx, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID)
    assert f.severity == "MODERATE-HIGH" and f.title == "WAF detected but not blocking attacks"
    assert ctx.waf_absence_emitted == "present_not_enforcing"


def test_a_suspected_waf_class_is_not_presence_note_266(monkeypatch):
    _no_exposure(monkeypatch)
    ctx = _ctx({"device_class": "waf", "device_class_confidence": "suspected"})
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    assert [f.finding_id for f in ctx.findings] == [_fid(ctx, h.WAF_ABSENT_CHECK_ID)]


def test_mail_ftp_and_confirmed_edge_firewalls_are_not_candidates(monkeypatch):
    _no_exposure(monkeypatch)
    for asset in ({"kind": "mail"}, {"kind": "FTP"},
                  {"device_class": "edge_firewall", "device_class_confidence": "confirmed"}):
        ctx = _ctx(asset)
        h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
        assert ctx.findings == [] and ctx.waf_absence_emitted == "skipped", asset
    # a SUSPECTED edge_firewall and an infra kind stay candidates (D3: kind is too coarse)
    for asset in ({"device_class": "edge_firewall", "device_class_confidence": "suspected"},
                  {"kind": "infra"}):
        ctx = _ctx(asset)
        h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
        assert ctx.waf_absence_emitted == "absent", asset


def test_the_partial_finding_honours_the_same_candidacy():
    ctx = _ctx({"kind": "mail"})
    ctx.waf_block_measured = {"passed": ["sqli"]}
    h._maybe_emit_partial_coverage_finding(ctx, SERVED, {"waf_present": True, "blocked": ["xss", "lfi"]})
    assert ctx.findings == []


def test_absence_plus_open_cve_findings_adds_a_separate_high(monkeypatch):
    # 3r (2026-10-23): HIGH needs a proven (HIGH/CRITICAL) finding behind the gap; an
    # out-of-date-only gap is MODERATE-HIGH (test_waf_exposure_3r.py).
    rows = [{"finding_id": "app.example.com:manual:F-02", "title": "Struts RCE confirmed by test",
             "severity": "HIGH", "cve": ["CVE-2021-41184"]}]
    _no_exposure(monkeypatch, ok=True, rows=rows)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    ids = {f.finding_id: f for f in ctx.findings}
    exp = ids[_fid(ctx, h.WAF_EXPOSED_CHECK_ID)]
    assert exp.severity == "HIGH" and "CVE-2021-41184" in exp.description
    assert ids[_fid(ctx, h.WAF_ABSENT_CHECK_ID)].severity == "MODERATE"
    assert ctx.waf_exposure_read_ok and ctx.waf_exposed_emitted


def test_a_failed_exposure_read_emits_nothing_and_records_it(monkeypatch):
    _no_exposure(monkeypatch, ok=False)
    ctx = _ctx()
    h._maybe_emit_no_waf_finding(ctx, SERVED, ABSENT)
    assert len(ctx.findings) == 1 and not ctx.waf_exposure_read_ok and not ctx.waf_exposed_emitted


def test_the_exposure_read_without_a_dsn_is_unknown_not_none():
    assert h._read_waf_exposure(_ctx(dsn=None)) == (False, [])


def test_the_exposure_query_reads_open_cve_rows_moderate_or_worse_and_skips_its_own():
    s = " ".join(h.WAF_EXPOSURE_READ_SQL.split())
    assert "cve IS NOT NULL AND cardinality(cve) > 0" in s
    assert "current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in s
    assert "severity::text IN ('CRITICAL', 'HIGH', 'MODERATE-HIGH', 'MODERATE')" in s
    assert "finding_id NOT LIKE %(own_prefix)s" in s
    assert s.startswith("SELECT") and "UPDATE" not in s and "DELETE" not in s


# ── settle at close-out ─────────────────────────────────────────────────────────────
class _Cur:
    def __init__(self, hits):
        self.hits, self.calls = hits, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        sql, params = self.calls[-1]
        if params and params.get("finding_id") in self.hits and sql.startswith("UPDATE"):
            return {"finding_id": params["finding_id"], "severity": "MODERATE"}
        return None


class _Conn:
    def __init__(self, hits=()):
        self.cur = _Cur(set(hits))

    def cursor(self):
        return self.cur


def _updates(conn):
    return [(sql, p["finding_id"]) for sql, p in conn.cur.calls if sql.startswith("UPDATE")]


def _j(x):
    return x


def test_nothing_measured_settles_nothing():
    conn = _Conn()
    assert h.settle_waf_absence_family(conn, _ctx(), _j) == 0 and conn.cur.calls == []


def test_a_measured_block_closes_both_new_ids_as_remediated():
    ctx = _ctx()
    ctx.waf_block_measured = {"blocked": ["xss"]}
    hits = {_fid(ctx, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID), _fid(ctx, h.WAF_EXPOSED_CHECK_ID)}
    conn = _Conn(hits)
    assert h.settle_waf_absence_family(conn, ctx, _j) == 2
    assert all("SET current_status = 'remediated'" in sql for sql, _ in _updates(conn))


def test_a_redirect_baseline_retracts_both_new_ids_as_false_positive():
    ctx = _ctx()
    ctx.waf_baseline_redirect = {"baseline_status": 301, "redirect_to": "https://app.example.com/"}
    hits = {_fid(ctx, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID), _fid(ctx, h.WAF_EXPOSED_CHECK_ID)}
    conn = _Conn(hits)
    assert h.settle_waf_absence_family(conn, ctx, _j) == 2
    ups = _updates(conn)
    assert sorted(f for _, f in ups) == sorted(hits)
    assert all("'false_positive'" in sql for sql, _ in ups)


def test_absent_supersedes_present_and_reopens_itself():
    ctx = _ctx()
    ctx.waf_absence_measured = {"baseline_status": 200}
    ctx.waf_absence_emitted = "absent"
    ctx.waf_exposure_read_ok = False
    conn = _Conn({_fid(ctx, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID), _fid(ctx, h.WAF_ABSENT_CHECK_ID)})
    assert h.settle_waf_absence_family(conn, ctx, _j) == 2
    ups = _updates(conn)
    assert ("closed_reclassified" in ups[0][0]) and ups[0][1] == _fid(ctx, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID)
    assert ("'regressed'" in ups[1][0]) and ups[1][1] == _fid(ctx, h.WAF_ABSENT_CHECK_ID)
    # read failed -> the exposed row is NOT touched
    assert _fid(ctx, h.WAF_EXPOSED_CHECK_ID) not in [f for _, f in ups]


def test_exposed_closes_only_after_a_successful_read_that_found_none():
    ctx = _ctx()
    ctx.waf_absence_measured = {"baseline_status": 200}
    ctx.waf_absence_emitted = "absent"
    ctx.waf_exposure_read_ok, ctx.waf_exposed_emitted = True, False
    exp = _fid(ctx, h.WAF_EXPOSED_CHECK_ID)
    conn = _Conn({exp})
    assert h.settle_waf_absence_family(conn, ctx, _j) == 1
    assert [f for _, f in _updates(conn)][-1] == exp
    # re-emitted this run -> left to the upsert, not closed
    ctx.waf_exposed_emitted = True
    conn = _Conn({exp})
    h.settle_waf_absence_family(conn, ctx, _j)
    assert exp not in [f for sql, f in _updates(conn) if "'remediated'" in sql]


def test_a_non_candidate_asset_closes_the_family_as_reclassified():
    ctx = _ctx({"kind": "mail"})
    ctx.waf_absence_measured = {"baseline_status": 200}
    ctx.waf_absence_emitted = "skipped"
    hits = {_fid(ctx, c) for c in (h.WAF_ABSENT_CHECK_ID, h.WAF_PRESENT_NOT_ENFORCING_CHECK_ID, h.WAF_EXPOSED_CHECK_ID)}
    conn = _Conn(hits)
    assert h.settle_waf_absence_family(conn, ctx, _j) == 3
    assert all("closed_reclassified" in sql for sql, _ in _updates(conn))


def test_a_new_style_context_built_with___new___is_safe():
    ctx = h.HeavyScanContext.__new__(h.HeavyScanContext)
    conn = _Conn()
    assert h.settle_waf_absence_family(conn, ctx, _j) == 0


def test_the_settle_step_runs_on_the_clean_path_after_314_and_before_history():
    import ast, inspect
    src = inspect.getsource(h)
    tree = ast.parse(src)
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, main)
    clean = body[:body.rindex("except DegradedRunError as dre")]
    i_reopen = clean.index("reopen_partial_if_superseded(conn, ctx, Json)")
    i_settle = clean.index("settle_waf_absence_family(conn, ctx, Json)")
    i_hist = clean.index("write_finding_history_for_scan_run(")
    assert i_reopen < i_settle < i_hist
    degraded = body[body.rindex("except DegradedRunError as dre"):]
    assert "settle_waf_absence_family" not in degraded, "never on the degraded path"
