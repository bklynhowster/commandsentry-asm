"""D-078 (Howie 2026-11-13 18:35 ET, "Go yes to both."): a fixed security-header or old-encryption
finding closes by itself; a closed header finding the quick scan sees again reopens at once.

Pins here (the round trip against a real PostgreSQL with these exact statements is in the push
evidence, close-fixed proof: header present / absent / empty, error page, re-emitted, person-closed,
HIGH, CSP verdicts, encryption after one vs two clean deep scans, witness missing, a check silent
fleet-wide, a degraded scan between, reopen, and a second run that changes nothing):

  * evidence is POSITIVE: a header closes only when this scan's own recorded reading has it, with
    a value, on a page that answered 200-399; a CSP finding only when csp_policy no longer says
    "does not limit scripts"; an error judging it closes nothing;
  * only the D-078 checks: the seven SECURITY_HEADERS and csp-scripts-not-limited, and the ten
    encryption checks; never csp-allows-eval, never HIGH, encryption LOW/MODERATE only, open rows
    only; "not seen" is read from last_seen_scan_run / last_observed_at, never quick-scan history;
  * encryption needs two clean deep scans in a row, each with a witness, and the check alive;
  * every close writes the update, then a history row bound to the proving scan, then an audit row;
  * any error rolls back the savepoint and returns 0: it never costs the scan;
  * placement: quick scan close-out before its history block; deep scan clean path after the
    regress loop and the other closures, before the history writer, never on the degraded path.
"""
import ast
import os
import re

import pytest

import close_fixed as cf
import run_light

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = "626f9631-78bd-4a4c-891b-030caee35f2f"
ASSET = "docs.example.test"
NAMES = [name for name, _s, _w in run_light.SECURITY_HEADERS]
KEY = run_light.httpx_header_key
ALL_HEADERS = {KEY(n): "x" for n in NAMES}


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self._last = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.calls.append((sql, params))
        if self.conn.raise_on and self.conn.raise_on in sql:
            raise RuntimeError("boom")
        self._last = sql

    def fetchall(self):
        if self._last is cf.READING_SQL:
            return self.conn.readings
        if self._last in (cf.HEADER_CANDIDATES_SQL, cf.TLS_CANDIDATES_SQL, cf.REOPEN_CANDIDATES_SQL):
            return self.conn.candidates
        return []

    def fetchone(self):
        if self._last in (cf.CLOSE_ONE_SQL, cf.REOPEN_ONE_SQL):
            return {"finding_id": "x"} if self.conn.update_hits else None
        return None


class FakeTxn:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.savepoints += 1
        return self

    def __exit__(self, et, ev, tb):
        self.conn.exits.append(et)
        return False


class FakeConn:
    def __init__(self, readings=(), candidates=(), update_hits=True, raise_on=None):
        self.readings = list(readings)
        self.candidates = list(candidates)
        self.update_hits = update_hits
        self.raise_on = raise_on
        self.calls = []
        self.savepoints = 0
        self.exits = []

    def cursor(self):
        return FakeCursor(self)

    def transaction(self):
        return FakeTxn(self)


def Json(x):
    return x


def _reading(status=200, headers=None):
    return {"content_jsonb": {"status_code": status, "header": dict(ALL_HEADERS if headers is None else headers)}}


def _cand(check, sev="LOW", old="detected", rem=None, lra=None):
    return {"finding_id": f"{ASSET}:light:{check}", "asset_id": ASSET, "title": "t", "severity": sev,
            "old_status": old, "last_observed_at": "2026-11-01 00:00:00+00", "last_seen_scan_run": "old",
            "remediated_at": rem, "last_regressed_at": lra}


def _headers(conn, ok=True, tier="light"):
    return cf.close_fixed_headers(conn, SCAN, ASSET, {"headers_check": {"ok": ok}}, Json,
                                  header_names=NAMES, header_key=KEY, tier=tier)


# ── what counts as evidence ─────────────────────────────────────────────────────────────────

def test_the_reading_is_read_as_the_header_check_itself_read_it():
    assert cf.reading_from_artifact({"status_code": 200, "header": {"a": "b"}}) == (200, {"a": "b"})
    raw = '{"status_code": 301, "header": {"x_frame_options": "DENY"}}\n{"second": 1}'
    assert cf.reading_from_artifact({"raw": raw}) == (301, {"x_frame_options": "DENY"})
    for bad in ({"raw": "not json"}, {"raw": ""}, {"status_code": "200", "header": {}},
                {"status_code": True, "header": {}}, {"status_code": 200}, None, [], "x"):
        assert cf.reading_from_artifact(bad) is None, bad


def test_a_header_counts_as_fixed_only_when_it_is_there_with_a_value():
    fixed = cf.fixed_header_checks({KEY("X-Content-Type-Options"): "nosniff",
                                    KEY("Referrer-Policy"): "   ",
                                    KEY("Permissions-Policy"): []}, NAMES, KEY)
    assert set(fixed) == {"missing-header-x-content-type-options"}


def test_the_key_translation_is_the_header_checks_own():
    # hyphens -> underscores, lowercase: a wire-format key must NOT count as the header
    assert cf.fixed_header_checks({"x-content-type-options": "nosniff"}, NAMES, KEY) == {}


@pytest.mark.parametrize("policy,closes", [
    ("default-src 'self'", True),                                   # limits scripts
    ("script-src 'self' 'unsafe-eval'", True),                      # eval only: no longer "not limited"
    ("script-src 'self' 'unsafe-inline'", False),                   # still not limited
    ("default-src *", False),
    ("img-src 'self'", False),                                      # no script rule at all
    ("", False),                                                    # empty policy limits nothing
])
def test_the_csp_finding_closes_only_on_the_scanners_own_verdict(policy, closes):
    fixed = cf.fixed_header_checks({KEY("Content-Security-Policy"): policy}, NAMES, KEY)
    assert (cf.CSP_CHECK in fixed) is closes


def test_an_error_judging_the_policy_closes_nothing(monkeypatch):
    def boom(_v):
        raise ValueError("strange header")
    monkeypatch.setattr(cf.csp_policy, "script_weakness", boom)
    fixed = cf.fixed_header_checks({KEY("Content-Security-Policy"): "default-src 'self'"}, NAMES, KEY)
    assert cf.CSP_CHECK not in fixed and "missing-header-content-security-policy" in fixed


def test_the_header_family_is_exactly_d078s():
    ids = cf.header_check_ids(NAMES)
    assert len(NAMES) == 7 and len(ids) == 8
    assert ids[-1] == "csp-scripts-not-limited"
    assert "csp-allows-eval" not in ids and not any("nonce" in i for i in ids)
    # the ids the header check mints are the ids this rule closes
    src = open(os.path.join(HERE, "run_light.py"), encoding="utf-8").read()
    assert 'check_name=f"missing-header-{header_name.lower()}"' in src


def test_the_encryption_checks_are_exactly_d078s():
    assert cf.TLS_CHECKS == ("TLS1", "TLS1_1", "cipherlist_3DES_IDEA", "BEAST", "BEAST_CBC_TLS1",
                             "SWEET32", "LUCKY13", "cipherlist_OBSOLETED", "HSTS", "security_headers")
    assert cf.WITNESS_EXCLUDED == ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "DNS_CAArecord")


# ── the statements ──────────────────────────────────────────────────────────────────────────

def _flat(sql):
    return re.sub(r"\s+", " ", sql)


def test_the_header_close_reads_who_last_saw_it_not_history():
    s = _flat(cf.HEADER_CANDIDATES_SQL)
    assert "finding_history" not in s
    assert "f.last_seen_scan_run IS DISTINCT FROM %(scan_run_id)s::text" in s
    assert "f.last_observed_at < s.started_at" in s
    assert "f.source::text = 'commandsentry_light'" in s
    assert "IN ('detected', 'confirmed', 'open', 'regressed')" in s
    assert "f.severity::text IN ('MODERATE', 'LOW', 'INFO')" in s
    assert "f.finding_id = ANY(%(finding_ids)s::text[])" in s and "FOR UPDATE OF f" in s


def test_the_encryption_close_needs_two_clean_deep_scans_in_a_row():
    s = _flat(cf.TLS_CANDIDATES_SQL)
    # the previous deep scan: the newest COMPLETE heavy one before this
    assert "p.intensity::text = 'heavy' AND p.status::text = 'complete' AND p.started_at < s.started_at" in s
    assert "ORDER BY p.started_at DESC LIMIT 1" in s
    assert "p.tool_status -> 'testssl.sh' ->> 'ok' = 'true'" in s
    # witness in THIS scan by last_seen (history is written after this step), in the previous by history
    assert "g.last_seen_scan_run = s.scan_run_id::text AND g.first_detected_at < s.started_at - interval '1 day'" in s
    assert "fh.finding_id = g.finding_id AND fh.scan_id = p.scan_run_id::text" in s
    # only an OBSERVATION row of the previous scan counts (a close writes 'remediated' for a row it did not see)
    assert "AND fh.status::text NOT IN ('remediated', 'validated_remediated', 'absent')" in s
    assert s.count("<> ALL(%(witness_excluded)s::text[])") == 2
    # same port as the finding, in BOTH scans
    assert s.count("substring(g.finding_id from ':[^:]*$') = substring(f.finding_id from ':[^:]*$')") == 2
    assert "g.first_detected_at < p.started_at - interval '1 day'" in s
    # seen by neither, nor since before the earlier one started
    assert "f.last_seen_scan_run IS DISTINCT FROM s.scan_run_id::text" in s
    assert "f.last_seen_scan_run IS DISTINCT FROM p.scan_run_id::text" in s
    assert "f.last_observed_at < p.started_at" in s
    assert "fx.finding_id = f.finding_id AND fx.scan_id = p.scan_run_id::text" in s
    # alive elsewhere, never itself
    assert "h.finding_id <> f.finding_id" in s and "h.last_observed_at > now() - interval '30 days'" in s
    assert "h.last_observed_at > p.started_at" in s       # rows of a broken detector cannot vouch for each other
    assert "f.severity::text IN ('LOW', 'MODERATE')" in s
    assert "AND regexp_replace(substr(f.finding_id, length(f.asset_id) + 10), ':[^:]*$', '') = ANY(%(checks)s::text[])" in s
    assert "HIGH" not in s and "CRITICAL" not in s


def test_no_statement_uses_a_like_wildcard_or_a_bare_percent():
    for sql in (cf.READING_SQL, cf.HEADER_CANDIDATES_SQL, cf.TLS_CANDIDATES_SQL, cf.REOPEN_CANDIDATES_SQL,
                cf.CLOSE_ONE_SQL, cf.REOPEN_ONE_SQL, cf.HISTORY_SQL, cf.AUDIT_SQL):
        assert " LIKE " not in sql.upper()
        assert not re.search(r"%(?!\()", sql), sql


def test_the_close_and_reopen_recheck_the_status_they_change():
    assert "current_status::text IN ('detected', 'confirmed', 'open', 'regressed')" in cf.CLOSE_ONE_SQL
    assert "SET current_status = 'remediated', remediated_at = now()" in cf.CLOSE_ONE_SQL
    assert "current_status::text IN ('remediated', 'validated_remediated')" in cf.REOPEN_ONE_SQL
    assert "remediated_at = NULL" in cf.REOPEN_ONE_SQL
    assert "last_regressed_at = coalesce(last_regressed_at, now())" in cf.REOPEN_ONE_SQL
    assert "ON CONFLICT (finding_id, scan_id) DO NOTHING" in cf.HISTORY_SQL


# ── the functions ───────────────────────────────────────────────────────────────────────────

def test_nothing_runs_unless_the_header_check_ran_ok():
    for ts in ({}, {"headers_check": {"degraded": "x"}}, {"headers_check": {"ok": "true"}}, None):
        conn = FakeConn([_reading()], [_cand("missing-header-x-frame-options")])
        assert cf.close_fixed_headers(conn, SCAN, ASSET, ts, Json, header_names=NAMES, header_key=KEY,
                                      tier="light") == 0
        assert cf.reopen_headers_seen_again(conn, SCAN, ASSET, ts, Json, header_names=NAMES, tier="light") == 0
        assert conn.calls == []


def test_nothing_runs_unless_the_encryption_test_ran_ok():
    conn = FakeConn(candidates=[_cand("x")])
    assert cf.close_fixed_tls(conn, SCAN, ASSET, {"testssl.sh": {"degraded": "y"}}, Json) == 0
    assert conn.calls == []


def test_the_switches_turn_each_rule_off(monkeypatch):
    monkeypatch.setattr(cf, "CLOSE_FIXED_HEADERS_ON", False)
    monkeypatch.setattr(cf, "CLOSE_FIXED_TLS_ON", False)
    conn = FakeConn([_reading()], [_cand("missing-header-x-frame-options")])
    assert _headers(conn) == 0
    assert cf.close_fixed_tls(conn, SCAN, ASSET, {"testssl.sh": {"ok": True}}, Json) == 0
    assert conn.calls == []


@pytest.mark.parametrize("readings", [[], [_reading(), _reading()]])
def test_exactly_one_recorded_reading_or_nothing(readings):
    conn = FakeConn(readings, [_cand("missing-header-x-frame-options")])
    assert _headers(conn) == 0
    assert [c[0] for c in conn.calls] == [cf.READING_SQL]


@pytest.mark.parametrize("status", [199, 400, 403, 404, 500, 503])
def test_an_error_page_closes_nothing(status):
    conn = FakeConn([_reading(status)], [_cand("missing-header-x-frame-options")])
    assert _headers(conn) == 0
    assert [c[0] for c in conn.calls] == [cf.READING_SQL]


def test_only_the_fixed_checks_are_asked_for():
    conn = FakeConn([_reading(200, {KEY("X-Frame-Options"): "DENY"})], [])
    assert _headers(conn) == 0
    sql, params = conn.calls[1]
    assert sql is cf.HEADER_CANDIDATES_SQL
    assert params["finding_ids"] == [f"{ASSET}:light:missing-header-x-frame-options"]
    assert params["scan_run_id"] == SCAN and params["asset_id"] == ASSET


def test_a_close_writes_update_then_history_then_audit():
    conn = FakeConn([_reading(302)], [_cand("missing-header-x-frame-options"),
                                      _cand("missing-header-strict-transport-security", "MODERATE")])
    assert _headers(conn, tier="heavy") == 2
    seq = [c[0] for c in conn.calls]
    assert seq == [cf.READING_SQL, cf.HEADER_CANDIDATES_SQL,
                   cf.CLOSE_ONE_SQL, cf.HISTORY_SQL, cf.AUDIT_SQL,
                   cf.CLOSE_ONE_SQL, cf.HISTORY_SQL, cf.AUDIT_SQL]
    hist = conn.calls[3][1]
    assert hist["status"] == "remediated" and hist["scan_run_id"] == SCAN and hist["severity"] == "LOW"
    aud = conn.calls[4][1]
    assert aud["action"] == "close_fixed_finding"
    assert aud["details"]["rule"] == "d078_header_seen_fixed_v1" and aud["details"]["tier"] == "heavy"
    assert aud["details"]["evidence"] == {"header": "X-Frame-Options", "present": True,
                                          "tool": "headers_check", "status_code": 302}
    assert "current_status = 'detected'" in aud["details"]["undo"]
    assert aud["before"]["current_status"] == "detected" and aud["after"]["current_status"] == "remediated"
    assert conn.savepoints == 1 and conn.exits == [None]


def test_a_row_closed_meanwhile_writes_no_history_or_audit():
    conn = FakeConn([_reading()], [_cand("missing-header-x-frame-options")], update_hits=False)
    assert _headers(conn) == 0
    assert [c[0] for c in conn.calls][-1] is cf.CLOSE_ONE_SQL


def test_an_error_rolls_back_the_savepoint_and_never_costs_the_scan():
    conn = FakeConn([_reading()], [_cand("missing-header-x-frame-options")], raise_on="admin_audit_log")
    assert _headers(conn) == 0
    assert conn.exits == [RuntimeError]          # the savepoint saw the error: rolled back whole


def test_a_conn_without_savepoints_is_survived():
    class Bare:
        def cursor(self):
            raise AssertionError("must not get here")
    assert _headers(Bare()) == 0


def test_the_reopen_writes_regressed_history_for_the_daily_email():
    conn = FakeConn(candidates=[_cand("missing-header-x-frame-options", old="remediated")])
    n = cf.reopen_headers_seen_again(conn, SCAN, ASSET, {"headers_check": {"ok": True}}, Json,
                                     header_names=NAMES, tier="light")
    assert n == 1
    seq = [c[0] for c in conn.calls]
    assert seq == [cf.REOPEN_CANDIDATES_SQL, cf.REOPEN_ONE_SQL, cf.HISTORY_SQL, cf.AUDIT_SQL]
    assert conn.calls[0][1]["finding_ids"] == [f"{ASSET}:light:{c}" for c in cf.header_check_ids(NAMES)]
    assert conn.calls[2][1]["status"] == "regressed"
    aud = conn.calls[3][1]
    assert aud["action"] == "auto_regress_observed" and aud["details"]["rule"] == "d078_header_seen_again_v1"
    # D-078: every reopen carries its undo, restoring all three fields it changed
    assert aud["details"]["undo"] == (
        "UPDATE public.findings SET current_status = 'remediated', remediated_at = NULL, "
        "last_regressed_at = NULL, updated_at = now() WHERE finding_id = "
        f"'{ASSET}:light:missing-header-x-frame-options' AND current_status = 'regressed'")
    assert aud["before"] == {"current_status": "remediated", "remediated_at": None, "last_regressed_at": None}


def test_the_reopen_undo_restores_the_earlier_times():
    conn = FakeConn(candidates=[_cand("missing-header-x-frame-options", old="validated_remediated",
                                      rem="2026-11-10 08:00:00+00:00", lra="2026-10-01 09:00:00+00:00")])
    cf.reopen_headers_seen_again(conn, SCAN, ASSET, {"headers_check": {"ok": True}}, Json,
                                 header_names=NAMES, tier="light")
    undo = conn.calls[3][1]["details"]["undo"]
    assert "current_status = 'validated_remediated'" in undo
    assert "remediated_at = '2026-11-10 08:00:00+00:00'" in undo
    assert "last_regressed_at = '2026-10-01 09:00:00+00:00'" in undo


def test_the_reopen_only_touches_rows_this_scan_saw_and_that_were_closed_as_fixed():
    s = _flat(cf.REOPEN_CANDIDATES_SQL)
    assert "f.current_status::text IN ('remediated', 'validated_remediated')" in s
    assert "f.last_seen_scan_run = %(scan_run_id)s::text" in s
    assert "false_positive" not in s and "wont_fix" not in s and "accepted_risk" not in s


def test_an_encryption_close_carries_both_scans_and_both_witnesses():
    row = dict(_cand("x", "MODERATE"), finding_id=f"{ASSET}:testssl:LUCKY13:1a2b3c4", check_id="LUCKY13",
               prev_scan_run_id="prev-1", prev_started_at="2026-11-06 00:00:00+00",
               witness_this="w1", witness_prev="w0")
    conn = FakeConn(candidates=[row])
    assert cf.close_fixed_tls(conn, SCAN, ASSET, {"testssl.sh": {"ok": True}}, Json) == 1
    params = conn.calls[0][1]
    assert params["checks"] == list(cf.TLS_CHECKS) and params["witness_excluded"] == list(cf.WITNESS_EXCLUDED)
    ev = conn.calls[3][1]["details"]["evidence"]
    assert ev == {"tool": "testssl.sh", "check": "LUCKY13", "scan_run_id": SCAN, "witness_this_scan": "w1",
                  "previous_deep_scan": "prev-1", "previous_started_at": "2026-11-06 00:00:00+00",
                  "witness_previous_scan": "w0"}
    assert conn.calls[3][1]["details"]["rule"] == "d078_tls_two_clean_deep_scans_v1"


# ── placement ───────────────────────────────────────────────────────────────────────────────

def _func_src(path, name):
    src = open(os.path.join(HERE, path), encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(name)


def test_the_quick_scan_reopens_then_closes_before_its_history_block():
    body = _func_src("run_light.py", "close_out")
    i_re = body.index("close_fixed.reopen_headers_seen_again(")
    i_cl = body.index("close_fixed.close_fixed_headers(")
    i_hist = body.index("write_finding_history_for_scan_run(")
    assert i_re < i_cl < i_hist
    assert body.index("cur.execute(CLOSE_SCAN_RUN_SQL") < i_re
    assert 'tier="light"' in body[i_re:i_hist]


def test_the_deep_scan_closes_on_the_clean_path_after_regress_before_history():
    src = open(os.path.join(HERE, "run_heavy.py"), encoding="utf-8").read()
    i_reg = src.index("regress_observed_for_scan_run")
    i_351 = src.index("n_signin = reopen_signin_rows_retracted_by_311(conn, ctx, Json)")
    i_h = src.index("n_fixed_hdr = close_fixed.close_fixed_headers(")
    i_t = src.index("n_fixed_tls = close_fixed.close_fixed_tls(")
    i_hist = src.index("n_history = write_finding_history_for_scan_run(", i_t)
    i_deg = src.index("except DegradedRunError as dre:")
    assert i_reg < i_351 < i_h < i_t < i_hist < i_deg
    assert src.count("close_fixed.close_fixed_headers(") == 1 and src.count("close_fixed.close_fixed_tls(") == 1
    assert 'tier="heavy"' in src[i_h:i_t]
    deg = _func_src("run_heavy.py", "degraded_out_heavy")
    assert "close_fixed" not in deg


def test_medium_does_not_take_part():
    src = open(os.path.join(HERE, "run_medium.py"), encoding="utf-8").read()
    assert "close_fixed" not in src


def _calls_in(path, func, names):
    """{assigned name: the ast.Call assigned to it} inside one function (or the module)."""
    src = open(os.path.join(HERE, path), encoding="utf-8").read()
    tree = ast.parse(src)
    if func:
        tree = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == func)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in names:
            found[node.targets[0].id] = node.value
    return found


def test_the_calls_are_unconditional_and_carry_the_right_arguments():
    got = _calls_in("run_light.py", "close_out", {"n_hdr_reopened", "n_hdr_closed"})
    got.update(_calls_in("run_heavy.py", "run", {"n_fixed_hdr", "n_fixed_tls"}))
    want = {"n_hdr_reopened": "reopen_headers_seen_again", "n_hdr_closed": "close_fixed_headers",
            "n_fixed_hdr": "close_fixed_headers", "n_fixed_tls": "close_fixed_tls"}
    for name, fn in want.items():
        call = got[name]
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute), name
        assert call.func.attr == fn and call.func.value.id == "close_fixed", name
        kw = {k.arg: k.value for k in call.keywords}
        assert [ast.unparse(a) for a in call.args] == ["conn", "ctx.scan_run_id", "ctx.asset_id", "ctx.tool_status", "Json"], name
        if fn != "close_fixed_tls":
            assert ast.unparse(kw["tier"]) in ("'light'", "'heavy'"), name
    assert ast.unparse(got["n_hdr_closed"].keywords[[k.arg for k in got["n_hdr_closed"].keywords].index("header_key")].value) == "httpx_header_key"


def test_the_quick_scan_close_out_runs_them_in_order(monkeypatch):
    """Drive the REAL run_light.close_out with everything around it faked: reopen, then close,
    then the history block, all after the scan row is closed."""
    from types import SimpleNamespace
    order = []
    monkeypatch.setattr(run_light, "bump_alive_clock", lambda *a, **k: False)
    monkeypatch.setattr(run_light, "write_scanner_surface", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "delta_close_eligible", lambda ts: True)
    monkeypatch.setattr(run_light, "write_finding_history_for_scan_run",
                        lambda conn, sid, notes=None: order.append("history") or 0)
    monkeypatch.setattr(run_light.close_fixed, "reopen_headers_seen_again",
                        lambda *a, **k: order.append(("reopen", k["tier"], tuple(k["header_names"]))) or 0)
    monkeypatch.setattr(run_light.close_fixed, "close_fixed_headers",
                        lambda *a, **k: order.append(("close", k["tier"], k["header_key"] is run_light.httpx_header_key)) or 0)
    conn = FakeConn()
    ctx = SimpleNamespace(tools_run=[], scan_run_id=SCAN, queue_id="q", tool_status={"headers_check": {"ok": True}},
                          asset_id=ASSET, open_ports=[])
    run_light.close_out(conn, ctx, 0, 0, Json)
    assert order == [("reopen", "light", tuple(NAMES)), ("close", "light", True), "history"]
    assert conn.calls[0][0] is run_light.CLOSE_SCAN_RUN_SQL
