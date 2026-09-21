#!/usr/bin/env python3
"""(relay 382-live-3) FIRE-ONCE disarm — mechanism A-refined (ruling 393).

⛔ THE INVARIANT: after a probe that fired via the PER-SCAN flag
(enforcement_probe_live=true — a sweep row or a 376 portal fire), the asset ends
DISARMED; after an ENV fire (354a-FIRE single dispatch, live=false) it does NOT
(manual single-host arms preserved). And the disarm is ATOMIC with the capture
write — same cursor, one commit in run() — so a crash cannot leave a fired host
armed.
"""
from __future__ import annotations

import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_light as L  # noqa: E402
from enforcement_probe import ENFORCEMENT_PROBE_ARTIFACT  # noqa: E402


def _ctx(*, live, fired):
    arts = []
    if fired is not None:
        arts.append((ENFORCEMENT_PROBE_ARTIFACT, "json",
                     json.dumps({"fired": fired, "host": "x", "path": "/"})))
    d = {}
    if live is not None:
        d["enforcement_probe_live"] = live
    return types.SimpleNamespace(
        descriptor=d, asset_id="asset-x", scan_run_id="run-1",
        intensity="light", findings=[], artifacts=arts)


# ── the decision (R2) — the wrong-signal mutant surface ──────────────────────

def test_per_scan_flag_fire_disarms():
    assert L._sweep_fire_should_disarm(_ctx(live=True, fired=True)) is True


def test_env_fire_is_NOT_auto_disarmed():
    # live=false = the 354a-FIRE single-dispatch env path — a deliberate manual
    # arm that must survive.
    assert L._sweep_fire_should_disarm(_ctx(live=False, fired=True)) is False


def test_a_dry_run_plan_disarms_nothing():
    # per-scan flag set but the probe did NOT fire (auth was false / dry-run).
    assert L._sweep_fire_should_disarm(_ctx(live=True, fired=False)) is False
    assert L._sweep_fire_should_disarm(_ctx(live=True, fired=None)) is False


def test_absent_flag_disarms_nothing():
    assert L._sweep_fire_should_disarm(_ctx(live=None, fired=True)) is False


def test_probe_fired_reads_only_a_true_fired_artifact():
    assert L._enforcement_probe_fired(_ctx(live=True, fired=True)) is True
    assert L._enforcement_probe_fired(_ctx(live=True, fired=False)) is False
    assert L._enforcement_probe_fired(_ctx(live=True, fired=None)) is False


# ── atomicity (R1): the disarm rides the SAME cursor as the capture write ─────

class _Cur:
    def __init__(self):
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, sql, params=None):
        self.calls.append((sql, params))
    def fetchone(self):
        return {"inserted": True}


class _Conn:
    def __init__(self):
        self.cur = _Cur()
        self.commits = 0
    def cursor(self):
        return self.cur
    def commit(self):
        self.commits += 1


def _run_wfa(ctx, monkeypatch):
    monkeypatch.setattr(L, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(L, "derive_validation_status", lambda *a, **k: "validated")
    conn = _Conn()
    L.write_findings_and_artifacts(conn, ctx, Json=lambda x: x)
    return conn


def test_flag_fire_issues_the_disarm_in_the_same_txn(monkeypatch):
    conn = _run_wfa(_ctx(live=True, fired=True), monkeypatch)
    disarms = [c for c in conn.cur.calls if c[0] is L.DISARM_ENFORCEMENT_SQL]
    assert len(disarms) == 1, "a flag-fire must disarm exactly once"
    assert disarms[0][1] == {"asset_id": "asset-x"}
    # ⛔ ATOMIC: write_findings_and_artifacts must NOT commit — run() commits once
    # after, so the disarm and the capture land together or not at all.
    assert conn.commits == 0, "the disarm must not be committed separately"


def test_env_fire_issues_NO_disarm(monkeypatch):
    conn = _run_wfa(_ctx(live=False, fired=True), monkeypatch)
    assert not any(c[0] is L.DISARM_ENFORCEMENT_SQL for c in conn.cur.calls), \
        "an env fire must not auto-disarm"


def test_dry_run_issues_no_disarm(monkeypatch):
    conn = _run_wfa(_ctx(live=True, fired=False), monkeypatch)
    assert not any(c[0] is L.DISARM_ENFORCEMENT_SQL for c in conn.cur.calls)


def test_the_disarm_sql_clears_the_per_asset_flag():
    sql = L.DISARM_ENFORCEMENT_SQL.lower()
    assert "update public.assets" in sql
    assert "enforcement_probe_authorized = false" in sql
