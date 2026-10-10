#!/usr/bin/env python3
"""302 step 3 — the medium and heavy writers keep CVE numbers (2026-10-09).

Only run_light's writer saved findings.cve. Heavy runs the light phases
(wpvulnerability, and now library_flaws) whose findings carry CVEs; the heavy
writer reuses run_medium.UPSERT_FINDING_SQL, which had no cve column, so a
finding first seen on a heavy run was stored without its CVE and could not be
scored until a later light run back-filled it. Both writers now pass cve, with
run_light's rule: a non-empty list wins, an empty one never blanks a list.
"""
from __future__ import annotations

import os
import re
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_light as L  # noqa: E402
import run_medium as M  # noqa: E402


def _norm(sql):
    return re.sub(r"\s+", " ", sql)


def test_shared_upsert_inserts_cve():
    sql = _norm(M.UPSERT_FINDING_SQL)
    assert "cwe, cve, \"references\"" in sql and "%(cwe)s, %(cve)s, %(references)s" in sql


def test_shared_upsert_uses_light_s_never_blank_rule():
    rule = ("cve = CASE WHEN EXCLUDED.cve IS NOT NULL AND array_length(EXCLUDED.cve, 1) > 0 "
            "THEN EXCLUDED.cve ELSE findings.cve END,")
    assert rule in _norm(M.UPSERT_FINDING_SQL)
    assert rule in _norm(L.UPSERT_FINDING_SQL)          # the same rule light has always had


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

    def fetchall(self):
        return []


class _Conn:
    def __init__(self):
        self.cur = _Cur()

    def cursor(self):
        return self.cur


def _upserts(conn):
    return [p for s, p in conn.cur.calls if s is M.UPSERT_FINDING_SQL]


def test_medium_writer_passes_an_empty_list_never_null(monkeypatch):
    """findings.cve is NOT NULL DEFAULT '{}': None would fail the insert."""
    monkeypatch.setattr(M, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(M, "derive_validation_status", lambda *a, **k: "unvalidated")
    f = M.MediumFinding(check_name="c", title="t", severity="LOW", category="config", description="d")
    ctx = types.SimpleNamespace(asset_id="a.example", scan_run_id="r", intensity="medium",
                                findings=[f], artifacts=[])
    conn = _Conn()
    M.write_findings_and_artifacts(conn, ctx, Json=lambda x: x)
    (p,) = _upserts(conn)
    assert p["cve"] == []


@pytest.mark.parametrize("cve,expected", [(["CVE-2021-41184"], ["CVE-2021-41184"]), ([], []), (None, [])])
def test_heavy_writer_passes_the_event_s_cves(monkeypatch, cve, expected):
    import run_heavy as H
    from cs_parsers.common import FindingEvent
    monkeypatch.setattr(H, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(H, "derive_validation_status", lambda *a, **k: "unvalidated")
    ev = FindingEvent(finding_id="a.example:light:libflaw-x", asset_id="a.example", scan_id="r",
                      source="commandsentry_light", title="t", severity="MODERATE", category="supply_chain",
                      observed_at="2026-10-09T00:00:00Z", cve=cve or [])
    if cve is None:
        ev.cve = None
    ctx = types.SimpleNamespace(asset_id="a.example", scan_run_id="r", intensity="heavy",
                                findings=[ev], artifacts=[])
    conn = _Conn()
    H.write_event_findings_and_artifacts(conn, ctx, Json=lambda x: x, write_artifacts=False)
    (p,) = _upserts(conn)
    assert p["cve"] == expected


def test_a_light_finding_run_inside_heavy_keeps_its_cve_end_to_end(monkeypatch):
    """LightFinding -> phase_contract adapter -> heavy writer: the CVE survives."""
    import run_heavy as H
    from phase_contract import _as_finding_event
    monkeypatch.setattr(H, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(H, "derive_validation_status", lambda *a, **k: "unvalidated")
    lf = L.LightFinding(check_name="libflaw-jquery-ui-cve-2021-41184", title="t", severity="MODERATE",
                        category="supply_chain", description="d", cve=["CVE-2021-41184"],
                        normalized_key_override="jslib-jquery-ui")
    ctx = types.SimpleNamespace(asset_id="a.example", scan_run_id="r", intensity="heavy", artifacts=[])
    ctx.findings = [_as_finding_event(lf, "light", ctx)]
    conn = _Conn()
    H.write_event_findings_and_artifacts(conn, ctx, Json=lambda x: x, write_artifacts=False)
    (p,) = _upserts(conn)
    assert p["cve"] == ["CVE-2021-41184"] and p["normalized_key"] == "jslib-jquery-ui"
    assert p["finding_id"] == "a.example:light:libflaw-jquery-ui-cve-2021-41184"
