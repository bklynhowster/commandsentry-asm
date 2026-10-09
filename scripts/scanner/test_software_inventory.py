#!/usr/bin/env python3
"""302 step 1 — keep the software versions the scan already sees (2026-10-09).

httpx tech-detect reports "IIS:10.0", "jQuery UI:1.12.1" and the like on every
light, medium and heavy run. Until now those versions lived only inside the raw
httpx artifact. software_inventory turns them into per-asset history rows in
asset_tech_history (the table the asset page's "Recent stack changes" panel
reads): one row the first time a product is seen, one when its version
changes, nothing when it is simply seen again. No new request goes to any
target: this only reads output the scan already produced.
"""
from __future__ import annotations

import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import software_inventory as S  # noqa: E402


def _row(tech, status=200, title="Home", url="https://a.example/"):
    return {"url": url, "status_code": status, "title": title, "tech": tech}


# ── what counts as a version ──────────────────────────────────────────────────

def test_versioned_entries_become_observations_unversioned_are_left_out():
    obs = S.observations_from_httpx_rows([_row(["IIS:10.0", "Microsoft ASP.NET:4.0.30319", "Windows Server"])])
    assert [(o.product, o.version) for o in obs] == [("IIS", "10.0"), ("Microsoft ASP.NET", "4.0.30319")]
    assert all(o.url == "https://a.example/" for o in obs)


def test_a_block_page_is_not_the_target_s_software():
    """A WAF's 403 page names the WAF's stack, not the site's (tech_detect ⑭′)."""
    assert S.observations_from_httpx_rows([_row(["Nginx:1.18.0"], status=403, title="403 Forbidden")]) == []


@pytest.mark.parametrize("ver", ["10.0", "4.0.30319", "1.12.1", "6.7.58", "28", "1.1.1k"])
def test_real_version_shapes_are_kept(ver):
    assert [o.version for o in S.observations_from_httpx_rows([_row([f"X:{ver}"])])] == [ver]


@pytest.mark.parametrize("ver", ["", "latest", "1773771062", "1.2.3.4.5.6.7", "v1.2", "1.2-beta", "1.2 ", "1..2",
                                 "12345.1"])
def test_anything_else_is_not_a_version(ver):
    """No guessing: a cache-buster timestamp, a word or a malformed number is not
    a version (asset_tech_history already holds 'Script Js?ver=1773771062' junk
    from the old offline script)."""
    assert S.observations_from_httpx_rows([_row([f"X:{ver}"])]) == []


def test_names_are_trimmed_and_an_empty_name_is_dropped():
    obs = S.observations_from_httpx_rows([_row(["  jQuery UI :1.12.1", ":1.0", 7, None])])
    assert [(o.product, o.version) for o in obs] == [("jQuery UI", "1.12.1")]


def test_the_same_pair_twice_is_one_observation_two_versions_are_two():
    obs = S.observations_from_httpx_rows([
        _row(["Yoast SEO:28.6"], url="https://a.example/"),
        _row(["Yoast SEO:28.6", "Yoast SEO:28.3"], url="https://a.example/blog"),
    ])
    assert sorted((o.product, o.version) for o in obs) == [("Yoast SEO", "28.3"), ("Yoast SEO", "28.6")]


def test_rows_without_tech_are_ignored():
    assert S.observations_from_httpx_rows([{"url": "x", "status_code": 200, "title": "t"}, "junk", None]) == []


# ── what gets written: first sighting, version change, or nothing ────────────

def _obs(product, version, url="https://a.example/"):
    return S.Observation(product=product, version=version, url=url)


def test_never_recorded_is_first_seen():
    rows = S.plan_history_rows([_obs("IIS", "10.0")], recorded=[])
    assert [(r["item_key"], r["version"], r["change_type"]) for r in rows] == [("iis", "10.0", "first_seen")]
    assert rows[0]["name"] == "IIS" and rows[0]["prior_value"] is None


def test_seen_again_writes_nothing():
    assert S.plan_history_rows([_obs("IIS", "10.0")], recorded=[("iis", "10.0")]) == []


def test_a_new_version_is_a_version_change_from_the_latest_recorded():
    rows = S.plan_history_rows([_obs("Slider Revolution", "6.7.58")],
                               recorded=[("slider revolution", "6.7.41"), ("slider revolution", "6.7.54")])
    assert len(rows) == 1 and rows[0]["change_type"] == "version_changed"
    assert rows[0]["prior_value"] == {"version": "6.7.54"}


def test_product_names_match_regardless_of_case():
    assert S.plan_history_rows([_obs("jQuery UI", "1.12.1")], recorded=[("jquery ui", "1.12.1")]) == []


def test_a_version_seen_before_is_not_written_again_even_if_not_the_latest():
    """Two pages of one site can run different versions; flip-flopping between
    them must not write a row every scan."""
    assert S.plan_history_rows([_obs("X", "1.0")], recorded=[("x", "1.0"), ("x", "2.0")]) == []


def test_new_value_carries_where_it_was_seen():
    rows = S.plan_history_rows([_obs("IIS", "10.0", url="https://h.example/login")], recorded=[])
    assert rows[0]["new_value"] == {"version": "10.0", "url": "https://h.example/login"}


# ── the database write ────────────────────────────────────────────────────────

class _Cur:
    def __init__(self, recorded=(), fail_on=None):
        self.calls = []
        self._recorded = [{"item_key": k, "version": v} for k, v in recorded]
        self._fail_on = fail_on
        self._last = None

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        self._last = sql
        if self._fail_on and self._fail_on in sql:
            raise RuntimeError("boom")

    def fetchall(self):
        return list(self._recorded) if self._last == S.SELECT_RECORDED_SQL else []


def _sqls(cur):
    return [c[0] for c in cur.calls]


def test_record_writes_inside_a_savepoint_and_returns_the_row_count():
    cur = _Cur()
    n = S.record(cur, "a.example", "run-1", [_obs("IIS", "10.0"), _obs("jQuery", "3.6.0")], Json=lambda x: x)
    assert n == 2
    sq = _sqls(cur)
    assert sq[0] == "SAVEPOINT software_inventory" and sq[-1] == "RELEASE SAVEPOINT software_inventory"
    assert sq.count(S.INSERT_HISTORY_SQL) == 2
    sel = [p for s, p in cur.calls if s == S.SELECT_RECORDED_SQL]
    assert sel == [{"asset_id": "a.example", "category": S.CATEGORY}]


def test_record_skips_what_is_already_recorded():
    cur = _Cur(recorded=[("iis", "10.0")])
    assert S.record(cur, "a.example", "run-1", [_obs("IIS", "10.0")], Json=lambda x: x) == 0
    assert S.INSERT_HISTORY_SQL not in _sqls(cur)


def test_insert_params():
    cur = _Cur()
    S.record(cur, "a.example", "run-9", [_obs("IIS", "10.0")], Json=lambda x: x)
    (p,) = [p for s, p in cur.calls if s == S.INSERT_HISTORY_SQL]
    assert p["asset_id"] == "a.example" and p["category"] == "web.technology"
    assert p["item_key"] == "iis" and p["name"] == "IIS" and p["version"] == "10.0"
    assert p["change_type"] == "first_seen" and p["source"] == "httpx" and p["confidence"] == "medium"
    assert p["prior_value"] is None and p["new_value"] == {"version": "10.0", "url": "https://a.example/"}
    assert "run-9" in p["notes"]


def test_scan_id_is_never_written():
    """asset_tech_history.scan_id references the legacy scans table, which never
    holds a scan_run id: writing one would fail the whole insert."""
    assert "scan_id" not in S.INSERT_HISTORY_SQL


def test_a_failure_rolls_back_only_the_inventory_and_never_raises():
    """The findings in the same transaction must survive an inventory problem."""
    cur = _Cur(fail_on="INSERT INTO public.asset_tech_history")
    assert S.record(cur, "a.example", "run-1", [_obs("IIS", "10.0")], Json=lambda x: x) == -1
    assert _sqls(cur)[-1] == "ROLLBACK TO SAVEPOINT software_inventory"


def test_nothing_observed_touches_nothing():
    cur = _Cur()
    assert S.record(cur, "a.example", "run-1", [], Json=lambda x: x) == 0
    assert cur.calls == []


# ── wiring: every tier records what its own httpx run saw ────────────────────

HTTPX_ROW = {"url": "https://a.example/", "status_code": 200, "title": "Home", "tech": ["IIS:10.0", "Bootstrap"]}


class _WCur(_Cur):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def fetchone(self):
        return {"inserted": True}


class _Conn:
    def __init__(self):
        self.cur = _WCur()

    def cursor(self):
        return self.cur

    def commit(self):
        pass


def _inventory_inserts(conn):
    return [p for s, p in conn.cur.calls if s == S.INSERT_HISTORY_SQL]


def test_light_writer_records_the_inventory(monkeypatch):
    import run_light as L
    monkeypatch.setattr(L, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(L, "derive_validation_status", lambda *a, **k: "unvalidated")
    ctx = types.SimpleNamespace(descriptor={}, asset_id="a.example", scan_run_id="run-L", intensity="light",
                                findings=[], artifacts=[("httpx_tech", "json", json.dumps(HTTPX_ROW))])
    conn = _Conn()
    L.write_findings_and_artifacts(conn, ctx, Json=lambda x: x)
    assert [(p["name"], p["version"]) for p in _inventory_inserts(conn)] == [("IIS", "10.0")]


def test_medium_writer_records_the_inventory(monkeypatch):
    import run_medium as M
    monkeypatch.setattr(M, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(M, "derive_validation_status", lambda *a, **k: "unvalidated")
    ctx = types.SimpleNamespace(asset_id="a.example", scan_run_id="run-M", intensity="medium",
                                findings=[], artifacts=[("httpx_tech", "json", json.dumps(HTTPX_ROW))])
    conn = _Conn()
    M.write_findings_and_artifacts(conn, ctx, Json=lambda x: x)
    assert [(p["name"], p["version"]) for p in _inventory_inserts(conn)] == [("IIS", "10.0")]


@pytest.mark.parametrize("write_artifacts", [True, False])
def test_heavy_writer_records_the_inventory_on_both_paths(monkeypatch, write_artifacts):
    """The degraded path passes write_artifacts=False; the inventory is still kept."""
    import run_heavy as H
    monkeypatch.setattr(H, "get_scanner_version", lambda: "vX")
    monkeypatch.setattr(H, "derive_validation_status", lambda *a, **k: "unvalidated")
    ctx = types.SimpleNamespace(asset_id="a.example", scan_run_id="run-H", intensity="heavy",
                                findings=[], artifacts=[("httpx", "json", json.dumps(HTTPX_ROW))])
    conn = _Conn()
    H.write_event_findings_and_artifacts(conn, ctx, Json=lambda x: x, write_artifacts=write_artifacts)
    assert [(p["name"], p["version"]) for p in _inventory_inserts(conn)] == [("IIS", "10.0")]
