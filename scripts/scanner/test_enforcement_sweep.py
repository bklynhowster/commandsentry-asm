#!/usr/bin/env python3
"""(relay 382) The enforcement-sweep planner + blast-radius preview.

⛔ TWO THINGS THESE TESTS GUARANTEE:
  1. SCOPE — protective resolved class AND an in-scope ownership; client hosts
     are out by default (the ROE allowlist), so the sweep never targets the
     whole world.
  2. THE PREVIEW FIRES NOTHING — and the module CANNOT fire: it carries no
     probe, no HTTP, no ENFORCEMENT_PROBE_LIVE, and no DB write. The live sweep
     is the routed follow-up; a preview that could fire would defeat its purpose.
"""
from __future__ import annotations

import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import enforcement_sweep as ES  # noqa: E402


def _asset(**kw):
    base = {
        "asset_id": "a1", "name": "host.example.com", "device_class": "waf",
        "ownership": "owned", "vendor_product": {"vendor": "Google", "product": "Cloud Armor"},
        "dryrun_device_class": None, "enforcement_probe_authorized": False,
    }
    base.update(kw)
    return base


# ── scope: protective classes only ──────────────────────────────────────────

def test_protective_classes_are_in_scope():
    for c in ("waf", "edge_firewall", "adc_lb"):
        assert ES.in_scope(_asset(device_class=c)) is True, c


def test_non_protective_classes_are_never_in_scope():
    for c in ("origin_host", "cloud_endpoint", "cdn", "unknown", None):
        assert ES.in_scope(_asset(device_class=c, dryrun_device_class=None)) is False, c


def test_protective_set_matches_the_portal_set():
    assert set(ES.PROTECTIVE_CLASSES) == {"waf", "edge_firewall", "adc_lb"}


# ── scope: ownership — client is out by default ─────────────────────────────

def test_owned_and_test_target_are_in_scope_by_default():
    assert ES.in_scope(_asset(ownership="owned")) is True
    assert ES.in_scope(_asset(ownership="test_target")) is True


def test_client_and_namesake_are_out_by_default():
    for o in ("client", "namesake", "UNKNOWN", None):
        assert ES.in_scope(_asset(ownership=o)) is False, o


def test_the_default_scope_is_the_ROE_allowlist():
    # Bound to the same authority the ROE gate enforces — not a second copy.
    from roe_gate import ROE_OWNERSHIP_ALLOWLIST
    assert ES.DEFAULT_OWNERSHIP_SCOPE == frozenset(ROE_OWNERSHIP_ALLOWLIST)
    assert ES.DEFAULT_OWNERSHIP_SCOPE == frozenset({"owned", "test_target"})


def test_widening_scope_includes_client_only_when_explicit():
    client = _asset(ownership="client")
    assert ES.in_scope(client) is False
    assert ES.in_scope(client, ownership_scope=frozenset({"owned", "client"})) is True


# ── resolution: live wins, else dry-run ─────────────────────────────────────

def test_live_class_wins_over_dryrun():
    a = _asset(device_class="waf", dryrun_device_class="origin_host")
    assert ES.resolved_device_class(a) == "waf"


def test_unknown_live_falls_back_to_the_dryrun_verdict():
    a = _asset(device_class="unknown", dryrun_device_class="waf")
    assert ES.resolved_device_class(a) == "waf"
    assert ES.in_scope(a) is True, "a soak-mode WAF must not be silently excluded"


def test_both_unknown_is_out_of_scope():
    a = _asset(device_class="unknown", dryrun_device_class=None)
    assert ES.resolved_device_class(a) is None
    assert ES.in_scope(a) is False


# ── the blast-radius preview ────────────────────────────────────────────────

def test_blast_radius_counts_only_in_scope_hosts():
    assets = [
        _asset(asset_id="w", device_class="waf", ownership="owned"),
        _asset(asset_id="c", device_class="waf", ownership="client"),      # client -> out
        _asset(asset_id="o", device_class="origin_host", ownership="owned"),  # not protective -> out
        _asset(asset_id="e", device_class="edge_firewall", ownership="test_target"),
    ]
    r = ES.build_blast_radius(assets)
    assert r["count"] == 2
    assert {h["asset_id"] for h in r["hosts"]} == {"w", "e"}


def test_blast_radius_is_marked_dry_run_and_unfired():
    r = ES.build_blast_radius([_asset()])
    assert r["dry_run"] is True
    assert r["fired"] is False


def test_blast_radius_reports_already_authorized_hosts():
    r = ES.build_blast_radius([
        _asset(asset_id="on", enforcement_probe_authorized=True),
        _asset(asset_id="off", enforcement_probe_authorized=False),
    ])
    by = {h["asset_id"]: h for h in r["hosts"]}
    assert by["on"]["already_authorized"] is True
    assert by["off"]["already_authorized"] is False


def test_blast_radius_records_the_ownership_scope_it_used():
    r = ES.build_blast_radius([_asset()])
    assert r["ownership_scope"] == ["owned", "test_target"]


# ── ⛔ THE SAFETY PIN: the module cannot fire ────────────────────────────────

def test_the_module_carries_no_firing_code():
    # ⛔ Checked as CODE, not prose — the docstring names the things it does NOT
    # do, so a substring scan would false-positive on its own explanation. Parse
    # the AST and look at imports and identifiers actually used.
    import ast
    tree = ast.parse(inspect.getsource(ES))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.Import):
            imported.update(n.name.split(".")[0] for n in node.names)
    assert "httpx" not in imported and "requests" not in imported, (
        "the planner imports an HTTP client — a preview must not be able to fire")
    assert not (imported & {"build_probe_plan", "probe_is_authorised", "record_probe_pair"}), (
        "the planner imports the probe firing helpers — firing is the routed follow-up")
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "ENFORCEMENT_PROBE_LIVE" not in names, (
        "the planner references the live-fire env flag as code — it must not arm anything")


def test_the_candidate_query_is_a_read():
    # The candidate/preview query must be a SELECT (the writes live in the
    # gated ARM/ENQUEUE constants, exercised separately below).
    sql = ES.FETCH_CANDIDATES_SQL.strip().lower()
    assert sql.startswith("select"), "the candidate query must be a SELECT"
    for w in ("insert", "update", "delete", "alter", "drop"):
        assert w not in sql, f"the candidate SQL contains a write keyword: {w!r}"


# ── (relay 382-live-2) the ARM+ENQUEUE live path — hard-gated ────────────────

class _FakeCur:
    def __init__(self):
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, sql, params=None):
        self.calls.append((sql, params))


class _FakeConn:
    def __init__(self):
        self.cur = _FakeCur()
        self.committed = 0
    def cursor(self):
        return self.cur
    def commit(self):
        self.committed += 1


def test_arm_enqueue_plan_covers_only_in_scope_hosts():
    assets = [
        _asset(asset_id="w", device_class="waf", ownership="owned"),
        _asset(asset_id="c", device_class="waf", ownership="client"),        # client -> out
        _asset(asset_id="o", device_class="origin_host", ownership="owned"),  # not protective -> out
    ]
    plan = ES.build_arm_enqueue_plan(assets)
    assert plan["arm"] == ["w"]
    assert [r["asset_id"] for r in plan["enqueue"]] == ["w"]


def test_disarm_IS_wired_now(relay_382_live_3=True):
    # ⛔ 382-live-3 flipped this True together with the run_light fire-once wiring
    # (mechanism A-refined). It is what unblocks --confirm. The disarm behaviour
    # itself is pinned in test_enforcement_disarm.py.
    assert ES._DISARM_WIRED is True


def test_execute_sweep_refuses_and_writes_nothing_without_confirm():
    conn = _FakeConn()
    r = ES.execute_sweep(conn, [_asset()], confirmed=False)
    assert r["executed"] is False and r["armed"] == 0 and r["enqueued"] == 0
    assert conn.cur.calls == [], "a non-confirmed sweep must write nothing"


def test_confirm_gate_refuses_INDEPENDENTLY_of_the_disarm_gate():
    # ⛔ relay 312 lesson — isolate each gate so neither masks the other. Even
    # with disarm wired, no --confirm must still write nothing (the confirm gate
    # standing alone). Without this, dropping the confirm check survives because
    # the disarm gate happens to also refuse.
    conn = _FakeConn()
    r = ES.execute_sweep(conn, [_asset()], confirmed=False, disarm_wired=True)
    assert r["executed"] is False and conn.cur.calls == [], (
        "confirm gate must refuse on its own, not rely on the disarm gate")


def test_execute_sweep_refuses_while_disarm_unwired_even_when_confirmed():
    # ⛔ THE FIRE-ONCE GATE: --confirm but no disarm story -> zero writes, so a
    # sweep can never leave the fleet standing-armed in the shipped state.
    conn = _FakeConn()
    r = ES.execute_sweep(conn, [_asset()], confirmed=True, disarm_wired=False)
    assert r["executed"] is False
    assert conn.cur.calls == [], "confirm without a wired disarm must write nothing"


def test_execute_sweep_arms_and_enqueues_only_in_scope_when_fully_enabled():
    # The enabled path's correctness — disarm_wired forced True in the TEST only
    # (the shipped module keeps it False). One ARM + one ENQUEUE for the in-scope
    # host; the client host is never touched.
    conn = _FakeConn()
    assets = [
        _asset(asset_id="w", device_class="waf", ownership="owned"),
        _asset(asset_id="c", device_class="waf", ownership="client"),
    ]
    r = ES.execute_sweep(conn, assets, confirmed=True, disarm_wired=True)
    assert r["executed"] is True and r["armed"] == 1 and r["enqueued"] == 1
    arms = [c for c in conn.cur.calls if "update public.assets" in c[0]]
    enq = [c for c in conn.cur.calls if "insert into public.scan_queue" in c[0]]
    assert len(arms) == 1 and arms[0][1] == {"asset_id": "w"}
    assert len(enq) == 1
    assert enq[0][1]["asset_id"] == "w"
    assert enq[0][1]["source"] == ES.SWEEP_ENQUEUE_SOURCE
    # ⛔ the client host id appears in NO write
    assert not any("c" == (c[1] or {}).get("asset_id") for c in conn.cur.calls)


def test_arm_sets_the_per_asset_flag_and_enqueue_sets_the_per_scan_flag():
    assert "enforcement_probe_authorized = true" in ES.ARM_SQL
    assert "enforcement_probe_live" in ES.ENQUEUE_SQL
    assert "'light'" in ES.ENQUEUE_SQL  # a sweep row is always a light scan


# ── (relay 381) the 2xx-vs-5xx signal in the fleet output ────────────────────

def test_sweep_signal_distinguishes_passthrough_from_origin_error():
    assert ES.sweep_attack_signal("not_enforcing", 200) == "not_enforcing_passthrough"
    assert ES.sweep_attack_signal("not_enforcing", 302) == "not_enforcing_passthrough"
    for s in (500, 502, 503, 599):
        assert ES.sweep_attack_signal("not_enforcing", s) == "not_enforcing_origin_error", s


def test_sweep_signal_leaves_enforcing_and_not_verified_alone():
    assert ES.sweep_attack_signal("enforcing", 403) == "enforcing"
    assert ES.sweep_attack_signal("not_verified", None) == "not_verified"


# ── never cron: the sweep is a manual CLI, no workflow reaches the live path ──

def test_no_workflow_invokes_the_sweep():
    import pathlib
    wf_dir = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
    for f in sorted(wf_dir.glob("*.yml")):
        assert "enforcement_sweep" not in f.read_text(), (
            f"{f.name} references the sweep — it must never be cron/workflow-driven")


def test_the_only_write_path_is_execute_sweep_behind_confirm():
    # The ARM/ENQUEUE SQL is reachable only through execute_sweep, which refuses
    # unless confirmed. No other function in the module runs them.
    import inspect
    for name, fn in inspect.getmembers(ES, inspect.isfunction):
        if name == "execute_sweep":
            continue
        src = inspect.getsource(fn)
        assert "ARM_SQL" not in src and "ENQUEUE_SQL" not in src, (
            f"{name} references the write SQL — writes must go through execute_sweep")
