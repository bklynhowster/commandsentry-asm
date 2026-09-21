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


def test_the_only_sql_is_a_read():
    # No write belongs in a dry-run preview. Pin the actual SQL constant.
    sql = ES.FETCH_CANDIDATES_SQL.strip().lower()
    assert sql.startswith("select"), "the candidate query must be a SELECT"
    for w in ("insert", "update", "delete", "alter", "drop"):
        assert w not in sql, f"the preview SQL contains a write keyword: {w!r}"
