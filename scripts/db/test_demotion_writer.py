#!/usr/bin/env python3
"""Regression tests for demotion_writer.py pure cores (no DB needed).

Covers the 4.7 load-bearing risks:
  - Q4 anti-single-probe: one flaky probe can never demote.
  - Q2 strengthened gate: partial outage / near-threshold / min-fleet / consecutive.
  - Q8 anti-drift: writer DWELL_DAYS must equal asset_dark_debounce_state() SQL constants.
  - Q5 classification: RST vs timeout -> service_gone vs unreachable.

Run: python3 scripts/db/test_demotion_writer.py   (or pytest).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from datetime import datetime, timedelta, timezone

import demotion_writer as dw

UTC = timezone.utc


# ── Q4: multi-probe aggregation — the anti-single-probe guard ──
def test_probe1_fail_probe2_success_stays_alive():
    # probe#1 says service_gone, probe#2 says alive -> MUST NOT demote.
    assert dw.aggregate_probes(["service_gone", "alive"], False)["decision"] == "alive"

def test_unanimous_concrete_demotes():
    r = dw.aggregate_probes(["service_gone", "service_gone", "service_gone"], False)
    assert r["decision"] == "demote_candidate" and r["reason"] == "service_gone"

def test_mixed_reasons_hold():
    assert dw.aggregate_probes(["dns_gone", "service_gone", "unreachable"], False)["decision"] == "mixed"

def test_importer_bump_midprobe_aborts():
    assert dw.aggregate_probes(["service_gone", "service_gone"], True)["decision"] == "alive"

def test_inconclusive_is_not_demotable():
    # resolver hiccup on a probe -> not unanimous-concrete -> HOLD, never demote.
    assert dw.aggregate_probes(["service_gone", "inconclusive", "service_gone"], False)["decision"] == "mixed"


# ── Q5: port outcome -> reason ──
def test_classify_ports():
    assert dw.classify_ports(["open", "refused"]) == "alive"
    assert dw.classify_ports(["refused", "refused"]) == "service_gone"
    assert dw.classify_ports(["noresponse", "noresponse"]) == "unreachable"
    assert dw.classify_ports(["refused", "noresponse"]) == "service_gone"  # ambiguous -> bounded
    assert dw.classify_ports([]) == "service_gone"


# ── Q2: strengthened sweep-health gate ──
def test_gate_healthy():
    g = dw.evaluate_gate(bumped=80, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert g["ok"] and g["reason"] == "healthy"

def test_gate_first_run_bootstraps():
    # First-ever sweep: no prior marker -> not consecutive -> ok False, but coverage_ok
    # True so the __sweep__ marker records healthy and run 2 can pass. Guards the deadlock
    # where sweep_healthy echoed the final gate decision and nothing ever went healthy.
    g = dw.evaluate_gate(bumped=80, denom=100, prev_healthy=None, prev_age_hours=None)
    assert not g["ok"] and g["coverage_ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_partial_outage_blocks():
    # 30% observed -> low fraction -> demote nothing (the failure the >=1-bump gate missed)
    g = dw.evaluate_gate(bumped=30, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert not g["ok"] and not g["coverage_ok"] and g["reason"] == "sweep_unhealthy_low_fraction"

def test_gate_near_threshold_human_review():
    g = dw.evaluate_gate(bumped=55, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert not g["ok"] and g["reason"] == "near_threshold_human_review"

def test_gate_no_consecutive_healthy():
    g = dw.evaluate_gate(bumped=90, denom=100, prev_healthy=False, prev_age_hours=6.0)
    assert not g["ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_prev_sweep_too_old():
    g = dw.evaluate_gate(bumped=90, denom=100, prev_healthy=True, prev_age_hours=20.0)
    assert not g["ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_min_fleet_requires_100():
    assert not dw.evaluate_gate(4, 5, True, 6.0)["ok"]          # 80% on tiny fleet -> blocked
    assert dw.evaluate_gate(5, 5, True, 6.0)["ok"]              # 100% on tiny fleet -> ok

def test_gate_empty_fleet():
    assert not dw.evaluate_gate(0, 0, True, 6.0)["ok"]


# ── Q8: writer/SQL constant parity (anti-drift) ──
def test_flip_at_values():
    t = datetime(2026, 7, 1, tzinfo=UTC)
    assert dw.flip_at(t, "dns_gone", None) == t + timedelta(days=7)
    assert dw.flip_at(t, "service_gone", None) == t + timedelta(days=14)
    assert dw.flip_at(t, "unreachable", None) is None          # HOLD
    assert dw.flip_at(t, "service_gone", 30) == t + timedelta(days=30)  # override

def test_dwell_matches_sql_migration():
    """DWELL_DAYS must equal the CASE in asset_dark_debounce_state() (migration 20260712a)."""
    mig = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "migrations", "20260712a_asset_dark_debounce_p2.sql")
    sql = open(mig).read().lower()
    m = re.search(r"when 'dns_gone'\s+then\s+(\d+).*?when 'unreachable'\s+then\s+(\d+).*?else\s+(\d+)",
                  sql, re.S)
    assert m, "could not find the d_days CASE in the migration"
    dns_gone, unreachable_days, service_gone = int(m.group(1)), int(m.group(2)), int(m.group(3))
    assert dw.DWELL_DAYS["dns_gone"] == dns_gone == 7
    assert dw.DWELL_DAYS["service_gone"] == service_gone == 14
    # unreachable is HOLD in the writer (None); the SQL uses 0 d_days but the fn returns
    # NULL days_remaining/flip for unreachable, so the 0 is inert.
    assert dw.DWELL_DAYS["unreachable"] is None and unreachable_days == 0


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run())
