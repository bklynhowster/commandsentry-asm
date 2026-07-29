"""Tests for the per-host scan planner (dispatch.build_scan_plan), P1.

Run:  pytest scripts/scanner/test_dispatch.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dispatch import build_scan_plan  # noqa: E402
from matrix_loader import load_matrix  # noqa: E402

M = load_matrix()


def _exposure_by_role(plan):
    return {e.role: e for e in plan.exposure_findings}


# ── exposure-is-the-finding + two-column severity (§6) ───────────────────
def test_rdp_exposure_emits_by_presence_and_defers_engine():
    plan = build_scan_plan(M, open_ports=[3389])
    assert plan.scan_profile == ["rdp"]
    assert plan.http_roles == []            # network engine not runnable in P1
    assert plan.deferred_roles == ["rdp"]   # carried until P3
    exp = _exposure_by_role(plan)
    assert "rdp" in exp and exp["rdp"].severity == "HIGH"   # base (no auth probe)
    assert exp["rdp"].port == 3389


def test_db_no_auth_is_critical_but_auth_detected_downgrades_to_high():
    # base = CRITICAL when we can't confirm an auth handshake...
    plan = build_scan_plan(M, open_ports=[5432])
    assert _exposure_by_role(plan)["db"].severity == "CRITICAL"
    # ...HIGH once an auth handshake is detected (4.7 ruling 3: not every open
    # DB is CRITICAL — an auth-gated one is HIGH).
    plan2 = build_scan_plan(M, open_ports=[5432], auth_results={"db": True})
    assert _exposure_by_role(plan2)["db"].severity == "HIGH"


def test_web_role_has_no_exposure_by_presence():
    plan = build_scan_plan(M, open_ports=[443], fingerprint_tokens=["react", "unpkg"])
    assert plan.http_roles == ["web-spa"]
    assert plan.exposure_findings == []      # web is per-finding, not exposed-by-presence
    assert plan.deferred_roles == []


def test_unmatched_port_becomes_a_fallback_finding():
    plan = build_scan_plan(M, open_ports=[1234])   # no matrix row for 1234
    assert plan.unmatched_ports == [1234]
    exp = _exposure_by_role(plan)
    assert "unmatched" in exp and exp["unmatched"].severity == "MODERATE"
    assert exp["unmatched"].port == 1234


def test_dead_kind_with_open_port_STILL_emits_exposure():
    # 4.7 ruling 2 / ruling 5 test-list: a 'dead' host with 3389 open must still
    # produce the rdp exposure finding — the label removes web depth, not exposure.
    plan = build_scan_plan(M, open_ports=[3389, 443], fingerprint_tokens=["react"], kind="dead")
    exp = _exposure_by_role(plan)
    assert "rdp" in exp and exp["rdp"].check_name == "exposure-rdp-3389"
    assert plan.http_roles == []         # web depth skipped by the dead label


def test_multi_service_host_unions_and_splits_engines():
    # DC-ish: ssh + smb + rdp + https-SPA → union; web runs now, network defers.
    plan = build_scan_plan(M, open_ports=[22, 445, 3389, 443], fingerprint_tokens=["react"])
    assert set(plan.scan_profile) == {"ssh", "smb", "rdp", "web-spa"}
    assert plan.http_roles == ["web-spa"]
    assert set(plan.deferred_roles) == {"ssh", "smb", "rdp"}
    # exposure findings for each network role, none for the web role
    exp_roles = {e.role for e in plan.exposure_findings}
    assert exp_roles == {"ssh", "smb", "rdp"}
    assert plan.unmatched_ports == []


def test_exposure_findings_have_distinct_check_names():
    # Exposure ⟂ CVE (§6): each exposure row is its own identity, never collapsed.
    plan = build_scan_plan(M, open_ports=[22, 445, 3389])
    names = [e.check_name for e in plan.exposure_findings]
    assert len(names) == len(set(names))     # all unique
    assert all(n.startswith("exposure-") for n in names)


def test_baseline_always_present_regardless_of_role():
    # spec §5: the universal baseline is in the plan no matter what the host is.
    for ports, fp in ([443], ["react"]), ([3389], []), ([1521], []):
        plan = build_scan_plan(M, open_ports=ports, fingerprint_tokens=fp)
        assert plan.baseline["staleness_hours"] == 72
        assert plan.baseline["light_cache_only"] is True


def test_prosalud_shape_is_web_spa_no_exposure():
    # The real prosalud: 80/443, nginx SPA on Unpkg → web-spa, clean.
    plan = build_scan_plan(M, open_ports=[80, 443], fingerprint_tokens=["nginx", "react", "unpkg"])
    assert plan.scan_profile == ["web-spa"]
    assert plan.exposure_findings == [] and plan.unmatched_ports == []


def test_dead_kind_yields_empty_plan():
    plan = build_scan_plan(M, open_ports=[80, 443], fingerprint_tokens=["react"], kind="dead")
    assert plan.scan_profile == ["dead"]
    assert plan.http_roles == [] and plan.exposure_findings == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
