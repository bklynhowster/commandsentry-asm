"""Tests for the discovery-signal reader + the P1a exposure wiring.

Covers surface_read.extract_signals (the schema-gated, fail-safe interpreter of
asset_surface.surface_data), its contract with dispatch.build_scan_plan
end-to-end, and run_medium.exposure_to_finding (the trust-critical source tag).

Run:  pytest scripts/scanner/test_surface_read.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from surface_read import extract_signals, pick_sub, SUPPORTED_SCHEMA_VERSIONS  # noqa: E402
from matrix_loader import load_matrix  # noqa: E402
from dispatch import build_scan_plan, ExposureFinding  # noqa: E402

M = load_matrix()
SV = sorted(SUPPORTED_SCHEMA_VERSIONS)[0]  # a supported version string (e.g. "3.0")


def _surface(*subs):
    return {"schema_version": SV, "subdomains": list(subs)}


def _sub(name, *, is_root=False, status=None, tech=None, services=None):
    return {
        "name": name,
        "is_root": is_root,
        "reachability": {"http_status": status} if status is not None else {},
        "fingerprint": {"tech": [{"name": t} for t in (tech or [])]},
        "services": [{"port": p, "service": s} for p, s in (services or [])],
    }


# ── pick_sub: name-match, is_root fallback, never guess (mirror derive_asset_kind) ─
def test_pick_sub_name_match_wins():
    sd = _surface(_sub("root.example.com", is_root=True),
                  _sub("api.example.com"))
    assert pick_sub(sd, "api.example.com")["name"] == "api.example.com"


def test_pick_sub_falls_back_to_root():
    sd = _surface(_sub("root.example.com", is_root=True), _sub("other.example.com"))
    assert pick_sub(sd, "nomatch.example.com")["is_root"] is True


def test_pick_sub_no_match_no_root_returns_none():
    sd = _surface(_sub("a.example.com"), _sub("b.example.com"))
    assert pick_sub(sd, "z.example.com") is None


# ── schema-version gate = fail-safe None (never misread a foreign shape) ──
def test_unsupported_schema_returns_none():
    sd = {"schema_version": "9.9", "subdomains": [_sub("x.example.com", status=200)]}
    assert extract_signals(sd, "x.example.com") is None


def test_missing_schema_returns_none():
    sd = {"subdomains": [_sub("x.example.com", status=200)]}
    assert extract_signals(sd, "x.example.com") is None


def test_not_a_dict_returns_none():
    assert extract_signals(None, "x") is None
    assert extract_signals("garbage", "x") is None
    assert extract_signals([], "x") is None


def test_no_matching_sub_returns_none():
    sd = _surface(_sub("a.example.com"))
    assert extract_signals(sd, "nomatch.example.com") is None


# ── signal extraction: ports, fingerprint tokens, has_http ───────────────
def test_web_spa_signals():
    sd = _surface(_sub("prosalud.example.com", is_root=True, status=200,
                       tech=["nginx", "React", "unpkg"],
                       services=[(80, "http"), (443, "https")]))
    ports, tokens, has_http = extract_signals(sd, "prosalud.example.com")
    assert ports == [80, 443]
    assert "React" in tokens and "unpkg" in tokens
    assert has_http is True


def test_rdp_host_signals_no_http():
    sd = _surface(_sub("dc.example.com", is_root=True,
                       services=[(3389, "ms-wbt-server")]))
    ports, tokens, has_http = extract_signals(sd, "dc.example.com")
    assert ports == [3389]
    assert tokens == []
    assert has_http is False


def test_has_http_true_when_80_or_443_present_even_without_service_label():
    # A bare 443 with an odd/blank service label must still read as http so it
    # is never mis-emitted as an unmatched-port exposure.
    sd = _surface(_sub("x.example.com", is_root=True, services=[(443, None)]))
    ports, _, has_http = extract_signals(sd, "x.example.com")
    assert ports == [443] and has_http is True


def test_has_http_true_from_status_only():
    sd = _surface(_sub("x.example.com", is_root=True, status=500, services=[]))
    _, _, has_http = extract_signals(sd, "x.example.com")
    assert has_http is True


def test_non_int_ports_are_dropped_not_crashed():
    sub = _sub("x.example.com", is_root=True)
    sub["services"] = [{"port": "eighty"}, {"port": 22, "service": "ssh"}, {"nope": 1}]
    sd = _surface(sub)
    ports, _, _ = extract_signals(sd, "x.example.com")
    assert ports == [22]


def test_missing_subkeys_do_not_crash():
    # A sub with only a name (no reachability/fingerprint/services) → empty
    # signals, no exception.
    sd = _surface({"name": "x.example.com", "is_root": True})
    ports, tokens, has_http = extract_signals(sd, "x.example.com")
    assert ports == [] and tokens == [] and has_http is False


# ── end-to-end contract: surface_data → extract_signals → build_scan_plan ─
def test_e2e_prosalud_shape_is_web_spa_clean():
    sd = _surface(_sub("prosalud.example.com", is_root=True, status=200,
                       tech=["nginx", "react", "unpkg"],
                       services=[(80, "http"), (443, "https")]))
    ports, tokens, has_http = extract_signals(sd, "prosalud.example.com")
    plan = build_scan_plan(M, open_ports=ports, fingerprint_tokens=tokens,
                           has_http=has_http)
    assert plan.scan_profile == ["web-spa"]
    assert plan.exposure_findings == [] and plan.unmatched_ports == []


def test_e2e_rdp_exposure_emitted_by_presence():
    sd = _surface(_sub("dc.example.com", is_root=True,
                       services=[(3389, "ms-wbt-server")]))
    ports, tokens, has_http = extract_signals(sd, "dc.example.com")
    plan = build_scan_plan(M, open_ports=ports, fingerprint_tokens=tokens,
                           has_http=has_http)
    assert [e.check_name for e in plan.exposure_findings] == ["exposure-rdp-3389"]
    assert plan.exposure_findings[0].severity == "HIGH"


def test_e2e_dead_host_with_live_rdp_still_exposes():
    # The silent-narrowing guard, sourced from real discovery shape: a 'dead'
    # host that still has 3389 open MUST still produce the rdp exposure.
    sd = _surface(_sub("ghost.example.com", is_root=True, status=503,
                       services=[(3389, "ms-wbt-server"), (443, "https")]))
    ports, tokens, has_http = extract_signals(sd, "ghost.example.com")
    plan = build_scan_plan(M, open_ports=ports, fingerprint_tokens=tokens,
                           has_http=has_http, kind="dead")
    exp = {e.role for e in plan.exposure_findings}
    assert "rdp" in exp
    assert plan.http_roles == []          # web depth dropped by the dead label


# ── exposure_to_finding: the trust-critical source tag + mapping ─────────
#
# COMMAND, 2026-07-29 (4.7 ruling Q3): these two tests exercise
# `run_medium.exposure_to_finding`, which is part of the PR 2 WIRING and is
# deliberately absent from Command in PR 1 (modules land inert). They are
# skipped here — but the skip is keyed on the FUNCTION EXISTING, not on a
# hand-set flag or a version marker.
#
# That matters. A plain `@pytest.mark.skip("until PR 2")` would have to be
# manually removed, and a skip nobody removes is a permanently disabled test —
# the same "passes by never running" failure mode that produced today's CI
# floors and the soak's empty red-flag check. Keying on the import means the
# moment PR 2 adds exposure_to_finding to Command's run_medium.py, these two
# tests start running by themselves. Nothing to remember, nothing to rot.
#
# On Prodex the function is present, so both tests run there normally and this
# block is a no-op — the file stays byte-identical across instances.
def _wiring_or_skip():
    """Return (exposure_to_finding, MediumFinding), or skip if the wiring is absent."""
    try:
        from run_medium import exposure_to_finding, MediumFinding
    except ImportError:
        pytest.skip("run_medium.exposure_to_finding not present — PR 2 wiring not landed "
                    "on this instance yet; this test self-enables when it is")
    return exposure_to_finding, MediumFinding


def test_exposure_to_finding_carries_isolation_source():
    exposure_to_finding, _MediumFinding = _wiring_or_skip()
    ef = ExposureFinding(port=5432, role="db", severity="CRITICAL",
                         check_name="exposure-db-5432",
                         title="DB exposed", note="open db")
    mf = exposure_to_finding(ef, "asset-123")
    # The whole false-close-isolation guarantee rides on this exact string.
    assert mf.source == "commandsentry_exposure"
    assert mf.category == "info_disclosure"
    assert mf.severity == "CRITICAL"
    assert mf.check_name == "exposure-db-5432"
    assert mf.cwe == [668]
    assert "exposure" in mf.tags and "network" in mf.tags and "db" in mf.tags
    assert "asset-123" in (mf.raw_excerpt or "")
    # 4.7 ruling 1 — lifecycle note present (original ExposureFinding.note
    # preserved + the manual-remediation/P3-auto-close sentence appended).
    assert "open db" in mf.description
    assert "P3 network engine" in mf.description


def test_exposure_finding_id_segment_is_exposure_not_medium():
    # The write path derives an ':exposure:' id segment from source, so the P3
    # network engine re-emits the SAME finding_id (no duplicate row).
    exposure_to_finding, MediumFinding = _wiring_or_skip()
    ef = ExposureFinding(port=3389, role="rdp", severity="HIGH",
                         check_name="exposure-rdp-3389", title="t", note="n")
    mf = exposure_to_finding(ef, "asset-9")
    seg = "exposure" if mf.source == "commandsentry_exposure" else "medium"
    assert f"asset-9:{seg}:{mf.check_name}" == "asset-9:exposure:exposure-rdp-3389"
    # a normal tool finding (source=None) keeps the ':medium:' segment
    normal = MediumFinding(check_name="x", title="t", severity="LOW",
                           category="info_disclosure", description="d")
    seg2 = "exposure" if normal.source == "commandsentry_exposure" else "medium"
    assert seg2 == "medium"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
