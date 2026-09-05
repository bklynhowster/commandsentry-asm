"""Tests for the shared ASM-surface diff (Obsidian 225, 4.7 Option B).

The load-bearing test is test_first_write_emits_only_first_seen_no_false_close +
test_cross_producer_diff_WOULD_false_close_documents_danger: together they pin 4.7's Q6
guard — a producer's FIRST surface write (prior None) emits asset_first_seen and NO
port_closed, and diffing a thin scanner blob against a fuller ASM baseline WOULD false-close
(so the scanner must never be handed the ASM baseline; it diffs against its own prior).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from surface_diff import (  # noqa: E402
    build_scanner_surface_blob,
    compute_events,
    flatten_services,
)


def _asm_blob(ports, host="www.prodexlabs.com", naabu_ok=True):
    """An asm-discover-shaped baseline blob (top-level subdomains[].services[])."""
    return {"subdomains": [{
        "name": host,
        "probe_status": {"naabu": {"ok": naabu_ok}},
        "services": [{"port": p, "protocol": "tcp"} for p in ports],
    }]}


def test_scanner_blob_shape_flattens():
    b = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    m = flatten_services(b)
    assert {k[1] for k in m} == {80, 443}
    assert all(k[0] == "www.prodexlabs.com" for k in m)
    assert b["coverage"] == "partial" and b["source"] == "scanner_light"


def test_first_write_emits_only_first_seen_no_false_close():
    # THE guard (4.7 Q6): prior None → exactly one asset_first_seen, NO port_closed, even
    # though the blob carries ports. This is what makes the scanner's first write on an
    # already-discovered asset safe (fleet-wide false-close storm prevented).
    b = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    ev = compute_events("www.prodexlabs.com", None, b, "scanner_light")
    assert [e["event_type"] for e in ev] == ["asset_first_seen"], ev


def test_cross_producer_diff_WOULD_false_close_documents_danger():
    # If the scanner diffed against asm-discover's FULLER baseline, it would emit false
    # port_closed for 22 + 8080 (ports the thin light scan never scanned). This documents WHY
    # per-producer baselines are mandatory — the caller must NEVER pass the asm baseline here.
    asm = _asm_blob([80, 443, 22, 8080])
    light = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    ev = compute_events("www.prodexlabs.com", asm, light, "scanner_light")
    closed = sorted(e["port"] for e in ev if e["event_type"] == "port_closed")
    assert closed == [22, 8080], f"danger must be real (proves the guard's necessity): {closed}"


def test_scanner_vs_own_prior_no_false_close():
    # Diffing against the scanner's OWN prior (same coverage) → no spurious events.
    p1 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    p2 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    assert compute_events("www.prodexlabs.com", p1, p2, "scanner_light") == []


def test_scanner_naabu_failed_suppresses_close():
    # J5a fail-closed: naabu failed this scan → a "missing" port must NOT close (carry forward).
    p1 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    p2 = build_scanner_surface_blob("www.prodexlabs.com", [80], False, "partial", "scanner_light")
    assert compute_events("www.prodexlabs.com", p1, p2, "scanner_light") == []


def test_scanner_real_close_when_naabu_ok():
    p1 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    p2 = build_scanner_surface_blob("www.prodexlabs.com", [80], True, "partial", "scanner_light")
    ev = compute_events("www.prodexlabs.com", p1, p2, "scanner_light")
    assert len(ev) == 1 and ev[0]["event_type"] == "port_closed" and ev[0]["port"] == 443, ev


def test_scanner_real_open():
    p1 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    p2 = build_scanner_surface_blob("www.prodexlabs.com", [80, 443, 8443], True, "partial", "scanner_light")
    ev = compute_events("www.prodexlabs.com", p1, p2, "scanner_light")
    assert len(ev) == 1 and ev[0]["event_type"] == "port_opened" and ev[0]["port"] == 8443, ev
