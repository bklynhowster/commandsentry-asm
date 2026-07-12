"""
test_heavy_netdepth.py — unit tests for Heavy Phase 1 net depth
(naabu port discovery + fingerprintx service ID) in run_heavy.py.

Spec: HEAVY_PHASE1_NETDEPTH_SPEC v2 + HEAVY_PHASE1_BUILD_DELTA (4.7 D1–D5).

Coverage:
  parsers      _parse_naabu_ports / _parse_fingerprintx — line-JSON, blank
               and garbage lines, non-int ports, proto defaults, service
               fallback.
  four-gate    run_naabu_phase / run_fingerprintx_phase — the conservative
               reachable-AND-rc0-AND-nonempty gate. The safety hinge: a
               degraded net tool returns ok=False so run()'s all-or-nothing
               pairing credits NEITHER tool in tools_run → the note-127
               autocloser can't false-close the other tool's
               commandsentry_heavy findings (4.7 D1). Absence-of-evidence
               (rc0 + zero ports) is NOT credited (4.7 Q5).
  identity     4.7 D4 — the service is EXCLUDED from finding_id (title only),
               so a fingerprintx service flap re-observes rather than churns.

Run with:
  cd scripts/scanner && python3 -m pytest test_heavy_netdepth.py -v
  (or plain `python3 test_heavy_netdepth.py` — main() runs the same paths
   without pytest, matching test_run_heavy.py's convention.)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import run_heavy
from run_heavy import (
    HeavyScanContext,
    _parse_fingerprintx,
    _parse_naabu_ports,
    run_fingerprintx_phase,
    run_naabu_phase,
)

_DUMMY_WORK_DIR = Path("/tmp")


def _mk_ctx(reachable: bool = True) -> HeavyScanContext:
    """Minimal heavy ctx for the net-depth phases (they read hostname,
    asset_id, scan_run_id, target_proven_reachable; append to findings /
    artifacts)."""
    return HeavyScanContext(
        descriptor={},
        hostname="demo.example.com",
        asset_id="asset-123",
        scan_run_id="scan-abc",
        queue_id="q-1",
        intensity="heavy",
        target_proven_reachable=reachable,
    )


class _StubCmd:
    """Swap run_heavy.run_cmd for a canned (rc, stdout, stderr); record the
    call so a test can assert the tool was (or was NOT) invoked."""

    def __init__(self, rc: int, stdout: str, stderr: str = ""):
        self._ret = (rc, stdout, stderr)
        self.calls: list = []
        self._orig = None

    def __enter__(self):
        self._orig = run_heavy.run_cmd

        def fake(cmd, timeout=30, input_str=None, env_extra=None):
            self.calls.append({"cmd": cmd, "input_str": input_str})
            return self._ret

        run_heavy.run_cmd = fake
        return self

    def __exit__(self, *exc):
        run_heavy.run_cmd = self._orig
        return False


# ─── _parse_naabu_ports ─────────────────────────────────────────────────

def test_parse_naabu_basic():
    stdout = (
        json.dumps({"host": "h", "ip": "1.2.3.4", "port": 22, "protocol": "tcp"}) + "\n"
        + json.dumps({"host": "h", "ip": "1.2.3.4", "port": 443, "protocol": "tcp"}) + "\n"
    )
    ports = _parse_naabu_ports(stdout)
    assert [p["port"] for p in ports] == [22, 443], ports
    assert all(p["proto"] == "tcp" for p in ports), ports
    assert ports[0]["ip"] == "1.2.3.4", ports


def test_parse_naabu_skips_blank_and_garbage():
    stdout = "\n" + "not json at all\n" + json.dumps({"port": 80, "protocol": "tcp"}) + "\n   \n"
    ports = _parse_naabu_ports(stdout)
    assert [p["port"] for p in ports] == [80], ports


def test_parse_naabu_skips_non_int_port():
    stdout = (
        json.dumps({"port": None, "protocol": "tcp"}) + "\n"
        + json.dumps({"protocol": "tcp"}) + "\n"          # no port key
        + json.dumps({"port": "22", "protocol": "tcp"}) + "\n"  # string, not int
    )
    assert _parse_naabu_ports(stdout) == [], "non-int ports must be dropped"


def test_parse_naabu_default_proto_tcp():
    stdout = json.dumps({"port": 8080}) + "\n"   # no protocol field
    ports = _parse_naabu_ports(stdout)
    assert ports[0]["proto"] == "tcp", ports


# ─── _parse_fingerprintx ────────────────────────────────────────────────

def test_parse_fpx_basic():
    stdout = (
        json.dumps({"host": "h", "port": 22, "transport": "tcp", "protocol": "ssh"}) + "\n"
        + json.dumps({"host": "h", "port": 3306, "transport": "tcp", "protocol": "mysql"}) + "\n"
    )
    svc = _parse_fingerprintx(stdout)
    assert svc[(22, "tcp")] == "ssh", svc
    assert svc[(3306, "tcp")] == "mysql", svc


def test_parse_fpx_service_fallback_and_unknown():
    stdout = (
        json.dumps({"port": 25, "transport": "tcp", "service": "smtp"}) + "\n"  # 'service' fallback
        + json.dumps({"port": 9999, "transport": "tcp"}) + "\n"                 # neither → unknown
    )
    svc = _parse_fingerprintx(stdout)
    assert svc[(25, "tcp")] == "smtp", svc
    assert svc[(9999, "tcp")] == "unknown", svc


def test_parse_fpx_skips_garbage():
    stdout = "junk\n\n" + json.dumps({"port": 22, "transport": "tcp", "protocol": "ssh"}) + "\n"
    svc = _parse_fingerprintx(stdout)
    assert svc == {(22, "tcp"): "ssh"}, svc


# ─── run_naabu_phase — four-gate ────────────────────────────────────────

def test_naabu_not_reachable_returns_false_no_probe():
    """No testssl reachability proof → skip before firing naabu. The egress
    guard: don't scan-blind over the tunnel, and don't credit."""
    ctx = _mk_ctx(reachable=False)
    with _StubCmd(0, json.dumps({"port": 22, "protocol": "tcp"})) as stub:
        ok, ports = run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    assert ok is False and ports == [], (ok, ports)
    assert stub.calls == [], "naabu must NOT run when unreachable"
    assert ctx.findings == []


def test_naabu_rc_nonzero_returns_false():
    ctx = _mk_ctx()
    with _StubCmd(1, "", "boom"):
        ok, ports = run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    assert ok is False and ports == [], (ok, ports)
    assert ctx.findings == [], "degraded naabu must emit no findings"


def test_naabu_rc0_empty_ports_returns_false():
    """rc0 but zero open ports = absence-of-evidence, NOT evidence-of-absence
    (4.7 Q5). Not credited → autocloser can't false-close prior port findings."""
    ctx = _mk_ctx()
    with _StubCmd(0, "\n   \n"):
        ok, ports = run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    assert ok is False and ports == [], (ok, ports)
    assert ctx.findings == []


def test_naabu_rc0_with_ports_returns_true_and_emits_findings():
    ctx = _mk_ctx()
    stdout = (
        json.dumps({"port": 22, "protocol": "tcp"}) + "\n"
        + json.dumps({"port": 443, "protocol": "tcp"}) + "\n"
    )
    with _StubCmd(0, stdout):
        ok, ports = run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    assert ok is True, (ok, ports)
    assert [p["port"] for p in ports] == [22, 443]
    assert len(ctx.findings) == 2
    ev = ctx.findings[0]
    assert ev.source == "commandsentry_heavy", ev.source     # NOT 'naabu' (not a source enum)
    assert ev.severity == "INFO"
    assert "open" in ev.title
    assert ev.port == 22 and ev.protocol == "tcp"
    # artifact captured for the writer
    assert ctx.artifacts and ctx.artifacts[0][0] == "naabu"


def test_naabu_does_not_self_credit_tools_run():
    """Phase functions must NOT touch tools_run — run()'s pairing owns the
    all-or-nothing credit (4.7 D1). If a phase self-credited, a partial scan
    could false-close."""
    ctx = _mk_ctx()
    with _StubCmd(0, json.dumps({"port": 22, "protocol": "tcp"}) + "\n"):
        run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    assert ctx.tools_run == [], "naabu phase must not append to tools_run"
    assert ctx.tool_status == {}, "naabu phase must not touch tool_status"


# ─── run_fingerprintx_phase — four-gate + skip-list ─────────────────────

def test_fpx_skips_80_443_no_probe_returns_true():
    """Only 80/443 open → nothing eligible after the WAF-L7 skip; return ok
    (vacuously true) without firing fingerprintx (4.7 D5)."""
    ctx = _mk_ctx()
    open_ports = [{"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"}]
    with _StubCmd(0, "should-not-be-used") as stub:
        ok = run_fingerprintx_phase(ctx, _DUMMY_WORK_DIR, open_ports)
    assert ok is True, ok
    assert stub.calls == [], "fingerprintx must not run when all ports skipped"
    assert ctx.findings == []


def test_fpx_rc_nonzero_returns_false():
    ctx = _mk_ctx()
    open_ports = [{"port": 22, "proto": "tcp"}]
    with _StubCmd(1, "", "err"):
        ok = run_fingerprintx_phase(ctx, _DUMMY_WORK_DIR, open_ports)
    assert ok is False, ok
    assert ctx.findings == []


def test_fpx_empty_stdout_returns_false():
    ctx = _mk_ctx()
    open_ports = [{"port": 22, "proto": "tcp"}]
    with _StubCmd(0, "   \n"):
        ok = run_fingerprintx_phase(ctx, _DUMMY_WORK_DIR, open_ports)
    assert ok is False, "rc0 + empty output is degraded, not credited"
    assert ctx.findings == []


def test_fpx_rc0_with_services_true_and_service_in_title():
    ctx = _mk_ctx()
    open_ports = [{"port": 22, "proto": "tcp"}]
    with _StubCmd(0, json.dumps({"port": 22, "transport": "tcp", "protocol": "ssh"}) + "\n") as stub:
        ok = run_fingerprintx_phase(ctx, _DUMMY_WORK_DIR, open_ports)
    assert ok is True
    # 80/443 excluded from the stdin target list
    assert "demo.example.com:22" in stub.calls[0]["input_str"]
    assert len(ctx.findings) == 1
    ev = ctx.findings[0]
    assert ev.source == "commandsentry_heavy"
    assert "ssh" in ev.title, "service belongs in the (mutable) title"


# ─── 4.7 D4 identity — service EXCLUDED from finding_id ─────────────────

def test_fpx_identity_excludes_service_flap():
    """THE D4 guarantee. Same port, two different services across two scans →
    IDENTICAL finding_id (stable per port), DIFFERENT title. A fingerprintx
    flap re-observes; it does NOT churn the finding (which would eventually
    feed the went-dark lifecycle a false close)."""
    open_ports = [{"port": 22, "proto": "tcp"}]

    ctx1 = _mk_ctx()
    with _StubCmd(0, json.dumps({"port": 22, "transport": "tcp", "protocol": "ssh"}) + "\n"):
        run_fingerprintx_phase(ctx1, _DUMMY_WORK_DIR, open_ports)

    ctx2 = _mk_ctx()
    with _StubCmd(0, json.dumps({"port": 22, "transport": "tcp", "protocol": "http"}) + "\n"):
        run_fingerprintx_phase(ctx2, _DUMMY_WORK_DIR, open_ports)

    id1, id2 = ctx1.findings[0].finding_id, ctx2.findings[0].finding_id
    assert id1 == id2, f"service flap must NOT churn finding_id: {id1} != {id2}"
    assert ctx1.findings[0].title != ctx2.findings[0].title, "title should reflect the service"


def test_naabu_and_fpx_same_port_distinct_finding_ids():
    """Existence (naabu) and service (fingerprintx) are two findings per port
    → distinct finding_ids, so they roll up separately."""
    ctx = _mk_ctx()
    with _StubCmd(0, json.dumps({"port": 22, "protocol": "tcp"}) + "\n"):
        _, ports = run_naabu_phase(ctx, _DUMMY_WORK_DIR)
    naabu_id = ctx.findings[0].finding_id

    ctx2 = _mk_ctx()
    with _StubCmd(0, json.dumps({"port": 22, "transport": "tcp", "protocol": "ssh"}) + "\n"):
        run_fingerprintx_phase(ctx2, _DUMMY_WORK_DIR, [{"port": 22, "proto": "tcp"}])
    fpx_id = ctx2.findings[0].finding_id

    assert naabu_id != fpx_id, "existence and service findings must be distinct"


def test_naabu_identity_stable_across_runs():
    """Same asset + port + proto → identical finding_id run-to-run (stable
    re-observation, no churn)."""
    ids = []
    for _ in range(2):
        ctx = _mk_ctx()
        with _StubCmd(0, json.dumps({"port": 443, "protocol": "tcp"}) + "\n"):
            run_naabu_phase(ctx, _DUMMY_WORK_DIR)
        ids.append(ctx.findings[0].finding_id)
    assert ids[0] == ids[1], f"naabu finding_id not stable: {ids}"


# ─── Test driver — bare-Python fallback (mirrors test_run_heavy.py) ─────

def _all_tests():
    return [v for k, v in globals().items() if k.startswith("test_") and callable(v)]


def main() -> int:
    tests = _all_tests()
    failed: list[tuple[str, str]] = []
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed.append((t.__name__, str(e)))
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            failed.append((t.__name__, f"{type(e).__name__}: {e}"))
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"{len(tests) - len(failed)} / {len(tests)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
