from __future__ import annotations
import json
from pathlib import Path
import run_heavy as h

ADDR = "136.81.173.196"


def _ctx(mirror=False):
    c = h.HeavyScanContext(descriptor={"cisa_mirror": {"pointing": []}} if mirror else {},
                           hostname="prod.prodexlabs.com", asset_id="asset-1", scan_run_id="scan-1",
                           queue_id="queue-1", intensity="heavy", target_proven_reachable=True)
    return c


def _proof(complete=True):
    return {"one_pass": [22], "attempted": [22], "proof_overflow": [] if complete else [9000],
            "reanswered": [22], "proven": [22], "unproven": [], "control_ports_open": [],
            "accept_all_controls": False, "proof_complete": complete, "budget_exhausted": False,
            "max_proof_ports": 12, "proof_budget_s": 90,
            "results": [{"port": 22, "status": "proven", "kind": "ssh", "fingerprint": "hash"}]}


def _wire(monkeypatch, complete=True):
    calls = []
    monkeypatch.setattr(h.pf, "authorized_address", lambda host: ADDR)
    monkeypatch.setattr(h, "run_cmd", lambda cmd, timeout=30: (calls.append(cmd) or
                          (0, json.dumps({"port": 22, "protocol": "tcp"}) + "\n", "")))
    monkeypatch.setattr(h.pf, "prove_ports", lambda *a, **k: _proof(complete))
    return calls


def test_every_scoped_heavy_uses_full_sweep_and_application_params(monkeypatch):
    calls = _wire(monkeypatch)
    ok, ports = h.run_naabu_phase(_ctx(), None)
    assert ok is True and [p["port"] for p in ports] == [22]
    assert calls[0][calls[0].index("-p") + 1] == "-" and "-top-ports" not in calls[0]
    ctx = _ctx()
    h.run_naabu_phase(ctx, None)
    assert ctx.findings[0].params["port_sweep"] == "prodex_all_tcp"
    assert ctx.findings[0].params["application_proof"] == "ssh"
    assert ctx.findings[0].severity == "INFO"


def test_overflow_records_finding_but_never_credits_autoclose(monkeypatch):
    _wire(monkeypatch, complete=False)
    ctx = _ctx()
    ok, ports = h.run_naabu_phase(ctx, None)
    assert ok is False and [p["port"] for p in ports] == [22]
    assert len(ctx.findings) == 1
    artifact = [json.loads(b) for n, _k, b in ctx.artifacts if n == "prodex_full_ports"][0]
    assert artifact["proof_overflow"] == [9000] and artifact["proof_complete"] is False


def test_cisa_descriptor_keeps_precedence(monkeypatch):
    monkeypatch.setattr(h, "run_cisa_mirror_sweep", lambda ctx: (True, [{"port": 1, "proto": "tcp"}]))
    monkeypatch.setattr(h.pf, "authorized_address", lambda host: (_ for _ in ()).throw(AssertionError("scope path ran")))
    assert h.run_naabu_phase(_ctx(mirror=True), None)[0] is True


def test_unscoped_name_keeps_old_web_gate(monkeypatch):
    monkeypatch.setattr(h.pf, "authorized_address", lambda host: None)
    ctx = _ctx()
    ctx.target_proven_reachable = False
    ctx.egress_ip_initial = None
    assert h.run_naabu_phase(ctx, None) == (False, [])


def test_scope_file_is_prodex_only():
    scope = h.pf.load_scope()
    repo = Path(__file__).resolve().parents[2].name
    if repo == "prodexsentry-asm":
        assert len(scope) == 17 and scope["52.244.87.51"]["names"] == ["gov.prodexlabs.com"]
        assert scope["34.67.20.186"]["reserved"] is False
        for address in ("150.171.110.18", "66.33.60.130", "76.76.21.61",
                        "97.107.135.178", "170.187.131.209", "185.3.93.228"):
            assert scope[address]["reserved"] is False and scope[address]["dynamic"] is True
    else:
        assert scope == {}
