from __future__ import annotations
import prodex_full_ports as pf
import prodex_port_backstop as backstop

ADDR = "136.81.173.196"
SCOPE = {ADDR: {"address": ADDR, "names": ["prod.prodexlabs.com", "demo.prodexlabs.com"], "reserved": True}}


def test_scope_requires_expected_name_and_current_address():
    assert pf.authorized_address("prod.prodexlabs.com", scope=SCOPE, resolver=lambda h: [ADDR]) == ADDR
    assert pf.authorized_address("prod.prodexlabs.com", scope=SCOPE, resolver=lambda h: ["203.0.113.9"]) is None
    assert pf.authorized_address("ph-test.prodexlabs.com", scope=SCOPE, resolver=lambda h: [ADDR]) is None


def test_absent_scope_is_fail_closed(tmp_path):
    assert pf.load_scope(tmp_path / "absent.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert pf.load_scope(bad) == {}


def test_sweep_covers_every_tcp_port():
    cmd = pf.sweep_command("prod.prodexlabs.com", 250)
    assert cmd[cmd.index("-p") + 1] == "-"
    assert "-top-ports" not in cmd and "CONNECT" in cmd


def _probe(host, port, named):
    if port == 22:
        return {"kind": "ssh", "fingerprint": "real-ssh", "default_fingerprint": "lb-default"}
    if port == 443:
        return {"kind": "https", "fingerprint": "real-cert", "default_fingerprint": "lb-default"}
    return {"kind": "https", "fingerprint": "lb-default", "default_fingerprint": "lb-default"}


def test_application_proof_accepts_real_and_rejects_default_and_phantom():
    result = pf.prove_ports("prod.prodexlabs.com", [22, 443, 8080, 9000], "scan-a",
                            reconfirm=lambda h, p: p != 9000, probe=_probe)
    assert result["proven"] == [22, 443]
    assert result["proof_complete"] is True
    states = {r["port"]: r["status"] for r in result["results"]}
    assert states[8080] == "default_response" and states[9000] == "phantom"


def test_control_default_is_not_application_proof():
    result = pf.prove_ports("prod.prodexlabs.com", [8443], "scan-a",
                            reconfirm=lambda h, p: True, probe=_probe)
    assert result["proven"] == [] and result["accept_all_controls"] is True
    assert result["results"][0]["status"] == "default_response"


def test_cap_overflow_is_recorded_and_incomplete_even_with_proven_ports():
    result = pf.prove_ports("prod.prodexlabs.com", list(range(1000, 1013)), "scan-a",
                            reconfirm=lambda h, p: True,
                            probe=lambda h, p, named: {"kind": "x", "fingerprint": f"real-{p}"})
    assert len(result["proven"]) == pf.MAX_PROOF_PORTS
    assert len(result["proof_overflow"]) == 1 and result["proof_complete"] is False


def test_budget_overflow_is_recorded_and_incomplete():
    ticks = iter([0, 0, 100, 100, 100, 100])
    result = pf.prove_ports("prod.prodexlabs.com", [22], "scan-a", clock=lambda: next(ticks),
                            reconfirm=lambda h, p: True, probe=_probe)
    assert result["budget_exhausted"] is True and result["proof_complete"] is False
    assert result["proof_overflow"] == [22]


def test_rotation_is_stable_and_changes_with_scan_id():
    ports = list(range(1000, 1020))
    assert pf.candidate_order(ports, "same") == pf.candidate_order(ports, "same")
    assert pf.candidate_order(ports, "one") != pf.candidate_order(ports, "two")


def test_backstop_groups_names_by_address_and_skips_recent_and_active():
    assets = [{"asset_id": "1", "name": "demo.prodexlabs.com"},
              {"asset_id": "2", "name": "prod.prodexlabs.com"},
              {"asset_id": "3", "name": "ph-test.prodexlabs.com"}]
    selected = backstop.choose(assets, recent={"prod.prodexlabs.com"}, active=set(),
                               scope=SCOPE, resolver=lambda h: [ADDR])
    assert selected == []
    selected = backstop.choose(assets, recent=set(), active={"demo.prodexlabs.com"},
                               scope=SCOPE, resolver=lambda h: [ADDR])
    assert [r["name"] for r in selected] == ["prod.prodexlabs.com"]
    assert all(r["asset_id"] != "3" and r["name"] != ADDR for r in selected)


def test_dynamic_scope_follows_current_dns_but_static_scope_refuses():
    dynamic = {"203.0.113.1": {"names": ["docs.prodexlabs.com"], "dynamic": True}}
    assert pf.authorized_address("docs.prodexlabs.com", scope=dynamic,
                                 resolver=lambda h: ["203.0.113.9"]) == "203.0.113.9"
    assert pf.authorized_address("docs.prodexlabs.com", scope=dynamic, resolver=lambda h: []) is None
    assert pf.authorized_address("prod.prodexlabs.com", scope=SCOPE,
                                 resolver=lambda h: ["203.0.113.9"]) is None


def test_backstop_never_selects_unscoped_name():
    assets = [{"asset_id": "3", "name": "ph-test.prodexlabs.com"}]
    assert backstop.choose(assets, set(), set(), scope=SCOPE, resolver=lambda h: [ADDR]) == []


def test_backstop_stops_at_five_addresses():
    scope = {}
    assets = []
    addresses = []
    for i in range(7):
        address = f"203.0.113.{i + 1}"
        name = f"n{i}.prodexlabs.com"
        addresses.append(address)
        scope[address] = {"address": address, "names": [name]}
        assets.append({"asset_id": str(i), "name": name})
    selected = backstop.choose(assets, set(), set(), scope=scope, resolver=lambda h: addresses)
    assert len(selected) == 5


def test_backstop_dry_run_rolls_back_and_writes_nothing():
    class Cursor:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def execute(self, sql, params=None): self.conn.calls.append((sql, params))
        def fetchall(self): return self.conn.rows.pop(0)
    class Conn:
        def __init__(self): self.calls, self.rows, self.rolled_back = [], [[], [], []], False
        def cursor(self): return Cursor(self)
        def rollback(self): self.rolled_back = True
        def commit(self): raise AssertionError("dry run must not commit")
    conn = Conn()
    assert backstop.run(conn, scope=SCOPE, resolver=lambda h: [ADDR], dry_run=True, log=lambda s: None) == []
    assert conn.rolled_back is True
    assert all("insert into" not in call[0].lower() for call in conn.calls)


def test_command_backstop_exits_before_needing_a_dsn(monkeypatch, tmp_path):
    monkeypatch.setattr(backstop.pf, "SCOPE_PATH", tmp_path / "absent.json")
    monkeypatch.delenv("SUPABASE_DSN", raising=False)
    assert backstop.main([]) == 0
