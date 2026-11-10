"""The address scan that copies CISA's Cyber Hygiene scanning: the wiring.

Prodex plan 2026-11-10. poll_queue refuses to scan an address on CISA's list unless one
of its names still points at it (the safety rail), and puts 'cisa_mirror' in the
descriptor; run_heavy then sweeps every TCP port with CISA's ping first, keeps one pass
apart from what answers again, and lists CISA's risky services. Every other asset is
untouched: no table, no row, or no descriptor key means the old path, line for line.

    cd scripts/scanner && python3 -m pytest test_cisa_mirror_wiring.py -q
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

import cisa_mirror as cm  # noqa: E402
import poll_queue as PQ  # noqa: E402
import run_heavy as h  # noqa: E402

ADDR = "136.81.173.196"
ROW = {"address": ADDR, "names": ["prod.prodexlabs.com", "trial.prodexlabs.com"], "priority": 0}


def _asset(asset_id):
    keys = ("name organization type kind apex_domain aliases current_risk enforcement_probe_authorized "
            "device_class device_class_confidence vendor_product vendor_product_confidence "
            "is_cloud_endpoint cloud_provider top_hosting_org").split()
    a = {k: None for k in keys}
    a.update({"asset_id": asset_id, "name": asset_id, "organization": "unknown", "type": "ip", "kind": "web",
              "apex_domain": asset_id, "aliases": [], "current_risk": "UNKNOWN"})
    return a

# ── poll_queue: the safety rail ──────────────────────────────────────────────────────

def test_an_asset_not_on_the_list_is_not_touched():
    assert PQ.cisa_mirror_block(None, "prod.prodexlabs.com") == (None, None)


def test_an_address_scans_while_a_name_points_at_it():
    block, why = PQ.cisa_mirror_block(ROW, ADDR, resolve=lambda n: [ADDR] if n == "trial.prodexlabs.com" else ["1.2.3.4"])
    assert why is None
    assert block == {"names": ROW["names"], "pointing": ["trial.prodexlabs.com"], "priority": 0}


def test_no_name_pointing_refuses_and_says_why():
    block, why = PQ.cisa_mirror_block(ROW, ADDR, resolve=lambda n: ["34.1.1.1"])
    assert block is None
    assert ADDR in why and "not scanned" in why and "prod.prodexlabs.com" in why


def test_a_name_that_no_longer_resolves_does_not_count():
    def gone(n):
        raise OSError("NXDOMAIN")
    assert PQ.cisa_mirror_block(ROW, ADDR, resolve=gone)[0] is None


class _Cur:
    def __init__(self, answers):
        self.answers, self.sql = list(answers), []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.sql.append(sql)

    def fetchone(self):
        return self.answers.pop(0)


class _Conn:
    def __init__(self, answers):
        self.cur = _Cur(answers)

    def cursor(self):
        return self.cur


def test_before_the_table_exists_nothing_is_asked_of_it():
    c = _Conn([{"present": False}])
    assert PQ.fetch_cisa_mirror(c, ADDR) is None
    assert len(c.cur.sql) == 1 and "to_regclass('public.cisa_mirror_addresses')" in c.cur.sql[0]


def test_the_row_is_read_when_the_table_exists():
    assert PQ.fetch_cisa_mirror(_Conn([{"present": True}, dict(ROW)]), ADDR) == ROW
    assert PQ.fetch_cisa_mirror(_Conn([{"present": True}, None]), "prod.prodexlabs.com") is None


def test_the_real_refusal_reaches_abort_claim(monkeypatch, capsys):
    calls = []

    class FakeConn:
        def commit(self):
            calls.append("commit")

        def rollback(self):
            pass

        def close(self):
            pass

    class FakePsycopg:
        @staticmethod
        def connect(*a, **k):
            return FakeConn()

    monkeypatch.setattr(PQ, "_import_deps", lambda: (FakePsycopg, None))
    monkeypatch.setattr(PQ, "claim_next_scan", lambda c: {"queue_id": "q1", "asset_id": ADDR, "intensity": "heavy", "authenticated": False})
    monkeypatch.setattr(PQ, "create_scan_run", lambda c, q: "s1")
    monkeypatch.setattr(PQ, "fetch_asset", lambda c, a: {"asset_id": ADDR})
    monkeypatch.setattr(PQ, "fetch_cisa_mirror", lambda c, a: dict(ROW))
    monkeypatch.setattr(cm, "names_pointing_here", lambda a, n, r: [])
    monkeypatch.setattr(PQ, "abort_claim", lambda c, q, err: calls.append(("abort", q, err)))
    assert PQ.run("postgres://x") == 0
    aborts = [c for c in calls if isinstance(c, tuple)]
    assert len(aborts) == 1 and "not scanned" in aborts[0][2]
    assert capsys.readouterr().out == ""


def test_run_puts_the_block_in_the_descriptor_when_a_name_points(monkeypatch, capsys):
    class FakeConn:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    class FakePsycopg:
        @staticmethod
        def connect(*a, **k):
            return FakeConn()

    monkeypatch.setattr(PQ, "_import_deps", lambda: (FakePsycopg, None))
    monkeypatch.setattr(PQ, "claim_next_scan", lambda c: {"queue_id": "q1", "asset_id": ADDR, "intensity": "heavy", "authenticated": False})
    monkeypatch.setattr(PQ, "create_scan_run", lambda c, q: "s1")
    monkeypatch.setattr(PQ, "fetch_asset", lambda c, a: _asset(ADDR))
    monkeypatch.setattr(PQ, "fetch_cisa_mirror", lambda c, a: dict(ROW))
    monkeypatch.setattr(cm, "names_pointing_here", lambda a, n, r: ["prod.prodexlabs.com"])
    assert PQ.run("postgres://x") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["cisa_mirror"]["pointing"] == ["prod.prodexlabs.com"]


def test_an_ordinary_asset_gets_no_block(monkeypatch, capsys):
    class FakeConn:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    class FakePsycopg:
        @staticmethod
        def connect(*a, **k):
            return FakeConn()

    monkeypatch.setattr(PQ, "_import_deps", lambda: (FakePsycopg, None))
    monkeypatch.setattr(PQ, "claim_next_scan", lambda c: {"queue_id": "q1", "asset_id": "prod.prodexlabs.com", "intensity": "heavy", "authenticated": False})
    monkeypatch.setattr(PQ, "create_scan_run", lambda c, q: "s1")
    monkeypatch.setattr(PQ, "fetch_asset", lambda c, a: _asset("prod.prodexlabs.com"))
    monkeypatch.setattr(PQ, "fetch_cisa_mirror", lambda c, a: None)
    assert PQ.run("postgres://x") == 0
    assert "cisa_mirror" not in json.loads(capsys.readouterr().out)


# ── run_heavy: every port, CISA's ping, what answers again ───────────────────────────

def _ctx(mirror=True):
    c = h.HeavyScanContext(
        descriptor={"cisa_mirror": {"names": ROW["names"], "pointing": ["prod.prodexlabs.com"], "priority": 0}} if mirror else {},
        hostname=ADDR, asset_id=ADDR,
        scan_run_id="00000000-0000-0000-0000-000000000001",
        queue_id="00000000-0000-0000-0000-000000000002",
        intensity="heavy",
    )
    c.target_proven_reachable = True
    return c


def _naabu(ports):
    return "\n".join(json.dumps({"host": ADDR, "ip": ADDR, "port": p, "protocol": "tcp"}) for p in ports) + "\n"


@pytest.fixture
def sweep(monkeypatch):
    seen = {"cmds": [], "knocked": []}

    def fake_run_cmd(cmd, timeout=30, **k):
        seen["cmds"].append((cmd, timeout))
        return seen.get("rc", 0), _naabu(seen.get("ports", [80, 443, 3389, 8888])), ""

    def fake_knock_state(host, port, timeout=2):
        seen["knocked"].append(port)
        return seen.get("knock", {443: "open"}).get(port, "silent")   # default: up, like a front door

    monkeypatch.setattr(h, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(h, "_icmp_answers", lambda host: seen.get("icmp", False))
    monkeypatch.setattr(h, "_knock_state", fake_knock_state)
    monkeypatch.setattr(h, "_reconfirm_port", lambda host, port, *a, **k: port != 8888)
    monkeypatch.setattr(h, "_cloud_scope", lambda *a, **k: (_ for _ in ()).throw(AssertionError("cloud gate must not run")))
    return seen


def _artifact(ctx, name):
    got = [json.loads(b) for n, _k, b in ctx.artifacts if n == name]
    assert len(got) == 1
    return got[0]


def test_the_mirror_sweeps_every_port_and_skips_the_cloud_gate(sweep):
    sweep["knock"] = {443: "open"}
    ok, ports = h.run_naabu_phase(_ctx(), None)
    assert ok is True and [p["port"] for p in ports] == [80, 443, 3389]
    cmd, timeout = sweep["cmds"][-1]
    assert cmd == cm.sweep_command(ADDR, h.NAABU_RATE) and timeout == h.CISA_SWEEP_TIMEOUT_S


def test_one_pass_and_what_answered_again_are_both_kept(sweep):
    sweep["knock"] = {443: "open"}
    ctx = _ctx()
    h.run_naabu_phase(ctx, None)
    a = _artifact(ctx, "cisa_mirror")
    assert a["one_pass"] == [80, 443, 3389, 8888]
    assert a["reanswered"] == [80, 443, 3389] and a["phantom"] == [8888]
    assert a["cisa_sees_up"] is True and a["names_pointing"] == ["prod.prodexlabs.com"]
    titles = sorted(f.title for f in ctx.findings)
    assert titles == ["Service inventory: 3389/tcp open", "Service inventory: 443/tcp open", "Service inventory: 80/tcp open"]


def test_the_second_ping_runs_only_when_the_first_gets_nothing(sweep):
    sweep["knock"] = {443: "refused"}
    h.run_naabu_phase(_ctx(), None)
    assert sorted(sweep["knocked"]) == sorted(cm.PING_PORTS_FIRST)
    sweep["knocked"].clear()
    sweep["knock"] = {}
    ctx = _ctx()
    h.run_naabu_phase(ctx, None)
    assert len(sweep["knocked"]) == 1000
    assert _artifact(ctx, "cisa_mirror")["cisa_sees_up"] is False


def test_a_failed_sweep_is_not_credited(sweep):
    sweep["rc"] = 124
    ctx = _ctx()
    assert h.run_naabu_phase(ctx, None) == (False, [])
    assert not ctx.findings
    assert _artifact(ctx, "cisa_mirror")["sweep_rc"] == 124


def test_nothing_answering_again_is_not_credited(sweep, monkeypatch):
    monkeypatch.setattr(h, "_reconfirm_port", lambda *a, **k: False)
    assert h.run_naabu_phase(_ctx(), None) == (False, [])


def test_an_ordinary_asset_still_takes_the_old_path(monkeypatch):
    monkeypatch.setattr(h, "run_cisa_mirror_sweep", lambda ctx: (_ for _ in ()).throw(AssertionError("mirror must not run")))
    hit = {}
    monkeypatch.setattr(h, "_resolve_ips", lambda host: [])
    monkeypatch.setattr(h, "_cloud_scope", lambda a, ips: hit.setdefault("gate", (True, "test")))
    monkeypatch.setattr(h, "_shallow_curated_probe", lambda host: [])
    assert h.run_naabu_phase(_ctx(mirror=False), None) == (False, [])
    assert "gate" in hit


def test_risky_services_follow_the_greeting_then_the_port():
    ctx = _ctx()
    ctx.artifacts.append(("service_greeting", "json", json.dumps([
        {"port": 21, "greeting": "SSH-2.0-OpenSSH_9.6"},
        {"port": 3389, "greeting": None},
    ])))
    n = h.run_cisa_mirror_risky(ctx, [{"port": 21, "proto": "tcp"}, {"port": 3389, "proto": "tcp"},
                                      {"port": 443, "proto": "tcp"}])
    assert n == 1
    f = ctx.findings[-1]
    assert f.port == 3389 and f.severity == "INFO" and f.normalized_key == "cisa-risky-service-rdp-3389-tcp"
    assert "Remote Desktop (RDP)" in f.title and f.source == "commandsentry_heavy"


def test_the_risky_finding_id_is_stable_per_address_and_port():
    a, b = _ctx(), _ctx()
    h.run_cisa_mirror_risky(a, [{"port": 445, "proto": "tcp"}])
    h.run_cisa_mirror_risky(b, [{"port": 445, "proto": "tcp"}])
    assert a.findings[-1].finding_id == b.findings[-1].finding_id


def test_run_calls_the_risky_list_only_for_an_address_on_the_list():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_heavy.py"), encoding="utf-8").read()
    i = src.index("run_greeting_phase(ctx, open_ports)\n            # Prodex plan 2026-11-10")
    assert 'if ctx.descriptor.get("cisa_mirror"):\n                run_cisa_mirror_risky(ctx, open_ports)' in src[i:i + 300]



# ── Kimi addr1 review: MF1 a CISA-down address is not swept; MF2 before the web gate ──

def _naabu_calls(seen):
    return [c for c, _t in seen["cmds"] if c and c[0] == "naabu"]


def test_an_address_cisas_ping_calls_down_is_not_swept(sweep):
    sweep["knock"] = {}                     # nothing answers any of the 1,000 ping ports
    ctx = _ctx()
    ctx.egress_ip_initial = "45.134.140.135"
    assert h.run_naabu_phase(ctx, None) == (False, [])
    assert _naabu_calls(sweep) == [] and not ctx.findings
    a = _artifact(ctx, "cisa_mirror")
    assert a["cisa_sees_up"] is False and a["exit_proven"] is True
    assert a["swept"].startswith("not swept") and a["one_pass"] == []


def test_down_with_no_proof_the_exit_works_is_unknown_not_down(sweep):
    sweep["knock"] = {}
    ctx = _ctx()
    ctx.target_proven_reachable = False
    ctx.egress_ip_initial = None
    assert h.run_naabu_phase(ctx, None) == (False, [])
    a = _artifact(ctx, "cisa_mirror")
    assert a["cisa_sees_up"] is None and a["exit_proven"] is False
    assert _naabu_calls(sweep) == []


def test_the_mirror_runs_before_the_web_gate(sweep):
    # an address with only SSH open: testssl proved nothing, CISA's ping still answers
    sweep["knock"] = {22: "open"}
    sweep["ports"] = [22]
    ctx = _ctx()
    ctx.target_proven_reachable = False
    ok, ports = h.run_naabu_phase(ctx, None)
    assert ok is True and [p["port"] for p in ports] == [22]
    assert len(_naabu_calls(sweep)) == 1


def test_an_ordinary_asset_keeps_the_web_gate():
    ctx = _ctx(mirror=False)
    ctx.target_proven_reachable = False
    assert h.run_naabu_phase(ctx, None) == (False, [])


def test_the_icmp_timestamp_gap_is_said_not_hidden():
    assert "no ICMP\ntimestamp request" in cm.__doc__ or "no ICMP timestamp" in " ".join(cm.__doc__.split())



# ── moved here from test_migration_20261110b.py (2026-11-10 15:2x): a migration's test must pass on
# main plus its own two files; the scanner code it checks lands with this push, not with the migration.

def test_the_scanner_reads_the_columns_the_migration_creates():
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    sql = open(os.path.join(here, "..", "db", "migrations", "20261110b_cisa_mirror_addresses.sql"), encoding="utf-8").read()
    pq = open(os.path.join(here, "poll_queue.py"), encoding="utf-8").read()
    assert "select address, names, priority\n  from public.cisa_mirror_addresses" in pq
    assert "to_regclass('public.cisa_mirror_addresses')" in pq
    for col in ("address", "names", "priority", "next_scan_at", "last_counted_scan_run"):
        assert re.search(rf"^\s+{col}\s", sql, re.M), col
