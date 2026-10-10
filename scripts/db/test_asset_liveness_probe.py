"""Tests for the liveness probe worker's pure cores (Obsidian 161 step 2).

probe_asset is exercised with the network primitives (resolve_host/probe_port) monkeypatched, so
no sockets are opened. sweep_ok is the 4.7-Q7 egress fail-safe.
"""
import asset_liveness_probe as w


# ── sweep-health egress fail-safe (4.7 Q7) ────────────────────────────────────────
def test_sweep_ok_aborts_when_fleet_mostly_silent():
    verdicts = [{"any_port_responded": False}] * 95 + [{"any_port_responded": True}] * 5
    ok, reason = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is False and "egress" in reason               # 5% < 10% floor -> our egress, abort


def test_sweep_ok_passes_with_healthy_response_rate():
    verdicts = [{"any_port_responded": True}] * 20 + [{"any_port_responded": False}] * 80
    ok, reason = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is True and "20/100" in reason


def test_sweep_ok_small_fleet_has_no_floor():
    # a tiny fleet can legitimately be mostly quiet — never abort on it
    ok, reason = w.sweep_ok([{"any_port_responded": False}] * 4, fleet_size=4)
    assert ok is True and "small_fleet" in reason


def test_sweep_ok_none_verdicts_dont_count_as_responded():
    # skipped assets (resolver hiccup -> None) must not inflate the responded fraction
    verdicts = [None] * 95 + [{"any_port_responded": True}] * 5
    ok, _ = w.sweep_ok(verdicts, fleet_size=100)
    assert ok is False


# ── probe_asset (primitives patched) ──────────────────────────────────────────────
def test_probe_asset_nxdomain_is_not_responded(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: (None, "nxdomain"))
    v = w.probe_asset("gone.example.com", [443, 80, 22])
    assert v == {"any_port_responded": False, "any_port_open": False,
                 "per_port_results": {"_dns": "nxdomain"}}


def test_probe_asset_resolver_hiccup_skips(monkeypatch):
    # EAI_AGAIN etc. -> inconclusive -> None (don't record a wrong verdict)
    monkeypatch.setattr(w, "resolve_host", lambda h: (None, "inconclusive"))
    assert w.probe_asset("flaky.example.com", [443]) is None


def test_probe_asset_rst_only_responded_not_open(monkeypatch):
    # the ftp.unimacgraphics.com shape: host answers with RST on every probed port
    monkeypatch.setattr(w, "resolve_host", lambda h: ("208.199.0.160", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "refused")
    v = w.probe_asset("ftp.unimacgraphics.com", [22, 443, 990, 21])
    assert v["any_port_responded"] is True                  # host answered -> digest SUPPRESSES
    assert v["any_port_open"] is False                      # no open service -> demotion may act
    assert set(v["per_port_results"]) == {"22", "443", "990", "21"}


def test_probe_asset_open_service_is_open(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: ("1.2.3.4", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "open" if p == 443 else "noresponse")
    v = w.probe_asset("web.example.com", [443, 80])
    assert v["any_port_responded"] is True and v["any_port_open"] is True


def test_probe_asset_all_timeout_is_dark(monkeypatch):
    monkeypatch.setattr(w, "resolve_host", lambda h: ("1.2.3.4", "ok"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "noresponse")
    v = w.probe_asset("dead.example.com", [443, 80, 22])
    assert v["any_port_responded"] is False and v["any_port_open"] is False   # genuinely dark


# ── Note 307 (2026-10-10) — the VPN re-check of hosts the direct sweep could not reach ─────────
def test_recheck_targets_are_only_the_hosts_whose_latest_check_was_quiet():
    latest = [("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False),
              ("pm.unimacgraphics.com", False), ("ftp.commandmi.com", False),
              ("portal.unimacgraphics.com", True)]
    quiet, controls, dropped = w.split_recheck_targets(latest)
    assert quiet == ["ftp.commandmi.com", "ftp.unimacgraphics.com", "pm.unimacgraphics.com"]
    assert controls == ["portal.unimacgraphics.com", "www.unimacgraphics.com"]
    assert dropped == 0


def test_recheck_is_capped_and_says_how_many_it_dropped():
    latest = [(f"h{i:02d}.example", False) for i in range(30)] + [("ok.example", True)]
    quiet, controls, dropped = w.split_recheck_targets(latest, max_targets=25, n_controls=3)
    assert len(quiet) == 25 and dropped == 5
    assert quiet[0] == "h00.example"                         # sorted -> reproducible
    assert controls == ["ok.example"]


def test_controls_are_capped():
    latest = [(f"ok{i}.example", True) for i in range(9)] + [("q.example", False)]
    _, controls, _ = w.split_recheck_targets(latest, n_controls=3)
    assert controls == ["ok0.example", "ok1.example", "ok2.example"]


def test_tunnel_is_proved_only_by_a_control_that_answered():
    assert w.tunnel_ok([{"any_port_responded": True}, {"any_port_responded": False}])[0] is True
    ok, why = w.tunnel_ok([{"any_port_responded": False}, None])
    assert ok is False and "tunnel broken" in why
    ok, why = w.tunnel_ok([])
    assert ok is False and "no control" in why


def _routes(default_dev, route_dev):
    out = {("route", "show", "default", "table", "main"): f"default via 10.1.0.1 dev {default_dev} proto dhcp\n",
           ("route", "get", "1.1.1.1"): f"1.1.1.1 dev {route_dev} table 51820 src 10.64.0.2 uid 0\n"}
    return lambda args: out[tuple(args[1:])]


TUNNEL = _routes("eth0", "us-chi-wg-201")


class _Cur:
    def __init__(self, rows, log):
        self.rows, self.log = rows, log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.log.append((sql, params))

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, rows):
        # the production query returns (asset_id, latest_answered, last_answered_at)
        self.rows = [tuple(r) + (None,) * (3 - len(r)) for r in rows]
        self.sql, self.commits = [], 0

    def cursor(self):
        return _Cur(self.rows, self.sql)

    def commit(self):
        self.commits += 1


def _wire(monkeypatch, answers):
    """answers: host -> port result for every port; the network primitives are patched."""
    monkeypatch.setattr(w, "known_ports", lambda conn, a: [443])
    monkeypatch.setattr(w, "resolve_host", lambda h: ("192.0.2.1", "ok") if h in answers else (None, "nxdomain"))
    monkeypatch.setattr(w, "probe_port", lambda ip, p, **k: "noresponse")
    calls = []

    def probe_asset(a, ports):
        calls.append(a)
        r = answers.get(a, "noresponse")
        return {"any_port_responded": r in ("open", "refused"), "any_port_open": r == "open",
                "per_port_results": {str(p): {"result": r} for p in ports}}
    monkeypatch.setattr(w, "probe_asset", probe_asset)
    written = []
    monkeypatch.setattr(w, "write_verdict", lambda conn, a, sid, v, src: written.append((a, v["any_port_responded"], src)))
    return calls, written


def test_recheck_writes_vpn_verdicts_for_the_quiet_hosts_when_the_tunnel_is_proved(monkeypatch):
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False),
                  ("pm.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open",
                                         "ftp.unimacgraphics.com": "open",
                                         "pm.unimacgraphics.com": "noresponse"})
    n = w.run_recheck(conn, dry_run=False, sweep_id="00000000-0000-0000-0000-000000000307",
                      source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=TUNNEL)
    assert n == 2
    assert calls[0] == "www.unimacgraphics.com"              # the control is probed FIRST
    assert sorted(written) == [("ftp.unimacgraphics.com", True, "liveness_vpn"),
                               ("pm.unimacgraphics.com", False, "liveness_vpn")]
    assert ("www.unimacgraphics.com", True, "liveness_vpn") not in written   # controls are not re-written
    assert conn.commits == 2                                 # one per host: a timeout keeps what's done


def test_a_broken_tunnel_writes_nothing(monkeypatch):
    """⛔ A broken tunnel's silence written as 'liveness_vpn' would be a second, false witness
    against a live host."""
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {})                  # nothing answers through the tunnel
    assert w.run_recheck(conn, dry_run=False, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=TUNNEL) == 0
    assert written == [] and conn.commits == 0
    assert calls == ["www.unimacgraphics.com"]               # quiet hosts never probed


def test_nothing_quiet_means_nothing_probed(monkeypatch):
    conn = _Conn([("www.unimacgraphics.com", True)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open"})
    assert w.run_recheck(conn, dry_run=False, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=TUNNEL) == 0
    assert calls == [] and written == []


def test_recheck_dry_run_probes_but_writes_nothing(monkeypatch):
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open",
                                         "ftp.unimacgraphics.com": "open"})
    assert w.run_recheck(conn, dry_run=True, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=TUNNEL) == 1
    assert written == [] and conn.commits == 0


def test_resolver_hiccup_on_a_quiet_host_skips_it(monkeypatch):
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open"})
    real = w.probe_asset
    monkeypatch.setattr(w, "probe_asset", lambda a, p: None if a == "ftp.unimacgraphics.com" else real(a, p))
    assert w.run_recheck(conn, dry_run=False, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=TUNNEL) == 0
    assert written == []


def test_recheck_reads_the_latest_verdict_of_confirmed_live_hosts_only():
    sql = " ".join(w.Q_LATEST_VERDICT_PER_LIVE_ASSET.split())
    assert "DISTINCT ON (v.asset_id)" in sql
    assert "ORDER BY v.asset_id, v.probed_at DESC" in sql
    assert "a.discovery_status = 'confirmed_live'" in sql


def test_the_vpn_label_is_the_default_for_the_recheck_mode(monkeypatch):
    seen = {}

    class _C:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(w.psycopg, "connect", lambda *a, **k: _C())
    monkeypatch.setattr(w, "run_recheck", lambda conn, dry_run, sweep_id, source, baseline_ip: seen.update(r=source, b=baseline_ip))
    monkeypatch.setattr(w, "run", lambda conn, dry_run, sweep_id, source: seen.update(s=source))
    monkeypatch.setattr("sys.argv", ["x", "--dsn", "postgres://x", "--recheck-unresponsive", "--baseline-ip", "203.0.113.10"])
    assert w.main() == 0 and seen == {"r": "liveness_vpn", "b": "203.0.113.10"}
    monkeypatch.setattr("sys.argv", ["x", "--dsn", "postgres://x"])
    seen.clear()
    assert w.main() == 0 and seen == {"s": "liveness_sweep"}


# ── independent review 2026-10-10: prove the ROUTE, not just that something answers ────────────
def test_route_is_proved_only_when_egress_differs_from_the_runners_own_address():
    assert w.route_ok("203.0.113.10", "198.51.100.7")[0] is True
    ok, why = w.route_ok("203.0.113.10", "203.0.113.10")
    assert ok is False and "runner's own address" in why          # failed rotation: bare IP
    assert w.route_ok("", "198.51.100.7")[0] is False              # no baseline -> refuse
    assert w.route_ok("203.0.113.10", "")[0] is False              # egress unreadable -> refuse


def test_egress_is_read_from_the_first_echo_service_that_gives_an_ipv4():
    answers = {"https://api.ipify.org": "<html>rate limited</html>",
               "https://ifconfig.me": "198.51.100.7\n"}

    def fetch(url):
        if url not in answers:
            raise OSError("down")
        return answers[url]
    assert w.current_egress_ip(fetch) == "198.51.100.7"
    assert w.current_egress_ip(lambda u: (_ for _ in ()).throw(OSError("all down"))) == ""


def test_a_failed_rotation_probes_nothing_and_writes_nothing(monkeypatch):
    """The blocker the review found: rotation tore the tunnel down, the job is on the runner's own
    address, the controls (which answer GitHub's addresses anyway) would 'prove' the tunnel, and the
    firewalled hosts would be written as silent VPN checks."""
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open"})
    n = w.run_recheck(conn, dry_run=False, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="203.0.113.10",
                      route_run=TUNNEL)
    assert n == 0 and calls == [] and written == [] and conn.sql == []


def test_the_cap_keeps_the_intermittent_hosts_and_drops_the_long_dead_ones():
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    dead = [(f"a{i:02d}.dead.example", False, None) for i in range(30)]     # never answered, sort early
    rows = dead + [("pm.unimacgraphics.com", False, now - timedelta(hours=30)),
                   ("ftp.unimacgraphics.com", False, now - timedelta(hours=5)),
                   ("www.unimacgraphics.com", True, now)]
    quiet, _, dropped = w.split_recheck_targets(rows, max_targets=25)
    assert quiet[:2] == ["ftp.unimacgraphics.com", "pm.unimacgraphics.com"]   # most recent answer first
    assert dropped == 7 and "a29.dead.example" not in quiet


def test_the_local_route_must_not_leave_by_the_runners_own_device():
    assert w.route_device_ok(TUNNEL)[0] is True
    ok, why = w.route_device_ok(_routes("eth0", "eth0"))
    assert ok is False and "runner's own device" in why
    ok, why = w.route_device_ok(lambda a: "")                       # unreadable -> refuse
    assert ok is False and "could not read" in why


def test_a_bare_route_probes_nothing_even_if_the_egress_check_passes(monkeypatch):
    """The egress echo can be fooled if the runner's public address changed during the job; the
    routing table cannot. Either proof failing stops the re-check."""
    conn = _Conn([("www.unimacgraphics.com", True), ("ftp.unimacgraphics.com", False)])
    calls, written = _wire(monkeypatch, {"www.unimacgraphics.com": "open"})
    n = w.run_recheck(conn, dry_run=False, sweep_id="s", source="liveness_vpn",
                      baseline_ip="203.0.113.10", egress_ip="198.51.100.7",
                      route_run=_routes("eth0", "eth0"))
    assert n == 0 and calls == [] and written == [] and conn.sql == []
