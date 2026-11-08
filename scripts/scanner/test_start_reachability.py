"""push-421 (job 4z) — the start-of-scan reachability check.

start_reachability_check runs ONCE at the start of a scan, after the tunnel
is up and before any target-bound step (Howie's rulings D1′/D2′, 2026-11-07):

  - start exit reaches the target  → proceed, no exit switched.
  - start exit silent, cnn.com answers → try up to 2 backup exits; the first
    that answers carries the scan and becomes egress_ip_initial /
    vpn_config_used.
  - no exit (start + backups) answers while cnn.com does → stop the scan,
    reason ASSET_UNREACHABLE_ALL_EXITS (routed to degraded_out, never clean).
  - start exit silent AND cnn.com silent → dead-exit path, unchanged: proceed
    and let the first phase's ensure_healthy_egress handle it.
  - validate_mode / no tunnel → no-op, proceed.

The three I/O boundaries (the TCP knock, the cnn.com control probe, the tunnel
bring-up) are monkeypatched so every scenario is offline and deterministic.

FAIL-FIRST: on today's code start_reachability_check / start_check_summary /
ASSET_UNREACHABLE_ALL_EXITS do not exist, so this whole module fails to import
— the honest first-failure for a brand-new function.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import run_medium  # noqa: E402
from degradation import ASSET_UNREACHABLE_ALL_EXITS  # noqa: E402

# A name that can never resolve (RFC 6761), so a missing stand-in can't reach
# a real host.
TARGET = "target.invalid"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Every test here is offline. A connect to anything but 127.0.0.1, any
    command (tunnel switch, httpx), or an exit-address read fails the test
    loudly instead of reaching out. Tests that need one of these replace it
    with their own stand-in (a later setattr wins)."""
    import socket
    real_connect = socket.create_connection

    def guarded(address, *a, **k):
        if address[0] != "127.0.0.1":
            raise AssertionError(f"test tried to reach {address[0]}:{address[1]}")
        return real_connect(address, *a, **k)
    monkeypatch.setattr(socket, "create_connection", guarded)
    monkeypatch.setattr(run_medium, "run_cmd",
                        lambda cmd, *a, **k: pytest.fail(f"test tried to run {cmd[:2]}"))
    monkeypatch.setattr(run_medium, "capture_egress_ip",
                        lambda: pytest.fail("test tried to read the exit address"))


class _Ctx:
    """Minimal ScanContext stand-in — only the fields the start check reads
    or writes. web_host is passed as an argument, not read off ctx."""

    def __init__(self, vpn_config_used="us-qas-wg-302", validate_mode=False):
        self.validate_mode = validate_mode
        self.vpn_config_used = vpn_config_used
        self.egress_ip_initial = "203.0.113.1"
        self.egress_ips_seen = ["203.0.113.1"]
        self.start_check = []


def _patch(monkeypatch, *, answers, cnn, available, bringups=None):
    """Wire the three boundaries.

    answers: dict config_name -> bool. start_exit_answers consults the exit
      currently 'up' (tracked in state['current']).
    cnn: bool returned by control_probe_reachable.
    available: the /etc/wireguard pool (_load_rotation_regions).
    bringups: dict config_name -> ip|None; None means bring-up failed.
    """
    state = {"current": None}

    def fake_start_exit_answers(host, ports=(443, 80)):
        cur = state["current"]
        ok = answers.get(cur, False)
        disp = {"443": "reset" if ok else "timeout"}
        return ok, disp

    def fake_control_probe_reachable():
        return cnn

    def fake_bring_up(ctx, config_name):
        ip = (bringups or {}).get(config_name)
        if ip:
            state["current"] = config_name
            if ip not in ctx.egress_ips_seen:
                ctx.egress_ips_seen.append(ip)
        return ip

    monkeypatch.setattr(run_medium, "start_exit_answers", fake_start_exit_answers)
    monkeypatch.setattr(run_medium, "control_probe_reachable",
                        fake_control_probe_reachable)
    monkeypatch.setattr(run_medium, "bring_up_named_exit", fake_bring_up)
    monkeypatch.setattr(run_medium, "_load_rotation_regions",
                        lambda shuffle=True: list(available))
    return state


def test_start_exit_reaches_target_proceeds_no_switch(monkeypatch):
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(monkeypatch, answers={"us-qas-wg-302": True}, cnn=True,
               available=["us-qas-wg-302", "us-lax-wg-701"])
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701")

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is True and reason == ""
    assert ctx.vpn_config_used == "us-qas-wg-302"   # unchanged
    assert len(ctx.start_check) == 1
    assert ctx.start_check[0]["stage"] == "start_exit"
    assert ctx.start_check[0]["answered"] is True


def test_backup_exit_answers_carries_scan(monkeypatch):
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(
        monkeypatch,
        answers={"us-qas-wg-302": False, "us-lax-wg-701": True},
        cnn=True,
        available=["us-qas-wg-302", "us-lax-wg-701", "us-slc-wg-302"],
        bringups={"us-lax-wg-701": "198.51.100.7"},
    )
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701, us-slc-wg-302")

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is True and reason == ""
    # the backup that answered becomes the scan's first exit
    assert ctx.vpn_config_used == "us-lax-wg-701"
    assert ctx.egress_ip_initial == "198.51.100.7"
    assert "198.51.100.7" in ctx.egress_ips_seen
    stages = [e["stage"] for e in ctx.start_check]
    assert stages == ["start_exit", "backup"]
    assert ctx.start_check[-1]["answered"] is True


def test_no_exit_answers_stops_degraded(monkeypatch):
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(
        monkeypatch,
        answers={"us-qas-wg-302": False, "us-lax-wg-701": False,
                 "us-slc-wg-302": False},
        cnn=True,
        available=["us-qas-wg-302", "us-lax-wg-701", "us-slc-wg-302"],
        bringups={"us-lax-wg-701": "198.51.100.7",
                  "us-slc-wg-302": "198.51.100.9"},
    )
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701, us-slc-wg-302")

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is False
    assert reason == ASSET_UNREACHABLE_ALL_EXITS
    # start + 2 backups all recorded
    assert len([e for e in ctx.start_check if e["stage"] == "backup"]) == 2
    # every exit tried has cnn.com's answer on record
    assert [e.get("control") for e in ctx.start_check] == [
        "answered", "answered", "answered"]


def test_silent_backup_with_dead_exit_is_recorded_as_such(monkeypatch):
    """cnn.com answers on the start exit but not on a backup: the backup is
    recorded 'silent' for cnn.com too, and the count says so."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(monkeypatch, answers={}, cnn=True,
                available=["us-qas-wg-302", "us-lax-wg-701"],
                bringups={"us-lax-wg-701": "198.51.100.7"})
    st["current"] = "us-qas-wg-302"
    calls = iter([True, False])                 # start exit yes, backup no
    monkeypatch.setattr(run_medium, "control_probe_reachable", lambda: next(calls))
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701")
    ok, reason = run_medium.start_reachability_check(ctx, TARGET)
    assert (ok, reason) == (False, ASSET_UNREACHABLE_ALL_EXITS)
    assert [e.get("control") for e in ctx.start_check] == ["answered", "silent"]
    assert "cnn.com answered through 1 of them" in run_medium.start_check_summary(ctx.start_check)


def test_never_more_than_two_backup_exits(monkeypatch):
    """Four exits listed, none answers: exactly 2 tunnels brought up, then the
    scan stops (ruling D1′: up to 2 more exits at the start)."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    listed = ["us-lax-wg-701", "us-slc-wg-302", "us-phx-wg-202", "us-sea-wg-401"]
    _patch(monkeypatch, answers={}, cnn=True,
           available=["us-qas-wg-302", *listed],
           bringups={c: f"198.51.100.{i + 1}" for i, c in enumerate(listed)})
    tried = []
    real_bring = run_medium.bring_up_named_exit

    def counting(c, name):
        tried.append(name)
        return real_bring(c, name)
    monkeypatch.setattr(run_medium, "bring_up_named_exit", counting)
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", ", ".join(listed))

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert (ok, reason) == (False, ASSET_UNREACHABLE_ALL_EXITS)
    assert tried == ["us-lax-wg-701", "us-slc-wg-302"]


def test_cnn_silent_leaves_to_midrun_unchanged(monkeypatch):
    """Start exit silent AND cnn.com silent → dead-exit path. push-421 does
    NOT switch exits here; it proceeds and the first phase's existing
    ensure_healthy_egress owns the case."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(monkeypatch, answers={"us-qas-wg-302": False}, cnn=False,
               available=["us-qas-wg-302", "us-lax-wg-701"],
               bringups={"us-lax-wg-701": "198.51.100.7"})
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701")

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is True and reason == "egress_suspect"
    assert ctx.vpn_config_used == "us-qas-wg-302"   # no switch
    assert ctx.start_check[-1]["control"] == "silent"


def test_bringup_failure_skips_to_next_backup(monkeypatch):
    """A backup whose tunnel won't come up is recorded failed and the next
    backup is tried."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(
        monkeypatch,
        answers={"us-qas-wg-302": False, "us-slc-wg-302": True},
        cnn=True,
        available=["us-qas-wg-302", "us-lax-wg-701", "us-slc-wg-302"],
        bringups={"us-lax-wg-701": None,            # bring-up fails
                  "us-slc-wg-302": "198.51.100.9"},
    )
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701, us-slc-wg-302")

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is True and reason == ""
    assert ctx.vpn_config_used == "us-slc-wg-302"
    failed = [e for e in ctx.start_check
              if e.get("bringup") == "failed"]
    assert [e["config"] for e in failed] == ["us-lax-wg-701"]


def test_empty_fallbacks_random_from_pool(monkeypatch):
    """Empty SCANNER_VPN_FALLBACKS → a random exit from the pool is tried
    (D2′ (b)). With one non-current config available and it answering, the
    scan proceeds on it."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(
        monkeypatch,
        answers={"us-qas-wg-302": False, "us-lax-wg-701": True},
        cnn=True,
        available=["us-qas-wg-302", "us-lax-wg-701"],
        bringups={"us-lax-wg-701": "198.51.100.7"},
    )
    st["current"] = "us-qas-wg-302"
    monkeypatch.delenv("SCANNER_VPN_FALLBACKS", raising=False)

    ok, reason = run_medium.start_reachability_check(ctx, TARGET)

    assert ok is True and reason == ""
    assert ctx.vpn_config_used == "us-lax-wg-701"


def test_validate_mode_is_noop(monkeypatch):
    ctx = _Ctx(validate_mode=True)
    ok, reason = run_medium.start_reachability_check(ctx, TARGET)
    assert ok is True and reason == "validate_mode"
    assert ctx.start_check == []


def test_no_tunnel_does_not_switch(monkeypatch):
    """No WireGuard interface detected (vpn_config_used None) → never bring a
    tunnel up from here; proceed as today."""
    ctx = _Ctx(vpn_config_used=None)
    ok, reason = run_medium.start_reachability_check(ctx, TARGET)
    assert ok is True and reason == "no_tunnel"
    assert ctx.start_check[-1]["skipped"] == "no_tunnel"


def test_start_exit_answers_refused_or_reset_counts_as_answered(monkeypatch):
    """The knock rule (matches push-420's test): a refusal (RST on connect)
    or a reset above the handshake both mean the box answered → reachable."""
    monkeypatch.setattr(run_medium, "tcp_probe_disposition",
                        lambda h, p, **k: "refused" if p == 443 else "timeout")
    answered, disp = run_medium.start_exit_answers(TARGET)
    assert answered is True
    assert disp["443"] == "refused"


def test_start_exit_answers_all_timeout_is_no_answer(monkeypatch):
    """Only a timeout/error on EVERY port is 'no answer'."""
    monkeypatch.setattr(run_medium, "tcp_probe_disposition",
                        lambda h, p, **k: "timeout")
    answered, disp = run_medium.start_exit_answers(TARGET)
    assert answered is False
    assert disp == {"443": "timeout", "80": "timeout"}


def test_start_exit_answers_reset_on_80_counts(monkeypatch):
    """A reset on either port is enough — 443 silent, 80 answers → answered."""
    monkeypatch.setattr(run_medium, "tcp_probe_disposition",
                        lambda h, p, **k: "timeout" if p == 443 else "reset")
    answered, _ = run_medium.start_exit_answers(TARGET)
    assert answered is True


def test_start_check_summary_sentence_counts_only():
    """The reason line counts exits and names none (ruling D3′: the portal
    prints error_message to everyone; which exits Sentry tried is Howie's)."""
    s = run_medium.start_check_summary([
        {"stage": "start_exit", "config": "us-qas-wg-302", "control": "answered"},
        {"stage": "backup", "config": "us-lax-wg-701", "control": "silent"},
        {"stage": "backup", "config": "us-slc-wg-302", "bringup": "failed"},
    ])
    assert s == ("no answer from 2 exit(s) at the start of the scan; "
                 "cnn.com answered through 1 of them; "
                 "1 more could not be brought up")


def test_stopped_scan_reason_names_no_exit(monkeypatch):
    """End to end: the sentence that becomes error_message after a real
    no-answer run carries no exit name and no exit address."""
    ctx = _Ctx(vpn_config_used="us-qas-wg-302")
    st = _patch(monkeypatch, answers={}, cnn=True,
                available=["us-qas-wg-302", "us-lax-wg-701", "us-slc-wg-302"],
                bringups={"us-lax-wg-701": "198.51.100.7",
                          "us-slc-wg-302": "198.51.100.9"})
    st["current"] = "us-qas-wg-302"
    monkeypatch.setenv("SCANNER_VPN_FALLBACKS", "us-lax-wg-701 us-slc-wg-302")
    ok, _ = run_medium.start_reachability_check(ctx, TARGET)
    assert ok is False
    s = run_medium.start_check_summary(ctx.start_check)
    assert "wg-" not in s and "198.51.100" not in s and "203.0.113" not in s, s
    assert s == ("no answer from 3 exit(s) at the start of the scan; "
                 "cnn.com answered through 3 of them")
    # the names live in the forensics trail instead
    assert [e["config"] for e in ctx.start_check] == [
        "us-qas-wg-302", "us-lax-wg-701", "us-slc-wg-302"]


# ─── the knock sends nothing (real sockets, localhost only) ─────────────

def test_start_exit_answers_sends_no_bytes_and_open_port_answers():
    """A real listener on 127.0.0.1: the knock connects, sends NOTHING, and an
    open port counts as answered. Only localhost is touched."""
    import socket
    import threading

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    got = {}

    def accept_once():
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        data = b""
        try:
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        got["data"] = data
        conn.close()

    t = threading.Thread(target=accept_once, daemon=True)
    t.start()
    answered, disp = run_medium.start_exit_answers("127.0.0.1", (port,))
    t.join(timeout=5)
    srv.close()
    assert answered is True
    assert got.get("data") == b""          # not one byte beyond the handshake


def test_start_exit_answers_closed_port_refused_counts():
    """A closed localhost port refuses (RST) → the box answered → reachable."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                              # nothing listens there now
    answered, disp = run_medium.start_exit_answers("127.0.0.1", (port,))
    assert answered is True
    assert disp[str(port)] == "refused"


# ─── bring_up_named_exit: the named exit, no rotation counters ──────────

class _BringCtx(_Ctx):
    def __init__(self, validate_mode=False):
        super().__init__(validate_mode=validate_mode)
        self.rotation_count = 0
        self.region_idx = 0


def test_bring_up_named_exit_calls_script_with_that_config(monkeypatch):
    calls = []

    def fake_run_cmd(cmd, timeout=30, **k):
        calls.append(cmd)
        return 0, "", ""
    monkeypatch.setattr(run_medium, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(run_medium, "capture_egress_ip", lambda: "198.51.100.7")
    ctx = _BringCtx()

    ip = run_medium.bring_up_named_exit(ctx, "us-lax-wg-701")

    assert ip == "198.51.100.7"
    assert len(calls) == 1
    assert calls[0][0].endswith("vpn_rotate.sh")
    assert calls[0][1:] == ["us-lax-wg-701"]
    # start-of-scan exit choice is not a mid-run rotation
    assert ctx.rotation_count == 0 and ctx.region_idx == 0
    assert ctx.egress_ips_seen[-1] == "198.51.100.7"


def test_bring_up_named_exit_failure_returns_none(monkeypatch):
    monkeypatch.setattr(run_medium, "run_cmd",
                        lambda cmd, timeout=30, **k: (2, "", "handshake failed"))
    monkeypatch.setattr(run_medium, "capture_egress_ip",
                        lambda: pytest.fail("no egress read after a failed bring-up"))
    ctx = _BringCtx()
    assert run_medium.bring_up_named_exit(ctx, "us-lax-wg-701") is None
    assert ctx.rotation_count == 0


def test_bring_up_named_exit_validate_mode_never_runs_script(monkeypatch):
    monkeypatch.setattr(run_medium, "run_cmd",
                        lambda *a, **k: pytest.fail("no tunnel work in validate mode"))
    assert run_medium.bring_up_named_exit(_BringCtx(validate_mode=True),
                                          "us-lax-wg-701") is None


# ─── the trail reaches scan_run.rotation_log ────────────────────────────

def test_build_rotation_log_carries_start_check():
    class _C:
        rotation_count = 0
        egress_ips_seen = ["203.0.113.1", "198.51.100.7"]
        ban_events = []
        healthcheck_failures = []
        rotation_storm = False
        start_check = [{"stage": "start_exit", "answered": False},
                       {"stage": "backup", "answered": True}]
    log = run_medium.build_rotation_log(_C())
    assert log["start_check"] == _C.start_check
    assert log["count"] == 0               # backups are not counted as rotations


# ─── wiring: once, at the start, before anything touches the target ─────

def _src(mod, fn):
    import inspect
    return inspect.getsource(getattr(mod, fn))


def test_medium_run_calls_start_check_first_before_canonical_probe():
    """The start check is the first step that touches the target: after the
    validate-mode gate, BEFORE resolve_web_host's canonical probe (which on a
    blind exit would get nothing and lose the canonical host), and it knocks
    the asset's own hostname. Code review 421 (Kimi minor 1, DeepSeek question)."""
    src = _src(run_medium, "run")
    i_try = src.index("    try:\n")
    i_gate = src.index("assert_validate_mode_target_allowed(ctx.hostname, skip_vpn)")
    i_start = src.index("start_reachability_check(ctx, ctx.hostname)")
    i_web = src.index("resolve_web_host(ctx)")
    i_waf = src.index("detect_waf(ctx)")
    assert i_try < i_gate < i_start < i_web < i_waf
    assert src.count("start_reachability_check(") == 1
    assert "raise DegradedRunError(start_reason" in src[i_start:i_web]


def test_heavy_run_calls_start_check_before_first_target_phase():
    import run_heavy
    src = _src(run_heavy, "run")
    i_try = src.index("    try:\n")
    i_gate = src.index("assert_validate_mode_target_allowed(ctx.hostname, skip_vpn)")
    i_start = src.index("start_reachability_check(ctx, ctx.hostname)")
    i_passive = src.index("run_stack_id_passive_phase(ctx, work_dir)")
    i_testssl = src.index("run_testssl_phase(ctx, work_dir)")
    assert i_try < i_gate < i_start < i_passive < i_testssl
    assert src.count("start_reachability_check(") == 1
    assert "raise DegradedRunError(start_reason" in src[i_start:i_passive]


def test_scanner_yml_passes_fallbacks_to_medium_and_heavy_only():
    import yaml
    wf = yaml.safe_load((Path(__file__).resolve().parents[2]
                         / ".github/workflows/scanner.yml").read_text())
    steps = [s for job in wf["jobs"].values() for s in job.get("steps", [])]
    by_name = {s.get("name"): s for s in steps}
    want = "${{ vars.SCANNER_VPN_FALLBACKS || '' }}"
    for name in ("Run Medium tier", "Run Heavy tier"):
        assert by_name[name]["env"]["SCANNER_VPN_FALLBACKS"] == want, name
    assert "SCANNER_VPN_FALLBACKS" not in (by_name["Run Light tier"].get("env") or {})
