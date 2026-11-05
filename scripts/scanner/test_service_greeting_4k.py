"""Job 4k: the greeting reader. It sends nothing, reads each server's first line, and names
the product only where a public source ties the greeting to one ("going by its greeting").

Pinned here:
  1. against fake servers on this machine: SSH, FTP, SMTP, POP3 and IMAP greetings are read;
     a server that waits, hangs up or refuses is recorded; NOT ONE BYTE reaches any server;
  2. the product map, line by line, against Globalscape's own documents (KB 11439; EFT
     Specifications 8.3.2), and OpenSSH;
  3. the deep scan: one INFO service row per port that greeted, the fingerprintx-era key kept
     (re-observed, not listed twice), no credit, the artifact not a 'fingerprint%' name;
  4. discovery: both flows call the reader, the script still parses, and normalize names the
     service and keeps the greeting as its banner.
"""
from __future__ import annotations

import inspect
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import service_greeting as sg  # noqa: E402
import run_heavy  # noqa: E402
from run_heavy import HeavyScanContext, run_greeting_phase  # noqa: E402


# ─── fake servers ─────────────────────────────────────────────────────────────
class Fake:
    """mode: say | silent | close | refused. Records every byte a client sends."""
    def __init__(self, mode, line=b""):
        self.mode, self.line, self.conns, self.received = mode, line, 0, b""
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        if mode == "refused":
            self.sock.close()
            return
        self.sock.listen(5)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.conns += 1
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            if self.mode == "say":
                c.sendall(self.line)
            elif self.mode == "close":
                return
            c.settimeout(3)
            while True:
                try:
                    b = c.recv(4096)
                except OSError:
                    break
                if not b:
                    break
                self.received += b
        finally:
            try:
                c.close()
            except OSError:
                pass


def _read(f, **kw):
    r = sg.read_greeting("127.0.0.1", f.port, kw.get("connect_s", 2), kw.get("read_s", 1.5))
    time.sleep(0.2)
    return r


def test_ssh_greeting_read_and_nothing_sent():
    f = Fake("say", b"SSH-2.0-1.82_sshlib\r\n")
    r = _read(f)
    assert r["greeting"] == "SSH-2.0-1.82_sshlib" and r["protocol"] == "ssh", r
    assert r["product"]["product"] == "Globalscape EFT" and r["product"]["version"] == "8.0.5 or older", r
    assert f.received == b"" and f.conns == 1


def test_lines_before_the_ssh_line_are_skipped():
    f = Fake("say", b"Authorized use only\r\nSSH-2.0-9.8.1.0_openssh SCI\r\n")
    r = _read(f)
    assert r["greeting"] == "SSH-2.0-9.8.1.0_openssh SCI", r
    assert r["product"]["version"] == "8.3.x", r
    assert f.received == b""


def test_ftp_smtp_pop3_imap_greetings():
    cases = [(b"220 Microsoft FTP Service\r\n", "ftp"), (b"220 mx.example.com ESMTP Postfix\r\n", "smtp"),
             (b"+OK Dovecot ready.\r\n", "pop3"), (b"* OK [CAPABILITY IMAP4rev1] ready\r\n", "imap")]
    for line, proto in cases:
        f = Fake("say", line)
        r = _read(f)
        assert r["protocol"] == proto, (line, r)
        assert f.received == b"", line


def test_a_server_that_waits_hangs_up_or_refuses():
    w, h, x = Fake("silent"), Fake("close"), Fake("refused")
    rw, rh, rx = _read(w), _read(h), _read(x)
    assert rw["connected"] and rw["greeting"] is None and rw["error"] == "no greeting", rw
    assert rh["greeting"] is None and rh["error"] == "no greeting", rh
    assert not rx["connected"] and rx["error"] == "refused", rx
    assert w.received == b"" and h.received == b""


def test_junk_is_cleaned_and_capped():
    f = Fake("say", b"SSH-2.0-" + b"\x01\x02X" * 300 + b"\r\n")
    r = _read(f)
    assert len(r["greeting"]) == sg.MAX_LINE and all(32 <= ord(c) < 127 for c in r["greeting"]), r


def test_web_ports_skipped_and_the_cap_holds():
    assert not sg.read_greetings("127.0.0.1", [80, 443])
    f = Fake("say", b"SSH-2.0-OpenSSH_9.6p1\r\n")
    got = sg.read_greetings("127.0.0.1", [80, 443, f.port], connect_s=2, read_s=1)
    assert [g["port"] for g in got] == [f.port], got
    many = list(range(40000, 40030))
    assert len(sg.read_greetings("127.0.0.1", many, max_ports=3, connect_s=0.2, read_s=0.2)) == 3


def test_the_module_never_sends():
    src = inspect.getsource(sg)
    for w in (".send(", ".sendall(", ".sendto(", "makefile(", ".write("):
        assert w not in src, w


def test_command_line_reads_naabu_output():
    f = Fake("say", b"SSH-2.0-1.82_sshlib\r\n")
    with tempfile.TemporaryDirectory() as d:
        nj = Path(d) / "naabu.json"
        nj.write_text(json.dumps({"host": "127.0.0.1", "ip": "127.0.0.1", "port": f.port}) + "\n"
                      + json.dumps({"host": "127.0.0.1", "ip": "127.0.0.1", "port": 443}) + "\n")
        out = subprocess.run([sys.executable, str(HERE / "service_greeting.py"), "--naabu", str(nj)],
                             capture_output=True, text=True, timeout=60)
    rows = [json.loads(l) for l in out.stdout.splitlines()]
    assert out.returncode == 0 and len(rows) == 1, (out.stdout, out.stderr)
    assert rows[0]["host"] == "127.0.0.1" and rows[0]["greeting"] == "SSH-2.0-1.82_sshlib", rows


# ─── the product map, against the sources ─────────────────────────────────────
def test_product_map():
    cases = {
        "SSH-2.0-1.82_sshlib": ("Globalscape EFT", "8.0.5 or older"),         # KB 11439
        "SSH-2.0-9.8.1.0_openssh SCI": ("Globalscape EFT", "8.3.x"),          # Specs: 8.3.0 uses OpenSSH 9.8
        "SSH-2.0-9.5.0.0_openssh": ("Globalscape EFT", "8.2.1"),              # Specs: 8.2.1 uses OpenSSH 9.5
        "SSH-2.0-7.7.1.0_openssh": ("Globalscape EFT", "7.4.11 or later"),    # KB 11439
        "SSH-2.0-8.1.0.0_openssh SCI": ("Globalscape EFT", None),             # no source ties 8.1 to an EFT version
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5": ("OpenSSH", "9.6p1"),
    }
    for g, (prod, ver) in cases.items():
        p = sg.product_of(g)
        assert p and p["product"] == prod and p.get("version") == ver and p.get("source"), (g, p)
    for g in ("SSH-2.0-1.82_sshlibX", "SSH-2.0-9.8_openssh", "SSH-2.0-dropbear_2022.83", "220 hello", "", None):
        assert sg.product_of(g) is None, g


def test_names_never_say_vulnerable():
    for g in ("SSH-2.0-1.82_sshlib", "SSH-2.0-9.8.1.0_openssh SCI", "SSH-2.0-OpenSSH_9.6p1"):
        d = sg.describe(sg.product_of(g))
        assert "going by its greeting" in d and "vulnerab" not in d.lower(), d


# ─── the deep scan ────────────────────────────────────────────────────────────
def _ctx():
    return HeavyScanContext(descriptor={}, hostname="ftp.example.com", asset_id="asset-123",
                            scan_run_id="scan-abc", queue_id="q-1", intensity="heavy",
                            target_proven_reachable=True)


def _stub(results):
    calls = []

    def fake(host, ports, **kw):
        calls.append((host, list(ports)))
        return results
    return fake, calls


def test_deep_scan_service_rows(monkeypatch=None):
    results = [{"port": 22, "connected": True, "greeting": "SSH-2.0-1.82_sshlib", "protocol": "ssh",
                "product": sg.product_of("SSH-2.0-1.82_sshlib"), "error": None},
               {"port": 53, "connected": True, "greeting": None, "protocol": None, "product": None,
                "error": "no greeting"}]
    fake, calls = _stub(results)
    real = sg.read_greetings
    sg.read_greetings = fake
    try:
        ctx = _ctx()
        run_greeting_phase(ctx, [{"port": 22, "proto": "tcp"}, {"port": 53, "proto": "tcp"},
                                 {"port": 443, "proto": "tcp"}])
    finally:
        sg.read_greetings = real
    assert calls == [("ftp.example.com", [22, 53])], calls
    assert len(ctx.findings) == 1, ctx.findings
    ev = ctx.findings[0]
    assert ev.severity == "INFO" and ev.source == "commandsentry_heavy" and ev.port == 22
    assert ev.title == "Service inventory: 22/tcp/ssh, Globalscape EFT 8.0.5 or older (going by its greeting)", ev.title
    assert "SSH-2.0-1.82_sshlib" in ev.description and "confirm it's patched" in ev.description
    assert "vulnerab" not in (ev.title + ev.description).lower()
    old_key = run_heavy.stable_finding_id("asset-123", "commandsentry_heavy", "fingerprintx-service-22-tcp",
                                          "ftp.example.com:22/tcp")
    assert ev.finding_id == old_key, "the fingerprintx-era service row must be re-observed, not duplicated"
    assert ctx.fpx_services == {(22, "tcp"): "ssh"}, ctx.fpx_services
    assert [a[0] for a in ctx.artifacts] == ["service_greeting"]
    # Job 4y: the classifier now reads greetings by their own name (device_class_runner
    # _ART_GREETING), not through the old 'fingerprint%' pattern.
    assert not "service_greeting".startswith("fingerprint"), "greetings keep their own artifact name"
    assert ctx.tools_run == [] and ctx.tool_status == {}, "not a credited tool"


def test_deep_scan_only_web_ports_reads_nothing():
    fake, calls = _stub([])
    real = sg.read_greetings
    sg.read_greetings = fake
    try:
        ctx = _ctx()
        run_greeting_phase(ctx, [{"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"}])
    finally:
        sg.read_greetings = real
    assert calls == [] and ctx.findings == [] and ctx.artifacts == []


def test_deep_scan_never_fails_the_tier():
    def boom(*a, **k):
        raise OSError("tunnel down")
    real = sg.read_greetings
    sg.read_greetings = boom
    try:
        ctx = _ctx()
        run_greeting_phase(ctx, [{"port": 22, "proto": "tcp"}])
    finally:
        sg.read_greetings = real
    assert ctx.findings == [] and ctx.artifacts == []


def test_run_reads_greetings_after_naabu_only_when_naabu_passed():
    src = inspect.getsource(run_heavy.run)
    i = src.index("credit_net_depth(ctx, naabu_ok)")
    seg = src[i:i + 300]
    assert "if naabu_ok:" in seg and "run_greeting_phase(ctx, open_ports)" in seg, seg
    i2 = src.index('ctx.planned_steps = ["testssl.sh"')
    assert "greeting" not in src[i2:src.index("]", i2)], "not a planned step"


# ─── discovery ────────────────────────────────────────────────────────────────
_DISCOVER = REPO / "scanner" / "asm-discover.sh"


def test_discovery_calls_the_reader_in_both_flows_and_parses():
    text = _DISCOVER.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    assert code.count('python3 "$GREETER" --naabu "$wd/naabu.json" > "$wd/greetings.json"') == 2
    assert 'GREETER="$REPO_ROOT/scripts/scanner/service_greeting.py"' in code
    assert (REPO / "scripts" / "scanner" / "service_greeting.py").is_file()
    r = subprocess.run(["bash", "-n", str(_DISCOVER)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_normalize_names_the_service_and_keeps_the_greeting():
    sys.path.insert(0, str(REPO / "scanner"))
    import normalize
    normalize._cloud_providers_cache = None
    ip = "208.199.0.160"
    with tempfile.TemporaryDirectory() as d:
        w = Path(d)
        (w / "naabu.json").write_text("".join(json.dumps({"host": ip, "ip": ip, "port": p}) + "\n"
                                              for p in (22, 53, 2222)))
        (w / "greetings.json").write_text(
            json.dumps({"host": ip, "port": 22, "greeting": "SSH-2.0-1.82_sshlib", "protocol": "ssh"}) + "\n"
            + json.dumps({"host": ip, "port": 53, "greeting": None, "protocol": None}) + "\n"
            + json.dumps({"host": ip, "port": 2222, "greeting": "SSH-2.0-OpenSSH_9.6p1", "protocol": "ssh"}) + "\n")
        (w / "_probe_status.json").write_text(json.dumps({"naabu": {"ok": True}, "httpx_tech": {"ok": True}}))
        svcs = {s["port"]: s for s in normalize.build_services(w, {ip: {"ip": ip}})}
    assert set(svcs) == {22, 53, 2222}, svcs
    assert svcs[22]["service"] == "ssh" and svcs[22]["banner"] == "SSH-2.0-1.82_sshlib", svcs[22]
    assert svcs[53]["service"] == "dns" and svcs[53]["banner"] is None, svcs[53]
    assert svcs[2222]["service"] == "ssh", "a greeting names a service on a port the hints don't know"


if __name__ == "__main__":
    failed = 0
    for k, v in sorted(globals().items()):
        if k.startswith("test_") and callable(v):
            try:
                v()
                print("  PASS ", k)
            except Exception as e:  # noqa: BLE001
                failed += 1
                print("  FAIL ", k, type(e).__name__, e)
    sys.exit(1 if failed else 0)
