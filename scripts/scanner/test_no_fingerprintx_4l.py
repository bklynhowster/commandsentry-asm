"""Job 4l (2026-11-02): fingerprintx is out of both scanners, and stays out.

Why: fingerprintx v1.1.19's SSH check (pkg/plugins/services/ssh/ssh.go) logs in
with user 'admin' and password 'admin', then answers a keyboard-interactive
prompt with 'password', to learn whether a server takes passwords. The deep scan
(run_heavy.py) and discovery (scanner/asm-discover.sh) ran it on every open port
they found. The standing rule is no login attempts of any kind (Howie: "No
attempted logins whatsoever ... No logins, no credentials").

These tests pin:
  1. no code path in scripts/ or scanner/ starts fingerprintx again;
  2. the deep scan credits naabu on its own, and nothing for a degraded naabu;
  3. the heavy plan and run() no longer name fingerprintx;
  4. discovery writes no fingerprintx status, its script still parses, and
     normalize keeps every naabu port with a name from the port number
     (the J6 drop stays off without a fingerprintx "ok": its K4-safe direction).
"""
from __future__ import annotations

import inspect
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import run_heavy  # noqa: E402
from run_heavy import HeavyScanContext, credit_net_depth  # noqa: E402

# Ways a line could START fingerprintx (not merely name it):
#   python argv list   ["fingerprintx", ...]  /  ['fingerprintx', ...]
#   shell command      at line start, or after | ; && || $( or a backtick
_PY_ARGV = re.compile(r"""\[\s*["']fingerprintx["']""")
_SH_CMD = re.compile(r"""(^|\||;|&&|\|\||\$\(|`)\s*(exec\s+|command\s+|timeout\s+\S+\s+)?fingerprintx(\s|$)""")
_THIS = Path(__file__).resolve()


def _code_lines(path: Path):
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        yield n, line


def _scanned_files():
    for base in (REPO / "scripts", REPO / "scanner"):
        for p in sorted(base.rglob("*")):
            if p.suffix in (".py", ".sh") and p.is_file() and p.resolve() != _THIS:
                yield p


def test_nothing_in_the_repo_starts_fingerprintx():
    hits = []
    for p in _scanned_files():
        for n, line in _code_lines(p):
            if _PY_ARGV.search(line) or (p.suffix == ".sh" and _SH_CMD.search(line)):
                hits.append(f"{p.relative_to(REPO)}:{n}: {line.strip()}")
    assert not hits, "fingerprintx is started again (job 4l):\n" + "\n".join(hits)


def test_the_guard_would_catch_each_way_back():
    # The guard itself must bite, or test 1 proves nothing.
    assert _PY_ARGV.search('    rc, out, err = run_cmd(["fingerprintx", "--json"], timeout=600)')
    assert _PY_ARGV.search("    subprocess.run(['fingerprintx', '--json'])")
    for sh in ('      fingerprintx --json > "$wd/fingerprintx.json"',
               '  jq -r . "$wd/naabu.json" | fingerprintx --json',
               '  out=$(fingerprintx --json < targets)',
               '  timeout 60 fingerprintx -t host:22'):
        assert _SH_CMD.search(sh), sh
    # ...and must not bite on a mere mention (tool lists, installs, version loops).
    for ok in ('for t in subfinder dnsx httpx naabu fingerprintx nuclei; do',
               'go_install fingerprintx "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1"',
               '    "katana", "fingerprintx", "ffuf", "gau", "wireguard",'):
        assert not _SH_CMD.search(ok) and not _PY_ARGV.search(ok), ok


def test_run_heavy_has_no_fingerprintx_phase_left():
    for name in ("run_fingerprintx_phase", "_parse_fingerprintx", "FPX_SKIP_PORTS"):
        assert not hasattr(run_heavy, name), f"run_heavy.{name} is back (job 4l)"


def _ctx():
    return HeavyScanContext(descriptor={}, hostname="demo.example.com", asset_id="asset-123",
                            scan_run_id="scan-abc", queue_id="q-1", intensity="heavy",
                            target_proven_reachable=True)


def test_naabu_is_credited_on_its_own():
    ctx = _ctx()
    credit_net_depth(ctx, True)
    assert ctx.tools_run == ["naabu"], ctx.tools_run
    assert set(ctx.tool_status) == {"naabu"}, ctx.tool_status
    assert ctx.tool_status["naabu"].get("ok") is True, ctx.tool_status
    run_heavy.assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)


def test_a_degraded_naabu_credits_nothing():
    ctx = _ctx()
    credit_net_depth(ctx, False)
    assert ctx.tools_run == [] and ctx.tool_status == {}, (ctx.tools_run, ctx.tool_status)


def test_run_uses_credit_net_depth_and_never_names_fingerprintx():
    src = inspect.getsource(run_heavy.run)
    assert "credit_net_depth(ctx, naabu_ok)" in src
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "fingerprintx" not in code, "run() names fingerprintx outside a comment"
    i = src.index('ctx.planned_steps = ["testssl.sh"')
    plan = src[i:src.index("]", i) + 1]
    assert "naabu" in plan and "fingerprintx" not in plan, plan


def test_no_fingerprintx_finding_or_artifact_is_written():
    code = "\n".join(l for _, l in _code_lines(Path(run_heavy.__file__)))
    # The service-row key 'fingerprintx-service-<port>-<proto>' is allowed since job 4k:
    # run_greeting_phase keeps it so a service Sentry already listed is re-observed,
    # not listed twice. What stays forbidden: fingerprintx's artifact and its credit.
    for s in ('"fingerprintx", "json"', 'mark_tool_ok(ctx, "fingerprintx")',
              'tools_run.append("fingerprintx")'):
        assert s not in code, f"{s!r} still in run_heavy.py"


# ─── discovery ────────────────────────────────────────────────────────────────
_DISCOVER = REPO / "scanner" / "asm-discover.sh"


def test_discovery_script_still_parses():
    r = subprocess.run(["bash", "-n", str(_DISCOVER)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_discovery_writes_no_fingerprintx_status_or_output():
    text = "\n".join(l for _, l in _code_lines(_DISCOVER))
    assert '"fingerprintx":' not in text, "_probe_status.json names fingerprintx again"
    assert "fpx_rc" not in text
    assert "fingerprintx.json" not in text, "discovery writes a fingerprintx.json again"


def _build(ports, probe):
    sys.path.insert(0, str(REPO / "scanner"))
    import normalize  # the discovery normalizer (scanner/normalize.py)
    normalize._cloud_providers_cache = None
    ip = "35.227.202.53"   # a Google load balancer: in cloud-LB scope, where J6 used to drop
    attr = {"ip": ip, "asn": "AS15169", "asn_org": "Google LLC",
            "reverse_dns": "53.202.227.35.bc.googleusercontent.com"}
    with tempfile.TemporaryDirectory() as d:
        w = Path(d)
        (w / "naabu.json").write_text("".join(json.dumps({"host": ip, "port": p, "protocol": "tcp"}) + "\n"
                                              for p in ports))
        (w / "httpx.json").write_text(json.dumps({"port": 443, "status_code": 200}) + "\n")
        (w / "dnsx.json").write_text(json.dumps({"cname": []}) + "\n")
        (w / "_probe_status.json").write_text(json.dumps(probe))
        return normalize.build_services(w, {ip: attr})


def test_discovery_keeps_every_port_and_names_it_from_the_port_number():
    probe = {"naabu": {"ok": True}, "httpx_tech": {"ok": True}}   # what asm-discover writes now
    svcs = _build([22, 443, 8080], probe)
    assert {s["port"] for s in svcs} == {22, 443, 8080}, "a port was dropped without fingerprintx"
    by_port = {s["port"]: s for s in svcs}
    assert by_port[22]["service"] == "ssh" and by_port[22]["banner"] is None, by_port[22]
    assert by_port[8080]["service"] == "http-alt", by_port[8080]


def _all_tests():
    return [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    failed = 0
    for t in _all_tests():
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {t.__name__}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
