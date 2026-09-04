#!/usr/bin/env python3
"""
fortigate_threshold_probe.py — GO/NO-GO measurement for the FortiGate rotate-on-ban port.

WHY THIS EXISTS (spec 222, 4.7 ruling 2026-09-04)
-------------------------------------------------
The whole rotate-on-ban design rests on one thing that has NEVER been tested:
does per-relay rotation survive REAL template volume against Command's active
FortiGate (commandcommcentral.com)? Production has only ever fired the 5x
safe-only `medium:tech` plan at CCC (build_chunk_plan special-cases FortiGate
targets), so we have zero evidence.

The existing THRESHOLD_PROBE_MODE can't answer it: it's ALSO forced to safe-only
at CCC by the same is_fortigate_target override. So this is a small, ISOLATED,
opt-in diagnostic — it does NOT touch run_medium.py's production path. It fires a
BOUNDED real-template slice at CCC, watches a benign homepage probe for the hard
IP-ban, records how many requests it took, rotates to a fresh relay, and checks
whether rotation RECOVERS. That is the go/no-go 4.7 gated the build on.

WHAT IT MEASURES
  - requests-to-ban per relay under real templates (the real threshold; the ~70
    figure was diagnostic-direct-nuclei, may differ for real templates)
  - does rotation RECOVER cleanly (fresh relay → benign homepage 200 again)
  - the ban's homepage signature: 403 (WAF deny) vs 000 (connection killed)
  - Q3 guard (a): at a homepage 000, is the WG tunnel still up (ban) or down
    (transport)?  We never attribute a tunnel-down 000 to a ban.

WHAT IT IS NOT
  - Not a scan (no findings kept, no DB writes).
  - Not the production burst mechanism (Gap 1) — this only MEASURES; it gates that
    build. It does not permanently un-neuter the plan.

CONSERVATISM (Howie's directive 2026-09-04)
  - Fail-closed apex allowlist — CCC / sciimage apexes ONLY, refuse anything else.
  - Hard caps: --max-rotations, --burst-wall-s (per relay), --total-wall-s (whole run).
  - Low default rate. Benign monitor cadence is low so IT doesn't add ban budget.
  - workflow_dispatch only (see the workflow) — a human fires it, deliberately.

Exit 0 = ran to a clean verdict (go / rethink / no-go printed). Exit 2 = refused
(bad target / preconditions). The verdict is advisory text for a human, never an
automated go-ahead.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Fail-closed: only Command's own FortiGate apexes. Same allowlist shape as the
# other fortigate-*-canary diagnostics. api.* is excluded — it does NOT actively
# block (monitor mode), so a "pass" there would be meaningless.
ALLOWED_TARGETS = {
    "commandcommcentral.com",
    "www.commandcommcentral.com",
    "test.commandcommcentral.com",
    "sciimage.com",
    "www.sciimage.com",
}

WG_DIR = "/etc/wireguard"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[threshold-probe {ts}] {msg}", flush=True)


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, "", repr(e)


def egress_ip() -> str:
    for prov in ("https://api.ipify.org", "https://ifconfig.me", "https://icanhazip.com"):
        rc, out, _ = run(["curl", "-s", "--max-time", "8", prov], timeout=12)
        ip = out.strip()
        if rc == 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return ip
    return ""


def current_wg_iface() -> str | None:
    """The wireguard-go interface currently up (named by region)."""
    rc, out, _ = run(["pgrep", "-af", "wireguard-go"], timeout=8)
    if rc != 0:
        return None
    # "PID /path/wireguard-go <iface>"
    for line in out.splitlines():
        parts = line.split()
        if parts:
            return parts[-1]
    return None


def tunnel_up(iface: str | None) -> bool:
    """Q3 guard (a): is the WG tunnel actually up (recent handshake)? Used to tell
    a real IP-ban (tunnel up, homepage dead) from a transport drop (tunnel down)."""
    if not iface:
        return False
    rc, out, _ = run(["sudo", "wg", "show", iface, "latest-handshakes"], timeout=8)
    if rc != 0:
        return False
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[1].isdigit() and int(cols[1]) > 0:
            # handshake within a sane window = tunnel alive
            return (int(time.time()) - int(cols[1])) < 180
    return False


def homepage_probe(target: str) -> int:
    """Benign homepage via httpx (Go stack, matches nuclei — same reason
    run_medium.healthcheck uses httpx not curl). Returns HTTP code, 0 = no response."""
    rc, out, _ = run(
        ["httpx", "-silent", "-status-code", "-no-color", "-timeout", "10",
         "-u", f"https://{target}/"],
        timeout=15,
    )
    if rc != 0:
        return 0
    m = re.search(r"\[(\d{3})\]", out)
    return int(m.group(1)) if m else 0


BAN_CODES = {403, 429, 502, 503, 504}


def classify(target: str, iface: str | None) -> tuple[str, int]:
    """Return (state, code). state in {'clean','banned','transport','down'}.
      clean     — homepage 2xx/3xx
      banned    — homepage ban code (403/429/503) OR 000 WITH tunnel up
      transport — homepage 000 AND tunnel down (don't blame the relay)
      down/other— unexpected code
    """
    code = homepage_probe(target)
    if code == 0:
        return ("banned", 0) if tunnel_up(iface) else ("transport", 0)
    if code in BAN_CODES:
        return "banned", code
    if 200 <= code < 400:
        return "clean", code
    return "other", code


def list_relays() -> list[str]:
    try:
        return sorted(p.stem for p in Path(WG_DIR).glob("*.conf"))
    except Exception:
        return []


def latest_requests(stats_path: Path) -> int | None:
    """Parse nuclei -stats stderr for the most recent 'Requests: N' count."""
    try:
        text = stats_path.read_text(errors="ignore")
    except Exception:
        return None
    nums = re.findall(r"Requests:\s*(\d+)", text)
    return int(nums[-1]) if nums else None


def rotate_to(region: str, script_dir: Path) -> bool:
    rc, out, err = run(["bash", str(script_dir / "vpn_rotate.sh"), region], timeout=90)
    for line in (out + err).splitlines():
        log(f"  [rotate] {line}")
    return rc == 0


def run_burst(target: str, sev: str, rate: int, wall_s: int,
              monitor_every_s: int) -> dict:
    """Fire a bounded real-template nuclei burst; watch the benign homepage
    alongside. Stop at the first ban (record requests-to-ban) or when the burst
    wall-clock elapses (record total requests, no ban)."""
    iface = current_wg_iface()
    ip = egress_ip()
    base_state, base_code = classify(target, iface)
    log(f"  relay iface={iface} egress={ip} baseline homepage={base_state}({base_code})")
    if base_state != "clean":
        # Fresh relay not clean before we fire anything → Q3 guard (b):
        # 0 attack requests fired, so this is NOT a volume ban. Target-down or
        # transport. Do not blame/burn the relay.
        return {"relay": iface, "egress": ip,
                "banned_state": f"preburst_{base_state}",
                "requests_to_ban": 0, "note": "fresh relay not clean pre-burst "
                "(0 attack reqs fired → target-down/transport, NOT a volume ban) "
                "— Q3 guard b"}

    stats_path = Path("/tmp/nuclei_probe.stats")
    stats_path.write_text("")
    findings = "/tmp/nuclei_probe.jsonl"
    proc = subprocess.Popen(
        ["nuclei", "-u", f"https://{target}", "-severity", sev, "-ni",
         "-rate-limit", str(rate), "-stats", "-stats-interval", str(monitor_every_s),
         "-jsonl", "-o", findings, "-silent"],
        stdout=subprocess.DEVNULL,
        stderr=open(stats_path, "w"),
    )
    deadline = time.time() + wall_s
    result = {"relay": iface, "egress": ip, "banned_state": None,
              "requests_to_ban": None, "note": ""}
    try:
        while time.time() < deadline:
            time.sleep(monitor_every_s)
            if proc.poll() is not None:
                reqs = latest_requests(stats_path)
                result.update(banned_state="none", requests_to_ban=None,
                              requests_total=reqs,
                              note=f"burst completed without ban ({reqs} reqs)")
                log(f"  burst finished, no ban after ~{reqs} reqs")
                return result
            state, code = classify(target, iface)
            reqs = latest_requests(stats_path)
            log(f"  monitor: homepage={state}({code}) nuclei_reqs={reqs}")
            if state in ("banned", "transport"):
                result.update(banned_state=state, requests_to_ban=reqs,
                              homepage_code=code,
                              note=("HARD BAN" if state == "banned"
                                    else "tunnel-down (transport, not a ban) — Q3 guard a"))
                log(f"  → {result['note']} at ~{reqs} requests (homepage {state}/{code})")
                return result
        # wall-clock hit without ban
        reqs = latest_requests(stats_path)
        result.update(banned_state="none", requests_to_ban=None, requests_total=reqs,
                      note=f"burst wall-clock {wall_s}s elapsed, no ban ({reqs} reqs)")
        return result
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="commandcommcentral.com")
    ap.add_argument("--severity", default="critical,high",
                    help="real-template severity slice (bounded; default critical,high)")
    ap.add_argument("--rate", type=int, default=5, help="nuclei rate-limit (low)")
    ap.add_argument("--max-rotations", type=int, default=3)
    ap.add_argument("--burst-wall-s", type=int, default=180,
                    help="per-relay hard cap")
    ap.add_argument("--total-wall-s", type=int, default=1080,
                    help="whole-run hard cap (18 min)")
    ap.add_argument("--monitor-every-s", type=int, default=12,
                    help="benign-monitor cadence (low, so it doesn't add ban budget)")
    args = ap.parse_args()

    # Fail-closed allowlist.
    if args.target not in ALLOWED_TARGETS:
        log(f"REFUSED: '{args.target}' is not a Command FortiGate apex "
            f"(allowed: {sorted(ALLOWED_TARGETS)})")
        return 2

    script_dir = Path(__file__).resolve().parent.parent / "scanner"
    relays = list_relays()
    log(f"pool: {len(relays)} relay configs on disk")
    if len(relays) < 2:
        log("REFUSED: need at least 2 relays to test rotation recovery")
        return 2

    run_deadline = time.time() + args.total_wall_s
    used: list[str] = []
    results: list[dict] = []

    for rot in range(args.max_rotations + 1):
        if time.time() > run_deadline:
            log("total wall-clock reached — stopping")
            break
        iface = current_wg_iface()
        if iface:
            used.append(iface)
        log(f"── burst {rot + 1}/{args.max_rotations + 1} on {iface or '<bringup>'} ──")
        res = run_burst(args.target, args.severity, args.rate,
                        min(args.burst_wall_s, int(run_deadline - time.time())),
                        args.monitor_every_s)
        results.append(res)

        if res["banned_state"] == "transport":
            log("transport failure (tunnel down) — NOT a ban; would bring tunnel "
                "back in production. Stopping the diagnostic to avoid confounds.")
            break
        if res["banned_state"] not in ("banned",):
            log("no ban this burst — nothing to recover from; stopping.")
            break
        if rot >= args.max_rotations:
            log("max rotations reached")
            break

        # Rotate to a fresh, unused relay to test recovery.
        candidates = [r for r in relays if r not in used]
        if not candidates:
            log("no unused relays left within cap — stopping")
            break
        nxt = candidates[0]
        log(f"rotating to fresh relay: {nxt}")
        if not rotate_to(nxt, script_dir):
            log("rotation bring-up failed — recording and stopping")
            res["recovery"] = "rotate_failed"
            break
        state, code = classify(args.target, current_wg_iface())
        res["recovery"] = f"{state}({code})"
        log(f"post-rotation homepage on {nxt}: {state}({code})")
        if state != "clean":
            log("fresh relay did NOT come back clean — recovery questionable, stopping")
            break

    # ── Verdict (advisory text for a human) ─────────────────────────────────
    bans = [r for r in results if r.get("banned_state") == "banned"]
    thresholds = [r["requests_to_ban"] for r in bans if r.get("requests_to_ban")]
    recovered = [r for r in results if str(r.get("recovery", "")).startswith("clean")]

    summary = {
        "target": args.target, "severity": args.severity, "rate": args.rate,
        "bursts": results, "relays_used": used,
        "ban_thresholds_reqs": thresholds,
        "rotations_recovered": len(recovered),
    }
    print("\n=== THRESHOLD PROBE SUMMARY ===")
    print(json.dumps(summary, indent=2))

    md = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["## FortiGate real-template threshold probe — `%s`" % args.target, ""]
    lines.append(f"- severity slice: `{args.severity}` @ rate {args.rate}")
    lines.append(f"- relays exercised: {len(used)}")
    if thresholds:
        lines.append(f"- **requests-to-ban:** {thresholds} "
                     f"(median ~{sorted(thresholds)[len(thresholds)//2]})")
    else:
        lines.append("- **no hard ban observed** within caps")
    lines.append(f"- rotations that recovered to a clean homepage: "
                 f"{len(recovered)}/{max(0,len(bans))}")
    lines.append("")
    # go / rethink / no-go
    if bans and recovered and thresholds and max(thresholds) >= 40:
        verdict = ("### ✅ GO (provisional) — rotation recovers and the threshold "
                   "leaves working room. Build Gap 1 bursts sized from these numbers.")
    elif bans and recovered and thresholds:
        verdict = ("### ⚠ RETHINK — rotation recovers but the threshold is low; "
                   "rotation overhead may dominate. Consider accepting partial "
                   "coverage by design, or a coarser cadence.")
    elif bans and not recovered:
        verdict = ("### ❌ NO-GO — bans fired but rotation did NOT recover to a clean "
                   "homepage. The method does not survive real volume against CCC as-is; "
                   "escalate before building.")
    else:
        verdict = ("### ℹ INCONCLUSIVE — no hard ban within the caps (raise "
                   "--burst-wall-s / --severity, or the real threshold is high). "
                   "Re-run with a wider bound.")
    lines.append(verdict)
    print("\n" + verdict)
    if md:
        with open(md, "a") as f:
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
