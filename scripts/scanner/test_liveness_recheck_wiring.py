#!/usr/bin/env python3
"""(note 307, 2026-10-10) Pins the VPN liveness re-check step in scanner.yml.

⛔ WHY. Three Command hosts behind a firewall answered the 6-hourly liveness sweep from GitHub's
servers about 1 time in 5, so the digest called live servers dark every week. Howie chose to check
them the way the scanner reaches them: through the tunnel. The step rides a tunnel and a VPN slot
the scan already holds, so its position and its conditions ARE the design:

  * AFTER the tier runners  — the scan is never delayed or interfered with.
  * BEFORE the teardown     — the tunnel still exists.
  * only when the tunnel came up AND a slot is held — never on the bare runner IP, which is
    exactly the route the firewall turns away (a re-check from there would be a second, false
    witness against a live host).
  * continue-on-error + a short timeout — it can never fail or stall the scan.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STEP = "Liveness re-check through the VPN (quiet hosts only)"


def _steps():
    wf = yaml.safe_load((ROOT / ".github/workflows/scanner.yml").read_text())
    (job,) = [j for j in wf["jobs"].values() if any(s.get("name") == STEP for s in j.get("steps", []))]
    return [s.get("name", "") for s in job["steps"]], {s.get("name"): s for s in job["steps"]}


def test_the_recheck_runs_after_every_tier_and_before_the_tunnel_comes_down():
    names, _ = _steps()
    i = names.index(STEP)
    for tier in ("Run Light tier", "Run Medium tier", "Run Heavy tier"):
        assert names.index(tier) < i, f"{tier} must finish before the re-check"
    assert i < names.index("Tear down VPN"), "the tunnel must still exist"
    assert i < names.index("Release VPN slot"), "the slot must still be held"


def test_the_recheck_only_runs_inside_a_tunnel_this_job_brought_up():
    _, by = _steps()
    cond = " ".join(by[STEP]["if"].split())
    assert "steps.vpn.outcome == 'success'" in cond
    assert "steps.db_carveout.outcome == 'success'" in cond   # the DB must not be behind the tunnel
    assert "steps.vpn_slot.outputs.acquired == 'true'" in cond
    assert "github.event.inputs.skip_vpn != 'true'" in cond
    assert "!cancelled()" in cond          # still runs after a failed scan, not after a cancel


def test_the_recheck_can_never_fail_or_stall_the_scan():
    _, by = _steps()
    assert by[STEP].get("continue-on-error") is True
    assert 0 < int(by[STEP]["timeout-minutes"]) <= 2         # the slot may already be handed on


def test_the_recheck_runs_the_quiet_hosts_mode_of_the_shared_probe():
    _, by = _steps()
    run = by[STEP]["run"]
    assert "scripts/db/asset_liveness_probe.py" in run
    assert "--recheck-unresponsive" in run
    assert "--dry-run" not in run
    assert by[STEP]["env"]["SUPABASE_DSN"] == "${{ secrets.SUPABASE_DSN }}"


def test_the_recheck_is_handed_the_runners_own_address_to_prove_the_route_against():
    """Independent review, 2026-10-10: a failed mid-scan rotation leaves the job on the bare runner
    address while steps.vpn still reads success. The worker refuses unless its egress differs from
    the pre-VPN baseline the bring-up recorded."""
    _, by = _steps()
    assert by[STEP]["env"]["VPN_BASELINE_IP"] == "${{ steps.vpn.outputs.vpn_baseline_ip }}"
    assert by["Carve Supabase out of the VPN tunnel"]["id"] == "db_carveout"
    bringup = (ROOT / "scripts/scanner/vpn_bringup.sh").read_text()
    assert 'echo "vpn_baseline_ip=$BASELINE_IP" >> "$GITHUB_OUTPUT"' in bringup
