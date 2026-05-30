#!/usr/bin/env bash
#
# vpn_teardown.sh — Mullvad disconnect + logout. Best-effort cleanup.
#
# Always called via `if: always()` in the workflow so it runs after
# both successful and failed scans. Never fails the workflow itself.
#
# Why logout: Mullvad allows 5 simultaneous devices on one account.
# Each successful login consumes one. Without explicit logout, idle
# runners would accumulate device slots until the cap is hit.

set -u

log() { echo "[vpn-teardown] $*"; }

if ! command -v mullvad &>/dev/null; then
  log "mullvad CLI not installed — nothing to tear down"
  exit 0
fi

# We no longer enable lockdown-mode in bringup (it hangs the daemon
# per scan #36). The default kill switch on the active tunnel goes
# away when we disconnect, so post-job cleanup steps will have
# internet again automatically.

log "disconnecting"
timeout 10 mullvad disconnect 2>&1 || true
sleep 1

log "logging out (frees the device slot — Mullvad has 5-device cap)"
timeout 10 mullvad account logout 2>&1 || true

log "teardown complete"
exit 0
