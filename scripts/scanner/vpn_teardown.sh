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

# Disable lockdown-mode first so the post-job cleanup steps that need
# internet (apt cache, GH artifact upload, etc.) can still reach out.
log "disabling lockdown-mode"
timeout 5 mullvad lockdown-mode set off 2>&1 || true

log "disconnecting"
timeout 10 mullvad disconnect 2>&1 || true
sleep 1

log "logging out (frees the device slot — Mullvad has 5-device cap)"
timeout 10 mullvad account logout 2>&1 || true

log "teardown complete"
exit 0
