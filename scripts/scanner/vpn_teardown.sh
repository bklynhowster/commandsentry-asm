#!/usr/bin/env bash
#
# vpn_teardown.sh — Disconnect + log out of ExpressVPN. Best-effort:
# never fails the workflow even if disconnect itself errors. Always
# called via `if: always()` in the workflow so it runs after both
# successful and failed scans.
#
# Why logout (not just disconnect): every login consumes a "device
# slot" against Howie's 12-connection cap. Without logout, idle
# runners would accumulate sessions on the account.
#

# Don't `set -e` — teardown must always exit 0 so it doesn't poison
# workflow status. Use `|| true` on every individual command.
set -u

log() {
  echo "[vpn-teardown] $*"
}

CLI=""
if command -v expressvpnctl &>/dev/null; then
  CLI="expressvpnctl"
elif command -v expressvpn &>/dev/null; then
  CLI="expressvpn"
fi

if [[ -z "$CLI" ]]; then
  log "no ExpressVPN CLI on PATH — nothing to tear down"
  exit 0
fi

log "disconnecting (best effort)"
"$CLI" disconnect 2>&1 || true
sleep 2

log "disabling background mode"
"$CLI" background disable 2>&1 || true

log "releasing networklock so any cleanup steps that need internet still work"
"$CLI" set networklock false 2>&1 || true

log "logging out (frees the connection slot on Howie's account)"
"$CLI" logout 2>&1 || true

log "teardown complete"
exit 0
