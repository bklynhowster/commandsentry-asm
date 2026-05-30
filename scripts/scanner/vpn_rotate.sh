#!/usr/bin/env bash
#
# vpn_rotate.sh — Mullvad atomic region switch.
#
# Mullvad's CLI supports atomic location changes while connected: just
# `mullvad relay set location <new>` and the daemon will reconnect to
# the new location. No need for the explicit disconnect+connect dance
# that wedged ExpressVPN's daemon.
#
# Usage:
#   vpn_rotate.sh                  # uses default "us nyc"
#   vpn_rotate.sh "us chi"          # rotate to Chicago
#   vpn_rotate.sh "us lax"          # rotate to LA
#   vpn_rotate.sh "us"              # any US server
#
# Outputs (to $GITHUB_OUTPUT):
#   pre_ip           — egress IP before rotation
#   post_ip          — egress IP after rotation
#   rotation_cost_s  — total time in seconds
#
# Exit codes:
#   0 — rotated successfully, egress IP changed
#   2 — set-location or reconnect failed
#   3 — egress IP didn't change (rotation was a no-op or tunnel broken)

set -uo pipefail

REGION="${1:-us nyc}"

log() { echo "[vpn-rotate] $*"; }
err() { echo "[vpn-rotate] ERROR: $*" >&2; }

if ! command -v mullvad &>/dev/null; then
  err "mullvad CLI not installed — was vpn_bringup.sh run first?"
  exit 2
fi

# Egress IP probe with retry tolerance (lockdown-mode can briefly
# block traffic during reconnect).
get_egress_ip() {
  for round in 1 2 3 4 5; do
    for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
      ip=$(curl -s --max-time 6 "$url" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
      if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
      fi
    done
    [[ "$round" -lt 5 ]] && sleep 5
  done
  echo ""
}

PRE_IP=$(get_egress_ip)
log "pre-rotate egress: ${PRE_IP:-<unknown>}"

# ─── Atomic location switch ─────────────────────────────────────────
START=$(date +%s)
log "switching location to: $REGION"
LOCATION_OK=false
if timeout 10 mullvad relay set location $REGION 2>&1; then
  LOCATION_OK=true
else
  COUNTRY=$(echo "$REGION" | awk '{print $1}')
  log "  full region failed — falling back to country-only: $COUNTRY"
  if timeout 10 mullvad relay set location "$COUNTRY" 2>&1; then
    LOCATION_OK=true
    REGION="$COUNTRY"
  fi
fi

if ! $LOCATION_OK; then
  err "couldn't set new location"
  exit 2
fi

# Mullvad automatically reconnects when the location is changed while
# connected, but force it explicitly via `reconnect` (or `connect` as
# a fallback) so we know which command finished.
log "reconnecting to apply new location..."
if ! timeout 30 mullvad reconnect 2>&1; then
  log "  reconnect not available — falling back to connect"
  timeout 30 mullvad connect 2>&1 || true
fi

# Wait for tunnel to be 'Connected' again.
log "waiting for new tunnel to be 'Connected'..."
CONNECTED=false
for i in $(seq 1 30); do
  STATUS_OUT=$(timeout 3 mullvad status 2>&1 || true)
  if echo "$STATUS_OUT" | grep -qi "Connected"; then
    CONNECTED=true
    log "new tunnel up after ${i}s"
    break
  fi
  sleep 1
done

if ! $CONNECTED; then
  err "new tunnel never reached 'Connected' state"
  timeout 5 mullvad status -v 2>&1 || true
  exit 2
fi

END=$(date +%s)
TOTAL=$((END - START))
log "switch + reconnect took: ${TOTAL}s"

# Settle for new route table
sleep 3

POST_IP=$(get_egress_ip)
log "post-rotate egress: ${POST_IP:-<unknown>}"

if [[ -z "$POST_IP" ]]; then
  err "post-rotate egress could not be determined"
  exit 3
fi

if [[ -n "$PRE_IP" ]] && [[ "$POST_IP" == "$PRE_IP" ]]; then
  err "egress IP did not change (still $POST_IP) — got reassigned to same exit"
  exit 3
fi

# Publish outputs
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "pre_ip=$PRE_IP"             >> "$GITHUB_OUTPUT"
  echo "post_ip=$POST_IP"           >> "$GITHUB_OUTPUT"
  echo "rotation_cost_s=$TOTAL"     >> "$GITHUB_OUTPUT"
fi

log "✅ rotation successful: $PRE_IP → $POST_IP (${TOTAL}s)"
exit 0
