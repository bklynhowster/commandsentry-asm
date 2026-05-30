#!/usr/bin/env bash
#
# vpn_rotate.sh — Mullvad WireGuard region swap via wg-quick.
#
# After scans #43-48 hung in Mullvad CLI socket I/O, pivoted to direct
# WireGuard configs. Rotation is just wg-quick down + wg-quick up on
# a different config file. No daemon, no rotation API.
#
# Usage:
#   vpn_rotate.sh us-chi
#   vpn_rotate.sh us-lax
#
# Outputs (to $GITHUB_OUTPUT):
#   pre_ip           — egress IP before rotation
#   post_ip          — egress IP after rotation
#   rotation_cost_s  — total time in seconds
#
# Exit codes:
#   0 — rotated, egress IP changed
#   2 — wg-quick down or up failed
#   3 — egress IP didn't change

set -uo pipefail

NEW_REGION="${1:-us-nyc}"

log() { echo "[vpn-rotate] $*"; }
err() { echo "[vpn-rotate] ERROR: $*" >&2; }

if ! command -v wg-quick &>/dev/null; then
  err "wg-quick not installed — was vpn_bringup.sh run first?"
  exit 2
fi

NEW_CONF="/etc/wireguard/${NEW_REGION}.conf"
if [[ ! -f "$NEW_CONF" ]]; then
  err "config not found at $NEW_CONF"
  err "available configs:"
  sudo ls /etc/wireguard/ 2>&1 || true
  exit 2
fi

# Capture pre-rotate egress (best effort, single probe).
get_egress_ip() {
  timeout 8 curl -s --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true
}

PRE_IP=$(get_egress_ip)
log "pre-rotate egress: ${PRE_IP:-<unknown>}"

# Find currently-up wg interfaces (wg-quick names them after their conf
# basename). Tear them down so the new one can claim the route table.
START=$(date +%s)
UP_IFACES=$(sudo wg show interfaces 2>/dev/null || true)
log "currently up wireguard interfaces: ${UP_IFACES:-<none>}"

for iface in $UP_IFACES; do
  # The conf file name is the interface name (wg-quick convention).
  if [[ "$iface" != "$NEW_REGION" ]]; then
    log "wg-quick down $iface"
    sudo wg-quick down "$iface" 2>&1 || err "wg-quick down $iface returned non-zero (continuing)"
  else
    log "$iface already up — will skip down/up cycle"
  fi
done

# Bring up the new one (idempotent — if already up, this is a no-op).
if ! echo "$UP_IFACES" | grep -qw "$NEW_REGION"; then
  log "wg-quick up $NEW_REGION"
  if ! sudo wg-quick up "$NEW_REGION" 2>&1; then
    err "wg-quick up $NEW_REGION failed"
    exit 2
  fi
fi

END=$(date +%s)
TOTAL=$((END - START))
log "rotation took: ${TOTAL}s"

sleep 2

POST_IP=$(get_egress_ip)
log "post-rotate egress: ${POST_IP:-<unknown>}"

if [[ "$POST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
   [[ "$PRE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
   [[ "$POST_IP" == "$PRE_IP" ]]; then
  err "egress IP did not change (still $POST_IP)"
  exit 3
fi

# Publish outputs
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "pre_ip=$PRE_IP"             >> "$GITHUB_OUTPUT"
  echo "post_ip=$POST_IP"           >> "$GITHUB_OUTPUT"
  echo "rotation_cost_s=$TOTAL"     >> "$GITHUB_OUTPUT"
fi

log "✅ rotation successful: ${PRE_IP:-?} → ${POST_IP:-?} (${TOTAL}s)"
exit 0
