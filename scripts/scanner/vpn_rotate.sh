#!/usr/bin/env bash
#
# vpn_rotate.sh — Mullvad WireGuard region swap via wireguard-go userspace.
#
# Post-pivot to wireguard-go (see [[58 - wireguard-go Pivot Spec]] in
# Obsidian), rotation is: kill the old wireguard-go process for the
# current region, flush our rules+routes, then call wg_up_userspace.sh
# for the new region.
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
#   2 — bring-up of new region failed
#   3 — egress IP didn't change

set -uo pipefail

NEW_REGION="${1:-us-nyc}"
TABLE=51820

log() { echo "[vpn-rotate] $*"; }
err() { echo "[vpn-rotate] ERROR: $*" >&2; }

if ! command -v wireguard-go &>/dev/null; then
  err "wireguard-go not installed — was vpn_bringup.sh run first?"
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

START=$(date +%s)

# Find currently-running wireguard-go processes (named by interface).
# `pgrep -af "^[^ ]*wireguard-go "` returns "PID /path/to/wireguard-go <iface>".
CURRENT=$(pgrep -af "^[^ ]*wireguard-go " | awk '{print $NF}' | sort -u || true)
log "currently up wireguard-go interfaces: ${CURRENT:-<none>}"

# Tear down anything that isn't already the target region.
for iface in $CURRENT; do
  if [[ "$iface" != "$NEW_REGION" ]]; then
    log "tearing down $iface"
    sudo pkill -f "wireguard-go $iface" 2>&1 || err "  pkill returned non-zero (continuing)"
    sleep 0.5
    sudo ip link delete dev "$iface" 2>/dev/null || true
  else
    log "$iface already up — will skip rebuild cycle"
  fi
done

# Flush our rules + routes BEFORE bringing up the new tunnel — the
# new bring-up will re-add them with the same fwmark.
log "flushing previous policy routing"
while sudo ip -4 rule del not fwmark "$TABLE" table "$TABLE" 2>/dev/null; do :; done
while sudo ip -4 rule del table main suppress_prefixlength 0 2>/dev/null; do :; done
while sudo ip -6 rule del not fwmark "$TABLE" table "$TABLE" 2>/dev/null; do :; done
while sudo ip -6 rule del table main suppress_prefixlength 0 2>/dev/null; do :; done
sudo ip -4 route flush table "$TABLE" 2>/dev/null || true
sudo ip -6 route flush table "$TABLE" 2>/dev/null || true

# Bring up the new one if not already up.
if ! echo "$CURRENT" | grep -qw "$NEW_REGION"; then
  WG_UP="$(dirname "$0")/wg_up_userspace.sh"
  if [[ ! -x "$WG_UP" ]]; then
    err "wg_up_userspace.sh not found or not executable at $WG_UP"
    exit 2
  fi
  log "wg_up_userspace.sh $NEW_REGION"
  if ! "$WG_UP" "$NEW_REGION" 2>&1 | sed 's/^/[wg-up] /'; then
    err "wg_up_userspace.sh $NEW_REGION failed"
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
