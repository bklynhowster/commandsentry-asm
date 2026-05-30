#!/usr/bin/env bash
#
# vpn_teardown.sh — Tear down WireGuard userspace tunnels. Best-effort.
#
# Post-pivot to wireguard-go (see [[58 - wireguard-go Pivot Spec]]),
# tunnels are TUN devices created by the wireguard-go daemon, not
# kernel wg interfaces. Teardown is:
#   1. Kill the wireguard-go process for the interface (releases TUN)
#   2. Flush our ip rules (idempotent — safe if already gone)
#   3. ip link delete the interface if it lingers
#
# We don't bother with wg-quick down since we never used wg-quick up.

set -u

TABLE=51820

log() { echo "[vpn-teardown] $*"; }

# Find any wireguard-go processes — match by argv (the iface name).
# wireguard-go's process line looks like: `wireguard-go us-nyc`
WG_PIDS=$(pgrep -af "^[^ ]*wireguard-go " | awk '{print $1, $NF}' || true)

if [[ -z "$WG_PIDS" ]]; then
  log "no wireguard-go processes running — nothing to tear down"
else
  while read -r pid iface; do
    [[ -z "$pid" ]] && continue
    log "killing wireguard-go pid=$pid iface=$iface"
    sudo kill "$pid" 2>&1 || log "  (kill returned non-zero — process may already be gone)"
  done <<< "$WG_PIDS"
  # Brief grace period for processes to shut down + release TUN devices
  sleep 1
fi

# Best-effort: delete any lingering interfaces matching our naming pattern
for iface in us-nyc us-chi us-atl us-dal us-lax; do
  if ip link show "$iface" >/dev/null 2>&1; then
    log "ip link delete dev $iface"
    sudo ip link delete dev "$iface" 2>&1 || log "  (delete returned non-zero)"
  fi
done

# Flush our policy routing rules. Use 'while' loops because each call
# only deletes one matching rule, and we may have duplicates from
# multiple bring-ups in the same job.
log "flushing ip rules for table $TABLE"
while sudo ip -4 rule del not fwmark "$TABLE" table "$TABLE" 2>/dev/null; do :; done
while sudo ip -4 rule del table main suppress_prefixlength 0 2>/dev/null; do :; done
while sudo ip -6 rule del not fwmark "$TABLE" table "$TABLE" 2>/dev/null; do :; done
while sudo ip -6 rule del table main suppress_prefixlength 0 2>/dev/null; do :; done

# Routes in table 51820 disappear automatically when the interface goes away,
# but flush the table for cleanliness.
sudo ip -4 route flush table "$TABLE" 2>/dev/null || true
sudo ip -6 route flush table "$TABLE" 2>/dev/null || true

log "teardown complete"
exit 0
