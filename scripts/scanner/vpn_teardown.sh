#!/usr/bin/env bash
#
# vpn_teardown.sh — Tear down all wg-quick interfaces. Best-effort.

set -u

log() { echo "[vpn-teardown] $*"; }

if ! command -v wg-quick &>/dev/null; then
  log "wg-quick not installed — nothing to tear down"
  exit 0
fi

UP_IFACES=$(sudo wg show interfaces 2>/dev/null || true)
if [[ -z "$UP_IFACES" ]]; then
  log "no wireguard interfaces up — nothing to tear down"
  exit 0
fi

for iface in $UP_IFACES; do
  log "wg-quick down $iface"
  sudo wg-quick down "$iface" 2>&1 || log "  $iface down returned non-zero (continuing)"
done

log "teardown complete"
exit 0
