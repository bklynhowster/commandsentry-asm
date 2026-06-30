#!/usr/bin/env bash
#
# wg_up_userspace.sh — bring up a WireGuard tunnel via wireguard-go
# (userspace), bypassing wg-quick + the in-kernel `wireguard` module
# entirely. See [[58 - wireguard-go Pivot Spec]] in Obsidian for the
# full backstory.
#
# WHY: wg-quick's add_if() always runs `ip link add ... type wireguard`
# first, which on GH Actions hosted runners triggers kernel-module
# auto-load via systemd-modules-load.service — and that hangs in
# uninterruptible 'D' state forever. wireguard-go creates a TUN device
# instead (no kernel link type, no systemd path), so we never touch
# the problematic code path.
#
# Usage: wg_up_userspace.sh <region>
#   where /etc/wireguard/<region>.conf exists (already patched by
#   scripts/scanner/patch_wg_configs.py to remove DNS/Table/Killswitch).
#
# Exit codes:
#   0 — tunnel up, addresses + routes + rules in place
#   1 — config not found OR wireguard-go/wg binaries missing
#   2 — wireguard-go failed to start
#   3 — wg setconf rejected the (filtered) config
#   4 — ip command failed during routing setup

set -uo pipefail

REGION="${1:-us-nyc}"
IFACE="$REGION"  # match wg-quick's filename-as-interface convention
CONF="/etc/wireguard/${REGION}.conf"
TABLE=51820

log() { echo "[wg-up-us] $*"; }
err() { echo "[wg-up-us] ERROR: $*" >&2; }

[[ -f "$CONF" ]] || { err "config not found: $CONF"; exit 1; }
command -v wireguard-go >/dev/null || { err "wireguard-go not on PATH"; exit 1; }
command -v wg           >/dev/null || { err "wg not on PATH"; exit 1; }

# /etc/wireguard/*.conf are 0600 root:root by default. vpn_bringup.sh
# chmod's THIS region's config to 0644 before invoking us so awk can
# read it directly without a sudo cat (which mysteriously hung in scan
# #64 — possibly sudo hitting a systemd path on the runner). Keys are
# still root-owned; the runner is ephemeral + isolated so widening read
# perms on one file for the duration of the job is acceptable.
if ! [[ -r "$CONF" ]]; then
  err "config not readable by current user: $CONF"
  err "vpn_bringup.sh should have chmod'd it 0644 before calling us"
  ls -la "$CONF" >&2 || true
  exit 1
fi

# ─── 1. Create the userspace tunnel device ───────────────────────────
# wireguard-go forks to background by default and creates a TUN device
# named after its argv[1]. No kernel-link-type call, no modprobe, no
# systemd interaction.
log "starting wireguard-go for $IFACE (userspace, TUN-based)"
if ! sudo wireguard-go "$IFACE" 2>&1; then
  err "wireguard-go failed to start"
  exit 2
fi

# Give the daemon a moment to create the TUN device + UAPI socket.
sleep 1

# Verify the interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  err "wireguard-go ran but interface $IFACE didn't appear"
  ip -br link 2>&1 | sed 's/^/  /' >&2
  exit 2
fi
log "✓ TUN device $IFACE created"

# ─── 2. Apply the wg cryptokey config ────────────────────────────────
# wg setconf is strict — it rejects keys it doesn't recognize. Our
# patched configs include Address, Table, PostUp, PreDown — none of
# which are wg-setconf keys. Filter to only the recognized ones:
#   [Interface]: PrivateKey, ListenPort, FwMark
#   [Peer]:      PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive
WG_CONF=$(mktemp)
trap 'rm -f "$WG_CONF"' EXIT

awk '
  /^\[Interface\]/ { sect="iface"; print; next }
  /^\[Peer\]/      { sect="peer";  print; next }
  /^\[/            { sect="other"; next }
  sect=="iface" && /^[[:space:]]*(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
  sect=="peer"  && /^[[:space:]]*(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
  /^[[:space:]]*$/ { print; next }
  /^[[:space:]]*#/ { print; next }
' "$CONF" > "$WG_CONF"

log "applying wg config (filtered to setconf-compatible keys)"
if ! sudo wg setconf "$IFACE" "$WG_CONF"; then
  err "wg setconf rejected the config"
  err "filtered config (redacted):"
  sed -E 's/(PrivateKey|PublicKey|PresharedKey) = .*/\1 = <redacted>/' "$WG_CONF" | sed 's/^/  /' >&2
  exit 3
fi
log "✓ wg setconf applied"

# ─── 3. Extract addresses from the [Interface] block ─────────────────
# The patched configs keep the original Address= line (we only stripped
# DNS / Table / PostUp / PreDown / killswitch).
ADDR_LINE=$(awk '
  /^\[Peer\]/ { exit }
  /^[[:space:]]*Address[[:space:]]*=/ {
    sub(/^[[:space:]]*Address[[:space:]]*=[[:space:]]*/, "")
    print
    exit
  }
' "$CONF")
if [[ -z "$ADDR_LINE" ]]; then
  err "no Address= line found in [Interface] of $CONF"
  exit 4
fi
log "interface addresses: $ADDR_LINE"

IFS=',' read -ra ADDRS <<< "$ADDR_LINE"
for addr in "${ADDRS[@]}"; do
  addr=$(echo "$addr" | xargs)  # trim whitespace
  [[ -z "$addr" ]] && continue
  log "  ip address add $addr dev $IFACE"
  sudo ip address add "$addr" dev "$IFACE" 2>&1 || err "  (non-fatal — may already exist)"
done

# ─── 4. Bring the interface up + set MTU ─────────────────────────────
# MTU 1280 (IPv6 floor), not the usual WG 1420: heavy-tier testssl pulls
# full cert chains / large TLS handshakes. At 1420 the encapsulated packet
# (~1480 with WG overhead) blackholes on Mullvad/cloud underlays whose real
# path MTU is < 1500 — small HTTPS GETs fit, big handshakes stall (every
# testssl probe timed out → 900-byte degraded output, scans #836-840).
# 1280 makes the kernel auto-advertise a smaller TCP MSS so handshakes fit.
log "ip link set mtu 1280 up dev $IFACE"
if ! sudo ip link set mtu 1280 up dev "$IFACE"; then
  err "ip link set up failed"
  exit 4
fi

# ─── 5. fwmark + policy routing (mirrors what wg-quick does) ─────────
# Set fwmark BEFORE adding the routing rules so wg's own packets get
# tagged and bypass the catchall rule.
log "wg set $IFACE fwmark $TABLE"
sudo wg set "$IFACE" fwmark "$TABLE"

log "ip -4 rule + route setup"
sudo ip -4 rule add not fwmark "$TABLE" table "$TABLE"          2>&1 || true
sudo ip -4 rule add table main suppress_prefixlength 0          2>&1 || true
sudo ip -4 route add 0.0.0.0/0 dev "$IFACE" table "$TABLE"      2>&1 || true

log "ip -6 rule + route setup"
sudo ip -6 rule add not fwmark "$TABLE" table "$TABLE"          2>&1 || true
sudo ip -6 rule add table main suppress_prefixlength 0          2>&1 || true
sudo ip -6 route add ::/0 dev "$IFACE" table "$TABLE"           2>&1 || true

sudo sysctl -q net.ipv4.conf.all.src_valid_mark=1

log "✅ wireguard-go tunnel up on $IFACE (region $REGION)"

# Show what's actually running for the GH Actions log
log "wg show summary:"
sudo wg show "$IFACE" 2>&1 | sed 's/^/  /' || true
log "default routes:"
ip route show default 2>&1 | sed 's/^/  /' || true

exit 0
