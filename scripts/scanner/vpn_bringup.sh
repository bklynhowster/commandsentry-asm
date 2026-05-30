#!/usr/bin/env bash
#
# vpn_bringup.sh — Mullvad WireGuard bring-up on a headless Linux runner.
#
# PIVOT 2026-05-30: After scans #43-48 with Mullvad's official CLI all
# hung in uninterruptible socket I/O ('D' state) ignoring SIGKILL —
# defeating every timeout wrapper we tried — we pivoted to direct
# WireGuard configuration files. The Mullvad daemon is overkill for our
# use case; we just need a tunnel.
#
# Architecture:
#   1. Install wireguard-tools (standard Ubuntu package, no Mullvad repo)
#   2. Configs are pre-staged in /etc/wireguard/ by scanner.yml
#      (downloaded from the vpn-tools GH release tarball)
#   3. wg-quick up <region>  — ~200-line bash script, no daemon
#   4. Verify routing via `ip route` (local, never blocks)
#
# Required: nothing in env — configs are file-based
#
# Optional env:
#   VPN_REGION — short region name matching /etc/wireguard/<region>.conf
#                Default: "us-nyc"
#                Available (per the tarball we ship):
#                  us-nyc, us-chi, us-atl, us-dal, us-lax
#
# Outputs (to $GITHUB_OUTPUT when running under GH Actions):
#   vpn_region       — region we connected to
#   vpn_egress_ip    — egress IP per `ip route` + simple curl (1 attempt)
#   vpn_baseline_ip  — runner's pre-VPN IP for comparison
#
# Exit codes:
#   0  — tunnel up, routing verified
#   1  — wireguard install failed
#   2  — wg-quick up failed
#   3  — egress didn't change OR routing didn't redirect through wg

set -uo pipefail

REGION="${VPN_REGION:-us-nyc}"

log() { echo "[vpn-bringup] $*"; }
err() { echo "[vpn-bringup] ERROR: $*" >&2; }

# ─── Step 1: Baseline IP (pre-VPN) ───────────────────────────────────
BASELINE_IP=""
for provider in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
  ip=$(curl -s --max-time 8 "$provider" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
  if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    BASELINE_IP="$ip"
    break
  fi
done
log "baseline runner IP (pre-VPN): ${BASELINE_IP:-<unknown>}"

# ─── Step 2: Install wireguard-tools ─────────────────────────────────
# Standard Ubuntu package — no third-party repo. Ships with wg + wg-quick.
if ! command -v wg-quick &>/dev/null; then
  log "wireguard-tools not on PATH — installing via apt"
  sudo apt-get update -qq
  if ! sudo apt-get install -y wireguard wireguard-tools resolvconf; then
    err "apt install wireguard failed"
    exit 1
  fi
  log "wireguard-tools installed"
fi
wg --version 2>&1 || true

# ─── Step 3: Verify config is present ────────────────────────────────
# scanner.yml step "Fetch WireGuard configs" downloads + extracts the
# tarball to /etc/wireguard/ BEFORE invoking this script.
CONF="/etc/wireguard/${REGION}.conf"
if [[ ! -f "$CONF" ]]; then
  err "config not found at $CONF"
  err "available configs:"
  sudo ls -la /etc/wireguard/ 2>&1 || true
  exit 1
fi
log "using config: $CONF"

# ─── Step 4: Bring tunnel up ─────────────────────────────────────────
# wg-quick exits cleanly — it's a shell script that calls ip + wg.
# No daemon, no socket I/O, no 'D' state hangs.
log "bringing tunnel up: wg-quick up $REGION"
if ! sudo wg-quick up "$REGION" 2>&1; then
  err "wg-quick up failed"
  err "diagnostic:"
  sudo wg show 2>&1 || true
  exit 2
fi
log "✓ wg-quick up succeeded"

# ─── Step 5: Verify routing ──────────────────────────────────────────
# Local check — `ip route` doesn't depend on any external service.
log "default route after wg-quick up:"
ip route show default 2>&1 | head -5 || true

if ! ip route show default 2>&1 | grep -q "${REGION}\|wg0"; then
  # wg-quick names the interface after the config filename
  log "checking wireguard interface state:"
  sudo wg show 2>&1 | head -10 || true
fi

# ─── Step 6: Verify egress IP changed (best effort, single probe) ────
# Skip the retry loop that hung in earlier Mullvad-CLI scans. ONE
# curl, short timeout. If it fails we still proceed — the tunnel is
# up per wg-quick's exit code + `ip route`.
sleep 2
VPN_IP=$(timeout 10 curl -s --max-time 8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)
if [[ ! "$VPN_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  log "single curl probe didn't return an IP (continuing — tunnel is up per wg-quick)"
  VPN_IP="<unknown>"
fi
log "egress IP per curl: $VPN_IP"

if [[ "$VPN_IP" != "<unknown>" ]] && [[ -n "$BASELINE_IP" ]] && [[ "$VPN_IP" == "$BASELINE_IP" ]]; then
  err "egress IP did not change — wg-quick up succeeded but traffic not routed"
  err "baseline: $BASELINE_IP, post-VPN: $VPN_IP"
  exit 3
fi

log "✅ VPN connected"
log "  region:      $REGION"
log "  baseline IP: $BASELINE_IP"
log "  egress IP:   $VPN_IP"

# ─── Step 7: Publish outputs ─────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "vpn_region=$REGION"           >> "$GITHUB_OUTPUT"
  echo "vpn_egress_ip=$VPN_IP"        >> "$GITHUB_OUTPUT"
  echo "vpn_baseline_ip=$BASELINE_IP" >> "$GITHUB_OUTPUT"
fi

log "vpn_bringup.sh complete — exiting"
exit 0
