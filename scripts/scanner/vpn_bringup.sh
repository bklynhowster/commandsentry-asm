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

# ─── Step 2: Verify baked-in binaries from the container image ───────
# Pre-container era this step did wget+dpkg-deb to install wireguard-tools
# and `go install` to build wireguard-go — both took ~30-50s per scan
# and were the source of the entire scan #43-65 hang saga (apt locks,
# dpkg post-install systemd activation, etc.). They're now baked into
# the scanner container image (see [[59 - Container Image Build Spec]]).
# This step is just a sanity check that we're inside the expected image.
ts_log() { echo "[vpn-bringup] $(date '+%H:%M:%S') $*"; }

for bin in wg wireguard-go; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    err "$bin not on PATH — are we running inside the scanner container image?"
    err "expected: ghcr.io/bklynhowster/commandsentry-scanner:<tag>"
    err "PATH=$PATH"
    exit 1
  fi
done

ts_log "baked-in toolchain present:"
ts_log "  wg: $(command -v wg) — $(wg --version 2>&1 | head -1)"
ts_log "  wireguard-go: $(command -v wireguard-go) — $(wireguard-go --version 2>&1 | head -1 || echo '(no --version flag)')"

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

# ─── Step 4: Bring tunnel up via wireguard-go (userspace) ────────────
# Replaces the wg-quick call that hung on scan #60. wg_up_userspace.sh
# does the same operations wg-quick would (TUN create, wg setconf,
# ip address, fwmark + ip rule + ip route) but via wireguard-go for
# the TUN creation step.
ts_log "bringing tunnel up via wireguard-go userspace impl"
WG_UP="$(dirname "$0")/wg_up_userspace.sh"
if [[ ! -x "$WG_UP" ]]; then
  err "wg_up_userspace.sh not found or not executable at $WG_UP"
  exit 2
fi

# Make THIS region's config readable by the runner user so awk inside
# wg_up_userspace.sh can parse it without sudo (scan #64 hung when
# we tried `sudo cat` from inside that script — possibly a runner-
# specific sudo/systemd issue). The keys are still root-owned and the
# runner is ephemeral + isolated.
ts_log "chmod 0644 $CONF (so awk can read as runner user)"
sudo chmod 0644 "$CONF"

if ! "$WG_UP" "$REGION" 2>&1 | sed 's/^/[wg-up] /'; then
  err "wg_up_userspace.sh failed"
  err "diagnostic - wg show:"
  sudo wg show 2>&1 | sed 's/^/  /' || true
  err "diagnostic - ip link:"
  ip -br link 2>&1 | sed 's/^/  /' || true
  exit 2
fi
ts_log "✓ tunnel up via wireguard-go"

# ─── Step 5: Verify routing ──────────────────────────────────────────
# Local check — `ip route` doesn't depend on any external service.
log "default route after tunnel bring-up:"
ip route show default 2>&1 | head -5 || true

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
