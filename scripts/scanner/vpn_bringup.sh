#!/usr/bin/env bash
#
# vpn_bringup.sh — Install (if needed) + connect ExpressVPN on a Linux
# Github Actions runner so Medium / Heavy tier scans can egress through
# a residential-shaped IP that won't trip FortiGate / Cloudflare WAFs.
#
# Why ExpressVPN: per [[project_phase4_expressvpn_requirement]] (memory
# note 2026-05-16) — Howie has ExpressVPN+ Advanced (12 simultaneous
# connections) and verified the Smart Connect exit IPs work against
# Command's FortiGate. JA3/JA4 fingerprints align with residential
# traffic, not cloud-runner traffic.
#
# Why NOT OpenVPN: Howie researched this 2026-05-16 — the official
# expressvpnctl CLI is explicitly headless-friendly and gives access
# to all the same features (network lock, lightway-udp, region pin)
# with cleaner ergonomics than .ovpn configs.
#
# Required environment:
#   EXPRESSVPN_ACTIVATION_CODE   — GH secret containing Howie's activation code
#
# Optional environment:
#   VPN_REGION       — region name; default "USA - New York" (forensic-friendly)
#   EXPRESSVPN_DEB_URL — direct URL to a downloadable .deb installer if
#                        expressvpnctl isn't already present on the runner.
#                        Hosting suggestions: private GH release asset,
#                        S3 with pre-signed URL, etc.
#
# Outputs (written to $GITHUB_OUTPUT when running under GH Actions):
#   vpn_region       — connected region (echoes back the input or default)
#   vpn_egress_ip    — actual egress IP verified after connect
#   vpn_baseline_ip  — runner's baseline IP before VPN was brought up
#
# Exit codes:
#   0  — VPN connected, egress IP verified different from baseline
#   1  — installation failed
#   2  — login or connect failed
#   3  — egress IP did not change (kill switch / leak risk)
#

set -uo pipefail

REGION="${VPN_REGION:-USA - New York}"

log() {
  echo "[vpn-bringup] $*"
}

err() {
  echo "[vpn-bringup] ERROR: $*" >&2
}

# ─── Step 0: Sanity ──────────────────────────────────────────────────
if [[ -z "${EXPRESSVPN_ACTIVATION_CODE:-}" ]]; then
  err "EXPRESSVPN_ACTIVATION_CODE env var is required"
  exit 2
fi

# ─── Step 1: Baseline IP (pre-VPN) ───────────────────────────────────
# Captured here so we can later prove the egress IP actually changed.
# Use multiple providers — if one is rate-limiting GH Actions IPs,
# the other may succeed.
BASELINE_IP=""
for provider in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
  ip=$(curl -s --max-time 8 "$provider" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
  if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    BASELINE_IP="$ip"
    break
  fi
done
log "baseline runner IP (pre-VPN): ${BASELINE_IP:-<unknown>}"

# ─── Step 2: Install expressvpnctl if needed ─────────────────────────
if ! command -v expressvpnctl &>/dev/null && ! command -v expressvpn &>/dev/null; then
  log "expressvpnctl not found on PATH — attempting install"

  if [[ -n "${EXPRESSVPN_DEB_URL:-}" ]]; then
    log "downloading installer from EXPRESSVPN_DEB_URL"
    if ! curl -fsSL "$EXPRESSVPN_DEB_URL" -o /tmp/expressvpn.deb; then
      err "failed to download installer from EXPRESSVPN_DEB_URL"
      exit 1
    fi
    log "installing via dpkg"
    if ! sudo dpkg -i /tmp/expressvpn.deb; then
      # dpkg may fail due to missing deps — try to fix
      sudo apt-get install -y -f -qq || true
      if ! command -v expressvpnctl &>/dev/null && ! command -v expressvpn &>/dev/null; then
        err "dpkg install failed even after apt-get -f"
        exit 1
      fi
    fi
    rm -f /tmp/expressvpn.deb
  else
    err "expressvpnctl is not installed and EXPRESSVPN_DEB_URL is not set"
    err "Either pre-install the CLI in a custom runner image, or set"
    err "EXPRESSVPN_DEB_URL to a downloadable .deb installer."
    exit 1
  fi
fi

# Some installs expose the binary as `expressvpn`, newer as `expressvpnctl`.
# Use whichever is present.
CLI=""
if command -v expressvpnctl &>/dev/null; then
  CLI="expressvpnctl"
elif command -v expressvpn &>/dev/null; then
  CLI="expressvpn"
fi

if [[ -z "$CLI" ]]; then
  err "expressvpnctl install reported success but the binary is not on PATH"
  exit 1
fi

log "using CLI: $CLI"
"$CLI" --version 2>/dev/null || true

# ─── Step 3: Login ───────────────────────────────────────────────────
# Write the activation code to a 600-permission tmp file, then nuke it
# immediately after login. Never echo the code itself in logs.
ACTCODE_FILE=$(mktemp /tmp/expressvpn-actcode.XXXXXX)
chmod 600 "$ACTCODE_FILE"
printf '%s' "$EXPRESSVPN_ACTIVATION_CODE" > "$ACTCODE_FILE"

if ! "$CLI" login "$ACTCODE_FILE" 2>&1; then
  err "login failed"
  rm -f "$ACTCODE_FILE"
  exit 2
fi
rm -f "$ACTCODE_FILE"
log "login OK"

# ─── Step 4: Configure ───────────────────────────────────────────────
# background enable: headless / no system tray
# networklock true: kill switch — fail closed if VPN drops mid-scan
# protocol lightwayudp: ExpressVPN's modern UDP protocol, lower latency
#                       and a less-fingerprintable handshake than OpenVPN
"$CLI" background enable 2>&1 || true
"$CLI" set networklock true 2>&1 || true
"$CLI" set protocol lightwayudp 2>&1 || true
log "policies set: background, networklock, lightwayudp"

# ─── Step 5: Connect ─────────────────────────────────────────────────
log "connecting to: $REGION"
if ! "$CLI" connect "$REGION" 2>&1; then
  err "connect to '$REGION' failed"
  exit 2
fi

# Give the route table a beat to settle
sleep 4

# ─── Step 6: Verify egress IP changed ────────────────────────────────
VPN_IP=""
for provider in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
  ip=$(curl -s --max-time 8 "$provider" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
  if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    VPN_IP="$ip"
    break
  fi
done

log "egress IP after connect: ${VPN_IP:-<unknown>}"

if [[ -z "$VPN_IP" ]]; then
  err "couldn't determine egress IP from any provider"
  exit 3
fi

if [[ -n "$BASELINE_IP" ]] && [[ "$VPN_IP" == "$BASELINE_IP" ]]; then
  err "egress IP did not change — VPN is not actually routing traffic"
  err "baseline: $BASELINE_IP, post-VPN: $VPN_IP"
  exit 3
fi

log "✅ VPN connected"
log "  region:      $REGION"
log "  baseline IP: $BASELINE_IP"
log "  egress IP:   $VPN_IP"

# ─── Step 7: Publish outputs ─────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "vpn_region=$REGION"          >> "$GITHUB_OUTPUT"
  echo "vpn_egress_ip=$VPN_IP"       >> "$GITHUB_OUTPUT"
  echo "vpn_baseline_ip=$BASELINE_IP" >> "$GITHUB_OUTPUT"
fi

exit 0
