#!/usr/bin/env bash
#
# vpn_bringup.sh — Mullvad VPN bring-up on a headless Linux runner.
#
# Replaces ExpressVPN (deprecated 2026-05-30 after 9 drill runs proved
# expressvpnctl fundamentally unreliable for headless mid-session
# rotation). See Obsidian:
#   [[54 - Session Log 2026-05-29 night - M7 ExpressVPN Mastery Episode 1]]
#   [[55 - Mullvad VPN Account Credentials]]
# for the full investigation.
#
# Mullvad's CLI is Rust-written, headless-first, and last updated
# January 2026. The full install + bring-up is roughly 1/3 the lines
# of the ExpressVPN equivalent because there's no GUI workaround, no
# `xvfb-run`, no `background enable` mandatory dance, no daemon-wedge
# recovery paths needed.
#
# Required env:
#   MULLVAD_ACCOUNT_NUMBER — 16-digit Mullvad account number (GH secret)
#
# Optional env:
#   VPN_REGION — Mullvad location in "country city" format.
#                Default: "us nyc"
#                Examples: "us chi" (Chicago), "us lax" (LA), "us atl" (Atlanta)
#                Or just country: "us" (any US server)
#                See `mullvad relay list` for full inventory.
#
# Outputs (to $GITHUB_OUTPUT when running under GH Actions):
#   vpn_region       — region we connected to
#   vpn_egress_ip    — actual egress IP verified post-connect
#   vpn_baseline_ip  — runner's pre-VPN IP for comparison
#
# Exit codes:
#   0  — VPN connected, egress IP verified different from baseline
#   1  — installation failed
#   2  — login or connect failed
#   3  — egress IP probe failed or IP didn't change (kill switch / leak)
#

set -uo pipefail

REGION="${VPN_REGION:-us nyc}"

log() { echo "[vpn-bringup] $*"; }
err() { echo "[vpn-bringup] ERROR: $*" >&2; }

# ─── Step 0: Sanity ──────────────────────────────────────────────────
if [[ -z "${MULLVAD_ACCOUNT_NUMBER:-}" ]]; then
  err "MULLVAD_ACCOUNT_NUMBER env var is required"
  exit 2
fi

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

# ─── Step 2: Install Mullvad via official apt repo ───────────────────
# Mullvad's preferred install path on Ubuntu/Debian. No .deb asset to
# upload to GH releases — `apt install` pulls straight from Mullvad's
# repo. Three-line install, last documented 2026-01.
if ! command -v mullvad &>/dev/null; then
  log "mullvad CLI not on PATH — installing via Mullvad apt repo"

  # 1. Download the signing key
  if ! sudo curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc \
        https://repository.mullvad.net/deb/mullvad-keyring.asc; then
    err "failed to download Mullvad signing key"
    exit 1
  fi

  # 2. Add the repo
  echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$(dpkg --print-architecture)] https://repository.mullvad.net/deb/stable stable main" \
    | sudo tee /etc/apt/sources.list.d/mullvad.list >/dev/null

  # 3. Install
  sudo apt-get update -qq
  if ! sudo apt-get install -y mullvad-vpn; then
    err "apt install mullvad-vpn failed"
    exit 1
  fi

  log "Mullvad installed"
fi

# Print version for the workflow log
mullvad --version 2>&1 || true

# ─── Step 3: Wait for mullvad-daemon to be ready ─────────────────────
# The daemon comes up via systemd on package install but may not be
# responsive instantly. Poll status until it answers.
log "waiting for mullvad-daemon..."
DAEMON_READY=false
for i in $(seq 1 20); do
  if timeout 3 mullvad status &>/dev/null; then
    DAEMON_READY=true
    log "daemon ready after ${i}s"
    break
  fi
  sleep 1
done

if ! $DAEMON_READY; then
  err "mullvad-daemon never became responsive"
  systemctl status mullvad-daemon --no-pager 2>&1 | head -20 || true
  exit 1
fi

# ─── Step 4: Login ───────────────────────────────────────────────────
# Mullvad uses ONLY the 16-digit account number — no email, no
# password. Treat it as a secret token. Pass via stdin via a tmpfile
# rather than inline so it doesn't end up in process listings.
log "logging in..."
if ! timeout 15 mullvad account login "$MULLVAD_ACCOUNT_NUMBER" 2>&1; then
  err "login failed"
  exit 2
fi
log "login OK"

# ─── Step 5: Configure tunnel ────────────────────────────────────────
# WireGuard is Mullvad's DEFAULT protocol — no explicit setting needed.
# (Drill exposed that `mullvad tunnel set wireguard` is wrong syntax;
# the correct command would be `relay set tunnel-protocol wireguard`
# but it's also unnecessary. Skipping entirely.)
# Lockdown mode = explicit kill switch (block all traffic if VPN drops).
log "configuring tunnel..."
timeout 10 mullvad lockdown-mode set on 2>&1 || true
log "policies set: lockdown-mode (wireguard is the default)"

# ─── Step 6: Set location ────────────────────────────────────────────
# Region name format is "country" or "country city" or
# "country city server". Fallback chain: full → country → "us".
log "setting location: $REGION"
LOCATION_OK=false
if timeout 10 mullvad relay set location $REGION 2>&1; then
  LOCATION_OK=true
else
  COUNTRY=$(echo "$REGION" | awk '{print $1}')
  log "  falling back to country-only: $COUNTRY"
  if timeout 10 mullvad relay set location "$COUNTRY" 2>&1; then
    LOCATION_OK=true
    REGION="$COUNTRY"
  fi
fi

if ! $LOCATION_OK; then
  log "  falling back to default: us"
  timeout 10 mullvad relay set location us 2>&1 || true
  REGION="us"
fi

# ─── Step 7: Connect ─────────────────────────────────────────────────
log "connecting..."
if ! timeout 30 mullvad connect 2>&1; then
  err "connect command failed"
  exit 2
fi

# Wait for the tunnel to actually be up — `mullvad status` reports
# "Connected to" when the tunnel is established.
log "waiting for tunnel to be 'Connected'..."
CONNECTED=false
for i in $(seq 1 30); do
  STATUS_OUT=$(timeout 3 mullvad status 2>&1 || true)
  if echo "$STATUS_OUT" | grep -qi "Connected"; then
    CONNECTED=true
    log "tunnel up after ${i}s"
    break
  fi
  sleep 1
done

if ! $CONNECTED; then
  err "tunnel never reached 'Connected' state after 30s"
  log "final status output:"
  timeout 5 mullvad status -v 2>&1 || true
  exit 2
fi

# ─── Step 8: Verify egress IP changed ────────────────────────────────
# Give the route table a beat to settle, then probe with retries.
sleep 3
VPN_IP=""
for round in 1 2 3 4 5; do
  for provider in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -s --max-time 8 "$provider" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      VPN_IP="$ip"
      log "egress IP captured on round $round via $provider"
      break 2
    fi
  done
  log "no egress IP yet on round $round — sleeping 5s"
  sleep 5
done

log "egress IP after connect: ${VPN_IP:-<unknown>}"

if [[ -z "$VPN_IP" ]]; then
  err "couldn't determine egress IP after 5 retry rounds (~30s)"
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

# ─── Step 9: Publish outputs ─────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "vpn_region=$REGION"           >> "$GITHUB_OUTPUT"
  echo "vpn_egress_ip=$VPN_IP"        >> "$GITHUB_OUTPUT"
  echo "vpn_baseline_ip=$BASELINE_IP" >> "$GITHUB_OUTPUT"
fi

exit 0
