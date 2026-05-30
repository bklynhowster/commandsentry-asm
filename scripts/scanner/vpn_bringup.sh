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
#   VPN_REGION         — region name; default "USA - New York" (forensic-friendly)
#   EXPRESSVPN_INSTALLER_PATH — local path to a pre-downloaded ExpressVPN
#                        installer. Supports both formats:
#                          .run  — universal Linux installer (recommended)
#                          .deb  — Debian/Ubuntu package
#                        The workflow should download the asset from a
#                        GH release via `gh release download` and set this
#                        env var to the resulting path.
#   EXPRESSVPN_DEB_URL — legacy: direct URL to a .deb installer. Kept for
#                        backward compatibility; prefer EXPRESSVPN_INSTALLER_PATH.
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

  INSTALLER=""

  # Preferred: EXPRESSVPN_INSTALLER_PATH set by the workflow (gh release
  # download dropped the asset locally).
  if [[ -n "${EXPRESSVPN_INSTALLER_PATH:-}" ]] && [[ -f "$EXPRESSVPN_INSTALLER_PATH" ]]; then
    INSTALLER="$EXPRESSVPN_INSTALLER_PATH"
    log "using pre-downloaded installer: $INSTALLER"

  # Legacy: download from a URL (works for .deb hosted publicly or signed S3).
  elif [[ -n "${EXPRESSVPN_DEB_URL:-}" ]]; then
    log "downloading installer from EXPRESSVPN_DEB_URL"
    if ! curl -fsSL "$EXPRESSVPN_DEB_URL" -o /tmp/expressvpn.deb; then
      err "failed to download installer from EXPRESSVPN_DEB_URL"
      exit 1
    fi
    INSTALLER="/tmp/expressvpn.deb"
  else
    err "expressvpnctl is not installed and no installer source provided."
    err "Set EXPRESSVPN_INSTALLER_PATH to a local .run or .deb file,"
    err "or EXPRESSVPN_DEB_URL to a downloadable URL."
    exit 1
  fi

  # Install based on file extension.
  case "$INSTALLER" in
    *.run)
      log "installing via universal .run installer"
      chmod +x "$INSTALLER" || true
      # ExpressVPN's .run installer explicitly refuses being launched via
      # sudo — it greps $SUDO_USER and bails with "Do not run this
      # installer with sudo." Workaround: spawn a fresh bash via sudo
      # and unset all SUDO_* vars so the installer sees a clean root
      # shell.
      #
      # Run #5 (2026-05-29) confirmed the .run installer ALSO bails
      # immediately on headless systems — its full install log was a
      # single line "Started install process" before exiting with no
      # binary written. The check is presumably "is $DISPLAY set". So
      # we install xvfb and run the installer under xvfb-run, which
      # provides a virtual X framebuffer that satisfies the check
      # without requiring a real display.
      log "installing xvfb to satisfy installer's GUI requirement"
      sudo apt-get update -qq >/dev/null 2>&1 || true
      sudo apt-get install -y -qq xvfb >/dev/null 2>&1 || \
        err "xvfb install failed — installer may still fail headless check"

      sudo bash -c "unset SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND; \
        xvfb-run --auto-servernum --server-args='-screen 0 1024x768x24' '$INSTALLER'" \
        || log "installer exited non-zero (will verify success via CLI-on-PATH check below)"
      ;;
    *.deb)
      log "installing via dpkg"
      if ! sudo dpkg -i "$INSTALLER"; then
        # dpkg may fail due to missing deps — try to fix
        sudo apt-get install -y -f -qq || true
        if ! command -v expressvpnctl &>/dev/null && ! command -v expressvpn &>/dev/null; then
          err "dpkg install failed even after apt-get -f"
          exit 1
        fi
      fi
      ;;
    *)
      err "unknown installer format: $INSTALLER (expected .run or .deb)"
      exit 1
      ;;
  esac
fi

# Some installs expose the binary as `expressvpn`, newer as `expressvpnctl`.
# Use whichever is present. The .run installer may also drop the binary
# in a non-standard location (e.g. /opt/expressvpn/) that isn't in the
# default $PATH on the runner — check known install paths explicitly.
CLI=""
for candidate in expressvpnctl expressvpn; do
  if command -v "$candidate" &>/dev/null; then
    CLI="$candidate"
    break
  fi
done

# Fallback: scan known install locations if not found via PATH.
if [[ -z "$CLI" ]]; then
  log "binary not on PATH — searching known install locations"
  for path in \
    /usr/bin/expressvpnctl \
    /usr/local/bin/expressvpnctl \
    /opt/expressvpn/bin/expressvpnctl \
    /opt/expressvpn/expressvpnctl \
    /usr/bin/expressvpn \
    /usr/local/bin/expressvpn \
    /opt/expressvpn/bin/expressvpn; do
    if [[ -x "$path" ]]; then
      CLI="$path"
      log "found at: $path"
      # Also extend PATH so subsequent calls work without absolute path.
      export PATH="$(dirname "$path"):$PATH"
      break
    fi
  done
fi

if [[ -z "$CLI" ]]; then
  err "ExpressVPN CLI not found after install"
  err "PATH=$PATH"
  err "Searching filesystem for anything 'expressvpn'-related:"
  sudo find / -xdev -iname '*expressvpn*' 2>/dev/null | head -40 || true
  err "dpkg packages matching expressvpn:"
  dpkg -l 2>/dev/null | grep -i expressvpn || echo "  (none)"
  # Cat the installer's own log — it usually explains why it bailed.
  # On the previous run we observed /tmp/expressvpn_install.log existed
  # even though no binary was installed, suggesting the installer made
  # an internal decision (likely "headless = skip everything").
  if [[ -f /tmp/expressvpn_install.log ]]; then
    err "=== /tmp/expressvpn_install.log (full contents) ==="
    sudo cat /tmp/expressvpn_install.log 2>&1 || cat /tmp/expressvpn_install.log 2>&1 || true
    err "=== end install log ==="
  else
    err "no /tmp/expressvpn_install.log to inspect"
  fi
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
# background enable: REQUIRED on headless. Per ExpressVPN's official CLI
#   tutorial (verified 2026-05-29): "To use connection commands in the
#   CLI, either the ExpressVPN GUI client must be running, OR background
#   mode must be enabled." On a GH runner there's no GUI client, so
#   without this every subsequent `connect` would silently fail.
# networklock true: kill switch — fail closed if VPN drops mid-scan
# protocol lightwayudp: ExpressVPN's modern UDP protocol, lower latency
#                       and a less-fingerprintable handshake than OpenVPN
"$CLI" background enable 2>&1 || true
"$CLI" set networklock true 2>&1 || true
"$CLI" set protocol lightwayudp 2>&1 || true
log "policies set: background, networklock, lightwayudp"

# ─── Step 5: Connect ─────────────────────────────────────────────────
# Region lookup proved FLAKY in vpn-drill.yml run #3 (2026-05-30):
# expressvpnctl normalizes "USA - New York" to "usa-new-york" and
# sometimes can't find the region (probably an ExpressVPN backend
# hiccup — the SAME name worked fine in run #2 minutes earlier).
#
# Defensive fallback chain:
#   1. Try the exact region name as provided
#   2. If that fails, try common normalization variants
#   3. If all named regions fail, fall back to `connect` (no arg) which
#      uses Smart Location — ExpressVPN picks the closest exit. We
#      sacrifice region-pinning but at least the scan can proceed.
log "connecting to: $REGION"
# Drill #7 (2026-05-30) hung for >5 min on a single connect call when
# the daemon wedged. Wrap every CLI invocation in `timeout` so a single
# hang can't lock the whole workflow.
CONNECT_OK=false
if timeout 20 "$CLI" connect "$REGION" 2>&1; then
  CONNECT_OK=true
else
  err "connect to '$REGION' failed — trying fallback name formats"
  KEBAB=$(echo "$REGION" | sed -e 's/.*/\L&/' -e 's/ *- */-/g' -e 's/ /-/g')
  COUNTRY=$(echo "$REGION" | sed 's/ *-.*//')
  for variant in "$KEBAB" "$COUNTRY" "us" "USA"; do
    log "  trying: $variant"
    if timeout 20 "$CLI" connect "$variant" 2>&1; then
      CONNECT_OK=true
      REGION="$variant"  # so the output reflects what actually worked
      break
    fi
  done
fi

if ! $CONNECT_OK; then
  err "all named-region attempts failed — falling back to Smart Location"
  log "available regions per expressvpnctl get regions (first 40):"
  timeout 10 "$CLI" get regions 2>&1 | head -40 || true
  if timeout 20 "$CLI" connect 2>&1; then
    CONNECT_OK=true
    REGION="<smart-location>"
  fi
fi

if ! $CONNECT_OK; then
  err "even Smart Location connect failed — VPN cannot be brought up"
  exit 2
fi

# Give the route table a beat to settle
sleep 4

# ─── Step 6: Verify egress IP changed ────────────────────────────────
# Retry loop: vpn-drill.yml run #1 (2026-05-30) showed that after a
# full GUI install (xvfb-run successfully tricked the installer into
# running the GUI path), the post-connect tunnel takes longer than 4s
# to be route-able. networklock=true means IP-probe curls hit the
# killswitch and time out before we recover.
#
# Strategy: probe each provider; if all three fail, sleep 5s and try
# again. Total cap of 5 rounds = up to ~30s additional wait beyond the
# initial 4s sleep before declaring the tunnel dead.
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
  log "no egress IP yet on round $round — sleeping 5s and retrying"
  sleep 5
done

log "egress IP after connect: ${VPN_IP:-<unknown>}"

if [[ -z "$VPN_IP" ]]; then
  err "couldn't determine egress IP from any provider after 5 retry rounds (~30s)"
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
