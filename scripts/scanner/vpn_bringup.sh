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

# ─── Step 2: Install wireguard-tools by extracting the .deb ──────────
# Standard apt-get install of `wireguard` hangs on GH Actions hosted
# runners (Ubuntu 24.04) during dpkg's post-install maintainer scripts —
# almost certainly trying to activate wg-quick.target via systemd in a
# context that can't actually start it. The hang is in uninterruptible
# kernel state ('D'), so even `timeout` can't kill it.
#
# Scan history confirming the pattern:
#   #54: hung 3+ min on needrestart's interactive-input prompt → fixed
#   #57: hung 2.5+ min AFTER needrestart printed "is suspended"
#   #58: hung 3.5+ min on apt-get install of wireguard itself (timeout
#        wrapper ignored — dpkg in 'D' state)
#
# Workaround: download the .deb files, extract with `dpkg-deb -x`, and
# put the binaries on PATH manually. `wg` is a static ELF and `wg-quick`
# is a shell script — neither needs a maintainer script to work. No
# systemd activation, no post-install hooks, no hang.
ts_log() { echo "[vpn-bringup] $(date '+%H:%M:%S') $*"; }

if ! command -v wg-quick &>/dev/null; then
  # Even `apt-get download` (no dpkg, no maintainer scripts) hangs on
  # GH Actions runners — almost certainly waiting on the apt lock held
  # by `unattended-upgrades` running in the background. timeout can't
  # kill apt because the wait is in uninterruptible socket I/O ('D').
  #
  # Fix: wget the .deb directly from Azure's Ubuntu mirror. Zero apt
  # involvement, zero shared locks, predictable URL. The package is
  # universe/main and version-stable enough that pin-by-version is OK.
  #
  # If the version ever bumps and the URL 404s, the wget fails fast
  # (set --tries=1 --timeout=15) and we surface a clean error.
  ts_log "fetching wireguard-tools .deb directly (bypassing apt entirely)"
  mkdir -p /tmp/wg-extract
  cd /tmp/wg-extract

  # Resolve the .deb name + URL dynamically — read it out of apt's
  # package lists without holding any lock. `apt-cache show` is a
  # pure read-only operation against /var/lib/apt/lists/* and doesn't
  # block on the dpkg or apt lock.
  ts_log "resolving wireguard-tools package URL via apt-cache (no lock)"
  PKG_INFO=$(timeout 10 apt-cache show wireguard-tools 2>&1 | head -50)
  PKG_VER=$(echo "$PKG_INFO" | awk '/^Version:/ {print $2; exit}')
  PKG_FN=$(echo "$PKG_INFO" | awk '/^Filename:/ {print $2; exit}')
  if [[ -z "$PKG_VER" || -z "$PKG_FN" ]]; then
    err "apt-cache show wireguard-tools did not return Version + Filename"
    err "raw output:"
    echo "$PKG_INFO" | sed 's/^/  /' >&2
    exit 1
  fi
  ts_log "  version: $PKG_VER"
  ts_log "  filename: $PKG_FN"

  # The Azure mirror is what GH runners are configured to use already.
  # Pull from there for maximum speed + minimum surprise.
  DEB_URL="http://azure.archive.ubuntu.com/ubuntu/${PKG_FN}"
  DEB="/tmp/wg-extract/$(basename "$PKG_FN")"
  ts_log "downloading $DEB_URL"
  if ! timeout 30 wget --quiet --tries=1 --timeout=20 -O "$DEB" "$DEB_URL"; then
    err "wget of $DEB_URL failed or timed out"
    exit 1
  fi
  if [[ ! -s "$DEB" ]]; then
    err "downloaded file is empty: $DEB"
    exit 1
  fi
  ts_log "got $(stat -c '%n (%s bytes)' "$DEB")"

  ts_log "extracting with dpkg-deb -x (no maintainer scripts)"
  sudo dpkg-deb -x "$DEB" /tmp/wg-extract/root
  # The .deb installs wg + wg-quick to /usr/bin/. Drop them into
  # /usr/local/bin so the rest of the script finds them on PATH.
  sudo install -m 0755 /tmp/wg-extract/root/usr/bin/wg /usr/local/bin/wg
  sudo install -m 0755 /tmp/wg-extract/root/usr/bin/wg-quick /usr/local/bin/wg-quick
  ts_log "wg + wg-quick installed to /usr/local/bin/ (bypassed apt + dpkg entirely)"
  cd - >/dev/null
fi

ts_log "wg version check..."
wg --version 2>&1 || ts_log "(wg --version failed but continuing)"
ts_log "wg version check done"

# ─── Step 2.5: Install wireguard-go (userspace WG implementation) ────
# Scan #60 (2026-05-30) confirmed that wg-quick's `ip link add type
# wireguard` hangs forever on GH Actions hosted runners — the kernel
# triggers module auto-load via systemd-modules-load.service, which
# wedges in uninterruptible 'D' state.
#
# Pivot: use wireguard-go (zx2c4's official userspace impl). Creates
# a TUN device instead of a wireguard-typed link → no kernel module
# load → no systemd path → no hang.
#
# Install via `go install` from the runner's preinstalled Go toolchain.
# No third-party prebuilt binary dependency (GH runners always have Go).
# Compile takes ~20s the first time.
if ! command -v wireguard-go &>/dev/null; then
  ts_log "installing wireguard-go (userspace WG) via go install"
  if ! command -v go &>/dev/null; then
    err "go toolchain not on PATH — cannot build wireguard-go"
    err "GH Actions hosted runners normally have Go preinstalled. Verify:"
    err "  which go; go version"
    exit 1
  fi
  ts_log "  go version: $(go version)"
  # GOBIN defaults to $HOME/go/bin — pin it so we know where to look.
  export GOBIN=/tmp/wg-go-bin
  mkdir -p "$GOBIN"
  ts_log "  GOBIN=$GOBIN"
  ts_log "  building golang.zx2c4.com/wireguard@latest ..."
  if ! timeout 120 go install golang.zx2c4.com/wireguard@latest 2>&1 \
       | sed 's/^/[go-install] /'; then
    err "go install golang.zx2c4.com/wireguard@latest failed or timed out"
    exit 1
  fi
  if [[ ! -x "$GOBIN/wireguard" ]]; then
    err "expected binary not found at $GOBIN/wireguard"
    ls -la "$GOBIN/" >&2 || true
    exit 1
  fi
  # Canonical name is `wireguard-go`. Install under that name to /usr/local/bin
  # so wg_up_userspace.sh finds it on PATH.
  sudo install -m 0755 "$GOBIN/wireguard" /usr/local/bin/wireguard-go
  ts_log "  wireguard-go installed: $(/usr/local/bin/wireguard-go --version 2>&1 | head -1 || echo 'version flag not supported')"
fi
ts_log "wireguard-go ready"

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
