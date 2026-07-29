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
#   vpn_egress_ip    — verified post-VPN egress IP (3 providers, 3 attempts)
#   vpn_baseline_ip  — runner's pre-VPN IP for comparison
#
# Exit codes:
#   0  — tunnel up, egress change VERIFIED
#   1  — wireguard install failed
#   2  — wg-quick up failed
#   3  — VERDICT: egress didn't change (traffic not routed through wg)
#   4  — egress IP unreadable after retries — cannot verify (no fail-open)
#   5  — no pre-VPN baseline captured — nothing to compare against

set -uo pipefail

log() { echo "[vpn-bringup] $*"; }
err() { echo "[vpn-bringup] ERROR: $*" >&2; }

# After the 5-region → 205-region pool expansion, configs are now named
# us-nyc-wg-001.conf etc. (per-server) rather than us-nyc.conf (per-city).
# If the requested VPN_REGION matches an existing .conf, use it. Otherwise
# pick the first available .conf alphabetically — works whether the pool
# is 5 or 205 regions.
REGION="${VPN_REGION:-}"
if [[ -z "$REGION" ]] || [[ ! -f "/etc/wireguard/${REGION}.conf" ]]; then
  FIRST_CONF=$(sudo ls /etc/wireguard/ 2>/dev/null | grep '\.conf$' | head -1)
  if [[ -n "$FIRST_CONF" ]]; then
    REGION="${FIRST_CONF%.conf}"
    log "VPN_REGION='${VPN_REGION:-<unset>}' not available — falling back to first config: $REGION"
  fi
fi

# ─── Shared egress probe — 3 providers, N attempts ───────────────────
# Used for BOTH the pre-VPN baseline and the post-VPN verification. They
# used to differ: baseline tried three providers, the post-VPN check tried
# ipify once. The verification was less robust than the measurement it
# verified against, which is backwards for a safety gate.
# Echoes an IPv4 on success, empty string on failure.
probe_egress_ip() {
  local attempts="${1:-3}" a p ip
  for ((a = 1; a <= attempts; a++)); do
    for p in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
      ip=$(curl -s --max-time 8 "$p" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
      if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"; return 0
      fi
    done
    [[ $a -lt $attempts ]] && sleep $((a * 2))
  done
  echo ""; return 1
}

# ─── Step 1: Baseline IP (pre-VPN) ───────────────────────────────────
BASELINE_IP="$(probe_egress_ip 2)"
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

# ─── Step 6: Verify egress actually changed — SAFETY GATE, no fail-open ──
#
# 2026-07-29 (gate audit, docs/gate_criticality_matrix.md). This previously did
# ONE curl to ipify and, if that curl failed, logged "continuing — tunnel is up
# per wg-quick" and PROCEEDED with the comparison skipped. That is a fail-open
# in a safety gate: a single flaky HTTP request was enough to let a scan run
# with egress UNVERIFIED — potentially over the naked GitHub runner IP, which
# is the exact thing this gate exists to prevent.
#
# wg-quick's exit code and `ip route` only prove the interface came up. They do
# not prove traffic leaves through it; a wrong route table satisfies both and
# still egresses on the runner's own address.
#
# Verdict vs transport, same invariant as gate_retry.py:
#   IP changed          -> VERDICT pass   -> proceed
#   IP unchanged        -> VERDICT fail   -> exit 3 (was already correct)
#   IP unreadable       -> TRANSPORT      -> retry; if still unreadable, exit 4
#   no baseline to compare -> UNVERIFIABLE -> exit 5
# 4.7 G4 is categorical: safety gates never fail open, and there is deliberately
# no env var to override this. Blocking a scan costs a cadence slot; scanning
# someone else's infrastructure from an unapproved address costs a lot more.
sleep 2
VPN_IP="$(probe_egress_ip 3)"
if [[ -z "$VPN_IP" ]]; then
  err "egress IP UNREADABLE after 3 attempts across 3 providers"
  err "the tunnel may be fine, but we cannot PROVE traffic is routed through it"
  err "refusing to scan with unverified egress (safety gate — no fail-open)"
  exit 4
fi
log "egress IP per curl: $VPN_IP"

if [[ -z "$BASELINE_IP" ]]; then
  err "no pre-VPN baseline IP was captured — nothing to compare against"
  err "cannot prove egress changed; refusing to scan with unverified egress"
  exit 5
fi

if [[ "$VPN_IP" == "$BASELINE_IP" ]]; then
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
