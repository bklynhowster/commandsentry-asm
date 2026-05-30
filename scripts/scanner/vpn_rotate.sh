#!/usr/bin/env bash
#
# vpn_rotate.sh — Disconnect + reconnect ExpressVPN to a specified region.
# Captures the egress IP before and after so the caller can prove the
# rotation actually happened (different IP).
#
# Why this exists: pillar #2 of Phase 4a M7b — the ability to rotate
# egress mid-scan. Two flavors:
#   • Same region   → expect a new /24 within the same region's pool
#   • Cross region  → expect a new ASN entirely
#
# Usage:
#   vpn_rotate.sh "USA - New York"
#   vpn_rotate.sh "USA - Chicago"
#   vpn_rotate.sh "USA - Los Angeles"
#
# Outputs (to stdout for log capture):
#   [vpn-rotate] pre-rotate egress: <IP>
#   [vpn-rotate] disconnecting...
#   [vpn-rotate] disconnect took: Xs
#   [vpn-rotate] connecting to <region>...
#   [vpn-rotate] connect took: Xs
#   [vpn-rotate] post-rotate egress: <IP>
#   [vpn-rotate] total rotation cost: Xs
#
# Exit codes:
#   0 — rotated successfully, egress IP changed
#   2 — disconnect or connect failed
#   3 — egress IP did not change (rotation was a no-op — same exit
#       happened to be assigned again, retry recommended)

set -uo pipefail

REGION="${1:-USA - New York}"

log() {
  echo "[vpn-rotate] $*"
}

err() {
  echo "[vpn-rotate] ERROR: $*" >&2
}

# Locate the CLI — same probe logic as vpn_bringup.sh.
CLI=""
for candidate in expressvpnctl expressvpn; do
  if command -v "$candidate" &>/dev/null; then
    CLI="$candidate"
    break
  fi
done
if [[ -z "$CLI" ]]; then
  for path in /usr/bin/expressvpnctl /usr/local/bin/expressvpnctl \
              /opt/expressvpn/bin/expressvpnctl /opt/expressvpn/expressvpnctl \
              /usr/bin/expressvpn /usr/local/bin/expressvpn \
              /opt/expressvpn/bin/expressvpn; do
    if [[ -x "$path" ]]; then
      CLI="$path"
      export PATH="$(dirname "$path"):$PATH"
      break
    fi
  done
fi
if [[ -z "$CLI" ]]; then
  err "no ExpressVPN CLI on PATH — was vpn_bringup.sh run first?"
  exit 2
fi

# Capture egress IP with retry tolerance — vpn-drill.yml run #2
# (2026-05-30) showed that after reconnect, the route table can take
# longer than expected to settle. Same retry pattern as the bringup
# fix in commit d77d510: up to 5 rounds = ~30s additional wait.
get_egress_ip() {
  for round in 1 2 3 4 5; do
    for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
      ip=$(curl -s --max-time 6 "$url" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
      if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return 0
      fi
    done
    # First round: don't sleep — caller might already have waited.
    # Subsequent rounds: 5s backoff between rounds.
    [[ "$round" -lt 5 ]] && sleep 5
  done
  echo ""
}

PRE_IP=$(get_egress_ip)
log "pre-rotate egress: ${PRE_IP:-<unknown>}"

# Disconnect with timing — non-fatal. vpn-drill.yml run #4 (2026-05-30)
# showed expressvpnctl's disconnect can time out after 5s (CLI internal
# timeout) when a tunnel gets into a weird state. In that case the
# subsequent `connect` will replace whatever's there, so don't bail.
START_DISC=$(date +%s)
log "disconnecting..."
if ! "$CLI" disconnect 2>&1; then
  err "disconnect failed (non-fatal — connect will replace existing tunnel)"
fi
END_DISC=$(date +%s)
log "disconnect took: $((END_DISC - START_DISC))s"

# Brief settle delay — the route table needs a beat to release the
# previous tunnel interface before connect can claim it.
sleep 2

# Connect with timing — same defensive fallback chain as vpn_bringup.sh
# (expressvpnctl region lookup is flaky between runs per drill #3 obs).
START_CONN=$(date +%s)
log "connecting to: $REGION ..."
CONNECT_OK=false
if "$CLI" connect "$REGION" 2>&1; then
  CONNECT_OK=true
else
  err "connect to '$REGION' failed — trying fallback name formats"
  KEBAB=$(echo "$REGION" | tr 'A-Z ' 'a-z' | sed 's/ *- */-/g')
  COUNTRY=$(echo "$REGION" | sed 's/ *-.*//')
  for variant in "$KEBAB" "$COUNTRY" "us" "USA"; do
    log "  trying: $variant"
    if "$CLI" connect "$variant" 2>&1; then
      CONNECT_OK=true
      REGION="$variant"
      break
    fi
  done
fi

if ! $CONNECT_OK; then
  err "all named-region attempts failed — falling back to Smart Location"
  "$CLI" get regions 2>&1 | head -40 || true
  if "$CLI" connect 2>&1; then
    CONNECT_OK=true
    REGION="<smart-location>"
  fi
fi

if ! $CONNECT_OK; then
  err "even Smart Location connect failed"
  exit 2
fi
END_CONN=$(date +%s)
log "connect took: $((END_CONN - START_CONN))s"

# Settle for the new route table.
sleep 3

# Capture post-rotate egress IP.
POST_IP=$(get_egress_ip)
log "post-rotate egress: ${POST_IP:-<unknown>}"

TOTAL=$((END_CONN - START_DISC + 5))  # +5 for the two sleeps + IP probes
log "total rotation cost: ~${TOTAL}s"

if [[ -z "$POST_IP" ]]; then
  err "post-rotate egress could not be determined — VPN may not be routing"
  exit 3
fi

if [[ -n "$PRE_IP" ]] && [[ "$POST_IP" == "$PRE_IP" ]]; then
  err "egress IP did not change (still $POST_IP) — got reassigned to same exit"
  exit 3
fi

# Publish outputs for GH Actions consumption.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "pre_ip=$PRE_IP"        >> "$GITHUB_OUTPUT"
  echo "post_ip=$POST_IP"      >> "$GITHUB_OUTPUT"
  echo "rotation_cost_s=$TOTAL" >> "$GITHUB_OUTPUT"
fi

log "✅ rotation successful: $PRE_IP → $POST_IP"
exit 0
