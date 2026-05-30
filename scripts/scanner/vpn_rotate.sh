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

# Build region name variants up front. Fix from drill #5: previous
# `tr 'A-Z ' 'a-z'` was buggy — tr's source longer than target meant
# spaces got mapped to 'z' (e.g., "USA - New York" → "usaz-znewyork").
# Use sed for both lowercase and space-to-hyphen normalization.
KEBAB=$(echo "$REGION" | sed -e 's/.*/\L&/' -e 's/ *- */-/g' -e 's/ /-/g')
COUNTRY=$(echo "$REGION" | sed 's/ *-.*//')
log "region variants: primary='$REGION' kebab='$KEBAB' country='$COUNTRY'"

# ─── Strategy A: try direct connect WITHOUT explicit disconnect ─────
# Drill #5 (2026-05-30) revealed that explicit disconnect can wedge
# the daemon — every subsequent CLI call times out at 5s, including
# connect attempts. Try the "switch in one op" pattern first: just
# call connect with the new region while still connected. If
# expressvpnctl supports atomic switch, we never touch the wedge-
# prone disconnect path.
START_CONN=$(date +%s)
CONNECT_OK=false

log "attempting direct switch (connect without explicit disconnect): $REGION ..."
if timeout 15 "$CLI" connect "$REGION" 2>&1; then
  CONNECT_OK=true
  log "✓ direct switch worked"
else
  log "direct switch failed — trying disconnect+connect dance"
fi

# ─── Strategy B: fall back to disconnect+connect dance ──────────────
if ! $CONNECT_OK; then
  log "disconnecting (non-fatal — connect will replace tunnel anyway)..."
  timeout 8 "$CLI" disconnect 2>&1 || err "disconnect timed out (continuing)"
  sleep 2

  log "connecting to: $REGION ..."
  if timeout 15 "$CLI" connect "$REGION" 2>&1; then
    CONNECT_OK=true
  fi
fi

# ─── Strategy C: try common region name variants ────────────────────
if ! $CONNECT_OK; then
  err "connect to '$REGION' failed — trying fallback name formats"
  for variant in "$KEBAB" "$COUNTRY" "us" "USA"; do
    log "  trying: $variant"
    if timeout 15 "$CLI" connect "$variant" 2>&1; then
      CONNECT_OK=true
      REGION="$variant"
      break
    fi
  done
fi

# ─── Strategy D: Smart Location (no region arg) ─────────────────────
if ! $CONNECT_OK; then
  err "all named-region attempts failed — falling back to Smart Location"
  if timeout 15 "$CLI" connect 2>&1; then
    CONNECT_OK=true
    REGION="<smart-location>"
  fi
fi

# ─── Diagnostic dump if everything failed ───────────────────────────
if ! $CONNECT_OK; then
  err "all rotation strategies failed — dumping daemon state"
  err "=== expressvpnctl status ==="
  timeout 5 "$CLI" status 2>&1 || echo "  (status command also wedged)"
  err "=== expressvpnctl get smartlocation ==="
  timeout 5 "$CLI" get smartlocation 2>&1 || echo "  (get smartlocation wedged)"
  err "=== expressvpnctl get regions (first 30 lines) ==="
  timeout 10 "$CLI" get regions 2>&1 | head -30 || echo "  (get regions wedged)"
  err "=== journalctl -u expressvpn-service (last 30 lines) ==="
  sudo journalctl -u expressvpn-service.service --no-pager -n 30 2>&1 || \
    echo "  (journalctl unavailable)"
  exit 2
fi
END_CONN=$(date +%s)
log "connect took: $((END_CONN - START_CONN))s"

# Settle for the new route table.
sleep 3

# Capture post-rotate egress IP.
POST_IP=$(get_egress_ip)
log "post-rotate egress: ${POST_IP:-<unknown>}"

# When the direct-switch path is taken, START_DISC is never set
# (disconnect was skipped entirely). Use START_CONN as the rotation
# start in that case — direct switch IS the rotation start.
TOTAL=$((END_CONN - ${START_DISC:-$START_CONN} + 5))
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
