#!/usr/bin/env bash
# COMMANDsentry — ASM discovery engine
# ────────────────────────────────────
# Reads target config from data/targets.yml, runs the lean ASM tool stack,
# pipes raw outputs to a working dir, hands off to normalize.py for final JSON.
#
# Usage:
#   ./asm-discover.sh <target-id>           # scan one target by ID
#   ./asm-discover.sh --all                 # scan every enabled target
#   ./asm-discover.sh <target-id> --dry-run # show what would run, don't execute
#
# Exits non-zero on:
#   - missing target / scope_verified false
#   - all phases failed
#   - normalizer validation failure

# NO `set -e` — phases run independently, individual tool failure shouldn't kill the whole scan.
set -uo pipefail

# ─── Locate repo root (works whether script is symlinked or not) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGETS_FILE="$REPO_ROOT/data/targets.yml"
ASSETS_DIR="$REPO_ROOT/data/assets"
RAW_DIR="$REPO_ROOT/data/raw"     # gitignored, raw tool outputs
PROFILES_DIR="$SCRIPT_DIR/profiles"
NORMALIZER="$SCRIPT_DIR/normalize.py"

# ─── Helpers ───────────────────────────────────────────────────────
log()   { printf "\033[1;36m[%s]\033[0m %s\n" "$(date -u +%H:%M:%S)" "$*" >&2; }
warn()  { printf "\033[1;33m[%s WARN]\033[0m %s\n" "$(date -u +%H:%M:%S)" "$*" >&2; }
fail()  { printf "\033[1;31m[%s FAIL]\033[0m %s\n" "$(date -u +%H:%M:%S)" "$*" >&2; }
phase() { printf "\033[1;35m▸ Phase: %s\033[0m\n" "$*" >&2; }

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { fail "Required tool not found: $1 — run scanner/install-tools.sh"; exit 2; }
}

# ─── Argument parsing ──────────────────────────────────────────────
TARGET_ID=""
DRY_RUN=0
SCAN_ALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)     SCAN_ALL=1; shift ;;
    --dry-run) DRY_RUN=1;  shift ;;
    -h|--help)
      grep '^#' "$0" | head -25 | sed 's/^# \?//'
      exit 0 ;;
    *)
      [[ -z "$TARGET_ID" ]] && TARGET_ID="$1" && shift || { fail "Unexpected arg: $1"; exit 1; } ;;
  esac
done

if [[ -z "$TARGET_ID" && $SCAN_ALL -eq 0 ]]; then
  fail "Usage: $0 <target-id> | --all"
  exit 1
fi

# ─── Tool sanity check ─────────────────────────────────────────────
for t in subfinder dnsx httpx naabu fingerprintx nuclei wafw00f whois jq yq python3; do
  require_tool "$t"
done

# ─── Read target config ────────────────────────────────────────────
[[ -f "$TARGETS_FILE" ]] || { fail "$TARGETS_FILE not found. Copy targets.yml.example."; exit 1; }

read_target_field() {
  local id="$1" field="$2"
  yq ".targets[] | select(.id == \"$id\") | .$field" "$TARGETS_FILE" 2>/dev/null | sed 's/^null$//'
}

list_enabled_targets() {
  yq '.targets[] | select(.enabled != false) | .id' "$TARGETS_FILE" 2>/dev/null | tr -d '"'
}

# ─── Single target discovery flow ──────────────────────────────────
discover_one() {
  local id="$1"
  local type value scope owner profile rate

  type=$(read_target_field "$id" "type")
  value=$(read_target_field "$id" "value")
  scope=$(read_target_field "$id" "scope_verified")
  owner=$(read_target_field "$id" "owner")
  profile=$(read_target_field "$id" "profile")
  rate=$(read_target_field "$id" "rate_limit")

  [[ -z "$type" || -z "$value" ]] && { fail "Target '$id' missing type or value"; return 1; }

  if [[ "$scope" != "true" ]]; then
    fail "Target '$id' scope_verified is not true. Refusing to scan."
    fail "Set scope_verified: true in targets.yml after confirming authorization. See docs/runbook.md."
    return 2
  fi

  # Default profile
  [[ -z "$rate" || "$rate" == "null" ]] && rate="normal"
  local profile_file="$PROFILES_DIR/$rate.env"
  [[ -f "$profile_file" ]] || { fail "Rate profile not found: $rate (looking for $profile_file)"; return 1; }

  # Load profile
  set -a; source "$profile_file"; set +a

  # Working dir for raw outputs (one per scan)
  local scan_id="scan_$(date -u +%Y-%m-%dT%H:%M:%SZ)_$(openssl rand -hex 4 2>/dev/null || echo "$$")"
  local work_dir="$RAW_DIR/$id/$scan_id"
  mkdir -p "$work_dir"

  log "═══════════════════════════════════════════════════════════"
  log "Target:    $id"
  log "Type:      $type"
  log "Value:     $value"
  log "Owner:     ${owner:-unset}"
  log "Profile:   $rate"
  log "Scan ID:   $scan_id"
  log "Work dir:  $work_dir"
  log "═══════════════════════════════════════════════════════════"

  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY RUN — not executing phases"
    return 0
  fi

  local started_at; started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "$started_at" > "$work_dir/_started"
  echo "$type"       > "$work_dir/_target_type"
  echo "$value"      > "$work_dir/_target_value"
  echo "$id"         > "$work_dir/_target_id"
  cp "$profile_file" "$work_dir/_profile.env"

  case "$type" in
    fqdn) discover_fqdn "$value" "$work_dir" ;;
    apex) discover_apex "$value" "$work_dir" ;;
    ip)   discover_ip   "$value" "$work_dir" ;;
    cidr) discover_cidr "$value" "$work_dir" ;;
    asn)  fail "asn type not yet implemented (Phase 2)"; return 1 ;;
    *)    fail "Unknown target type: $type"; return 1 ;;
  esac

  local completed_at; completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "$completed_at" > "$work_dir/_completed"

  # Hand off to normalizer
  phase "normalize → JSON"
  local out_json="$ASSETS_DIR/$id.json"
  local prev_json="$out_json"   # for delta computation

  python3 "$NORMALIZER" \
    --target-id   "$id" \
    --scan-id     "$scan_id" \
    --work-dir    "$work_dir" \
    --schema      "$REPO_ROOT/schemas/asset-schema.md" \
    --targets     "$TARGETS_FILE" \
    --previous    "$prev_json" \
    --out         "$out_json"

  if [[ $? -eq 0 ]]; then
    log "✓ Wrote $out_json"
  else
    fail "Normalizer failed — output not written"
    return 3
  fi
}

# ─── Phase: FQDN discovery ─────────────────────────────────────────
discover_fqdn() {
  local target="$1" wd="$2"

  phase "DNS resolution + records (dnsx)"
  echo "$target" | dnsx -silent -resp -a -aaaa -cname -mx -ns -txt -json \
    -t "${DNSX_THREADS:-25}" -timeout 5 \
    > "$wd/dnsx.json" 2> "$wd/dnsx.err" || warn "dnsx phase had errors (see dnsx.err)"

  phase "WHOIS lookup"
  whois "$target" > "$wd/whois.txt" 2> "$wd/whois.err" || warn "whois phase had errors"

  # Extract resolved IPs for downstream phases
  jq -r '.a[]?, .aaaa[]?' "$wd/dnsx.json" 2>/dev/null | sort -u > "$wd/_resolved_ips.txt"
  local ip_count=$(wc -l < "$wd/_resolved_ips.txt")
  log "Resolved $ip_count IP(s)"

  if [[ $ip_count -eq 0 ]]; then
    warn "No IPs resolved — skipping IP-dependent phases"
    return 0
  fi

  phase "Port discovery (naabu)"
  naabu -list "$wd/_resolved_ips.txt" \
    -top-ports "${NAABU_TOP_PORTS:-1000}" \
    -rate "${NAABU_RATE:-1000}" \
    -scan-type CONNECT \
    -silent -json \
    > "$wd/naabu.json" 2> "$wd/naabu.err" || warn "naabu had errors"

  phase "Service fingerprinting (fingerprintx)"
  if [[ -s "$wd/naabu.json" ]]; then
    jq -r '"\(.host):\(.port)"' "$wd/naabu.json" 2>/dev/null | \
      fingerprintx --json > "$wd/fingerprintx.json" 2> "$wd/fingerprintx.err" || warn "fingerprintx had errors"
  else
    echo "" > "$wd/fingerprintx.json"
  fi

  phase "HTTP fingerprinting (httpx)"
  echo "$target" | httpx -silent -json \
    -tech-detect -title -status-code -server -content-type \
    -tls-grab -follow-redirects \
    -threads "${HTTPX_THREADS:-25}" \
    > "$wd/httpx.json" 2> "$wd/httpx.err" || warn "httpx had errors"

  phase "WAF detection (wafw00f)"
  wafw00f "$target" -a -o "$wd/wafw00f.json" -f json 2> "$wd/wafw00f.err" || warn "wafw00f had errors"

  phase "TLS posture (testssl)"
  if grep -q '"port":443' "$wd/naabu.json" 2>/dev/null; then
    testssl.sh --jsonfile "$wd/testssl.json" --quiet --warnings off \
      --severity LOW "$target:443" > "$wd/testssl.log" 2>&1 || warn "testssl had errors"
  else
    log "Port 443 not open, skipping testssl"
  fi

  phase "Exposure templates (nuclei)"
  echo "$target" | nuclei -silent -json-export "$wd/nuclei.json" \
    -tags "${NUCLEI_TAGS:-exposure,misconfig,disclosure}" \
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-cve,intrusive,fuzz}" \
    -severity "${NUCLEI_SEVERITY:-info,low,medium}" \
    -concurrency "${NUCLEI_CONCURRENCY:-25}" \
    -rate-limit "${NUCLEI_RATE_LIMIT:-150}" \
    > "$wd/nuclei.log" 2> "$wd/nuclei.err" || warn "nuclei had errors"

  log "FQDN phases complete for $target"
}

# ─── Phase: Apex discovery (subdomain enum + per-sub FQDN scan) ────
discover_apex() {
  local apex="$1" wd="$2"

  phase "Subdomain enumeration (subfinder)"
  subfinder -d "$apex" -silent -json \
    -t "${SUBFINDER_CONCURRENCY:-10}" \
    > "$wd/subfinder.json" 2> "$wd/subfinder.err" || warn "subfinder had errors"

  jq -r '.host' "$wd/subfinder.json" 2>/dev/null | sort -u > "$wd/_subdomains.txt"
  echo "$apex" >> "$wd/_subdomains.txt"
  sort -u -o "$wd/_subdomains.txt" "$wd/_subdomains.txt"

  local sub_count=$(wc -l < "$wd/_subdomains.txt")
  log "Discovered $sub_count subdomain(s) including apex"

  phase "Liveness check (httpx) on all subdomains"
  httpx -list "$wd/_subdomains.txt" -silent -json \
    -tech-detect -title -status-code -server \
    -threads "${HTTPX_THREADS:-25}" \
    > "$wd/httpx_apex.json" 2> "$wd/httpx_apex.err" || warn "httpx apex had errors"

  jq -r 'select(.status_code != null) | .input' "$wd/httpx_apex.json" 2>/dev/null \
    | sort -u > "$wd/_live_subdomains.txt"
  local live_count=$(wc -l < "$wd/_live_subdomains.txt")
  log "$live_count subdomain(s) responding"

  # Phase 1: only deep-scan the apex itself; Phase 2 will iterate each live sub
  phase "Deep scan on apex"
  discover_fqdn "$apex" "$wd"
}

# ─── Phase: Single IP discovery ────────────────────────────────────
discover_ip() {
  local ip="$1" wd="$2"

  phase "Reverse DNS + WHOIS"
  dig +short -x "$ip" > "$wd/reverse_dns.txt" 2>&1 || true
  whois "$ip" > "$wd/whois.txt" 2> "$wd/whois.err" || warn "whois had errors"

  echo "$ip" > "$wd/_resolved_ips.txt"

  phase "Port discovery (naabu)"
  naabu -host "$ip" \
    -top-ports "${NAABU_TOP_PORTS:-1000}" \
    -rate "${NAABU_RATE:-1000}" \
    -scan-type CONNECT \
    -silent -json \
    > "$wd/naabu.json" 2> "$wd/naabu.err" || warn "naabu had errors"

  phase "Service fingerprinting (fingerprintx)"
  if [[ -s "$wd/naabu.json" ]]; then
    jq -r '"\(.host):\(.port)"' "$wd/naabu.json" 2>/dev/null | \
      fingerprintx --json > "$wd/fingerprintx.json" 2> "$wd/fingerprintx.err" || warn "fingerprintx had errors"
  fi

  phase "HTTP probe on web ports"
  if grep -qE '"port":(80|443|8080|8443)' "$wd/naabu.json" 2>/dev/null; then
    echo "$ip" | httpx -silent -json -tech-detect -title -status-code -server -tls-grab \
      -threads "${HTTPX_THREADS:-25}" \
      > "$wd/httpx.json" 2> "$wd/httpx.err" || warn "httpx had errors"

    wafw00f "$ip" -a -o "$wd/wafw00f.json" -f json 2> "$wd/wafw00f.err" || warn "wafw00f had errors"

    if grep -q '"port":443' "$wd/naabu.json" 2>/dev/null; then
      testssl.sh --jsonfile "$wd/testssl.json" --quiet --warnings off \
        --severity LOW --ip "$ip" "$ip:443" > "$wd/testssl.log" 2>&1 || warn "testssl had errors"
    fi

    echo "$ip" | nuclei -silent -json-export "$wd/nuclei.json" \
      -tags "${NUCLEI_TAGS:-exposure,misconfig,disclosure}" \
      -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-cve,intrusive,fuzz}" \
      -severity "${NUCLEI_SEVERITY:-info,low,medium}" \
      -concurrency "${NUCLEI_CONCURRENCY:-25}" \
      -rate-limit "${NUCLEI_RATE_LIMIT:-150}" \
      > "$wd/nuclei.log" 2> "$wd/nuclei.err" || warn "nuclei had errors"
  else
    log "No web ports open, skipping HTTP/WAF/TLS/exposure phases"
  fi

  log "IP phases complete for $ip"
}

# ─── Phase: CIDR sweep ─────────────────────────────────────────────
discover_cidr() {
  local cidr="$1" wd="$2"

  phase "Live host sweep (naabu CIDR)"
  naabu -host "$cidr" \
    -top-ports 100 \
    -rate "${NAABU_RATE:-1000}" \
    -scan-type CONNECT \
    -silent -json \
    > "$wd/naabu_cidr.json" 2> "$wd/naabu_cidr.err" || warn "naabu CIDR sweep had errors"

  jq -r '.host' "$wd/naabu_cidr.json" 2>/dev/null | sort -u > "$wd/_live_hosts.txt"
  local host_count=$(wc -l < "$wd/_live_hosts.txt")
  log "$host_count live host(s) in $cidr"

  # Phase 1: surface inventory only — don't recurse into per-host scans yet.
  # Each live host gets surfaced into the discovered[] queue for promotion.
  echo "" > "$wd/whois.txt"
  whois "$cidr" >> "$wd/whois.txt" 2> "$wd/whois.err" || warn "whois had errors"

  log "CIDR sweep complete; live hosts in _live_hosts.txt for promotion"
}

# ─── Main ──────────────────────────────────────────────────────────
mkdir -p "$ASSETS_DIR" "$RAW_DIR"

if [[ $SCAN_ALL -eq 1 ]]; then
  log "Scanning all enabled targets"
  list_enabled_targets | while read -r tid; do
    [[ -n "$tid" ]] || continue
    discover_one "$tid" || warn "Target '$tid' had a non-zero exit"
  done
else
  discover_one "$TARGET_ID"
fi

log "Done."
