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

  # ─── Empty-result guard — check for the abort marker ─────────────────
  # Per Advisor 4.7 (2026-06-06): if discover_apex / discover_fqdn / etc.
  # set _abort_reason because resolution returned empty, we MUST NOT
  # write the asset JSON. Doing so would bump last_seen on a zero-data
  # row and false-fire "went dark" alerts 72h later. Bail clean — the
  # previous run's data stays canonical and the next cron cycle retries.
  if [[ -f "$work_dir/_abort_reason" ]]; then
    local reason=$(cat "$work_dir/_abort_reason")
    warn "SCAN ABORTED for $id (reason: $reason) — no JSON written, no last_seen bump"
    return 1
  fi

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
  local mode="${3:-full}"    # "full" (default) or "fast" — fast skips testssl

  phase "DNS resolution + records (dig)"
  # 2026-06-06 — switched from dnsx to dig per Advisor 4.7. dnsx empirically
  # fails on GH Actions runners (Azure DNS view quirk — see the comment near
  # line ~285 of this file). The Tier 2 phantom gate was bitten by exactly
  # this 2026-06-06 evening; same risk applies here. If dnsx silently fails
  # here, _resolved_ips.txt comes back empty → naabu+httpx+testssl all run
  # against nothing → normalize.py writes an empty deep-scan JSON → importer
  # bumps last_seen with zero data → 72h later "asset went dark" alerts fire
  # on every owned asset. Dig is rock-solid in this environment.
  : > "$wd/_resolved_ips.txt"
  dig +short +time=3 +tries=2 A    "$target" 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >> "$wd/_resolved_ips.txt" || true
  dig +short +time=3 +tries=2 AAAA "$target" 2>/dev/null \
    | grep -E '^[0-9a-fA-F:]+$' >> "$wd/_resolved_ips.txt" || true
  sort -u -o "$wd/_resolved_ips.txt" "$wd/_resolved_ips.txt"

  # Also write a best-effort dnsx records snapshot for the normalizer's
  # MX/NS/TXT consumers. Failure here is non-fatal — _resolved_ips.txt
  # already came from dig.
  echo "$target" | dnsx -silent -resp -a -aaaa -cname -mx -ns -txt -json \
    -t "${DNSX_THREADS:-25}" -timeout 5 \
    > "$wd/dnsx.json" 2> "$wd/dnsx.err" || warn "dnsx records snapshot had errors (non-fatal — _resolved_ips.txt is from dig)"

  phase "WHOIS lookup"
  whois "$target" > "$wd/whois.txt" 2> "$wd/whois.err" || warn "whois phase had errors"

  local ip_count=$(wc -l < "$wd/_resolved_ips.txt")
  log "Resolved $ip_count IP(s)"

  if [[ $ip_count -eq 0 ]]; then
    # ─── EMPTY-RESULT GUARD ─────────────────────────────────────────────
    # Per Advisor 4.7 (2026-06-06): "couldn't resolve" must NOT be
    # conflated with "resolved to nothing." An empty resolution result
    # means EITHER the host is genuinely gone OR the resolver had a
    # transient blip. If we proceed with empty input, the cascade is:
    #   empty _resolved_ips → empty naabu/httpx/testssl output → empty
    #   deep-scan JSON → importer bumps last_seen on a zero-data row →
    #   72h later 'asset went dark' alerts fire on what was actually
    #   just a network glitch.
    # Even dig can blip. Abort the scan for this target instead. Set a
    # marker that the caller (discover_one) checks before invoking the
    # normalizer. No JSON written → no last_seen bump → previous scan's
    # data stays canonical. Next cron cycle retries naturally.
    warn "RESOLUTION FAILURE on $target — aborting scan (no JSON write, no last_seen bump). Will retry next cycle."
    echo "resolution_failure" > "$wd/_abort_reason"
    return 1
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

  # testssl is the slowest single phase (~60-120s per host). Run it only on
  # apexes / FQDN-type targets where we want a real TLS audit. For per-sub
  # deep scans launched from discover_apex, mode="fast" skips testssl since
  # httpx -tls-grab above already captured the cert basics (issuer, dates,
  # SANs). Saves ~90s × N subs which is what blew the 90-min timeout.
  if [[ "$mode" == "fast" ]]; then
    log "Skipping testssl (mode=fast — per-sub deep scan)"
  elif grep -q '"port":443' "$wd/naabu.json" 2>/dev/null; then
    phase "TLS posture (testssl)"
    testssl.sh --jsonfile "$wd/testssl.json" --quiet --warnings off \
      --severity LOW "$target:443" > "$wd/testssl.log" 2>&1 || warn "testssl had errors"
  else
    log "Port 443 not open, skipping testssl"
  fi

  # Exposure templates removed — that's vuln scanning, not ASM.
  # See [[12 - Future: Vuln Scanning Module]] for the planned separate workflow.

  log "FQDN phases complete for $target"
}

# ─── Phase: Apex discovery (v3 — multi-source enum + per-sub deep scan) ─
# Three discovery sources merged & deduped before liveness check:
#   1. subfinder         — passive (CT logs, public aggregators)
#   2. DNS-derived       — MX, NS, SPF includes, DMARC rua hostnames within the apex
#   3. wordlist resolve  — dnsx brute-force against ~200 common sub names
# For each live subdomain, runs the full FQDN scan flow into a per-sub
# subdirectory. normalize.py walks all per-sub dirs to build the nested
# v3 asset record.
discover_apex() {
  local apex="$1" wd="$2"

  # ─── Source 1: passive (subfinder) ─────────────────────────
  phase "Subdomain enum source 1/3: passive (subfinder)"
  subfinder -d "$apex" -silent -json \
    -t "${SUBFINDER_CONCURRENCY:-10}" \
    > "$wd/subfinder.json" 2> "$wd/subfinder.err" </dev/null || warn "subfinder had errors"
  jq -r '.host' "$wd/subfinder.json" 2>/dev/null | sort -u > "$wd/_src_passive.txt"
  log "  passive: $(wc -l < "$wd/_src_passive.txt" | tr -d ' ') candidates"

  # ─── Source 2: DNS-derived (MX/NS/SPF/DMARC) ──────────────
  # Catches subs hidden behind wildcard certs (which subfinder misses) when
  # they're referenced in the apex zone records (e.g. mail.apex from MX).
  phase "Subdomain enum source 2/3: DNS-derived (MX/NS/SPF/DMARC)"
  if command -v dig >/dev/null 2>&1; then
    {
      # MX records → mail server hostnames
      dig +short MX "$apex" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//'
      # NS records → nameservers (often within apex if self-hosted)
      dig +short NS "$apex" 2>/dev/null | sed 's/\.$//'
      # SPF (TXT) → extract hostnames after a:, mx:, include: directives
      dig +short TXT "$apex" 2>/dev/null | tr -d '"' | grep -iE 'v=spf1' | tr ' ' '\n' | \
        grep -iE '^(a|mx|include|ptr):' | sed -E 's/^[a-zA-Z]+://'
      # DMARC TXT → rua/ruf addresses can reveal a reporting subdomain
      dig +short TXT "_dmarc.$apex" 2>/dev/null | tr -d '"' | tr ';' '\n' | \
        grep -iE 'rua|ruf' | grep -oiE 'mailto:[^,]+' | sed -E 's/mailto:[^@]+@//'
    } 2>/dev/null \
      | tr '[:upper:]' '[:lower:]' \
      | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
      | grep -E "(^|\.)${apex}$" \
      | sort -u > "$wd/_src_dns_derived.txt" 2>/dev/null
  else
    warn "dig not installed — DNS-derived enum skipped (install dnsutils)"
    : > "$wd/_src_dns_derived.txt"
  fi
  log "  DNS-derived: $(wc -l < "$wd/_src_dns_derived.txt" | tr -d ' ') candidates"

  # ─── Source 3: wordlist brute-force (dig in parallel) ──────
  # Replaces dnsx. dnsx empirically failed to resolve names from GH Actions
  # runners even with explicit -r resolvers (Azure DNS view differs, or some
  # other env quirk). dig is rock-solid and we proved it resolves the missing
  # names from any standard env. Parallelize via xargs -P 30 to keep wall-clock
  # ~10 seconds for ~250 names.
  #
  # Wildcard-DNS detection FIRST: if `*.apex` returns an A record for any
  # random name, every wordlist query "succeeds" and we'd flood the live list
  # with phantom subs. Detect by querying a junk name and skip wordlist if
  # it resolves.
  phase "Subdomain enum source 3/4: wordlist brute-force (dig)"
  local wordlist="$REPO_ROOT/scanner/wordlists/subdomains-asm.txt"
  local wildcard_test_name="zzznonexistent$(date +%s).${apex}"
  local has_wildcard=0
  # Use the system resolver. Forcing @1.1.1.1 was failing in sandboxed and
  # cloud-runner environments where outbound DNS to public resolvers is
  # restricted. The system resolver (Azure DNS on GH runners) reaches the
  # authoritative servers fine.
  if [[ -n "$(dig +short +time=2 +tries=1 A "$wildcard_test_name" 2>/dev/null | head -1)" ]]; then
    has_wildcard=1
    warn "Wildcard DNS detected on $apex (junk name '$wildcard_test_name' resolves) — skipping wordlist brute-force to avoid phantom hits"
  fi

  if [[ -f "$wordlist" && $has_wildcard -eq 0 ]]; then
    grep -vE '^[[:space:]]*(#|$)' "$wordlist" \
      | awk -v apex="$apex" '{print $1 "." apex}' \
      > "$wd/_wordlist_candidates.txt"
    local cand_count
    cand_count=$(wc -l < "$wd/_wordlist_candidates.txt" | tr -d ' ')
    log "  wordlist candidates: $cand_count"

    # Parallel dig via system resolver. 30 workers, 2s timeout, 1 retry.
    # ~250 names finish in ~10-15 seconds wall-clock.
    cat "$wd/_wordlist_candidates.txt" | xargs -P 30 -I'{}' bash -c '
      ip=$(dig +short +time=2 +tries=1 "{}" 2>/dev/null | head -1)
      [[ -n "$ip" ]] && echo "{}"
    ' > "$wd/_src_wordlist.txt" 2> "$wd/wordlist_dig.err"
  elif [[ ! -f "$wordlist" ]]; then
    warn "wordlist not found at $wordlist — brute-force enum skipped"
    : > "$wd/_src_wordlist.txt"
  else
    : > "$wd/_src_wordlist.txt"   # wildcard detected, skip
  fi
  log "  wordlist hits: $(wc -l < "$wd/_src_wordlist.txt" | tr -d ' ') (wildcard_dns=$has_wildcard)"

  # ─── Source 4: TLS cert SAN harvesting ────────────────────
  # Connect to the apex on :443, dump the cert, parse subjectAltName.
  # Even wildcard certs sometimes have specific SANs for things like
  # 'test.example.com'. Especially useful when the host is fronted by a CDN
  # that serves multiple sites from one cert.
  phase "Subdomain enum source 4/4: TLS cert SAN harvesting"
  : > "$wd/_src_cert_sans.txt"
  if command -v openssl >/dev/null 2>&1; then
    # Try apex on :443. -servername for SNI, -connect for the target IP+port.
    # Timeout the whole thing in case the host hangs. 2>&1 to ignore TLS warnings.
    timeout 10 openssl s_client -showcerts -servername "$apex" -connect "$apex:443" </dev/null 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null \
      | grep -oE 'DNS:[A-Za-z0-9._*-]+' \
      | sed 's/^DNS://' \
      | tr '[:upper:]' '[:lower:]' \
      | grep -E "(^|\.)${apex}$" \
      | grep -v '\*' \
      | sort -u > "$wd/_src_cert_sans.txt"
  else
    warn "openssl not installed — cert SAN harvesting skipped"
  fi
  log "  cert SAN hits: $(wc -l < "$wd/_src_cert_sans.txt" | tr -d ' ')"

  # ─── Merge + dedupe across all sources ────────────────────
  {
    cat "$wd/_src_passive.txt"
    cat "$wd/_src_dns_derived.txt"
    cat "$wd/_src_wordlist.txt"
    cat "$wd/_src_cert_sans.txt"
    echo "$apex"
  } | tr '[:upper:]' '[:lower:]' \
    | grep -E "(^|\.)${apex}$" \
    | sort -u > "$wd/_subdomains.txt"

  local sub_count
  sub_count=$(wc -l < "$wd/_subdomains.txt" | tr -d ' ')
  log "Multi-source enum total: $sub_count unique candidates (passive=$(wc -l < "$wd/_src_passive.txt" | tr -d ' '), dns=$(wc -l < "$wd/_src_dns_derived.txt" | tr -d ' '), wordlist=$(wc -l < "$wd/_src_wordlist.txt" | tr -d ' '), certSAN=$(wc -l < "$wd/_src_cert_sans.txt" | tr -d ' '))"

  phase "Liveness check (httpx) on all subdomains"
  httpx -list "$wd/_subdomains.txt" -silent -json \
    -tech-detect -title -status-code -server \
    -threads "${HTTPX_THREADS:-25}" \
    > "$wd/httpx_apex.json" 2> "$wd/httpx_apex.err" </dev/null || warn "httpx apex had errors"

  # Determine which subdomains are "live for scanning purposes". Five lanes:
  #   1. Anything that responded to HTTP via httpx
  #   2. Apex always (even if HTTP-dead — naabu still profiles its ports)
  #   3. DNS-derived subs (mail.*, ns.*, etc.) — real infra that may not speak HTTP
  #   4. Wordlist hits that resolved in DNS — they're real hosts even if httpx
  #      didn't get a 2xx (could be HTTP on non-standard port, blocked from the
  #      runner IP, or non-web service). Wildcard-DNS apexes already excluded
  #      this source upstream so this won't flood with phantoms.
  #   5. Cert SAN hits — names the TLS cert advertises = names the operator
  #      explicitly intended to serve. High signal even if HTTP probe fails.
  jq -r 'select(.status_code != null) | (.input // .host // .url)' "$wd/httpx_apex.json" 2>/dev/null \
    | sed -E 's#https?://##; s#/.*##' \
    | sort -u > "$wd/_live_subdomains.txt"
  echo "$apex" >> "$wd/_live_subdomains.txt"
  [[ -s "$wd/_src_dns_derived.txt" ]] && cat "$wd/_src_dns_derived.txt" >> "$wd/_live_subdomains.txt"
  [[ -s "$wd/_src_wordlist.txt"    ]] && cat "$wd/_src_wordlist.txt"    >> "$wd/_live_subdomains.txt"
  [[ -s "$wd/_src_cert_sans.txt"   ]] && cat "$wd/_src_cert_sans.txt"   >> "$wd/_live_subdomains.txt"
  sort -u -o "$wd/_live_subdomains.txt" "$wd/_live_subdomains.txt"

  # ─── Tier 2 phantom defense — DNS resolution gate ───────────────────
  # 2026-06-06 — Cert SAN harvesting (source 4) extracts subjectAltName
  # entries from the apex TLS cert without verifying any of them actually
  # resolve in public DNS. CT logs are append-only and permanent — they
  # contain SANs from certs issued years ago for hosts that were
  # decommissioned (or never deployed). Yesterday's phantom defense work
  # confirmed 12 ct_ghosts in inventory from exactly this pathway.
  #
  # Split the merged candidate list into:
  #   _resolved_subdomains.txt — at least one A or AAAA record returned
  #   _phantom_subdomains.txt  — no resolution (CT-log artifact suspected)
  # Only the resolved list goes through the deep-scan loop below; the
  # phantom list is preserved for the importer to tag discovery_status=ct_ghost.
  #
  # IMPORTANT: per the comment around line 285 of this same file, dnsx
  # empirically fails to resolve names from GH Actions runners (Azure DNS
  # view quirk). Initial Tier 2 implementation used dnsx and classified
  # EVERY candidate as phantom (including real hosts like www.cmi) — fixed
  # 2026-06-06 evening by switching to per-host dig (same pattern that
  # works for the wildcard-DNS check upstream).
  phase "Subdomain DNS resolution gate (Tier 2)"
  : > "$wd/_resolved_subdomains.txt"
  : > "$wd/_phantom_subdomains.txt"
  if [[ -s "$wd/_live_subdomains.txt" ]]; then
    while IFS= read -r _candidate; do
      [[ -z "$_candidate" ]] && continue
      local _a _aaaa
      _a=$(dig +short +time=3 +tries=2 A    "$_candidate" 2>/dev/null | head -1)
      _aaaa=$(dig +short +time=3 +tries=2 AAAA "$_candidate" 2>/dev/null | head -1)
      if [[ -n "$_a" || -n "$_aaaa" ]]; then
        echo "$_candidate" >> "$wd/_resolved_subdomains.txt"
      else
        echo "$_candidate" >> "$wd/_phantom_subdomains.txt"
      fi
    done < "$wd/_live_subdomains.txt"
    sort -u -o "$wd/_resolved_subdomains.txt" "$wd/_resolved_subdomains.txt"
    sort -u -o "$wd/_phantom_subdomains.txt"  "$wd/_phantom_subdomains.txt"
  fi
  local resolved_count phantom_count
  resolved_count=$(wc -l < "$wd/_resolved_subdomains.txt" | tr -d ' ')
  phantom_count=$(wc -l < "$wd/_phantom_subdomains.txt" | tr -d ' ')
  log "  DNS gate: $resolved_count resolved, $phantom_count phantom (CT-log artifacts suspected)"

  # Replace the merged candidate list with the resolved-only list. The
  # phantom list lives in _phantom_subdomains.txt for the normalizer to
  # surface in the JSON output. The deep-scan loop below now only iterates
  # over real hosts, saving runner time AND keeping the assets table clean.
  cp "$wd/_resolved_subdomains.txt" "$wd/_live_subdomains.txt"

  # Sanity cap — runaway sub counts blow the workflow's 90-min timeout.
  # Each sub deep-scan is ~3-5 min (naabu+httpx+wafw00f+testssl), so 40 subs
  # ≈ 2-3 hours wall-clock which is the real ceiling. Override per-target via
  # MAX_LIVE_SUBS in the rate profile if needed.
  local max_subs="${MAX_LIVE_SUBS:-40}"
  local raw_count=$(wc -l < "$wd/_live_subdomains.txt" | tr -d ' ')
  if [[ $raw_count -gt $max_subs ]]; then
    warn "$raw_count live subs exceeds cap ($max_subs) — keeping apex + first $max_subs alphabetical, dropping the rest"
    {
      echo "$apex"
      grep -vF "$apex" "$wd/_live_subdomains.txt" | head -n "$max_subs"
    } | sort -u > "$wd/_live_subdomains.txt.capped"
    mv "$wd/_live_subdomains.txt.capped" "$wd/_live_subdomains.txt"
  fi

  local live_count
  live_count=$(wc -l < "$wd/_live_subdomains.txt" | tr -d ' ')
  log "$live_count subdomain(s) to deep-scan (cap=$max_subs)"

  # Per-sub deep scan — each gets its own subdirectory under $wd/subs/{sub}/.
  # Apex gets "full" mode (with testssl); non-apex subs get "fast" (no testssl
  # — saves ~90s per sub, which adds up across 20+ subs).
  mkdir -p "$wd/subs"
  while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    local sub_mode="fast"
    [[ "$sub" == "$apex" ]] && sub_mode="full"
    phase "Deep scan: $sub (mode=$sub_mode)"
    local sub_dir="$wd/subs/$sub"
    mkdir -p "$sub_dir"
    discover_fqdn "$sub" "$sub_dir" "$sub_mode" </dev/null
  done < "$wd/_live_subdomains.txt"

  log "Apex deep-scan complete: $live_count sub(s) profiled under $wd/subs/"
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
    # Exposure templates removed — vuln scanning lives in a separate (future) workflow.
  else
    log "No web ports open, skipping HTTP/WAF/TLS phases"
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
