#!/usr/bin/env bash
# ============================================================================
# 04_rls_lockdown.sh — Prove the data is locked down from anon API access.
#
# This script uses the Supabase REST API (PostgREST) with the public anon key.
# It should return EMPTY arrays for every table — if it returns any row, RLS
# is misconfigured and the data is leaking.
#
# Required env vars:
#   SUPABASE_URL      e.g. https://hdygktppfvuspnumpfuq.supabase.co
#   SUPABASE_ANON_KEY the public anon key from Project Settings > API
#
# Usage:
#   export SUPABASE_URL='https://hdygktppfvuspnumpfuq.supabase.co'
#   export SUPABASE_ANON_KEY='eyJhbGciOi...'
#   ./scripts/db/checks/04_rls_lockdown.sh
# ============================================================================

set -euo pipefail

: "${SUPABASE_URL:?SUPABASE_URL not set}"
: "${SUPABASE_ANON_KEY:?SUPABASE_ANON_KEY not set}"

ok=0
bad=0

for table in assets scans findings finding_history evidence_artifacts; do
  body=$(curl -sS \
    -H "apikey: $SUPABASE_ANON_KEY" \
    -H "Authorization: Bearer $SUPABASE_ANON_KEY" \
    "$SUPABASE_URL/rest/v1/$table?select=*&limit=1")

  if [[ "$body" == "[]" ]]; then
    echo "  OK     $table -> empty (anon blocked)"
    ok=$((ok+1))
  else
    echo "  LEAK   $table -> non-empty response:"
    echo "         $body" | head -c 200
    echo
    bad=$((bad+1))
  fi
done

echo
if [[ $bad -eq 0 ]]; then
  echo "RLS lockdown verified: $ok tables returned empty to anon key."
  exit 0
else
  echo "RLS LOCKDOWN FAILED: $bad table(s) returned data to anon key."
  exit 1
fi
