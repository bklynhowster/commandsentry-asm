#!/usr/bin/env bash
#
# Mechanism tests for the VPN egress safety gate (G5).
#
# G5 is explicit that exit codes alone are not proof: an exit code cannot show
# that the retry loop actually ran, or that a verdict short-circuited instead of
# being retried. These tests assert CALL COUNTS as well as outcomes.
#
# The gate under test is step 6 of scripts/scanner/vpn_bringup.sh. We cannot run
# that script end to end here (it needs wireguard, root, and a real tunnel), so
# we extract probe_egress_ip() from the script itself — not a copy — and drive it
# with a stubbed `curl`. Extracting rather than duplicating means this test fails
# if someone edits the real function.
#
# Run: bash scripts/common/tests/test_vpn_egress_gate_mechanism.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/../../scanner/vpn_bringup.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ck() { # ck <name> <cond> [detail]
  if [[ "$2" == "1" ]]; then echo "PASS  $1"; PASS=$((PASS+1))
  else echo "FAIL  $1   ${3:-}"; FAIL=$((FAIL+1)); fi
}

# ─── Extract the real function from the real script ──────────────────
sed -n '/^probe_egress_ip() {/,/^}/p' "$GATE" > "$WORK/probe.sh"
if [[ ! -s "$WORK/probe.sh" ]]; then
  echo "FATAL: could not extract probe_egress_ip() from $GATE"
  echo "       (was it renamed? this test must track the real implementation)"
  exit 1
fi

COUNTER="$WORK/calls"

# Stubbed curl. Counts invocations in a FILE, deliberately: probe_egress_ip is
# invoked inside a command substitution, so a shell variable counter would be
# incremented in a subshell and lost. That bug made an early version of this
# test report a false PASS.
make_curl() { # make_curl <output-for-every-call>
  cat > "$WORK/curl" <<EOF
#!/usr/bin/env bash
n=\$(cat "$COUNTER" 2>/dev/null || echo 0); echo \$((n+1)) > "$COUNTER"
printf '%s' '$1'
EOF
  chmod +x "$WORK/curl"
}
make_curl_nth() { # make_curl_nth <n> <ip>  — succeed only on call n
  cat > "$WORK/curl" <<EOF
#!/usr/bin/env bash
n=\$(cat "$COUNTER" 2>/dev/null || echo 0); n=\$((n+1)); echo \$n > "$COUNTER"
[[ \$n -eq $1 ]] && printf '%s' '$2'
exit 0
EOF
  chmod +x "$WORK/curl"
}
run_probe() { # run_probe <attempts> -> echoes result; resets counter
  echo 0 > "$COUNTER"
  ( export PATH="$WORK:$PATH"
    # shellcheck disable=SC1090
    source "$WORK/probe.sh"
    sleep() { :; }          # collapse the backoff so the suite stays fast
    probe_egress_ip "$1" )
}
calls() { cat "$COUNTER"; }

# ─── 1. Happy path: first provider answers, exactly one call ─────────
make_curl "185.65.134.66"
out="$(run_probe 3)"
ck "MECHANISM_first_provider_hit_costs_one_call" "$([[ $(calls) == 1 ]] && echo 1)" "calls=$(calls)"
ck "OUTCOME_returns_the_ip" "$([[ "$out" == "185.65.134.66" ]] && echo 1)" "got '$out'"

# ─── 2. Provider fallback within a single attempt ────────────────────
make_curl_nth 2 "185.65.134.70"
out="$(run_probe 3)"
ck "MECHANISM_falls_through_to_2nd_provider_same_attempt" "$([[ $(calls) == 2 ]] && echo 1)" "calls=$(calls)"
ck "OUTCOME_second_provider_ip_returned" "$([[ "$out" == "185.65.134.70" ]] && echo 1)" "got '$out'"

# ─── 3. Full exhaustion: 3 providers × 3 attempts = 9 calls ──────────
# This is THE test. The old gate did one call and gave up; if this ever
# reports 1, the fail-open has been reintroduced.
make_curl ""
out="$(run_probe 3)"
ck "MECHANISM_exhausts_3_providers_x_3_attempts" "$([[ $(calls) == 9 ]] && echo 1)" "calls=$(calls) (expected 9)"
ck "OUTCOME_unreadable_returns_empty_not_a_placeholder" "$([[ -z "$out" ]] && echo 1)" "got '$out'"

# ─── 4. Baseline uses a shorter budget (2 attempts = 6 calls) ────────
make_curl ""
run_probe 2 >/dev/null
ck "MECHANISM_baseline_budget_is_2_attempts" "$([[ $(calls) == 6 ]] && echo 1)" "calls=$(calls) (expected 6)"

# ─── 5. Garbage is rejected, not returned ───────────────────────────
# ipify has been known to return an HTML error page with HTTP 200. A
# non-IPv4 body must be treated as no answer.
make_curl "<html>rate limited</html>"
out="$(run_probe 1)"
ck "OUTCOME_non_ip_body_rejected" "$([[ -z "$out" ]] && echo 1)" "got '$out'"

# ─── 6. The gate text itself must not have regressed ────────────────
# Match the CODE, not prose. The audit comment deliberately quotes the old
# fail-open log line to explain what was wrong, so grepping for that string
# matches the documentation and reports a false regression. The unambiguous
# tell is the placeholder assignment, which only ever existed to let the
# comparison be skipped.
ck "REGRESSION_no_unknown_placeholder" \
   "$(grep -q 'VPN_IP="<unknown>"' "$GATE" && echo 0 || echo 1)" \
   "VPN_IP=\"<unknown>\" is back — that placeholder IS the fail-open"
ck "REGRESSION_comparison_not_guarded_away" \
   "$(grep -q '\[\[ "\$VPN_IP" != "<unknown>" \]\]' "$GATE" && echo 0 || echo 1)" \
   "the != <unknown> guard is back; it makes the comparison skippable"
# Anchored to line start so the header's "#   4  — egress IP unreadable..."
# documentation cannot satisfy the check. Mutation testing caught this: a
# mutant with step 6 reverted still "passed" these two, because the doc
# comment survived. A check the documentation can satisfy is not a check.
ck "REGRESSION_unreadable_exits_nonzero" \
   "$(grep -qE '^\s*exit 4\s*$' "$GATE" && echo 1)" "executable 'exit 4' (unreadable) missing"
ck "REGRESSION_no_baseline_exits_nonzero" \
   "$(grep -qE '^\s*exit 5\s*$' "$GATE" && echo 1)" "executable 'exit 5' (no baseline) missing"
ck "REGRESSION_verification_uses_shared_probe" \
   "$(grep -q 'VPN_IP="\$(probe_egress_ip 3)"' "$GATE" && echo 1)" \
   "verification is not using probe_egress_ip"

echo
echo "───────────────────────────────"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] || exit 1
