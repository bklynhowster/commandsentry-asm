"""Tests for scripts/scanner/degradation.py

Spec: ~/Downloads/ISMS Procedures/COMMANDsentry/SPEC_SCANNER_DEGRADATION_HARDENING.md

Key invariants locked here:
  - Ruling ③: stderr-only pattern scan. A legit finding whose stdout text
    contains "connection refused" with healthy pre+post must NOT trigger
    degradation. Spurious abort during validate run = no mint = ghost-
    chasing. The named test case is `test_clean_stdout_finding_with_
    unreachable_text_is_not_degraded` and it's the load-bearing one.
  - Ruling ⑦: set-equality on tools_run vs tool_status.keys(). NOT a
    hardcoded count.
  - Ruling Q2: rotation_log cap at 500 each. Cap-hit flips rotation_storm
    AND stops appending. The 501st event is dropped silently — but
    rotation_storm=true is sufficient evidence of severe degradation.

Run:  pytest scripts/scanner/test_degradation.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make scripts/scanner importable like run_medium.py imports its siblings
sys.path.insert(0, str(Path(__file__).parent))

from degradation import (  # noqa: E402
    MAX_BAN_EVENTS,
    MAX_HEALTHCHECK_FAILURES,
    STDERR_DEGRADED_MATCH_THRESHOLD,
    VALIDATION_TARGETS,
    DegradedRunError,
    assert_tool_status_invariant,
    assert_validate_mode_target_allowed,
    cap_aware_append_ban,
    cap_aware_append_healthcheck_failure,
    is_tool_output_degraded,
)


# ═══════════════════════════════════════════════════════════════════════
# is_tool_output_degraded
# ═══════════════════════════════════════════════════════════════════════


def test_clean_stdout_finding_with_unreachable_text_is_not_degraded():
    """RULING ③ load-bearing test. Nuclei (or any tool) reporting
    'connection refused' as a closed-port INFO inside its stdout, with
    healthy pre+post and rc=0, must return None — NOT a degradation
    reason. If this test ever fails, the validate run will spuriously
    abort, no mint will land, and we chase a ghost in the scanner code."""
    result = is_tool_output_degraded(
        tool="nuclei",
        stdout="[medium] [closed-port] connection refused on port 22\n"
               "[low] [unreachable] no route to host on port 23",
        stderr="",
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result is None, (
        "stdout legitimately contains unreachable-pattern text from "
        "real findings. The detector must scan STDERR ONLY (ruling ③)."
    )


def test_post_health_false_is_degraded():
    """Authority 1: if the target stopped responding after a tool ran,
    we don't trust the tool's 'no findings' verdict — we may have been
    banned mid-tool."""
    result = is_tool_output_degraded(
        tool="ffuf",
        stdout="(empty)",
        stderr="",
        rc=0,
        pre_health=True,
        post_health=False,
    )
    assert result == "target_unreachable_after_run"


def test_pre_health_false_plus_nonzero_rc_is_degraded():
    """Authority 2: pre-tool health was already bad AND the tool exited
    non-zero — we almost certainly never reached the target."""
    result = is_tool_output_degraded(
        tool="nikto",
        stdout="",
        stderr="Connection error",
        rc=1,
        pre_health=False,
        post_health=False,
    )
    # Post is checked first, so we expect the post slug regardless. The
    # important behavior is "returns SOME reason," not which slug exactly.
    assert result == "target_unreachable_after_run"


def test_pre_health_false_post_health_true_plus_nonzero_rc_is_degraded():
    """Authority 2 in isolation: post recovered but pre-was-bad + non-zero
    rc means this attempt never landed."""
    result = is_tool_output_degraded(
        tool="nikto",
        stdout="",
        stderr="",
        rc=1,
        pre_health=False,
        post_health=True,
    )
    assert result == "target_unreachable_pre_run"


@pytest.mark.parametrize("pattern", [
    "Unable to connect to demo.testfire.net:443",
    "dial tcp: connection refused",
    "remote: connection reset by peer",
    "i/o timeout while reading",
    "no route to host",
    "Name or service not known",
    "could not resolve host: demo.testfire.net",
])
def test_stderr_unreachable_pattern_above_threshold_is_degraded(pattern):
    """Backstop 3 (softened — trap-1 2026-06-12): tool exits cleanly with
    healthy pre+post but emitted ≥STDERR_DEGRADED_MATCH_THRESHOLD
    reachability-failure strings to STDERR. Catches the case where the
    tool's exit handler swallowed the error but its stderr leaked the
    cause persistently."""
    # Repeat the pattern enough times to clear the threshold (3 by default).
    stderr_blob = "\n".join([pattern] * STDERR_DEGRADED_MATCH_THRESHOLD)
    result = is_tool_output_degraded(
        tool="ffuf",
        stdout="",
        stderr=stderr_blob,
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result == "output_stderr_contains_unreachable_pattern", (
        f"stderr containing {STDERR_DEGRADED_MATCH_THRESHOLD}× {pattern!r} "
        f"must trigger degradation"
    )


def test_stderr_single_match_with_healthy_post_is_transient(capsys):
    """RULING ① / Trap-1 load-bearing test 2026-06-12. A SINGLE stderr
    match with post_health=True must NOT abort — long nuclei / ffuf
    runs routinely emit one transient line during a legitimate scan
    of a healthy target. Spurious abort = no mint = chasing a ghost.

    Sub-threshold + healthy → log a warning and return None.
    Healthcheck is the authority; stderr backstop is the backstop only."""
    result = is_tool_output_degraded(
        tool="nuclei",
        stdout="(scan results)",
        stderr="[ERR] dial tcp 1.2.3.4:443: connection refused",  # 1 match
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result is None, (
        "single transient stderr match with healthy post MUST NOT "
        "abort — healthcheck is the authority"
    )
    captured = capsys.readouterr()
    assert "transient" in captured.err.lower(), (
        "transient should be logged so degradation is visible in scan log "
        "even when it doesn't abort"
    )


def test_stderr_two_matches_below_threshold_still_transient(capsys):
    """Confirm the threshold is ≥3 and below it stays transient even
    with multiple sub-threshold matches."""
    result = is_tool_output_degraded(
        tool="ffuf",
        stdout="",
        stderr="[ERR] connection refused\n[ERR] i/o timeout reading",  # 2
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result is None
    captured = capsys.readouterr()
    assert "transient" in captured.err.lower()


def test_stderr_threshold_value():
    """Lock the threshold constant. If you change this, update the
    test_stderr_*_below_threshold tests too, and document the new
    cadence in the degradation.py module docstring (trap-1 section)."""
    assert STDERR_DEGRADED_MATCH_THRESHOLD == 3


def test_stderr_clean_text_returns_none():
    """Sanity: stderr that is NOT a reachability pattern (typical tool
    chatter like 'Loaded 3 templates') is healthy."""
    result = is_tool_output_degraded(
        tool="nuclei",
        stdout="found 0 results",
        stderr="[INF] Loaded 1840 templates · v3.1.4\n[INF] Targets loaded: 1",
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result is None


def test_pattern_case_insensitive():
    """Real-world tool output mixes case (Connection refused vs
    connection refused). Patterns must match irrespective of case.

    Updated 2026-06-12 (trap-1): seed ≥STDERR_DEGRADED_MATCH_THRESHOLD
    matches so the threshold check fires; the assertion is about
    case-insensitive matching, not the threshold semantics."""
    upper_blob = "\n".join(
        ["CONNECTION REFUSED on port 443"] * STDERR_DEGRADED_MATCH_THRESHOLD
    )
    result = is_tool_output_degraded(
        tool="nikto",
        stdout="",
        stderr=upper_blob,
        rc=0,
        pre_health=True,
        post_health=True,
    )
    assert result == "output_stderr_contains_unreachable_pattern", (
        "uppercase stderr blob ≥threshold must trigger degradation"
    )


# ═══════════════════════════════════════════════════════════════════════
# assert_tool_status_invariant
# ═══════════════════════════════════════════════════════════════════════


def test_invariant_holds_returns_none():
    """Same set on both sides — no exception, no mutation.

    Uses the canonical {"ok": True} | {"degraded": "<slug>"} shape (see
    run_medium.py mark_tool_ok/mark_tool_degraded) so the fixture is
    consistent with the documented contract; the test itself checks
    set-equality of keys, not value shapes, but seeding the wrong shape
    here would contradict the docstring 4 lines below in
    test_invariant_missing_raises_after_autostamp."""
    tools_run = ["wafw00f", "httpx", "nuclei-chunk-1"]
    tool_status = {
        "wafw00f": {"ok": True},
        "httpx": {"ok": True},
        "nuclei-chunk-1": {"degraded": "skipped_target_unreachable"},
    }
    snapshot = dict(tool_status)
    assert_tool_status_invariant(tools_run, tool_status)
    # No mutation
    assert tool_status == snapshot


def test_invariant_missing_raises_after_autostamp():
    """tool in tools_run but missing from tool_status: auto-stamp with
    reason=no_status_recorded so the row captures the gap, THEN raise.

    Canonical shape per run_medium.py:425 mark_tool_degraded + run_light.py:
    a degraded entry is {"degraded": "<slug>"}, NOT {"ok": False, ...}.
    Readers key on `"degraded" in entry` — this lock-in test ensures the
    invariant auto-stamp uses the documented shape, not an inline 3rd form."""
    tools_run = ["wafw00f", "httpx", "nuclei-chunk-1"]
    tool_status = {"wafw00f": {"ok": True}}  # missing httpx + nuclei-chunk-1
    with pytest.raises(DegradedRunError) as exc:
        assert_tool_status_invariant(tools_run, tool_status)
    assert exc.value.reason == "tool_status_invariant"
    # The auto-stamp must have happened BEFORE the raise, using the
    # CANONICAL shape (see docstring).
    assert tool_status["httpx"] == {"degraded": "no_status_recorded"}
    assert tool_status["nuclei-chunk-1"] == {"degraded": "no_status_recorded"}
    # And belt + suspenders: readers that key on "degraded in entry"
    # must find the new entries (this is the whole point of B2 — silent
    # gaps surface to downstream as degradation).
    assert "degraded" in tool_status["httpx"]
    assert "degraded" in tool_status["nuclei-chunk-1"]


def test_invariant_unclaimed_raises():
    """tool in tool_status but not in tools_run: coding bug — someone
    called mark_tool_ok without registering. Raises (no auto-stamp; we
    don't know what to add to tools_run)."""
    tools_run = ["wafw00f"]
    tool_status = {
        "wafw00f": {"ok": True},
        "phantom_tool": {"ok": True},  # never registered
    }
    with pytest.raises(DegradedRunError) as exc:
        assert_tool_status_invariant(tools_run, tool_status)
    assert exc.value.reason == "tool_status_invariant"
    assert "unclaimed" in str(exc.value)


def test_invariant_no_hardcoded_count():
    """Plans of any size must be valid as long as the sets match. Locks
    in ruling ⑦: NOT a hardcoded magic number."""
    for n in (3, 8, 11, 17, 50):
        tools = [f"tool-{i}" for i in range(n)]
        statuses = {t: {"ok": True} for t in tools}
        assert_tool_status_invariant(tools, statuses)  # no raise


# ═══════════════════════════════════════════════════════════════════════
# Rotation log caps (ruling Q2)
# ═══════════════════════════════════════════════════════════════════════


def test_ban_event_cap_at_max_ban_events():
    """First MAX_BAN_EVENTS entries append; the next one signals
    cap-hit and is dropped."""
    events: list[dict] = []
    rotation_storm = False

    for i in range(MAX_BAN_EVENTS):
        hit = cap_aware_append_ban(events, rotation_storm, {"i": i})
        assert hit is False, f"cap shouldn't trip on event {i}"
        assert len(events) == i + 1

    # The (MAX+1)th call must signal cap-hit AND not append
    hit = cap_aware_append_ban(events, rotation_storm, {"i": "overflow"})
    assert hit is True
    assert len(events) == MAX_BAN_EVENTS  # still capped


def test_ban_event_already_storm_is_silent_drop():
    """Once rotation_storm=True, further appends are silent no-ops.
    rotation_storm=true IS the evidence; we don't need every event."""
    events: list[dict] = []
    rotation_storm = True  # caller has already flipped this

    hit = cap_aware_append_ban(events, rotation_storm, {"i": "post-storm"})
    assert hit is False  # not signaling "first hit"
    assert len(events) == 0  # silent drop


def test_healthcheck_failure_cap():
    """Same shape as ban-event cap but for healthcheck failures."""
    failures: list[dict] = []
    rotation_storm = False

    for i in range(MAX_HEALTHCHECK_FAILURES):
        hit = cap_aware_append_healthcheck_failure(
            failures, rotation_storm, {"i": i}
        )
        assert hit is False
    hit = cap_aware_append_healthcheck_failure(
        failures, rotation_storm, {"i": "overflow"}
    )
    assert hit is True
    assert len(failures) == MAX_HEALTHCHECK_FAILURES


# ═══════════════════════════════════════════════════════════════════════
# DegradedRunError shape
# ═══════════════════════════════════════════════════════════════════════


def test_degraded_run_error_carries_reason_and_context():
    """The exception's .reason field must be a stable slug for use in
    scan_run.error_message AND tool_status[chunk]['reason'].
    The .context field carries human-readable detail."""
    e = DegradedRunError("rotation_exhausted", "nuclei[medium:exposure,config]")
    assert e.reason == "rotation_exhausted"
    assert e.context == "nuclei[medium:exposure,config]"
    assert "rotation_exhausted" in str(e)
    assert "nuclei[medium:exposure,config]" in str(e)


def test_degraded_run_error_context_optional():
    """Some abort sites just need the reason — context is optional."""
    e = DegradedRunError("tool_status_invariant")
    assert e.reason == "tool_status_invariant"
    assert e.context == ""
    assert "tool_status_invariant" in str(e)


# ═══════════════════════════════════════════════════════════════════════
# Validate-mode safety interlock (batch 2)
# ═══════════════════════════════════════════════════════════════════════
#
# These are unit tests; per advisor 2026-06-12 the GATE for the interlock
# is the live NEGATIVE TEST via workflow_dispatch — fire skip_vpn=true at
# a non-allowlisted target and watch it abort RED before any packet
# leaves. Unit tests prove the logic; the live refusal proves reality.
# Both layers exist; do not conflate them.


def test_validate_mode_skip_vpn_false_is_noop():
    """When skip_vpn=False, the interlock short-circuits without
    checking the allowlist. Normal medium runs use the ROE gate, not
    this one."""
    # Even with a hostname clearly NOT in VALIDATION_TARGETS, no raise.
    assert_validate_mode_target_allowed(
        target_hostname="commanddigital.com",  # namesake, not in allowlist
        skip_vpn=False,
    )
    # And with an asset_id-style "range:*" string — still no raise
    # because skip_vpn is False.
    assert_validate_mode_target_allowed(
        target_hostname="range:something",
        skip_vpn=False,
    )


def test_validate_mode_skip_vpn_true_on_allowlisted_target_proceeds():
    """When skip_vpn=True AND target is in VALIDATION_TARGETS, no raise."""
    # demo.testfire.net is the seeded entry; locked by
    # test_validation_targets_lock below.
    assert_validate_mode_target_allowed(
        target_hostname="demo.testfire.net",
        skip_vpn=True,
    )


def test_validate_mode_skip_vpn_true_on_non_allowlisted_target_aborts():
    """LOAD-BEARING. skip_vpn=True against ANY target outside the
    allowlist MUST raise DegradedRunError. The live negative test
    against a non-allowlisted scan_queue row will exercise this exact
    code path end-to-end; this test just locks the logic shape."""
    with pytest.raises(DegradedRunError) as exc:
        assert_validate_mode_target_allowed(
            target_hostname="commanddigital.com",  # namesake — should refuse
            skip_vpn=True,
        )
    assert exc.value.reason == "validate_mode_target_not_allowlisted"
    assert "commanddigital.com" in exc.value.context


@pytest.mark.parametrize("hostname", [
    "commanddigital.com",                              # namesake
    "api-v2.commandmarketinginnovations.com",          # unknown / phantom
    "commandcompanies.com",                            # owned
    "api.commandcommcentral.com",                      # owned
    "range:lightpath-dark-block",                      # range parent (asset_id shape)
    "internal.example.invalid",                        # nonexistent
    "",                                                # empty string
])
def test_validate_mode_rejects_non_allowlisted_targets(hostname):
    """Parametrized: any plausible non-allowlist input refuses.
    Includes the range:* asset_id shape (advisor must-fix-2 directly):
    even if a future contributor wires the comparison to ctx.asset_id
    by mistake, range-style strings can never match because the
    allowlist holds hostnames only."""
    with pytest.raises(DegradedRunError) as exc:
        assert_validate_mode_target_allowed(hostname, skip_vpn=True)
    assert exc.value.reason == "validate_mode_target_not_allowlisted"


def test_validation_targets_lock():
    """Lock-in: VALIDATION_TARGETS is exactly {demo.testfire.net}. If
    you add a host, update this assertion (and document why in the
    degradation.py allowlist block). Forces every allowlist change to
    pass through CI, mirrors ROE_OWNERSHIP_ALLOWLIST discipline."""
    assert VALIDATION_TARGETS == frozenset({"demo.testfire.net"})


def test_validate_mode_hostname_comparison_not_asset_id():
    """advisor must-fix-2 lock-in. The comparison field MUST be the
    target hostname the tools hit, NOT the asset_id PK. This test
    proves the assertion behaviorally: demo.testfire.net (hostname
    that IS in VALIDATION_TARGETS) proceeds, while a UUID-formatted
    string (the shape asset_id would take if it were a UUID PK)
    refuses. Even though for hostname-class assets the two values
    happen to coincide today, comparing the wrong field would silently
    fail on future shape changes."""
    # Real hostname → proceeds
    assert_validate_mode_target_allowed("demo.testfire.net", skip_vpn=True)
    # UUID-shaped input (what asset_id would be if the data model
    # ever flipped to UUID PKs) → refuses
    with pytest.raises(DegradedRunError):
        assert_validate_mode_target_allowed(
            "00000000-0000-0000-0000-000000000000",
            skip_vpn=True,
        )
