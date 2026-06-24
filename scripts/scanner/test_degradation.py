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
    POST_ROTATE_SETTLE_ATTEMPTS,
    POST_ROTATE_SETTLE_DELAY_S,
    PRE_ROTATE_RETRY_ATTEMPTS,
    PRE_ROTATE_RETRY_DELAY_S,
    STDERR_DEGRADED_MATCH_THRESHOLD,
    VALIDATION_TARGETS,
    DegradedRunError,
    assert_tool_status_invariant,
    assert_validate_mode_target_allowed,
    cap_aware_append_ban,
    cap_aware_append_healthcheck_failure,
    delta_close_eligible,
    egress_failure_reason,
    healthcheck_with_retry,
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


def test_chunk_name_uniqueness_with_index_for_ffuf():
    """Per-chunk B1 wiring lock-in (advisor batch 2 2026-06-13):
    ffuf chunks with the same wordlist size must use #index suffix
    to disambiguate, because set(tools_run) would collapse otherwise
    and silently mask a missing tool_status entry.

    Pre-fix tools_run shape (validate run 27466980596):
        ['ffuf[25w]', 'ffuf[25w]', 'ffuf[25w]', 'ffuf[24w]']  ← duplicates
    Post-fix shape:
        ['ffuf[25w]#1', 'ffuf[25w]#2', 'ffuf[25w]#3', 'ffuf[24w]#4']

    Locking the convention here so a future contributor who changes the
    ffuf chunked loop without re-reading the lesson can't silently
    re-collapse them. Failure here = re-introduce the validate-run gap.
    """
    # Simulate what the chunked loop should produce: 3 unique names for
    # 3 same-size chunks + 1 different.
    tools_run = [
        "wafw00f",
        "httpx[-td]",
        "nuclei[critical,high]",
        "nuclei[medium:cve]",
        "nuclei[medium:exposure,config]",
        "nuclei[medium:tech]",
        "nikto",
        "ffuf[25w]#1",
        "ffuf[25w]#2",
        "ffuf[25w]#3",
        "ffuf[24w]#4",
    ]
    tool_status = {t: {"ok": True} for t in tools_run}
    # The set-equality invariant must accept this shape unchanged.
    assert_tool_status_invariant(tools_run, tool_status)
    assert tool_status == {t: {"ok": True} for t in tools_run}, (
        "no mutation expected on a clean run"
    )


def test_chunk_name_collapse_without_index_breaks_invariant():
    """Counterpoint to test_chunk_name_uniqueness_with_index_for_ffuf —
    if you DROP the #index, the duplicates collapse in set() and the
    invariant gives a false-pass even with a missing stamp.

    This test isn't asserting the invariant FAILS — it's documenting
    the failure mode so the convention sticks: bare `ffuf[25w]` × 3 in
    tools_run + ONE 'ffuf[25w]' in tool_status would silently pass
    set-equality and HIDE the 2 missing stamps."""
    bad_tools_run = ["ffuf[25w]", "ffuf[25w]", "ffuf[25w]", "ffuf[24w]"]
    bad_tool_status = {
        "ffuf[25w]": {"ok": True},  # ONE entry for THREE list items
        "ffuf[24w]": {"ok": True},
    }
    # set() deduplicates → set-equality passes, masking the gap
    assert set(bad_tools_run) == set(bad_tool_status.keys())
    # This is WHY #index matters. Documented, not silenced.


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


# ═══════════════════════════════════════════════════════════════════════
# Trust-layer fix — Parts 2, 3, 4 + Bug D (2026-06-13)
# ═══════════════════════════════════════════════════════════════════════
# Spec: this PR's SPEC_TRUST_LAYER_FIX (see migration 20260613a header).
# These tests pin the invariant: validation_status='validated' ⟺
#   scanner_version ∈ scanner_validations WHERE retracted_at IS NULL
#   AND scan_quality='clean'. The mechanism splits across four enforcement
# points (derive_validation_status filter, UPSERT derive-on-write,
# degraded_out flip, re-derive sweep) — these tests cover three of the
# four that live in the runner. The sweep migration is verified via the
# acceptance gate queries on apply (file: 20260613b_findings_validation_resweep.sql).


from run_medium import (  # noqa: E402
    STAMP_FINDINGS_DEGRADED_SQL,
    UPSERT_FINDING_SQL,
    derive_validation_status,
)


class _FakeCursor:
    """Records executed SQL + params, returns canned fetchone result."""

    def __init__(self, fetchone_result):
        self._fetchone_result = fetchone_result
        self.executed_sql: str | None = None
        self.executed_params: tuple | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.executed_sql = sql
        self.executed_params = params

    def fetchone(self):
        return self._fetchone_result


class _FakeConn:
    def __init__(self, fetchone_result):
        self.cursor_obj = _FakeCursor(fetchone_result)

    def cursor(self):
        return self.cursor_obj


def test_derive_validation_status_filters_retracted():
    """Part 2 lock-in. derive_validation_status MUST include
    `retracted_at IS NULL` in its WHERE clause — otherwise a SHA that
    was retracted via the 20260613a column would still come back
    'validated' and re-stamp findings under it.

    Shape test: inspect the SQL the cursor saw. The behavioral test
    (active row found → 'validated', no row → 'unvalidated') runs
    against a fake cursor with canned results."""
    # Active row exists → 'validated'
    conn = _FakeConn(fetchone_result=(1,))
    result = derive_validation_status(conn, "medium", "abc123")
    assert result == "validated"
    assert "retracted_at IS NULL" in conn.cursor_obj.executed_sql
    assert conn.cursor_obj.executed_params == ("medium", "abc123")

    # No active row → 'unvalidated' (covers both "SHA never minted" and
    # "SHA minted but retracted" — the filter collapses them into the
    # same outcome at this layer)
    conn = _FakeConn(fetchone_result=None)
    result = derive_validation_status(conn, "medium", "0864fd3")
    assert result == "unvalidated"
    assert "retracted_at IS NULL" in conn.cursor_obj.executed_sql


def test_upsert_finding_sql_writes_first_detected_scan():
    """Bug D fix lock-in. The INSERT column list MUST include
    `first_detected_scan` and the VALUES MUST reference %(scan_run_id)s.
    Before this fix the column was never populated by the runner,
    which made Part 4's degraded_out update a no-op (it keys on
    `first_detected_scan = scan_run_id`)."""
    assert "first_detected_scan" in UPSERT_FINDING_SQL
    assert "%(scan_run_id)s" in UPSERT_FINDING_SQL


def test_upsert_finding_sql_preserves_first_detected_scan_on_update():
    """Bug D paired guarantee. On re-detect by a different scan_run,
    the original first_detected_scan must be preserved (mirrors
    first_detected_at LEAST semantics). COALESCE(findings.x,
    EXCLUDED.x) is the canonical pattern; a future refactor that
    drops the COALESCE would silently clobber the lineage."""
    assert "COALESCE(findings.first_detected_scan" in UPSERT_FINDING_SQL


def test_upsert_finding_sql_is_derive_on_write_not_upgrade_only():
    """Part 3 lock-in. The validation_status UPDATE must be a pure
    derive (validation_status = EXCLUDED.validation_status), NOT the
    old upgrade-only CASE that preserved 'validated' across re-emits.

    Negative test: the old CASE phrasing must NOT be in the SQL —
    if it sneaks back in via a refactor, junk re-validates on the
    next re-emit at a stale SHA."""
    # Positive: derive-on-write
    assert "validation_status = EXCLUDED.validation_status" in UPSERT_FINDING_SQL
    # Negative: old upgrade-only CASE phrasing
    assert "ELSE findings.validation_status" not in UPSERT_FINDING_SQL


def test_upsert_finding_sql_nulls_validated_at_on_demote():
    """Part 3 paired guarantee (advisor lean 2). When the derive flips
    a row from 'validated' → 'unvalidated', validated_at MUST be
    NULL'd. A non-null validated_at on an unvalidated row is the same
    contradiction class as validated+degraded. The CASE in the UPSERT
    handles three states: promote (stamp now()), demote (NULL),
    no-transition (preserve)."""
    # The demote branch must produce NULL
    assert "THEN NULL" in UPSERT_FINDING_SQL
    # And the promote branch must stamp now()
    assert "THEN now()" in UPSERT_FINDING_SQL


def test_stamp_findings_degraded_flips_validation_status():
    """Part 4 lock-in. degraded_out's findings flip must update
    validation_status='unvalidated' and validated_at=NULL alongside
    scan_quality='degraded'. The two columns move together because the
    invariant treats them as one assertion. Without this, a degraded
    run that detected new findings under a validated SHA would leave
    them stamped (validated AND degraded) — the exact contradiction
    class the acceptance gate is supposed to catch."""
    assert "scan_quality" in STAMP_FINDINGS_DEGRADED_SQL
    assert "'degraded'" in STAMP_FINDINGS_DEGRADED_SQL
    assert "validation_status" in STAMP_FINDINGS_DEGRADED_SQL
    assert "'unvalidated'" in STAMP_FINDINGS_DEGRADED_SQL
    assert "validated_at" in STAMP_FINDINGS_DEGRADED_SQL
    assert "NULL" in STAMP_FINDINGS_DEGRADED_SQL


def test_stamp_findings_degraded_scoped_to_first_detected_scan():
    """Part 4 scope guarantee (advisor scope note on #4). The flip
    must be keyed on `first_detected_scan = %(scan_run_id)s` — touching
    ONLY the findings this scan_run first detected. Existing findings
    re-detected by this degraded run keep their prior status; a
    degraded re-detect should not retroactively degrade a prior clean
    detection. This test guards against a future broadening of scope
    (e.g. `WHERE last_observed_scan = scan_run_id`) that would violate
    that invariant."""
    assert "first_detected_scan = %(scan_run_id)s" in STAMP_FINDINGS_DEGRADED_SQL
    # Negative: don't broaden to last-observed semantics
    assert "last_observed_scan" not in STAMP_FINDINGS_DEGRADED_SQL


# ═══════════════════════════════════════════════════════════════════════
# Pre-chunk abort invariant + degraded_out reconcile (2026-06-13)
# ═══════════════════════════════════════════════════════════════════════
# Surfaced by validate run 648313cd-d734-4b7f-b639-1f272dfdb48e:
# tools_run had 3 entries, tool_status had 4 keys (nuclei[medium:cve]
# auto-stamped via pre-chunk abort path that fired DegradedRunError
# BEFORE the per-chunk tools_run.append). assert_tool_status_invariant
# only runs in close_out (the clean path), so the gap persisted
# silently in the persisted scan_run row.
#
# Two fixes (both advisor-approved):
#   Fix A — nuclei pre-chunk abort path now appends chunk_name to
#           tools_run BEFORE mark_tool_degraded + raise. Matches the
#           ffuf abort site (run_medium.py:1864).
#   Fix B — degraded_out runs reconcile_tool_status_invariant BEFORE
#           the persist write. Reconciles instead of raising. Safety
#           net behind Fix A; protects against any future abort path
#           that re-introduces the gap.


from run_medium import reconcile_tool_status_invariant  # noqa: E402


class _MinimalCtx:
    """Stand-in for ScanContext with just the two fields the reconcile
    function touches. Avoids pulling in psycopg / dataclass machinery."""

    def __init__(self, tools_run=None, tool_status=None):
        self.tools_run = list(tools_run or [])
        self.tool_status = dict(tool_status or {})


def test_reconcile_no_op_when_already_consistent():
    """Reconcile is idempotent — when tools_run and tool_status are
    already set-equal, nothing changes. Guards against a future
    'helpful' edit that adds spurious entries on every call."""
    ctx = _MinimalCtx(
        tools_run=["wafw00f", "nuclei[critical,high]"],
        tool_status={
            "wafw00f": {"ok": True},
            "nuclei[critical,high]": {"ok": True},
        },
    )
    reconcile_tool_status_invariant(ctx)
    assert ctx.tools_run == ["wafw00f", "nuclei[critical,high]"]
    assert set(ctx.tool_status.keys()) == {"wafw00f", "nuclei[critical,high]"}


def test_reconcile_case_1_stamped_but_not_in_tools_run():
    """The exact scan_run 648313cd shape: nuclei[medium:cve] is stamped
    degraded in tool_status but missing from tools_run. After reconcile,
    tools_run catches up (the stamp is the source of truth — it knows
    the chunk attempted and how it failed)."""
    ctx = _MinimalCtx(
        tools_run=["wafw00f", "httpx[-td]", "nuclei[critical,high]"],
        tool_status={
            "wafw00f": {"ok": True},
            "httpx[-td]": {"ok": True},
            "nuclei[critical,high]": {"ok": True},
            "nuclei[medium:cve]": {"degraded": "skipped_target_unreachable"},
        },
    )
    reconcile_tool_status_invariant(ctx)
    assert set(ctx.tools_run) == set(ctx.tool_status.keys())
    assert "nuclei[medium:cve]" in ctx.tools_run
    # The stamp is preserved — reconcile MUST NOT clobber the
    # existing degraded reason with no_status_recorded.
    assert ctx.tool_status["nuclei[medium:cve]"] == {
        "degraded": "skipped_target_unreachable"
    }


def test_reconcile_case_2_in_tools_run_but_not_stamped():
    """Inverse case: a tool ran (in tools_run) but neither mark_tool_ok
    nor mark_tool_degraded landed (e.g. interrupted between append and
    stamp). Reconcile stamps degraded:no_status_recorded so the persisted
    row is consistent and the launder-block lock stays correct."""
    ctx = _MinimalCtx(
        tools_run=["wafw00f", "ghost_tool"],
        tool_status={"wafw00f": {"ok": True}},
    )
    reconcile_tool_status_invariant(ctx)
    assert set(ctx.tools_run) == set(ctx.tool_status.keys())
    assert ctx.tool_status["ghost_tool"] == {"degraded": "no_status_recorded"}


def test_reconcile_does_not_clobber_existing_ok_stamp():
    """Cross-class guard: if a tool is in tool_status with ok:true AND
    in tools_run, reconcile must leave both alone. A naive impl that
    stamps no_status_recorded based on tools_run membership alone
    would corrupt healthy entries."""
    ctx = _MinimalCtx(
        tools_run=["wafw00f"],
        tool_status={"wafw00f": {"ok": True}},
    )
    reconcile_tool_status_invariant(ctx)
    assert ctx.tool_status["wafw00f"] == {"ok": True}
    assert ctx.tools_run == ["wafw00f"]


# ═══════════════════════════════════════════════════════════════════════
# Task #21 [1b] — flush_artifacts_to_db: degraded forensics gap fix
# ═══════════════════════════════════════════════════════════════════════
# Surfaced by myordersauth prod (d0cbe39e) + test (bd2cef8f) 2026-06-14:
# scan_run_artifacts had 0 rows for both degraded runs despite wafw00f /
# httpx / nuclei chunks / nikto all having appended to ctx.artifacts.
# Cause: raise DegradedRunError → conn.rollback() discarded the pending
# artifact INSERTs. Fix: flush_artifacts_to_db called from degraded_out
# BEFORE the stamping queries. Per-artifact try/except so a bad blob
# doesn't crash the stamping that follows.


from run_medium import flush_artifacts_to_db  # noqa: E402


class _RecordingCursor:
    """Cursor that records every (sql, params) call. Optionally raises
    on the Nth call to simulate a bad-artifact INSERT failure."""

    def __init__(self, raise_on_call: int | None = None):
        self.calls: list[tuple[str, dict]] = []
        self._raise_on_call = raise_on_call

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.calls.append((sql, params))
        if (
            self._raise_on_call is not None
            and len(self.calls) == self._raise_on_call
        ):
            raise RuntimeError("simulated bad artifact insert")


class _RecordingConn:
    def __init__(self, raise_on_call: int | None = None):
        self.cursor_obj = _RecordingCursor(raise_on_call=raise_on_call)

    def cursor(self):
        return self.cursor_obj


def _fake_json(obj):
    """Stand-in for psycopg.types.json.Json — flush_artifacts_to_db
    wraps content in this. Identity wrapper is enough; the test never
    sends to a real DB."""
    return obj


class _ArtifactCtx:
    """Stand-in for ScanContext with just scan_run_id + artifacts."""

    def __init__(self, scan_run_id="test-run", artifacts=None):
        self.scan_run_id = scan_run_id
        self.artifacts = list(artifacts or [])


def test_flush_artifacts_empty_is_noop():
    """No artifacts in ctx → flush returns 0 written, makes 0 cursor calls."""
    ctx = _ArtifactCtx(artifacts=[])
    conn = _RecordingConn()
    written = flush_artifacts_to_db(conn, ctx, _fake_json)
    assert written == 0
    assert conn.cursor_obj.calls == []


def test_flush_artifacts_writes_each_appended_artifact():
    """Each artifact tuple (tool_name, output_format, content_str) becomes
    one INSERT_ARTIFACT_SQL execution with the right params."""
    ctx = _ArtifactCtx(
        scan_run_id="run-123",
        artifacts=[
            ("wafw00f", "text", "no WAF detected"),
            ("nikto", "text", "+ ERROR: stub stderr"),
        ],
    )
    conn = _RecordingConn()
    written = flush_artifacts_to_db(conn, ctx, _fake_json)
    assert written == 2
    assert len(conn.cursor_obj.calls) == 2
    # Verify the first call's shape
    first_sql, first_params = conn.cursor_obj.calls[0]
    assert "INSERT INTO public.scan_run_artifacts" in first_sql
    assert first_params["scan_run_id"] == "run-123"
    assert first_params["tool_name"] == "wafw00f"
    assert first_params["output_format"] == "text"
    assert first_params["size_bytes"] == len("no WAF detected".encode("utf-8"))


def test_flush_artifacts_per_artifact_isolation_one_bad_blob_does_not_crash():
    """LOAD-BEARING: if one artifact's INSERT raises (malformed JSON,
    oversize, transient lock, whatever), the flush MUST continue with
    the remaining artifacts. A raise mid-flush from degraded_out would
    lose the entire scan_run / scan_queue stamping path → queue row
    stuck at 'running' → partial unique index blocks future scans on
    the asset. This is the worst-case outcome we're guarding against."""
    ctx = _ArtifactCtx(
        artifacts=[
            ("wafw00f", "text", "ok"),
            ("bad_tool", "text", "this insert will raise"),
            ("nikto", "text", "should still get written"),
        ],
    )
    # Raise on the 2nd execute (the "bad_tool" insert)
    conn = _RecordingConn(raise_on_call=2)
    # The flush itself MUST NOT raise
    written = flush_artifacts_to_db(conn, ctx, _fake_json)
    # 1st succeeded, 2nd raised (not counted), 3rd succeeded
    assert written == 2
    # All 3 were attempted (cursor.execute was called for each)
    assert len(conn.cursor_obj.calls) == 3
    # The third call's tool_name confirms we continued past the failure
    third_sql, third_params = conn.cursor_obj.calls[2]
    assert third_params["tool_name"] == "nikto"


# ═══════════════════════════════════════════════════════════════════════
# A′ design — mark_tool_degraded stderr capture (2026-06-15)
# ═══════════════════════════════════════════════════════════════════════
# Captures the failed tool's stderr to ctx.artifacts (and GH log) at the
# universal chokepoint so EVERY tool's degraded path gets diagnostic
# preservation without per-tool plumbing. Supersedes the per-tool A
# variant. See run_medium.py:445 docstring for full rationale.


from run_medium import (  # noqa: E402
    MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES,
    extract_nikto_footer_count,
    mark_tool_degraded,
    mark_tool_skipped,
    nikto_is_degraded,
    parse_nikto_findings,
)


class _StderrCtx:
    """Stand-in for ScanContext with the two fields mark_tool_degraded
    touches when stderr is provided: tool_status (stamp) + artifacts
    (append). Avoids dataclass + psycopg machinery."""

    def __init__(self):
        self.tool_status: dict[str, dict] = {}
        self.artifacts: list[tuple[str, str, str]] = []


def test_mark_tool_degraded_backward_compat_no_stderr_kwarg():
    """Existing ~25 call sites that don't pass stderr= must continue to
    work exactly as before — only tool_status gets stamped, no artifact
    appended. Guards against an over-eager refactor that would force
    every site to provide stderr."""
    ctx = _StderrCtx()
    mark_tool_degraded(ctx, "nikto", "runtime_error")
    assert ctx.tool_status == {"nikto": {"degraded": "runtime_error"}}
    assert ctx.artifacts == []


def test_mark_tool_degraded_with_stderr_appends_artifact():
    """When stderr= is passed, append a (<tool>_stderr, text, stderr)
    artifact to ctx.artifacts so the flush loops (clean-path inline at
    write_findings_and_artifacts and degraded-path via
    flush_artifacts_to_db in degraded_out) carry it to scan_run_artifacts
    automatically. No 3-tuple → 4-tuple refactor needed."""
    ctx = _StderrCtx()
    mark_tool_degraded(
        ctx, "nikto", "runtime_error",
        stderr="+ ERROR: Unable to open '' for write:",
    )
    # tool_status still stamped
    assert ctx.tool_status == {"nikto": {"degraded": "runtime_error"}}
    # Artifact appended with the canonical name shape
    assert len(ctx.artifacts) == 1
    name, fmt, content = ctx.artifacts[0]
    assert name == "nikto_stderr"
    assert fmt == "text"
    assert content == "+ ERROR: Unable to open '' for write:"


def test_mark_tool_degraded_with_empty_stderr_does_not_append():
    """Empty / None stderr should NOT pollute ctx.artifacts with empty
    blobs — both are falsy, neither should produce an artifact. The
    `if stderr:` guard in mark_tool_degraded handles both cases. This
    matters because some pre-chunk abort paths have NO stderr to
    capture (the chunk hasn't run yet)."""
    # Empty string — falsy
    ctx = _StderrCtx()
    mark_tool_degraded(ctx, "nikto", "skipped_target_unreachable", stderr="")
    assert ctx.artifacts == []
    # None — explicit
    ctx = _StderrCtx()
    mark_tool_degraded(ctx, "nikto", "skipped_target_unreachable", stderr=None)
    assert ctx.artifacts == []


def test_mark_tool_degraded_caps_stderr_at_64kb():
    """A chatty tool that floods stderr with thousands of error lines
    must NOT bloat scan_run_artifacts. The cap is 64KB
    (MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES); a 1MB stderr should be
    truncated to exactly the cap."""
    cap = MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES
    assert cap == 64 * 1024
    huge_stderr = "x" * (10 * cap)  # 640KB
    ctx = _StderrCtx()
    mark_tool_degraded(
        ctx, "rotation_storm_tool", "stderr_flood",
        stderr=huge_stderr,
    )
    _, _, content = ctx.artifacts[0]
    assert len(content) == cap


def test_mark_tool_degraded_stderr_under_cap_not_truncated():
    """Sanity — small stderr (the common case, nikto's typical output is
    ~250 bytes) is passed through unchanged. Cap only kicks in when
    stderr exceeds the threshold."""
    small_stderr = "+ ERROR: Required module not found: JSON"  # ~40 bytes
    ctx = _StderrCtx()
    mark_tool_degraded(ctx, "nikto", "module_not_found", stderr=small_stderr)
    _, _, content = ctx.artifacts[0]
    assert content == small_stderr  # exact passthrough


def test_mark_tool_degraded_stderr_artifact_pairs_with_existing_tool_artifact():
    """The flush_artifacts_to_db loop iterates ctx.artifacts in append
    order. If the tool's primary stdout artifact was appended first
    (e.g. ('nikto', 'text', stdout) at run_medium.py:1568) and stderr
    gets appended via mark_tool_degraded, both should be present and
    distinguishable via the `_stderr` suffix. This test pins the naming
    convention so future tooling (dashboard, forensics queries) can
    rely on `<tool>` + `<tool>_stderr` pair semantics."""
    ctx = _StderrCtx()
    # Simulate the order in run_nikto: stdout appended first, then
    # mark_tool_degraded with stderr.
    ctx.artifacts.append(("nikto", "text", "Nikto v2.5 starting..."))
    mark_tool_degraded(ctx, "nikto", "runtime_error", stderr="+ ERROR: blah")
    assert len(ctx.artifacts) == 2
    names = [a[0] for a in ctx.artifacts]
    assert names == ["nikto", "nikto_stderr"]


# ═══════════════════════════════════════════════════════════════════════
# nikto_is_degraded — target_error_limit split (2026-06-15)
# ═══════════════════════════════════════════════════════════════════════
# Surfaced by scan_run 78a94f11 (myordersauth-test 2026-06-15): nikto ran
# 444s, reached ~5% coverage, hit its internal 20-consecutive-errors
# budget, and emitted:
#   + ERROR: *** Error limit (20) reached for host, giving up. ***
#   + ERROR: *** Consider using mitmproxy to avoid TLS fingerprinting. ***
# Before this split, the generic `+ ERROR:` catchall fired runtime_error —
# correct that the run is degraded, wrong that it's the same class as a
# Bug E crash. Advisor design (Howie 2026-06-15):
#   Three states: ok | runtime_error (crash) | target_error_limit (blocked partial)
# Do NOT mirror the maxtime exclusion — error-limit is NOT "worked within
# OUR budget," it's "target blocked us at 5% coverage." Treating it as
# 'ok' would re-create the success-shaped-lie class the detector exists
# to prevent.


# Real fixture from scan_run 78a94f11 (truncated for test clarity)
NIKTO_TARGET_ERROR_LIMIT_STDERR = (
    "+ ERROR: *** Error limit (20) reached for host, giving up. "
    "Last error: . ***\n"
    "+ ERROR: *** Consider using mitmproxy to avoid TLS fingerprinting. ***\n"
)

# Real fixture from scan_run c14e2fe2 (Bug E class, write-crash)
NIKTO_RUNTIME_CRASH_STDERR = (
    "+ ERROR: Unable to open '' for write: No such file or directory at "
    "/var/lib/nikto/plugins/nikto_report_text.plugin line 41.\n"
)

# Synthesized — maxtime cry-wolf guard fixture
NIKTO_MAXTIME_ONLY_STDOUT = (
    "- Nikto v2.6.0\n"
    "+ Target Hostname: demo.testfire.net\n"
    "+ Start Time: 2026-06-15 10:00:00 (GMT0)\n"
    "+ [013587] /: Some finding\n"
    "+ ERROR: Host maximum execution time of 540 seconds reached\n"
    "+ End Time: 2026-06-15 10:09:00 (GMT0)\n"
)


def test_nikto_is_degraded_target_error_limit_primary_pattern():
    """The "Error limit (N) reached for host" line is the load-bearing
    primary signal. Match alone (without the mitmproxy hint) is
    sufficient — nikto could remove the secondary hint in a future
    version, primary line is the contract."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr="+ ERROR: *** Error limit (20) reached for host, giving up. ***",
        rc=0,
    )
    assert is_deg is True
    assert reason == "target_error_limit"


def test_nikto_is_degraded_target_error_limit_secondary_pattern_alone():
    """The mitmproxy hint alone is also sufficient — defensive against a
    nikto version that uses different primary phrasing. Either signal
    independently triggers."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr="+ ERROR: *** Consider using mitmproxy to avoid TLS fingerprinting. ***",
        rc=0,
    )
    assert is_deg is True
    assert reason == "target_error_limit"


def test_nikto_is_degraded_target_error_limit_full_78a94f11_fixture():
    """Full fixture from the surfacing scan_run. Confirms the real-world
    shape that exposed this class lands cleanly on target_error_limit."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr=NIKTO_TARGET_ERROR_LIMIT_STDERR,
        rc=0,
    )
    assert is_deg is True
    assert reason == "target_error_limit"


def test_nikto_is_degraded_runtime_error_still_fires_for_bug_e_class():
    """Regression guard: the runtime_error reason must STILL fire for
    Bug E class crashes (rc=2 + write-to-null report). The target_error_
    limit split must not have swallowed the original detector."""
    is_deg, reason = nikto_is_degraded(
        stdout="- Nikto v2.6.0\n+ Target: demo.testfire.net\n",
        stderr=NIKTO_RUNTIME_CRASH_STDERR,
        rc=2,
    )
    assert is_deg is True
    assert reason == "runtime_error"


def test_nikto_is_degraded_maxtime_still_clean():
    """Regression guard: maxtime exclusion must still hold. A run that
    hit -maxtime is 'worked within OUR budget' — clean is honest."""
    is_deg, reason = nikto_is_degraded(
        stdout=NIKTO_MAXTIME_ONLY_STDOUT,
        stderr="",
        rc=0,
    )
    assert is_deg is False
    assert reason == ""


def test_nikto_is_degraded_error_limit_takes_precedence_over_runtime_error():
    """Priority order matters. If BOTH error-limit AND a generic crash-
    class `+ ERROR:` appear in the same run (unlikely but possible),
    target_error_limit should win — it's the more specific reason and
    the more accurate diagnostic. A crash mid-target-blocking is still
    a target-blocking event from the operator's perspective."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr=(
            "+ ERROR: *** Error limit (20) reached for host, giving up. ***\n"
            "+ ERROR: Some other crash text that would normally fire runtime_error\n"
        ),
        rc=0,
    )
    assert is_deg is True
    assert reason == "target_error_limit"


def test_nikto_is_degraded_clean_run_with_no_errors_stays_clean():
    """Baseline: a healthy run with banner + findings + clean End Time
    returns (False, '')."""
    is_deg, reason = nikto_is_degraded(
        stdout=(
            "- Nikto v2.6.0\n"
            "+ Target: demo.testfire.net\n"
            "+ Start Time: 2026-06-15 10:00:00 (GMT0)\n"
            "+ [013587] /: Some finding\n"
            "+ End Time: 2026-06-15 10:30:00 (GMT0)\n"
        ),
        stderr="",
        rc=0,
    )
    assert is_deg is False
    assert reason == ""


def test_nikto_is_degraded_help_banner_still_fires():
    """Regression guard on help_text_returned class."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr="Note: This is the short help output. Use -H for full help text.",
        rc=0,
    )
    assert is_deg is True
    assert reason == "help_text_returned"


def test_nikto_is_degraded_module_not_found_still_fires():
    """Regression guard on module_not_found class (no leading `+ `)."""
    is_deg, reason = nikto_is_degraded(
        stdout="",
        stderr="ERROR: Required module not found: JSON\n",
        rc=1,
    )
    assert is_deg is True
    assert reason == "module_not_found"


# ═══════════════════════════════════════════════════════════════════════
# #24 — mark_tool_skipped + skipped state acceptance (2026-06-15)
# ═══════════════════════════════════════════════════════════════════════
# Third state alongside {"ok": True} and {"degraded": "<slug>"}:
#   {"skipped": "<reason_slug>"}
# For policy-based intentional skips (auth-gated targets skip nikto +
# ffuf + nuclei attack chunks because no unauth surface exists).
# A skipped tool is NOT degraded — the scan correctly chose not to run
# it. scan_quality stays 'clean' for runs with only ok + skipped statuses.
# Consumer grep confirmed no external code filters on tool_status state
# in a way that would misclassify "skipped" as "not ok" → safe to add.


def test_mark_tool_skipped_writes_canonical_shape():
    """The third state shape is {"skipped": "<reason_slug>"}.
    Distinct from {"ok": True} and {"degraded": "..."}. Downstream
    readers can dispatch on the key (`"skipped" in entry` vs
    `"degraded" in entry` vs `"ok" in entry`)."""
    ctx = _StderrCtx()
    mark_tool_skipped(ctx, "nikto", "auth_gated")
    assert ctx.tool_status == {"nikto": {"skipped": "auth_gated"}}
    # NOT degraded; NOT ok
    assert "degraded" not in ctx.tool_status["nikto"]
    assert "ok" not in ctx.tool_status["nikto"]


def test_mark_tool_skipped_does_not_append_artifact():
    """Unlike mark_tool_degraded (which optionally takes stderr and
    appends an artifact), mark_tool_skipped takes no stderr — the tool
    didn't run, there's no stderr to capture. Catches a refactor that
    adds a spurious artifact append."""
    ctx = _StderrCtx()
    mark_tool_skipped(ctx, "nikto", "auth_gated")
    assert ctx.artifacts == []


def test_assert_tool_status_invariant_accepts_skipped_state():
    """LOAD-BEARING: the invariant assertion is value-blind on the set
    check — it only cares whether the key exists in tool_status,
    regardless of whether the value is {ok}, {degraded}, or {skipped}.
    Proves the design claim that adding the third state doesn't break
    the invariant. An auth-gated medium run with several skipped tools
    must satisfy the invariant cleanly (no missing/unclaimed)."""
    tools_run = ["wafw00f", "httpx[-td]", "nikto", "nuclei[critical,high]"]
    tool_status = {
        "wafw00f": {"ok": True},
        "httpx[-td]": {"ok": True},
        "nikto": {"skipped": "auth_gated"},                # NEW state
        "nuclei[critical,high]": {"skipped": "auth_gated"}, # NEW state
    }
    # Should NOT raise — set equality holds value-blind
    assert_tool_status_invariant(tools_run, tool_status)


def test_reconcile_tool_status_invariant_leaves_skipped_alone():
    """The reconcile in degraded_out stamps missing entries with
    {"degraded": "no_status_recorded"} — but it MUST NOT overwrite
    EXISTING entries (including skipped ones). Without this guarantee,
    an auth-gated run that then degrades for some unrelated reason
    would have its skipped entries clobbered to degraded."""
    ctx = _MinimalCtx(
        tools_run=["wafw00f", "nikto"],
        tool_status={
            "wafw00f": {"ok": True},
            "nikto": {"skipped": "auth_gated"},
        },
    )
    reconcile_tool_status_invariant(ctx)
    # skipped entry preserved exactly
    assert ctx.tool_status["nikto"] == {"skipped": "auth_gated"}
    # ok entry preserved exactly
    assert ctx.tool_status["wafw00f"] == {"ok": True}
    # tools_run unchanged
    assert ctx.tools_run == ["wafw00f", "nikto"]


def test_three_state_dispatch_pattern_works():
    """Forensics callers should be able to dispatch on the state key
    cleanly. Verifies the three-state model is mutually exclusive — a
    given entry is ok XOR degraded XOR skipped."""
    states = [
        ({"ok": True}, "ok"),
        ({"degraded": "runtime_error"}, "degraded"),
        ({"skipped": "auth_gated"}, "skipped"),
    ]
    for entry, expected_key in states:
        keys = set(entry.keys())
        # Exactly one of the three state markers
        markers = {"ok", "degraded", "skipped"} & keys
        assert markers == {expected_key}, (
            f"Entry {entry!r} should have exactly one state marker, "
            f"got {markers}"
        )


# ═══════════════════════════════════════════════════════════════════════
# #28 — nikto parser noise cleanup (2026-06-15)
# ═══════════════════════════════════════════════════════════════════════
# Surfaced by FortiWeb run on test.commandcommcentral (scan_run 14714f2f
# 2026-06-15): parser stored 6 findings while nikto's own footer reported
# 4 items. The 2 extras were no-[ID] meta lines (Platform:, No CGI
# Directories found) the prior denylist-of-prefixes missed. Plus 2 of
# the 4 "real" findings were "Suggested security header missing:" lines
# duplicating headers_check (light tier, canonical for headers).
#
# Fix per Howie 2026-06-15 advisor pass:
#   - Promote ONLY canonical shape: + [<digits>] /path: description
#   - Q1: drop nikto's "Suggested security header missing:" lines
#   - Q2: severity off ID range (999xxx=INFO, else LOW). nikto never
#     self-assigns MODERATE+ (low-fidelity source).
#   - Footer-guard for parser-drift detection.


# Fixture is the VERBATIM raw nikto stdout from scan_run
# 14714f2f-0446-4686-a593-49da179a508f (test.commandcommcentral.com,
# 2026-06-15 17:27-17:36 UTC). Pulled from scan_run_artifacts on
# 2026-06-15 — real data is the test surface.
#
# Note (2026-06-15 follow-up): the earlier synthesized fixture had
# "4 item(s) reported on remote host" but real nikto v2.6.0 emits
# "4 items reported on the remote host" — bare "items", no parens.
# That divergence let the original NIKTO_FOOTER_COUNT_RE silently
# fail against real output for the entire #28 PR window. Lesson
# pinned: synthesize-from-memory is unsafe for regex-target text;
# real verbatim or nothing.
#
# Shape:
#   1 nikto banner ("- Nikto v2.6.0") starts with "-" → bypass
#   Scaffolding/meta (Target IP/Hostname/Port, SSL Info + continuation
#     lines, Platform, Start Time, Server, No CGI, Scan terminated,
#     End Time, host(s) tested) — no [ID] → DROP at shape gate
#   2 header-missing lines ([013587]) → DROP at Q1 dedup
#   2 informational lines ([999992] wildcard cert + [999962] banner
#     changed) → KEEP as INFO
#   Footer reports 4 items (matches the 4 [<id>] lines).
NIKTO_FORTIWEB_FIXTURE = """-***** Pausing 1 second(s) per request
- Nikto v2.6.0
---------------------------------------------------------------------------
+ Target IP:          24.38.70.8
+ Target Hostname:    test.commandcommcentral.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:           Subject:  /C=US/ST=New Jersey/L=Secaucus/O=Strategic Content Imaging/CN=*.commandcommcentral.com
                      CN:       *.commandcommcentral.com
                      SAN:      *.commandcommcentral.com, commandcommcentral.com
                      Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                      Issuer:   /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http:\\/\\/certs.godaddy.com\\/repository\\//CN=Go Daddy Secure Certificate Authority - G2
+ Platform:           Linux/Unix
+ Start Time:         2026-06-15 17:27:18 (GMT0)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [999992] /: Server is using a wildcard certificate: *.commandcommcentral.com. See: https://en.wikipedia.org/wiki/Wildcard_certificate
+ [999962] /: Server banner changed from 'Microsoft-HTTPAPI/2.0' to ''.
+ [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
+ [013587] /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
+ Scan terminated: 0 errors and 4 items reported on the remote host
+ End Time:           2026-06-15 17:36:50 (GMT0) (572 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""


def test_nikto_parser_drops_no_id_scaffolding_and_meta_lines():
    """LOAD-BEARING: lines like 'Platform: Linux/Unix' and 'No CGI
    Directories found' must NEVER promote as findings. These have no
    [<digits>] ID and the canonical shape gate drops them.

    Pre-#28 bug: the denylist-of-prefixes missed these, the keyword
    severity map then mis-fired ('No CGI Directories FOUND' triggered
    the naive 'found' → LOW match), producing 2 noise findings per run.
    """
    findings, nikto_emitted, we_promoted = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    # No promoted finding should have "Platform" or "No CGI" in its title
    for f in findings:
        assert "Platform" not in f.title, (
            f"Platform: line promoted as finding (pre-#28 bug): {f.title}"
        )
        assert "No CGI" not in f.title, (
            f"No CGI Directories line promoted as finding (pre-#28 bug, "
            f"naive 'found' keyword mis-fired on negative): {f.title}"
        )


def test_nikto_parser_drops_suggested_header_missing_dupes():
    """Q1 advisor lock-in. nikto's '[013587] /: Suggested security
    header missing:' lines duplicate headers_check (light tier,
    canonical for HTTP security headers). Drop them at the parser —
    cleaner than downstream normalized_key dedup.

    Both 013587 lines in the FortiWeb fixture (referrer-policy +
    permissions-policy) must NOT appear in promoted findings."""
    findings, _, _ = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    for f in findings:
        assert "Suggested security header missing" not in f.title, (
            f"Header-missing dupe of headers_check promoted: {f.title}"
        )


def test_nikto_parser_keeps_999_range_as_info():
    """Q2 advisor lock-in. 999xxx is nikto's documented informational
    range. [999992] wildcard certificate + [999962] banner changed
    are real (low-fidelity) observations — keep as INFO, never higher.
    """
    findings, _, _ = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    info_999 = [f for f in findings if "999" in f.title or "wildcard certificate" in f.title or "banner changed" in f.title]
    assert len(info_999) == 2, (
        f"Expected exactly 2 999xxx findings (wildcard cert + banner), "
        f"got {len(info_999)}: {[f.title for f in info_999]}"
    )
    for f in info_999:
        assert f.severity == "INFO", (
            f"999xxx finding got severity {f.severity!r}; must be INFO. "
            f"Title: {f.title}"
        )


def test_nikto_parser_never_assigns_moderate_or_higher():
    """Q2 advisor principle lock-in. nikto is a low-fidelity DAST source;
    real severity comes from nuclei / CVE / manual triage. nikto's
    output must NEVER carry MODERATE / MODERATE-HIGH / HIGH / CRITICAL
    on its own — under-call beats over-call here (this gates #27 by
    not crying wolf in the change-visibility view).

    Test against the fixture; assert no finding has severity >= MODERATE."""
    findings, _, _ = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    forbidden = {"MODERATE", "MODERATE-HIGH", "HIGH", "CRITICAL"}
    for f in findings:
        assert f.severity not in forbidden, (
            f"nikto self-assigned {f.severity!r} on {f.title!r}. nikto must "
            f"only ever assign INFO or LOW; real severity is downstream."
        )


def test_nikto_parser_fortiweb_fixture_end_to_end_count():
    """Headline regression test — the exact FortiWeb scenario that
    surfaced #28. Pre-#28 stored 6 findings; post-#28 stores 2 (the
    999xxx INFOs). nikto_emitted=4 (matches nikto's own footer);
    we_promoted=2 (4 minus 2 Q1 header dupes)."""
    findings, nikto_emitted, we_promoted = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    assert len(findings) == 2, (
        f"Expected exactly 2 findings post-#28 (the 2 999xxx INFOs), "
        f"got {len(findings)}: {[f.title for f in findings]}"
    )
    assert nikto_emitted == 4, (
        f"shape-gate should have matched 4 [<id>] lines, got {nikto_emitted}"
    )
    assert we_promoted == 2, (
        f"after Q1 header-dedup, should have promoted 2, got {we_promoted}"
    )


def test_nikto_footer_count_extraction_from_fortiweb_fixture():
    """The footer guard parses 'N item(s) reported' from nikto's
    summary. For the FortiWeb fixture, count = 4."""
    assert extract_nikto_footer_count(NIKTO_FORTIWEB_FIXTURE) == 4


def test_nikto_footer_count_returns_none_when_absent():
    """Defensive: missing footer → None (don't crash, don't fake a count).
    Older nikto / truncated output / mid-scan-killed runs may not have
    a footer line."""
    stdout_no_footer = "- Nikto v2.6.0\n+ Target IP: 1.2.3.4\n"
    assert extract_nikto_footer_count(stdout_no_footer) is None


def test_nikto_footer_count_handles_all_three_text_forms():
    """LOAD-BEARING follow-up (2026-06-15): the original regex required
    literal 'item(s)' (parenthesized), but real nikto v2.6.0 emits
    'items' (bare plural). The synthesized fixture coincidentally had
    'item(s)' which masked the bug for an entire PR window — the
    footer guard was silently dead against real output.

    Lock in all three forms the regex MUST match:
      'N item reported'    — singular (some older nikto)
      'N items reported'   — bare plural (nikto v2.6.0, real output)
      'N item(s) reported' — parenthesized (some other versions)

    Any future regex change that re-narrows on this string trips this
    test immediately."""
    cases = [
        ("4 items reported on the remote host", 4),       # nikto v2.6.0 real
        ("12 item(s) reported on remote host", 12),       # parenthesized
        ("1 item reported", 1),                            # singular
        ("0 items reported on the remote host", 0),       # zero plural
    ]
    for footer_text, expected in cases:
        # Build a minimal stdout snippet around each footer text
        stdout = f"- Nikto v2.6.0\n+ Scan terminated: 0 errors and {footer_text}\n"
        got = extract_nikto_footer_count(stdout)
        assert got == expected, (
            f"footer text {footer_text!r} should yield {expected}, got {got!r}. "
            f"Regex change re-narrowed the footer matcher?"
        )


def test_nikto_footer_count_against_real_fortiweb_stdout():
    """Verbatim-real-data regression. The FORTIWEB fixture is the actual
    raw nikto stdout from scan_run 14714f2f. Footer says
    '4 items reported on the remote host' — bare 'items', no parens.
    The pre-follow-up regex (item\\(s\\)) returned None on this. The
    post-follow-up regex returns 4."""
    assert extract_nikto_footer_count(NIKTO_FORTIWEB_FIXTURE) == 4


def test_nikto_parser_drift_detection_via_footer_mismatch():
    """The footer guard's contract: shape-matched count should equal
    footer count. If they diverge, parser drift has happened. The
    PRE-Q1 promote (nikto_emitted) should match the footer; the
    POST-Q1 promote (we_promoted) does NOT, by design — that's the
    policy-drop, not parser drift."""
    nikto_emitted = 4
    we_promoted = 2
    footer_count = extract_nikto_footer_count(NIKTO_FORTIWEB_FIXTURE)
    # The shape-matched count IS the parser-drift signal — it should
    # match the footer.
    assert footer_count == nikto_emitted, (
        f"shape-matched {nikto_emitted} != footer {footer_count}; "
        f"would have logged a parser-drift warning"
    )
    # The post-Q1 promote diverges from the footer — that's a POLICY
    # drop (header dedup), NOT parser drift. Log message reflects this.
    assert footer_count != we_promoted, (
        "test sanity: footer should diverge from we_promoted because Q1 "
        "drops 2 header lines"
    )


def test_nikto_parser_empty_stdout_yields_no_findings():
    """Defensive: empty/whitespace stdout → no findings, zero counts."""
    findings, nikto_emitted, we_promoted = parse_nikto_findings(
        "", "demo.testfire.net"
    )
    assert findings == []
    assert nikto_emitted == 0
    assert we_promoted == 0


def test_nikto_parser_stable_check_name_slug_for_finding_id_continuity():
    """The finding_id derives from check_name. Across the #28 refactor
    the slug logic was preserved (re.sub on the full body lowercased) so
    existing findings in the DB match on re-detect rather than fragmenting
    into new finding_ids. Existing findings can be marked false_positive
    by deterministic slug.

    Lock-in: a wildcard-certificate line produces the expected slug
    prefix so the side-question UPDATE can target it precisely."""
    findings, _, _ = parse_nikto_findings(
        NIKTO_FORTIWEB_FIXTURE, "test.commandcommcentral.com"
    )
    cert_findings = [f for f in findings if "wildcard certificate" in f.title]
    assert len(cert_findings) == 1
    # Slug should start with "nikto-" and include "999992" (the ID)
    assert cert_findings[0].check_name.startswith("nikto-")
    assert "999992" in cert_findings[0].check_name


# ═══════════════════════════════════════════════════════════════════════
# #30 — healthcheck_with_retry: rotation-spiral guard (2026-06-16)
# ═══════════════════════════════════════════════════════════════════════
# Surfaced by scan_run 57a79615 (ftp.sciimage.com 2026-06-16): medium
# rotated twice in 10 seconds and gave up as skipped_target_unreachable
# while wafw00f + httpx had just been OK against the same egress.
# Pre-rotate: no retry, blip = rotation. Post-rotate: bare sleep 2,
# probe TARGET immediately on a tunnel that hadn't negotiated yet → 0
# → rotate → spiral. The retry helper is the unit-testable piece;
# vpn_rotate.sh's WG handshake poll is integration-only.


def _seq_healthcheck(results):
    """Return a healthcheck_fn that yields canned results in order.
    Each call pops the next (healthy, code) tuple. RuntimeError on
    overrun — tests should explicitly size results to match the
    expected attempts."""
    iter_results = iter(results)
    def fn():
        try:
            return next(iter_results)
        except StopIteration:
            raise RuntimeError(
                "healthcheck called more times than the test provided "
                "canned results — adjust the test's results list"
            )
    return fn


class _CountingSleep:
    """No-op sleep that records each call's delay. Tests assert on
    .calls (list of delay_s) to verify backoff timing without actually
    sleeping."""
    def __init__(self):
        self.calls: list[float] = []
    def __call__(self, delay_s: float) -> None:
        self.calls.append(delay_s)


def test_healthcheck_with_retry_first_attempt_healthy_returns_immediately():
    """LOAD-BEARING — the original bug. A single healthy probe must
    return (True, code) with ZERO sleeps. Tests the pre-rotate retry
    helper doesn't waste time when the first probe succeeds."""
    sleeper = _CountingSleep()
    healthy, code = healthcheck_with_retry(
        _seq_healthcheck([(True, 200)]),
        attempts=3,
        delay_s=2,
        sleep_fn=sleeper,
    )
    assert (healthy, code) == (True, 200)
    assert sleeper.calls == []  # no sleeps on first-attempt success


def test_healthcheck_with_retry_recovers_from_transient_blip():
    """The exact failure mode that broke scan_run 57a79615: first
    probe is a transient blip (code 0), second probe healthy. Without
    retry the scanner would have rotated; with retry it recovers
    cleanly. Asserts: (True, 200) returned, ONE sleep between probes."""
    sleeper = _CountingSleep()
    healthy, code = healthcheck_with_retry(
        _seq_healthcheck([(False, 0), (True, 200)]),
        attempts=3,
        delay_s=2,
        sleep_fn=sleeper,
    )
    assert (healthy, code) == (True, 200)
    assert sleeper.calls == [2]  # one sleep between attempt 1 and 2


def test_healthcheck_with_retry_all_attempts_unhealthy_returns_last():
    """When every probe fails, return the LAST (False, code) result
    and (attempts - 1) sleeps. Tests the exhaustion path that
    legitimately triggers rotation (no false positives on rotation
    pressure either — three consecutive failures IS a real signal)."""
    sleeper = _CountingSleep()
    healthy, code = healthcheck_with_retry(
        _seq_healthcheck([(False, 0), (False, 0), (False, 503)]),
        attempts=3,
        delay_s=2,
        sleep_fn=sleeper,
    )
    assert (healthy, code) == (False, 503)
    # 3 attempts → 2 sleeps between them
    assert sleeper.calls == [2, 2]


def test_healthcheck_with_retry_attempts_1_means_no_retry():
    """Single-attempt mode (used for validate-mode 'pristine-or-nothing'
    semantics) → equivalent to one direct healthcheck. ZERO sleeps."""
    sleeper = _CountingSleep()
    healthy, code = healthcheck_with_retry(
        _seq_healthcheck([(False, 0)]),
        attempts=1,
        delay_s=2,
        sleep_fn=sleeper,
    )
    assert (healthy, code) == (False, 0)
    assert sleeper.calls == []


def test_healthcheck_with_retry_recovers_on_last_attempt():
    """Edge case — final attempt is the healthy one. Asserts the loop
    catches recovery at the boundary (no off-by-one that would skip
    the last probe)."""
    sleeper = _CountingSleep()
    healthy, code = healthcheck_with_retry(
        _seq_healthcheck([(False, 0), (False, 0), (True, 200)]),
        attempts=3,
        delay_s=2,
        sleep_fn=sleeper,
    )
    assert (healthy, code) == (True, 200)
    # 2 sleeps before attempts 2 + 3; recovery on attempt 3 returns
    # before a 3rd sleep would happen
    assert sleeper.calls == [2, 2]


def test_pre_rotate_constants_match_advisor_spec():
    """Lock-in for the constants Howie specified 2026-06-16:
    'suggest 3, ~2s apart' for pre-rotate retry."""
    assert PRE_ROTATE_RETRY_ATTEMPTS == 3
    assert PRE_ROTATE_RETRY_DELAY_S == 2


def test_post_rotate_settle_constants_match_advisor_spec():
    """Lock-in for the post-rotate settle constants: 'suggest up to
    ~15s / 3 tries'. 3 tries × 5s delay = ~15s total wait."""
    assert POST_ROTATE_SETTLE_ATTEMPTS == 3
    assert POST_ROTATE_SETTLE_DELAY_S == 5


# ─── #30 follow-up — egress_failure_reason classification ────────────
# The reason-taxonomy branch is the diagnostic surface for every future
# failed run. Pin both classes explicitly so a future "helpful" edit
# doesn't silently flip the semantics.


def test_egress_failure_reason_all_zero_codes_is_egress_unstable():
    """All probes returned 0 = no HTTP response anywhere = tunnel never
    settled. egress_unstable is the honest read — rotation didn't help,
    target reachability was never observed at the application layer."""
    assert egress_failure_reason([0]) == "egress_unstable"
    assert egress_failure_reason([0, 0]) == "egress_unstable"
    assert egress_failure_reason([0, 0, 0]) == "egress_unstable"


def test_egress_failure_reason_contains_403_is_skipped_target_unreachable():
    """A 403 anywhere in the probe cycle = egress reached target,
    target responded (with a ban code). The tunnel works; the target
    is the problem. skipped_target_unreachable preserves the meaning
    'target won't speak useful HTTP to us' even when intermixed with
    transient 0s from other rotations."""
    assert egress_failure_reason([403]) == "skipped_target_unreachable"
    assert egress_failure_reason([0, 403]) == "skipped_target_unreachable"
    assert egress_failure_reason([0, 0, 403]) == "skipped_target_unreachable"


def test_egress_failure_reason_other_ban_codes_also_classify_as_target():
    """Any ban-or-error code from the BAN_OR_PATH_DOWN_CODES set
    (429/503/502/504/etc) is still proof egress reached target.
    Generalize beyond 403."""
    for code in (403, 429, 502, 503, 504):
        assert egress_failure_reason([0, code]) == "skipped_target_unreachable", (
            f"code {code} should classify as skipped_target_unreachable "
            f"(egress reached target, target responded with ban-class code)"
        )


def test_egress_failure_reason_empty_list_is_egress_unstable_defensive():
    """Defensive: empty input → 'egress_unstable'. Caller shouldn't
    pass an empty list (the loop always probes at least once before
    classifying) but if it does, 'no evidence the egress works' is
    the honest fallback."""
    assert egress_failure_reason([]) == "egress_unstable"


def test_egress_failure_reason_mixed_with_real_http_classifies_as_target():
    """Edge case: even a 'healthy' code like 200 in the probe list
    means egress worked. (Shouldn't happen in practice — if a 200
    landed, the caller would have returned (True, "") before
    classifying — but the classifier itself is value-blind on the
    'code > 0' rule.)"""
    assert egress_failure_reason([0, 200]) == "skipped_target_unreachable"
    assert egress_failure_reason([0, 301]) == "skipped_target_unreachable"


# ─── #32 — healthcheck probe + prior-tool-success short-circuit (2026-06-16)
# Surfaced by scan_run 1dd0891f (ftp.sciimage.com post-#30): wafw00f +
# httpx ok against ftp:443, curl healthcheck got 0 across 3 Mullvad
# IPs, scan declared egress_unstable. nuclei + httpx share the Go
# stack; curl is a different client. Fix: probe via httpx (primary) +
# prior-tool-success short-circuit when same-run ground truth shows
# target reachable (layered defense).
#
# The httpx probe change is integration-tested via the live re-fire
# (requires subprocess + network). The prior-tool-success short-
# circuit IS unit-testable via a minimal ctx stand-in.


class _ShortCircuitCtx:
    """Minimal ScanContext stand-in for #32 prior-tool-success tests.
    Only exposes the fields ensure_healthy_egress's short-circuit
    reads: target_proven_reachable + the surfaces needed by its log
    line. Avoids importing the full ScanContext dataclass + its psycopg
    dependency chain."""

    def __init__(self, target_proven_reachable: bool):
        self.target_proven_reachable = target_proven_reachable


def test_prior_tool_success_short_circuit_field_default_is_false():
    """Lock-in: new ScanContext field defaults to False. Catches a
    refactor that silently defaults to True (which would bypass every
    gate failure and re-create the rotation-spiral's silent-data
    pollution risk)."""
    from run_medium import ScanContext
    # Build a minimal ScanContext — only the required fields.
    ctx = ScanContext(
        descriptor={},
        hostname="example.com",
        asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    assert ctx.target_proven_reachable is False, (
        "target_proven_reachable must default to False — gate decisions "
        "should be evidence-based, not optimistic-default"
    )


# ─── #33 — ffuf catch-all redirect calibration (2026-06-16) ──────────
# Surfaced by scan_run c30bd212: ftp.sciimage.com 302-redirects every
# path to /Web/Account/Login.htm — ffuf emitted 99 phantom INFOs, one
# per wordlist entry. Fix: baseline calibration probes a random path
# at start of run_ffuf_chunked; per-path matches to the same Location
# are suppressed at emit + collapsed into one summary finding.


def test_should_suppress_ffuf_redirect_exact_match_returns_true():
    """LOAD-BEARING — the EXACT-equality safety vs. the 59ad6a13
    regression (blanket -fc/-fs filter that hid real /admin findings).
    A per-path redirect that EXACTLY matches the baseline gets
    suppressed."""
    from run_medium import should_suppress_ffuf_redirect
    baseline = "https://ftp.sciimage.com/Web/Account/Login.htm"
    assert should_suppress_ffuf_redirect(baseline, baseline) is True


def test_should_suppress_ffuf_redirect_distinct_redirect_emits():
    """Distinct redirect (≠ baseline) MUST NOT be suppressed — that's
    real signal (a /<word> path with a different Location is genuinely
    different from the catch-all)."""
    from run_medium import should_suppress_ffuf_redirect
    baseline = "https://ftp.sciimage.com/Web/Account/Login.htm"
    distinct = "https://ftp.sciimage.com/Some/Other/Page.htm"
    assert should_suppress_ffuf_redirect(distinct, baseline) is False


def test_should_suppress_ffuf_redirect_no_baseline_emits_everything():
    """No baseline calibrated (None) → no suppression → per-path
    emission unchanged from pre-#33 behavior. Targets without a
    host-wide redirect (most apps) work exactly as before."""
    from run_medium import should_suppress_ffuf_redirect
    assert should_suppress_ffuf_redirect("https://anywhere/x", None) is False
    assert should_suppress_ffuf_redirect("", None) is False


def test_should_suppress_ffuf_redirect_empty_redirect_emits():
    """Empty redirect (200/204/401/403 result with no Location header)
    → no suppression. Non-redirect ffuf results are unaffected."""
    from run_medium import should_suppress_ffuf_redirect
    baseline = "https://ftp.sciimage.com/Web/Account/Login.htm"
    assert should_suppress_ffuf_redirect("", baseline) is False
    assert should_suppress_ffuf_redirect(None, baseline) is False  # type: ignore[arg-type]


def test_should_suppress_ffuf_redirect_no_substring_match():
    """Regression guard against a future 'helpful' refactor to
    startswith / substring match. Suppression is EXACT-equality only.
    A path that redirects to a URL SHARING A PREFIX with the baseline
    is genuinely different and must emit."""
    from run_medium import should_suppress_ffuf_redirect
    baseline = "https://ftp.sciimage.com/Web/Account/Login.htm"
    # Same prefix, different actual path — must NOT be suppressed
    similar = "https://ftp.sciimage.com/Web/Account/Login.htm/extra"
    assert should_suppress_ffuf_redirect(similar, baseline) is False
    # Same suffix, different host — must NOT be suppressed
    different_host = "https://other.example.com/Web/Account/Login.htm"
    assert should_suppress_ffuf_redirect(different_host, baseline) is False


def test_emit_ffuf_catchall_summary_no_op_when_count_zero():
    """If no per-path findings were suppressed (no catchall detected or
    no wordlist words matched it), don't emit a summary. ctx.findings
    must not grow."""
    from run_medium import ScanContext, emit_ffuf_catchall_summary
    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_redirect = "https://example.com/login"
    ctx.ffuf_catchall_count = 0  # no per-path matches collapsed
    pre_findings_count = len(ctx.findings)
    emit_ffuf_catchall_summary(ctx)
    assert len(ctx.findings) == pre_findings_count, (
        "no-op required when ffuf_catchall_count is 0"
    )


def test_emit_ffuf_catchall_summary_no_op_when_no_baseline():
    """If no baseline was calibrated (None), don't emit. The count
    SHOULDN'T be > 0 in that case (the suppression predicate requires
    a baseline), but defensive."""
    from run_medium import ScanContext, emit_ffuf_catchall_summary
    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_redirect = None
    ctx.ffuf_catchall_count = 5  # defensive — shouldn't happen
    pre_findings_count = len(ctx.findings)
    emit_ffuf_catchall_summary(ctx)
    assert len(ctx.findings) == pre_findings_count


def test_emit_ffuf_catchall_summary_emits_exactly_one_finding():
    """The headline behavior — 99 phantom per-path findings become 1
    summary INFO. The summary carries the count + the redirect URL
    + INFO severity (never higher — nikto/ffuf can't self-assign
    MODERATE+ per #28 discipline)."""
    from run_medium import ScanContext, emit_ffuf_catchall_summary
    ctx = ScanContext(
        descriptor={}, hostname="ftp.sciimage.com",
        asset_id="ftp.sciimage.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_redirect = (
        "https://ftp.sciimage.com/Web/Account/Login.htm"
    )
    ctx.ffuf_catchall_count = 99
    emit_ffuf_catchall_summary(ctx)
    assert len(ctx.findings) == 1
    finding = ctx.findings[0]
    assert finding.severity == "INFO"
    assert "Catch-all redirect" in finding.title
    assert "99" in finding.title
    assert "Web/Account/Login.htm" in finding.title
    # Tagged for filterability
    assert "catchall_redirect" in finding.tags
    assert "ffuf" in finding.tags
    # Stable slug shape — same redirect → same finding_id on re-scan
    assert finding.check_name.startswith("ffuf-catchall-redirect-")


def test_ffuf_catchall_field_defaults():
    """Lock-in: new ScanContext fields default to safe non-suppressing
    values. ffuf_catchall_redirect=None means suppression is a no-op
    by default; ffuf_catchall_count=0 means no summary emission by
    default. Catches a refactor that defaults to suppress-all."""
    from run_medium import ScanContext
    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    assert ctx.ffuf_catchall_redirect is None
    assert ctx.ffuf_catchall_count == 0


# ═══════════════════════════════════════════════════════════════════════════
# S3 Part 1 (2026-06-18) — ffuf flood-cap: catch-all STATUS suppression.
# Generalizes #33's redirect-only catch-all to any uniform non-discriminating
# status (403/401/200/etc). Tests mirror the #33 redirect-path suite shape
# above so the safety semantics are pinned the same way.
# ═══════════════════════════════════════════════════════════════════════════


def test_should_suppress_ffuf_status_exact_match_returns_true():
    """The headline case — status equals baseline AND no redirect → suppress."""
    from run_medium import should_suppress_ffuf_status

    assert should_suppress_ffuf_status(403, 403, "") is True
    assert should_suppress_ffuf_status(401, 401, "") is True
    assert should_suppress_ffuf_status(200, 200, "") is True


def test_should_suppress_ffuf_status_distinct_status_emits():
    """Real discrimination on a blanket-403 host — a path that returns
    200 (the actual /admin survived) MUST emit. EXACT-equality only;
    no substring or range match."""
    from run_medium import should_suppress_ffuf_status

    # Baseline 403 catch-all; real /admin returned 200 → don't suppress.
    assert should_suppress_ffuf_status(200, 403, "") is False
    # Baseline 401 catch-all; a 200 hit on /robots.txt → don't suppress.
    assert should_suppress_ffuf_status(200, 401, "") is False
    # Even a "close" status (404 vs 403) is distinct → don't suppress.
    assert should_suppress_ffuf_status(404, 403, "") is False


def test_should_suppress_ffuf_status_no_baseline_emits_everything():
    """No catch-all status calibrated (None) → never suppress. The
    pre-S3 default behavior must be preserved when calibration fails."""
    from run_medium import should_suppress_ffuf_status

    assert should_suppress_ffuf_status(403, None, "") is False
    assert should_suppress_ffuf_status(200, None, "") is False
    assert should_suppress_ffuf_status(401, None, "") is False


def test_should_suppress_ffuf_status_zero_status_emits():
    """Defensive: status 0 (no response) shouldn't be suppressed even
    if baseline is 0. ffuf shouldn't emit rows for non-responses, but
    if one slips through we don't want it caught by status suppression."""
    from run_medium import should_suppress_ffuf_status

    assert should_suppress_ffuf_status(0, 403, "") is False
    assert should_suppress_ffuf_status(0, None, "") is False


def test_should_suppress_ffuf_status_redirect_skips_status_suppress():
    """If the result IS a redirect, status-suppress is a no-op (the
    redirect-suppress runs first and handles it). Prevents double-counting
    a 302 row in both ffuf_catchall_count AND ffuf_catchall_status_count.
    Specifically: a 302 row that happens to match a status baseline
    of 302 still falls through to the redirect path."""
    from run_medium import should_suppress_ffuf_status

    # 302 with redirect → status suppress is no-op (redirect path handles it).
    assert should_suppress_ffuf_status(302, 302, "https://x/login") is False
    # Same status, no redirect → status suppress fires.
    assert should_suppress_ffuf_status(302, 302, "") is True


def test_emit_ffuf_catchall_status_summary_no_op_when_count_zero():
    """No per-path matches collapsed → no summary emit. ctx.findings
    must not grow."""
    from run_medium import ScanContext, emit_ffuf_catchall_status_summary

    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_status = 403
    ctx.ffuf_catchall_status_count = 0
    pre = len(ctx.findings)
    emit_ffuf_catchall_status_summary(ctx)
    assert len(ctx.findings) == pre


def test_emit_ffuf_catchall_status_summary_no_op_when_no_baseline():
    """No baseline calibrated (None) → no emit even if count > 0
    (defensive — the predicate requires a baseline, so count should
    never grow above 0 without one, but lock the invariant)."""
    from run_medium import ScanContext, emit_ffuf_catchall_status_summary

    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_status = None
    ctx.ffuf_catchall_status_count = 5
    pre = len(ctx.findings)
    emit_ffuf_catchall_status_summary(ctx)
    assert len(ctx.findings) == pre


def test_emit_ffuf_catchall_status_summary_403_is_low_severity():
    """A host that blanket-403s every path is a weak posture signal —
    LOW finding, not INFO. The 'uniform deny across the wordlist'
    behavior earns one LOW row (more attention than the redirect
    summary's INFO, less than a real vuln)."""
    from run_medium import ScanContext, emit_ffuf_catchall_status_summary

    ctx = ScanContext(
        descriptor={}, hostname="cc.example.com", asset_id="cc.example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_status = 403
    ctx.ffuf_catchall_status_count = 99
    emit_ffuf_catchall_status_summary(ctx)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.severity == "LOW"
    assert "403" in f.title
    assert "99" in f.title
    assert "uniformly" in f.title.lower()
    assert "catchall_status" in f.tags
    assert "ffuf" in f.tags
    assert f.check_name.startswith("ffuf-catchall-status-")


def test_emit_ffuf_catchall_status_summary_401_is_low_severity():
    """401 uniform-auth-gate is the same shape as 403 blanket-deny —
    weak posture, LOW row. Pins the LOW classification for the second
    member of the gated-status pair."""
    from run_medium import ScanContext, emit_ffuf_catchall_status_summary

    ctx = ScanContext(
        descriptor={}, hostname="api.example.com",
        asset_id="api.example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_status = 401
    ctx.ffuf_catchall_status_count = 42
    emit_ffuf_catchall_status_summary(ctx)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.severity == "LOW"
    assert "401" in f.title


def test_emit_ffuf_catchall_status_summary_200_is_info():
    """A SPA / soft-404 host returning 200 to everything is informational —
    not weak posture, just non-discriminating. INFO row, not LOW."""
    from run_medium import ScanContext, emit_ffuf_catchall_status_summary

    ctx = ScanContext(
        descriptor={}, hostname="spa.example.com",
        asset_id="spa.example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.ffuf_catchall_status = 200
    ctx.ffuf_catchall_status_count = 50
    emit_ffuf_catchall_status_summary(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].severity == "INFO"


def test_ffuf_catchall_status_field_defaults():
    """Lock-in: new ScanContext fields default to safe non-suppressing
    values. ffuf_catchall_status=None → suppression no-op by default;
    ffuf_catchall_status_count=0 → no summary emission by default.
    Catches a refactor that defaults to suppress-all on an uncalibrated run."""
    from run_medium import ScanContext

    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    assert ctx.ffuf_catchall_status is None
    assert ctx.ffuf_catchall_status_count == 0


# ═══════════════════════════════════════════════════════════════════════════
# Live scan progress (note 103, 2026-06-24) — incremental flush_progress
# + flush_planned_steps + build_planned_steps. All three are best-effort:
# no DSN = no-op; bad DSN = swallow + continue; scan execution unaffected.
# ═══════════════════════════════════════════════════════════════════════════


def _progress_ctx(dsn=None):
    """Minimal ScanContext for flush/build progress tests."""
    from run_medium import ScanContext
    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
        dsn=dsn,
    )
    return ctx


def test_scan_context_progress_fields_default_safely():
    """ScanContext gains dsn + planned_steps for note 103. Both default
    to None — flush_progress + flush_planned_steps become no-ops, so
    test/validate-mode runs that don't set them keep working unchanged.
    Pins the defaults so a refactor can't accidentally enable always-on
    progress writes in test contexts."""
    ctx = _progress_ctx()
    assert ctx.dsn is None
    assert ctx.planned_steps is None


def test_flush_progress_no_op_when_dsn_unset():
    """No DSN configured → no DB connection attempted, no exception, no
    mutation of ctx. Mirrors the validate-mode contract (the run never
    tries to write progress when there's no DSN)."""
    from run_medium import flush_progress
    ctx = _progress_ctx(dsn=None)
    pre_status = dict(ctx.tool_status)
    pre_tools = list(ctx.tools_run)
    flush_progress(ctx)  # must not raise
    # ctx untouched by a no-op flush
    assert ctx.tool_status == pre_status
    assert ctx.tools_run == pre_tools


def test_flush_progress_swallows_bad_dsn_connection_failure():
    """Bad DSN (unreachable host on port 1 — guaranteed connect-refused)
    → flush swallows the exception, logs, returns normally. The scan
    MUST continue regardless of progress-write failures. This is the
    load-bearing 'best-effort' guarantee from note 103 §Part 1."""
    from run_medium import flush_progress
    # Use a DSN that will fail fast (RFC-5737 TEST-NET-1 + closed port)
    bad_dsn = "postgresql://nobody:nothing@192.0.2.1:1/never?connect_timeout=1"
    ctx = _progress_ctx(dsn=bad_dsn)
    ctx.tool_status = {"wafw00f": {"ok": True}}
    ctx.tools_run = ["wafw00f"]
    # Must NOT raise — best-effort discipline.
    flush_progress(ctx)
    # Ctx state preserved through the failed flush.
    assert ctx.tool_status == {"wafw00f": {"ok": True}}
    assert ctx.tools_run == ["wafw00f"]


def test_flush_planned_steps_no_op_when_dsn_unset():
    from run_medium import flush_planned_steps
    ctx = _progress_ctx(dsn=None)
    ctx.planned_steps = ["wafw00f", "httpx[-td]"]
    flush_planned_steps(ctx)  # must not raise
    # No mutation expected — write is no-op.
    assert ctx.planned_steps == ["wafw00f", "httpx[-td]"]


def test_flush_planned_steps_no_op_when_planned_steps_none():
    """planned_steps=None (Phase 1 hasn't run yet) → no-op even with a
    real DSN. The portal's denominator stays NULL → renders 'Scanning…'
    without a total, which is the graceful-degrade behavior."""
    from run_medium import flush_planned_steps
    ctx = _progress_ctx(dsn="postgresql://x")
    ctx.planned_steps = None
    flush_planned_steps(ctx)  # must not raise
    assert ctx.planned_steps is None


def test_flush_planned_steps_swallows_bad_dsn():
    """Same best-effort discipline as flush_progress for the one-shot
    planned_steps write."""
    from run_medium import flush_planned_steps
    bad_dsn = "postgresql://nobody:nothing@192.0.2.1:1/never?connect_timeout=1"
    ctx = _progress_ctx(dsn=bad_dsn)
    ctx.planned_steps = ["wafw00f", "httpx[-td]", "nikto"]
    flush_planned_steps(ctx)  # must not raise
    assert ctx.planned_steps == ["wafw00f", "httpx[-td]", "nikto"]


def test_mark_tool_ok_still_mutates_ctx_when_dsn_unset():
    """Regression: adding the progress flush to mark_tool_ok must not
    break the existing pure-ctx-mutation contract used by tests + the
    validate-mode run. dsn=None makes the flush a no-op; the
    tool_status mutation still happens normally."""
    from run_medium import mark_tool_ok
    ctx = _progress_ctx(dsn=None)
    mark_tool_ok(ctx, "wafw00f")
    assert ctx.tool_status == {"wafw00f": {"ok": True}}


def test_mark_tool_skipped_still_mutates_ctx_when_dsn_unset():
    from run_medium import mark_tool_skipped
    ctx = _progress_ctx(dsn=None)
    mark_tool_skipped(ctx, "nikto", "auth_gated")
    assert ctx.tool_status == {"nikto": {"skipped": "auth_gated"}}


def test_mark_tool_degraded_still_mutates_ctx_when_dsn_unset():
    from run_medium import mark_tool_degraded
    ctx = _progress_ctx(dsn=None)
    mark_tool_degraded(ctx, "ffuf[25w]#1", "egress_unstable")
    assert ctx.tool_status == {"ffuf[25w]#1": {"degraded": "egress_unstable"}}


# ─── build_planned_steps — phase plan generation ──────────────────────────


def test_build_planned_steps_includes_always_run_tools():
    """wafw00f + httpx[-td] are always in the plan regardless of
    auth_gated state. These run unconditionally in Phase 1."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = False
    steps = build_planned_steps(ctx)
    assert "wafw00f" in steps
    assert "httpx[-td]" in steps
    # wafw00f comes first (Phase 1 ordering)
    assert steps[0] == "wafw00f"
    assert steps[1] == "httpx[-td]"


def test_build_planned_steps_non_auth_gated_includes_full_suite():
    """Non-auth_gated medium scan: nuclei chunks + nikto + ffuf chunks
    all appear. The exact nuclei chunk names depend on build_chunk_plan
    (target-class + stack aware); test the surface — at least one
    nuclei chunk + nikto + at least one ffuf chunk."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = False
    steps = build_planned_steps(ctx)
    assert any(s.startswith("nuclei[") for s in steps), (
        f"expected at least one nuclei chunk in {steps}"
    )
    assert "nikto" in steps
    assert any(s.startswith("ffuf[") for s in steps), (
        f"expected at least one ffuf chunk in {steps}"
    )


def test_build_planned_steps_auth_gated_omits_ffuf_entirely():
    """auth_gated → ffuf chunks not in the plan (the runner skips ALL
    ffuf chunks for auth-gated targets — there's no unauth path surface
    to fuzz). 'Reflect the real plan, not a fixed 12' per note 103."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = True
    steps = build_planned_steps(ctx)
    assert not any(s.startswith("ffuf[") for s in steps), (
        f"auth_gated must drop ffuf from plan; got {steps}"
    )


def test_build_planned_steps_auth_gated_omits_nikto():
    """auth_gated → nikto not in the plan (skipped at runtime against
    auth-gated targets per #24 Phase 2). Plan must reflect the truth."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = True
    steps = build_planned_steps(ctx)
    assert "nikto" not in steps, f"auth_gated must drop nikto; got {steps}"


def test_build_planned_steps_auth_gated_keeps_only_tech_nuclei():
    """auth_gated → only the medium:tech nuclei chunk runs (everything
    else fires templates that 401/redirect uniformly = zero signal).
    Plan must include nuclei[medium:tech] and exclude other nuclei chunks."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = True
    steps = build_planned_steps(ctx)
    nuclei_steps = [s for s in steps if s.startswith("nuclei[")]
    # The tech chunk should be present; every nuclei chunk in the plan
    # must be a tech chunk.
    assert "nuclei[medium:tech]" in nuclei_steps, (
        f"expected nuclei[medium:tech] in {nuclei_steps}"
    )
    for chunk in nuclei_steps:
        assert ":tech" in chunk, (
            f"auth_gated must only plan :tech nuclei chunks; got {chunk}"
        )


def test_build_planned_steps_pure_function():
    """No side effects on ctx — calling repeatedly produces same result
    without mutating the input. Pinning so a future caching/memoization
    refactor can't accidentally introduce state."""
    from run_medium import build_planned_steps
    ctx = _progress_ctx()
    ctx.auth_gated = False
    first = build_planned_steps(ctx)
    second = build_planned_steps(ctx)
    assert first == second
    # Re-call with a different auth_gated value gives a different plan.
    ctx.auth_gated = True
    third = build_planned_steps(ctx)
    assert third != first


# ═══════════════════════════════════════════════════════════════════════════
# S3 Part 2 (2026-06-18) — ffuf severity tuning. Curated path-sensitivity
# (SECRET / ADMIN) × HTTP status → severity matrix. Replaces the blanket
# `severity='INFO'` at the per-path ffuf emit site so real hits surface
# above the INFO noise floor. Curated, anchored — same discipline as #36
# cross-source dedup.
# ═══════════════════════════════════════════════════════════════════════════


# ─── SECRET × accessible (200/204) → HIGH ──────────────────────────────────


def test_classify_dotenv_200_is_high():
    """The headline case — /.env returning 200 is direct secret exposure."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".env", "https://x/.env", 200) == "HIGH"


def test_classify_wp_config_200_is_high():
    """wp-config.php → HIGH on 200. WordPress DB creds + auth keys in the
    clear if this is publicly readable."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("wp-config.php", "https://x/wp-config.php", 200)
        == "HIGH"
    )


def test_classify_id_rsa_200_is_high():
    """SSH private key reachable → HIGH."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("id_rsa", "https://x/id_rsa", 200) == "HIGH"


def test_classify_dump_sql_200_is_high():
    """Database dump reachable → HIGH."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("dump.sql", "https://x/dump.sql", 200)
        == "HIGH"
    )


def test_classify_secret_nested_path_200_is_high():
    """Nested secret like backup/.env should also catch as SECRET — the
    trailing path component is what classifies."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("backup/.env", "https://x/backup/.env", 200)
        == "HIGH"
    )


# ─── SECRET × gated (401/403) → LOW ────────────────────────────────────────


def test_classify_dotenv_403_is_low():
    """/.env exists but is gated → LOW (inventory value)."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".env", "https://x/.env", 403) == "LOW"


def test_classify_git_config_403_is_low():
    """/.git/config matches the ADMIN_PATH entry; 403 → LOW. (The broader
    /.git directory would match SECRET; this specific config file matches
    ADMIN. Either way 403 lands LOW.)"""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity(".git/config", "https://x/.git/config", 403)
        == "LOW"
    )


def test_classify_secret_401_is_low():
    """401 is the auth-required twin of 403 — same LOW for sensitive paths."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("wp-config.php", "https://x/wp-config.php", 401)
        == "LOW"
    )


# ─── ADMIN × accessible (200/204) → MODERATE ────────────────────────────────


def test_classify_admin_200_is_moderate():
    """The headline case — /admin returning 200 is a privileged surface
    reachable to anyone. MODERATE, not HIGH (not a direct secret leak,
    but high-value attack surface)."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("admin", "https://x/admin", 200) == "MODERATE"
    )


def test_classify_phpmyadmin_200_is_moderate():
    """phpmyadmin landing page reachable → MODERATE."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("phpmyadmin", "https://x/phpmyadmin", 200)
        == "MODERATE"
    )


def test_classify_swagger_200_is_moderate():
    """Swagger UI reachable → MODERATE (API surface map exposed)."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("swagger", "https://x/swagger", 200)
        == "MODERATE"
    )


def test_classify_actuator_200_is_moderate():
    """Spring Boot /actuator exposed → MODERATE (env/config/metrics)."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("actuator", "https://x/actuator", 200)
        == "MODERATE"
    )


def test_classify_manager_html_200_is_moderate():
    """Tomcat /manager/html → MODERATE."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity(
            "manager/html", "https://x/manager/html", 200
        )
        == "MODERATE"
    )


# ─── ADMIN × gated (401/403) → LOW ──────────────────────────────────────────


def test_classify_admin_403_is_low():
    """/admin exists but is gated → LOW (inventory: 'they have an admin
    panel; it's locked down at the WAF or app layer')."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("admin", "https://x/admin", 403) == "LOW"


def test_classify_admin_401_is_low():
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("admin", "https://x/admin", 401) == "LOW"


# ─── generic × any → INFO ───────────────────────────────────────────────────


def test_classify_about_200_is_info():
    """Non-sensitive path /about → INFO regardless of status."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("about", "https://x/about", 200) == "INFO"


def test_classify_generic_403_is_info():
    """Generic 403 (single non-catchall, e.g. a path the WAF specifically
    blocks) stays INFO. Distinct from a SECRET/ADMIN 403 which goes LOW."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("api", "https://x/api", 403) == "INFO"


def test_classify_generic_401_is_info():
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("auth", "https://x/auth", 401) == "INFO"


# ─── redirects (301/302/307) → INFO always ─────────────────────────────────


def test_classify_admin_302_is_info():
    """Redirects stay INFO regardless of path class. The catch-all redirect
    case (#33) is suppressed before reaching here; surviving redirects are
    low signal regardless of where they point or what path they're on."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("admin", "https://x/admin", 302) == "INFO"


def test_classify_dotenv_301_is_info():
    """Even SECRET paths go INFO on a redirect — the redirect itself isn't
    the exposure, the destination would be (and gets emitted at the
    destination's status by the next probe in a real attack)."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".env", "https://x/.env", 301) == "INFO"


def test_classify_secret_307_is_info():
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("id_rsa", "https://x/id_rsa", 307) == "INFO"


# ─── SUBSTRING-GUARD — anchored regex must reject false positives ──────────


def test_classify_env_no_dot_is_not_secret():
    """`env` (no leading dot — already in FFUF_WORDS as a generic) must NOT
    match SECRET `\\.env`. This is the substring guard against the regex
    matching `env` inside `.env`. /env exists in the wordlist and SHOULD
    land INFO, not HIGH."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("env", "https://x/env", 200) == "INFO"


def test_classify_envrc_not_secret():
    """`.envrc` is a distinct file (shell config — not a secret exposure
    by itself). Must NOT match SECRET `\\.env`. The anchored regex
    requires the matched pattern to be the full word or trailing
    component — `.envrc` has trailing `rc` after `.env`, so no match."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".envrc", "https://x/.envrc", 200) == "INFO"


def test_classify_environment_not_secret():
    """`environment` contains `env` as substring but isn't a secret.
    The anchored regex rejects it."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("environment", "https://x/environment", 200)
        == "INFO"
    )


def test_classify_administrative_not_admin():
    """`administrative` contains `admin` as substring but isn't the admin
    surface. Must NOT match. Catches the broad-keyword failure mode."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity(
            "administrative", "https://x/administrative", 200
        )
        == "INFO"
    )


def test_classify_admin_panel_not_admin():
    """`admin-panel` contains `admin` as prefix but isn't a path-final
    match. Anchored regex rejects."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity(
            "admin-panel", "https://x/admin-panel", 200
        )
        == "INFO"
    )


def test_classify_wp_admin_does_match_admin_tier():
    """`wp-admin` IS an explicit ADMIN entry — must match as MODERATE,
    NOT fall through to INFO. Pins the WordPress-specific case so a
    future refactor that drops the entry breaks here."""
    from run_medium import classify_ffuf_severity
    assert (
        classify_ffuf_severity("wp-admin", "https://x/wp-admin", 200)
        == "MODERATE"
    )


# ─── case-insensitivity + edge cases ───────────────────────────────────────


def test_classify_case_insensitive():
    """`.ENV` is the same secret as `.env`. ffuf wordlists are mixed-case;
    don't lose a match on capitalization."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".ENV", "https://x/.ENV", 200) == "HIGH"
    assert classify_ffuf_severity("Admin", "https://x/Admin", 200) == "MODERATE"


def test_classify_empty_word_is_info():
    """Defensive — empty word (parser failure / blank entry) → INFO,
    don't raise."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity("", "https://x/", 200) == "INFO"


def test_classify_unknown_status_is_info():
    """Statuses outside the 200/204/401/403/30x set default to INFO.
    ffuf -mc is constrained today, but defensive against widening."""
    from run_medium import classify_ffuf_severity
    assert classify_ffuf_severity(".env", "https://x/.env", 500) == "INFO"
    assert classify_ffuf_severity("admin", "https://x/admin", 404) == "INFO"


# ─── #35 delta-close interaction — elevating severity doesn't break close ──


def test_classify_ffuf_severity_does_not_interfere_with_close():
    """Lock-in: an elevated severity is just a string in the finding row.
    delta_close_for_scan_run (#35) keys on last_seen_scan_run, NOT on
    severity. The UPSERT max-severity ratchet (~L2543 in run_medium.py)
    preserves elevated severity across re-scans, but the close path
    remains independent of severity entirely.

    This test verifies the helper's output is purely a string — no
    side effects on ScanContext, no global state. The actual close
    SQL is exercised by the existing #35 test suite (delta_close_eligible
    + DB integration). This test pins that elevating severity here can't
    leak into close-eligibility.
    """
    from run_medium import classify_ffuf_severity, ScanContext

    ctx = ScanContext(
        descriptor={}, hostname="example.com", asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    pre_findings = len(ctx.findings)
    pre_tools = list(ctx.tools_run)
    pre_tool_status = dict(ctx.tool_status)

    # Call the classifier across the matrix
    for word, status in [
        (".env", 200), (".env", 403), ("admin", 200), ("admin", 403),
        ("about", 200), ("admin", 302),
    ]:
        result = classify_ffuf_severity(word, f"https://x/{word}", status)
        assert isinstance(result, str)

    # No mutation of ctx whatsoever — classifier is pure.
    assert len(ctx.findings) == pre_findings
    assert ctx.tools_run == pre_tools
    assert ctx.tool_status == pre_tool_status


# ─── idempotency — repeated calls return identical results ─────────────────


def test_classify_ffuf_severity_idempotent():
    """Pure function — same input gives same output across N calls. Pinning
    so a future caching/memoization optimization can't accidentally drift."""
    from run_medium import classify_ffuf_severity
    cases = [
        (".env", "https://x/.env", 200, "HIGH"),
        ("admin", "https://x/admin", 200, "MODERATE"),
        (".env", "https://x/.env", 403, "LOW"),
        ("admin", "https://x/admin", 403, "LOW"),
        ("about", "https://x/about", 200, "INFO"),
        ("env", "https://x/env", 200, "INFO"),
        ("admin", "https://x/admin", 302, "INFO"),
    ]
    for word, url, status, expected in cases:
        a = classify_ffuf_severity(word, url, status)
        b = classify_ffuf_severity(word, url, status)
        assert a == b == expected, (
            f"({word!r}, {status}) expected {expected!r}, got {a!r}/{b!r}"
        )


# ─── lock-in: path-table membership ─────────────────────────────────────────


def test_secret_paths_contain_required_entries():
    """The SECRET path table contains the core entries from the S3 spec.
    A future PR that drops one of these (e.g. as part of a 'cleanup') has
    to break this test to do so — forces an explicit decision."""
    from run_medium import SECRET_PATHS_PATTERNS
    required = {
        r"\.env", r"\.git", r"\.sql", r"wp-config\.php",
        r"id_rsa", r"\.htpasswd", r"\.aws/credentials",
    }
    missing = required - set(SECRET_PATHS_PATTERNS)
    assert missing == set(), f"SECRET_PATHS missing: {missing}"


def test_admin_paths_contain_required_entries():
    """The ADMIN path table contains the core entries from the S3 spec."""
    from run_medium import ADMIN_PATHS_PATTERNS
    required = {r"admin", r"phpmyadmin", r"swagger", r"actuator", r"wp-admin"}
    missing = required - set(ADMIN_PATHS_PATTERNS)
    assert missing == set(), f"ADMIN_PATHS missing: {missing}"


def test_target_proven_reachable_field_settable():
    """Sanity: the field is writable. Sites that get a real HTTP
    response from the target (detect_waf parse, detect_tech_stack
    parse, nuclei chunk success) set it True. Tests that the field
    behaves like a normal bool — catches a future refactor that
    accidentally makes it a property/frozen field."""
    from run_medium import ScanContext
    ctx = ScanContext(
        descriptor={},
        hostname="example.com",
        asset_id="example.com",
        scan_run_id="00000000-0000-0000-0000-000000000000",
        queue_id="00000000-0000-0000-0000-000000000000",
        intensity="medium",
    )
    ctx.target_proven_reachable = True
    assert ctx.target_proven_reachable is True


@pytest.mark.skip(reason=(
    "Needs a real-DB integration harness — current pytest setup can't exercise "
    "the clean→degraded fallback transaction sequence at unit level. The "
    "guarantee that there are NO duplicate artifact rows when clean-path "
    "writes partial → close_out raises invariant → rollback → degraded_out "
    "re-flushes is TRANSACTIONAL ONLY: autocommit=False at psycopg.connect + "
    "atomic conn.rollback() before degraded_out runs means the clean-path "
    "partial inserts are discarded before flush_artifacts_to_db touches the "
    "DB. Cannot be DB-enforced via UNIQUE (scan_run_id, tool_name) because "
    "tools legitimately emit multiple artifacts under the same tool_name "
    "(e.g. httpx_tech writes one per line in some configs). Records the gap; "
    "when an integration harness exists, write the test that: (1) opens a "
    "transaction, (2) inserts N artifact rows via the clean-path loop, (3) "
    "triggers a close_out invariant failure, (4) catches it, rolls back, "
    "calls degraded_out which re-flushes via flush_artifacts_to_db, (5) "
    "commits, (6) asserts scan_run_artifacts has exactly N rows (not 2N)."
))
def test_no_duplicate_artifacts_on_clean_to_degraded_fallback():
    """PLACEHOLDER for the clean→degraded fallback duplicate-prevention
    test. See @skip reason for the full rationale and the integration-
    harness blueprint. Logged here so the gap doesn't disappear into
    backlog."""
    pass


def test_flush_artifacts_handles_non_json_string_content():
    """run_medium.py wraps non-JSON content as {'raw': <str>} before
    passing to Json(). Stub that path: a content_str that's not valid
    JSON should still produce one INSERT (with the raw fallback), not
    a raise."""
    ctx = _ArtifactCtx(
        artifacts=[
            ("nikto", "text", "+ ERROR: not even close to JSON"),
        ],
    )
    conn = _RecordingConn()
    written = flush_artifacts_to_db(conn, ctx, _fake_json)
    assert written == 1
    _, params = conn.cursor_obj.calls[0]
    # The wrapped content should be the raw fallback dict
    assert params["content_jsonb"] == {"raw": "+ ERROR: not even close to JSON"}


def test_reconcile_does_not_raise():
    """Reconcile must NEVER raise — we're already in degraded_out;
    raising would lose the original DegradedRunError context and
    likely fail the entire degrade-stamping path. assert_tool_status_
    invariant raises (close_out path); reconcile_tool_status_invariant
    DOES NOT (degraded path)."""
    # Maximally inconsistent input — both cases at once
    ctx = _MinimalCtx(
        tools_run=["a", "b", "c"],
        tool_status={"b": {"ok": True}, "d": {"degraded": "x"}},
    )
    # Should not raise
    reconcile_tool_status_invariant(ctx)
    assert set(ctx.tools_run) == set(ctx.tool_status.keys())
    # a, c got stamped degraded:no_status_recorded; d got appended to tools_run
    assert ctx.tool_status["a"] == {"degraded": "no_status_recorded"}
    assert ctx.tool_status["c"] == {"degraded": "no_status_recorded"}
    assert "d" in ctx.tools_run
    # b and d unchanged
    assert ctx.tool_status["b"] == {"ok": True}
    assert ctx.tool_status["d"] == {"degraded": "x"}


# ═══════════════════════════════════════════════════════════════════════
# delta_close_eligible (#35 — live-path delta-close gate)
# ═══════════════════════════════════════════════════════════════════════

def test_delta_close_eligible_all_ok():
    assert delta_close_eligible(
        {"wafw00f": {"ok": True}, "httpx[-td]": {"ok": True},
         "nikto": {"ok": True}, "nuclei[medium:tech]": {"ok": True}}
    ) is True


def test_delta_close_eligible_one_degraded_blocks():
    # HEADLINE SAFETY (Python side): a single degraded tool -> not eligible
    # -> nothing closes. Over-closing (false-remediation) is the failure
    # delta-close exists to avoid.
    assert delta_close_eligible(
        {"wafw00f": {"ok": True}, "nuclei[medium:tech]": {"degraded": "egress_unstable"}}
    ) is False


def test_delta_close_eligible_one_skipped_blocks():
    # auth_gated skips nikto/ffuf -> partial scan -> must NOT close (it didn't
    # re-run those tools; a finding they'd re-find could be wrongly closed).
    assert delta_close_eligible(
        {"wafw00f": {"ok": True}, "httpx[-td]": {"ok": True},
         "nikto": {"skipped": "auth_gated"}}
    ) is False


def test_delta_close_eligible_empty_is_false():
    # No tools ran -> nothing proven -> not eligible.
    assert delta_close_eligible({}) is False


def test_delta_close_eligible_ok_value_irrelevant():
    # Eligibility is key-membership of 'ok', value-blind (matches the
    # three-state tool_status invariant elsewhere).
    assert delta_close_eligible({"x": {"ok": True}, "y": {"ok": "whatever"}}) is True
