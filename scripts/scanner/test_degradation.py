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
