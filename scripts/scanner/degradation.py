"""Scanner degradation primitives — fail-closed on "we didn't actually scan."

Spec: ~/Downloads/ISMS Procedures/COMMANDsentry/SPEC_SCANNER_DEGRADATION_HARDENING.md

This module exposes:

  - DegradedRunError      — raised whenever the runner detects that the
                            scan plan did not / cannot execute against
                            the real target. Caller (run_medium.py top-
                            level run()) catches once, stamps
                            scan_run.status='degraded', and exits 1.

  - is_tool_output_degraded — unified per-tool detector primitive. Run it
                              BEFORE any add_finding() from that tool's
                              output. Non-None reason → call
                              mark_tool_degraded() AND raise.

  - MAX_BAN_EVENTS / MAX_HEALTHCHECK_FAILURES — rotation_log retention
                                                caps (advisor ruling Q2).

Design notes (per advisor rulings 2026-06-12):

  Q1 strict — first chunk-skip aborts. v1 only. TODO: a future S2 "partial-
  degraded" mode might collect remaining chunks and mark the run degraded
  at end (so 8 good chunks aren't thrown away when 1 skips). Not built now.

  ③ stderr-only — the unreachable-pattern backstop scans stderr only, NOT
  stdout. Tool stdout legitimately contains finding text that may quote
  network-error strings (e.g. nuclei reporting "connection refused" as a
  closed-port INFO with post_health=True). A spurious abort during the
  validate run = no mint = chasing a ghost. The healthcheck is the
  authority; the text scan is the backstop only.

  Trap-1 softening (advisor 2026-06-12, pre-batch-2):
  A SINGLE stderr match is not enough to abort. nuclei / ffuf routinely
  emit a transient "i/o timeout" / "connection reset" line during a
  legitimate long run. The threshold STDERR_DEGRADED_MATCH_THRESHOLD
  gates the abort; below that, when post_health is True, the line is
  logged as a transient warning and we trust the healthcheck. Only the
  two healthcheck-driven authorities stay hard-abort.
"""
from __future__ import annotations

import re
import sys
from typing import Optional


# ─── Rotation log caps (advisor ruling Q2 2026-06-12) ────────────────────
# Hard caps on rotation_log subarrays to prevent rotation-storm bloat
# (testfire-bans-every-IP scenario). When either cap is hit, the runner
# sets rotation_storm=true and stops appending. The cap-hit itself is
# independent evidence of severe degradation.
MAX_BAN_EVENTS: int = 500
MAX_HEALTHCHECK_FAILURES: int = 500


# ─── Stderr backstop threshold (advisor trap-1 2026-06-12, pre-batch-2) ──
# Number of reachability-failure-pattern matches required across stderr
# before the backstop fires. Long nuclei / ffuf runs routinely emit ONE
# transient "i/o timeout" or "connection reset" line during a legitimate
# scan of a healthy target — a single match would spuriously abort the
# validate run. Threshold is matches across all patterns combined
# (sum over patterns of pattern.findall(stderr)). Single match with a
# reachable target post-tool downgrades to a logged warning.
STDERR_DEGRADED_MATCH_THRESHOLD: int = 3


class DegradedRunError(Exception):
    """Raised when the runner detects a degradation condition.

    A medium scan that hits this exception is NOT a clean run. The caller
    must stamp scan_run.status='degraded', stamp findings.scan_quality=
    'degraded' for any findings already written by this run, and exit 1
    (workflow goes RED — degradation IS a failure of the scan, even
    though the runner itself didn't crash).

    Reason slugs (stable strings — surfaced in scan_run.error_message and
    used in tool_status[chunk]={ok: false, reason: <slug>}):

      - "rotation_exhausted"            — chunk hit all-IPs-banned, skipped
      - "tool_status_invariant"         — tools_run != tool_status.keys()
      - "target_unreachable_after_run"  — post-tool healthcheck failed
      - "target_unreachable_pre_run"    — pre-tool healthcheck + rc!=0
      - "output_stderr_contains_unreachable_pattern" — stderr regex match
      - "tool_startup_failure"          — bare-ERROR in first ~5 stderr lines
                                          (the 0864fd3 retraction class)
      - "validate_mode_target_not_allowlisted" — batch 2 (validate-mode)
      - "vpn_bringup_failed"            — batch 2 (validate-mode)
      - "asset_pre_flight_unreachable"  — pre-first-chunk probe failed
    """

    def __init__(self, reason: str, context: str = "") -> None:
        self.reason = reason
        self.context = context
        msg = f"degraded: {reason}"
        if context:
            msg += f": {context}"
        super().__init__(msg)


# Patterns that indicate "we can't see the target." Scoped to stderr per
# ruling ③ — stdout is finding territory and must not be scanned.
#
# Add to this list with care: a pattern that matches text legitimately
# emitted by a tool's stderr during a HEALTHY run will produce spurious
# aborts that kill the validate-run path. The healthcheck remains the
# authority; these patterns catch the "tool exited 0 with healthy post-
# probe but emitted reachability noise to stderr" edge case.
_UNREACHABLE_STDERR_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"unable to connect to",
        r"connection refused",
        r"connection reset",
        r"i/o timeout",
        r"no route to host",
        r"name or service not known",
        r"could not resolve host",
    )
]


def is_tool_output_degraded(
    tool: str,
    stdout: str,
    stderr: str,
    rc: int,
    pre_health: bool,
    post_health: bool,
) -> Optional[str]:
    """Returns a degradation reason slug, or None if the output is genuine.

    Authority order:
      1. post_health=False  → "target_unreachable_after_run"
      2. rc!=0 + pre_health=False → "target_unreachable_pre_run"
      3. stderr matches a reachability-failure regex
         → "output_stderr_contains_unreachable_pattern"
      4. None — output represents a real (possibly empty) scan result.

    Call site: every tool parser runs this BEFORE add_finding(). Non-None
    return → call `mark_tool_degraded(ctx, tool, <slug>)` which writes
    the canonical {"degraded": "<slug>"} shape into ctx.tool_status,
    THEN raise DegradedRunError(<slug>, f"{tool}: ...").

    DO NOT inline `tool_status[tool] = {"ok": False, "reason": <slug>}` —
    that was the third shape we purged 2026-06-12 (advisor ruling ③
    re-confirmed: readers key on `"degraded" in entry`; the inline shape
    silently misses these, defeating B2). Always go through
    mark_tool_degraded so the shape stays canonical.

    Per advisor ruling ③ 2026-06-12, the regex scan reads STDERR ONLY.
    Tool stdout can legitimately contain unreachable-pattern strings as
    part of a real finding (nuclei port-closed INFO, etc.). The unit
    test `test_clean_stdout_finding_with_unreachable_text_is_not_degraded`
    in test_degradation.py locks this in.

    Args:
      tool: identifier surfaced in the log line (not used in logic — just
            for traceability if the caller logs the result).
      stdout: tool's stdout — NOT scanned for patterns.
      stderr: tool's stderr — IS scanned for patterns.
      rc: tool's exit code.
      pre_health: healthcheck result BEFORE the tool ran. True if target
                  responded to a basic curl probe.
      post_health: healthcheck result AFTER the tool ran. True if target
                   still responds.

    Returns:
      None if the output represents a real scan (even if zero findings).
      A reason slug (one of the DegradedRunError reason strings) if
      degradation was detected.
    """
    # Authority 1: post-run healthcheck. If the target stopped responding
    # to us, we cannot trust any "no findings" result — we may have been
    # banned mid-tool. Hard abort.
    if not post_health:
        return "target_unreachable_after_run"

    # Authority 2: pre-run health was already bad AND the tool exited
    # non-zero. We almost certainly never reached the target this
    # attempt. Hard abort.
    if rc != 0 and not pre_health:
        return "target_unreachable_pre_run"

    # Backstop 3 (softened — trap-1, advisor 2026-06-12): tool exited
    # "successfully" with healthy pre + post, BUT emitted unreachable
    # noise to STDERR. Tight scope per ruling ③.
    #
    # Single-match-aborts would spuriously kill the validate run on a
    # stray "i/o timeout" line — common in long nuclei / ffuf passes
    # against healthy targets. Threshold check: total match COUNT across
    # all patterns must be >= STDERR_DEGRADED_MATCH_THRESHOLD before we
    # treat it as load-bearing evidence.
    #
    # When match count is 1..(threshold-1) AND post_health=True, the
    # healthcheck (the documented authority) says the target is fine —
    # downgrade to a logged warning and return None. If a future tool
    # genuinely degrades that way, the post-tool healthcheck would have
    # already caught it via authority #1.
    stderr_lower = stderr.lower()
    match_count = sum(len(p.findall(stderr_lower))
                      for p in _UNREACHABLE_STDERR_PATTERNS)
    if match_count >= STDERR_DEGRADED_MATCH_THRESHOLD:
        return "output_stderr_contains_unreachable_pattern"
    if match_count > 0:
        # Sub-threshold + healthy post — log + trust the healthcheck.
        # post_health=True is implied by reaching this branch (the
        # `not post_health` short-circuit above already returned).
        print(
            f"[degradation] {tool}: {match_count} stderr unreachable "
            f"pattern hit(s) below threshold "
            f"{STDERR_DEGRADED_MATCH_THRESHOLD}; "
            f"post_health=True — treating as transient, NOT degraded",
            file=sys.stderr,
        )

    # Genuine output. Could be zero findings (clean scan of clean target).
    return None


def assert_tool_status_invariant(
    tools_run: list[str], tool_status: dict[str, dict]
) -> None:
    """Set-equality check on tools_run vs tool_status.keys(), per ruling ⑦.

    Every tool that was attempted (and thus appended to tools_run) MUST
    have a corresponding tool_status entry recording whether it
    completed cleanly or was degraded. Skipped chunks MUST also stamp a
    tool_status entry with reason="skipped_target_unreachable" so the
    set stays balanced.

    Detects two failure classes:
      - `missing`: in tools_run but no status entry — silent-skip class.
        These get auto-stamped with reason="no_status_recorded" so the
        scan_run row captures the gap rather than hiding it, then we
        raise.
      - `unclaimed`: status entry but not in tools_run — coding bug
        class (someone called mark_tool_ok/degraded without first
        registering the tool in tools_run). Still abort.

    NOT a hardcoded count (e.g. "must be 11"). The plan size varies by
    target class + stack-aware variants + FortiGate-routing branch. Set
    equality is the invariant.

    Raises:
      DegradedRunError("tool_status_invariant", ...) if the sets differ.
      Mutates tool_status to record the missing-tool stamps before raising.
    """
    expected = set(tools_run)
    actual = set(tool_status.keys())

    missing = expected - actual
    unclaimed = actual - expected

    if not missing and not unclaimed:
        return  # invariant holds

    # Auto-stamp missing entries so the scan_run row captures the gap.
    # Canonical shape per the documented contract
    # (run_medium.py:425 mark_tool_degraded + run_light.py): the entry
    # for a degraded tool is {"degraded": "<reason_slug>"}, NOT
    # {"ok": False, "reason": ...}. Readers key on `"degraded" in entry`
    # — the inline-3rd-shape would silently miss these and undercount
    # the worst degradations (this is the whole point of B2).
    for t in missing:
        tool_status[t] = {"degraded": "no_status_recorded"}

    detail = []
    if missing:
        detail.append(f"missing={sorted(missing)}")
    if unclaimed:
        detail.append(f"unclaimed={sorted(unclaimed)}")
    raise DegradedRunError("tool_status_invariant", " ".join(detail))


def cap_aware_append_ban(ctx_ban_events: list[dict], ctx_rotation_storm: bool,
                         event: dict) -> bool:
    """Append a ban event to ctx.ban_events with the MAX_BAN_EVENTS cap.

    Returns True if the cap was just hit by this call (caller should
    flip ctx.rotation_storm=True). Returns False otherwise (already-capped
    or still room).

    Pattern lets the caller manage the flag without leaking the list-
    mutation into the caller's branch. See run_medium.py's append helper
    for the bound-to-ctx wrapper.
    """
    if ctx_rotation_storm:
        return False  # already capped, drop silently
    if len(ctx_ban_events) >= MAX_BAN_EVENTS:
        return True  # signal the caller to set rotation_storm
    ctx_ban_events.append(event)
    return False


def cap_aware_append_healthcheck_failure(
    failures_list: list[dict],
    ctx_rotation_storm: bool,
    event: dict,
) -> bool:
    """Same shape as cap_aware_append_ban but for healthcheck failures."""
    if ctx_rotation_storm:
        return False
    if len(failures_list) >= MAX_HEALTHCHECK_FAILURES:
        return True
    failures_list.append(event)
    return False
