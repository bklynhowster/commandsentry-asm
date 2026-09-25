"""270 step 1 — every phase records when it finished, not just nuclei.

    python3 -m pytest scripts/scanner/test_phase_window_270.py -q

⛔ THE GAP THIS CLOSES. A heavy run has 20 phases and exactly ONE carried
timing: nuclei, via #39b. run_phase measures a true `elapsed` for everything it
runs, but 14 of the 20 self-bookkeep and never reach it — so ~half of a ~2000s
scan was unattributed. You cannot size a work budget, justify a wall-clock
ceiling, or decide how long a VPN slot must be held while half the clock is
invisible. Every phase funnels through one of the five markers, so the stamp
lives there.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as rm  # noqa: E402


class _Ctx:
    """Minimal ScanContext stand-in — the markers only touch tool_status."""
    def __init__(self):
        self.tool_status = {}


def _drive():
    ctx = _Ctx()
    rm.mark_tool_ok(ctx, "dns_posture")
    time.sleep(0.05)
    rm.mark_tool_ok(ctx, "tls_check")
    time.sleep(0.05)
    rm.mark_tool_skipped(ctx, "wpvulnerability", "not_applicable")
    time.sleep(0.05)
    rm.mark_tool_degraded(ctx, "nikto", "exception_Timeout")
    return ctx


def test_every_outcome_path_records_a_completion_time():
    """ok / skipped / degraded all stamp. A phase that ran and failed is exactly
    the one whose duration you most want when asking where the budget went."""
    ctx = _drive()
    for name in ("dns_posture", "tls_check", "wpvulnerability", "nikto"):
        assert ctx.tool_status[name].get("completed_at_s") is not None, name


def test_the_window_measures_the_gap_between_phases():
    ctx = _drive()
    for name in ("tls_check", "wpvulnerability", "nikto"):
        w = ctx.tool_status[name].get("phase_window_s")
        assert w is not None and w >= 0, f"{name}: {w}"


def test_the_first_phase_has_NO_window_rather_than_a_guess():
    """⚠ There is no predecessor to measure from. Leaving it blank is honest;
    back-filling it from an assumed run-start would be a fabricated number in
    the one field whose whole purpose is to be trusted."""
    ctx = _drive()
    assert "phase_window_s" not in ctx.tool_status["dns_posture"]
    assert ctx.tool_status["dns_posture"].get("completed_at_s") is not None


def test_the_stamp_never_clobbers_the_VERDICT():
    """⛔ The markers REPLACE the entry wholesale; the stamp runs after. If it
    ever overwrote the outcome, a degraded phase would read as timed-and-fine —
    the fourth data loss at a translation boundary in this workstream."""
    ctx = _drive()
    assert ctx.tool_status["nikto"].get("degraded") == "exception_Timeout"
    assert ctx.tool_status["wpvulnerability"].get("skipped") == "not_applicable"
    assert ctx.tool_status["tls_check"].get("ok") is True


def test_phase_window_is_NOT_called_elapsed_s():
    """`elapsed_s` means a TRUE measured duration (nuclei chunks, #39b).
    phase_window_s is DERIVED and includes inter-phase overhead. Two different
    things must not share a name — that conflation is how the other three
    losses happened."""
    ctx = _drive()
    for name, entry in ctx.tool_status.items():
        assert "elapsed_s" not in entry, (
            f"{name} carries elapsed_s — a derived interval is masquerading as "
            "a measured duration")
