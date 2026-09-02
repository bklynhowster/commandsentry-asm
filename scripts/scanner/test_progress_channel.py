#!/usr/bin/env python3
"""A′ — 4.7 (53)/(54)/㊿/㊾/(55). The progress channel through the recorder.

WHY THESE ARE MECHANISM TESTS, NOT DOC. `_LegacyRecorder`'s isolation exists
because of production run #2621: a legacy phase's internal flush_progress wrote
the recorder's single-entry bookkeeping over the real scan_run row, 11 tools to
1, mid-run. A′ threads ONE narrow channel through that isolation. If the channel
ever widens, #2621 comes back.

And the marker itself is the ⑭′ family: `"ok" in entry` passed `{"ok": False}`
and bit three consumers at once. Documentation did not prevent that. These tests
are what prevent this one.

Run: python3 -m pytest test_progress_channel.py
"""
from __future__ import annotations

import pytest

from phase_contract import (ProgressPayload, _LegacyRecorder,
                            _merge_chunk_progress, entry_is_provisional)


class _FakeCtx:
    def __init__(self):
        self.tools_run = []
        self.tool_status = {}
        self.findings = []
        self.artifacts = []
        self.dsn = None            # keeps flush_progress a no-op in tests


def _payload(**over):
    kw = dict(phase_name="nuclei", chunks_resolved=2, chunks_total=6,
              chunks_ok=1, chunks_cut=1)
    kw.update(over)
    return ProgressPayload(**kw)


# ── (54) structural narrowness ──────────────────────────────────────────────

def test_payload_rejects_non_provisional():
    """The invariant that makes this channel structurally incapable of becoming
    the authoritative write path."""
    with pytest.raises(ValueError, match="in_progress=True"):
        _payload(in_progress=False)


def test_payload_rejects_resolved_exceeding_total():
    with pytest.raises(ValueError, match="cannot exceed"):
        _payload(chunks_resolved=7, chunks_total=6, chunks_ok=7, chunks_cut=0)


def test_payload_rejects_resolved_that_is_not_ok_plus_cut():
    """㊾ correction — resolved means TERMINATED. If ok+cut disagrees with
    resolved, something counted a STARTED chunk and the bar over-reports."""
    with pytest.raises(ValueError, match="TERMINATED, not started"):
        _payload(chunks_resolved=3, chunks_ok=1, chunks_cut=1)


def test_payload_is_frozen():
    p = _payload()
    with pytest.raises(Exception):
        p.chunks_resolved = 99      # type: ignore[misc]


def test_recorder_rejects_bare_dict():
    """The TYPE is the contract. A dict would let this channel carry arbitrary
    state through the isolation."""
    rec = _LegacyRecorder(_FakeCtx())
    rec._install_chunk_progress_cb("nuclei", lambda p: None)
    with pytest.raises(TypeError, match="only a ProgressPayload"):
        rec.emit_chunk_progress({"phase_name": "nuclei"})   # type: ignore[arg-type]


def test_recorder_rejects_progress_for_another_phase():
    rec = _LegacyRecorder(_FakeCtx())
    rec._install_chunk_progress_cb("nuclei", lambda p: None)
    with pytest.raises(ValueError, match="executing phase"):
        rec.emit_chunk_progress(_payload(phase_name="nikto"))


def test_merge_independently_revalidates():
    """Second layer (4.7 (54)): even if the recorder's check were bypassed, the
    executor's merge refuses a non-provisional payload. One layer gets edited
    away; two is the ⑭′ lesson."""
    with pytest.raises(ValueError, match="provisional"):
        _merge_chunk_progress(_FakeCtx(), object())          # type: ignore[arg-type]


# ── (53) isolation preserved ────────────────────────────────────────────────

def test_recorder_dsn_stays_none_after_installing_callback():
    """🔴 THE #2621 INVARIANT. If this ever becomes truthy, the legacy phase's
    internal flush_progress fires against the recorder and overwrites the real
    scan_run row mid-run."""
    rec = _LegacyRecorder(_FakeCtx())
    rec._install_chunk_progress_cb("nuclei", lambda p: None)
    assert rec.dsn is None


def test_recorder_bookkeeping_still_isolated_from_real_ctx():
    real = _FakeCtx()
    rec = _LegacyRecorder(real)
    rec._install_chunk_progress_cb("nuclei", lambda p: None)
    rec.tools_run.append("nuclei[critical,high]")
    rec.tool_status["nuclei[critical,high]"] = {"ok": True}
    assert real.tools_run == [], "recorder leaked tools_run into the real ctx"
    assert real.tool_status == {}, "recorder leaked tool_status into the real ctx"


def test_emit_is_a_noop_without_an_installed_callback():
    """A legacy phase called outside the executor path must be harmless."""
    rec = _LegacyRecorder(_FakeCtx())
    rec.emit_chunk_progress(_payload())          # must not raise


def test_merge_touches_only_the_one_phase_key():
    real = _FakeCtx()
    real.tool_status["nikto"] = {"ok": True}
    _merge_chunk_progress(real, _payload())
    assert real.tool_status["nikto"] == {"ok": True}, "merge clobbered a sibling"
    assert entry_is_provisional(real.tool_status["nuclei"])


# ── ㊿ no consumer may treat a provisional entry as a verdict ────────────────

def _autoclose_20260828a_predicate(entry) -> bool:
    """Mirror of migration 20260828a/20260902a's SQL test
    `tool_status -> t.tool ->> 'ok' = 'true'`. Pinned here because the SQL
    cannot be unit-tested from this repo."""
    return isinstance(entry, dict) and entry.get("ok") is True


KNOWN_TOOL_STATUS_VERDICT_CONSUMERS = [
    ("autoclose_20260902a_sql_predicate", _autoclose_20260828a_predicate),
]


@pytest.mark.parametrize("name,consumer", KNOWN_TOOL_STATUS_VERDICT_CONSUMERS)
def test_no_consumer_treats_in_progress_as_verdict(name, consumer):
    """㊿. A provisional entry must never read as coverage.

    Two independent reasons it is refused, and BOTH are deliberate:
      1. ok is False  → every existing `ok == true` consumer already rejects it
                        without knowing this feature exists (fail-safe default).
      2. in_progress   → the explicit signal for consumers that need to tell
                        "no verdict yet" apart from "verdict: not ok".
    """
    provisional = _payload().as_entry()
    assert consumer(provisional) is False, (
        f"{name} treated an in_progress entry as a verdict")


def test_provisional_entry_is_detected_by_value_not_key_membership():
    """The ⑭′ trap, restated: key membership is not a value test."""
    assert entry_is_provisional({"in_progress": True}) is True
    assert entry_is_provisional({"in_progress": False}) is False, (
        "membership-style check would call this provisional")
    assert entry_is_provisional({"ok": True}) is False


def test_as_entry_carries_ok_false():
    """Load-bearing: the fail-safe half of the two reasons above."""
    assert _payload().as_entry()["ok"] is False


# ── ㊿ run_phase strips the marker on EVERY outcome ──────────────────────────

def _mutating_markers(ctx):
    """Markers that UPDATE the existing entry instead of rebinding it.

    🔴 THIS IS THE POINT OF THE TEST. Today every branch in run_phase rebinds
    ctx.tool_status[name] to a fresh dict, so a leftover in_progress marker is
    already impossible and a test using the real markers would pass whether or
    not the strip exists — it would pin nothing.

    4.7 ㊿ asked for the strip to be EXPLICIT precisely so a future path that
    mutates rather than replaces cannot ship a provisional marker on an
    authoritative verdict. These markers simulate that future path, so this
    test fails if the pop is removed.
    """
    def ok(c, n):
        c.tool_status.setdefault(n, {}).update({"ok": True})

    def degraded(c, n, reason, **kw):
        c.tool_status.setdefault(n, {}).update({"degraded": reason})

    def skipped(c, n, reason):
        c.tool_status.setdefault(n, {}).update({"skipped": reason})
    return dict(mark_ok=ok, mark_degraded=degraded, mark_skipped=skipped)


@pytest.mark.parametrize("make_result", [
    pytest.param(lambda PR: PR.ok(), id="ok"),
    pytest.param(lambda PR: PR.degraded("boom"), id="degraded"),
    pytest.param(lambda PR: PR.skipped("n/a"), id="skipped"),
    pytest.param(lambda PR: PR.partial("wall_clock_cut"), id="partial"),
])
def test_run_phase_strips_in_progress_from_every_outcome(make_result):
    import pathlib

    from phase_contract import HEAVY, PhaseResult, PhaseSpec, run_phase

    ctx = _FakeCtx()
    ctx.active_probe_authorized = False
    ctx.intensity = "heavy"
    # A provisional snapshot left behind by A′ mid-phase.
    ctx.tool_status["t"] = _payload(phase_name="t").as_entry()

    spec = PhaseSpec(fn=lambda c, w: make_result(PhaseResult), name="t", tier=HEAVY)
    run_phase(spec, ctx, pathlib.Path("/tmp"), **_mutating_markers(ctx))

    final = ctx.tool_status["t"]
    assert "in_progress" not in final, (
        f"authoritative verdict kept the provisional marker: {final}")
    assert not entry_is_provisional(final)
