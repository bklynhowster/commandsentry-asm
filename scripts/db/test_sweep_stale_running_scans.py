#!/usr/bin/env python3
"""Tests for the liveness sweeper.

The defect this file guards against is not a wrong threshold — it is a safety
net that exists only in a comment. `poll_queue.py` promised "the liveness
sweeper (separate cron, M11)" and no such thing was ever built, so a runner
killed mid-scan wedged its asset out of every fleet sweep. `cooked.prodexlabs.com`
sat that way for 53.6 days without anything noticing.

So these tests pin BEHAVIOUR (what gets swept, what does not) and the three
guardrails, not implementation shape.
"""
from __future__ import annotations

import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from sweep_stale_running_scans import (            # noqa: E402
    DEFAULT_MAX_SWEEP, DEFAULT_STALE_HOURS, SWEEP_TAG, _reason, find_stale,
    should_abort)

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


def _row(hours_ago, asset="a.example.com"):
    return {"asset_id": asset, "intensity": "heavy",
            "started_at": NOW - timedelta(hours=hours_ago)}


# ── what gets swept ─────────────────────────────────────────────────────────

def test_the_real_53_day_row_is_swept():
    """🔴 THE CASE THAT PROVED THE GAP. cooked.prodexlabs.com, running since
    2026-07-10, silently excluded from every enqueue for 53.6 days."""
    stale = find_stale([_row(53.6 * 24, "cooked.prodexlabs.com")],
                       DEFAULT_STALE_HOURS, now=NOW)
    assert len(stale) == 1
    assert stale[0]["asset_id"] == "cooked.prodexlabs.com"


def test_a_live_run_is_not_swept():
    """The longest legitimate run observed is ~39 min (cumulative heavy with
    testssl). Sweeping one of those would kill a scan that is working."""
    assert find_stale([_row(0.65)], DEFAULT_STALE_HOURS, now=NOW) == []


def test_boundary_just_under_the_threshold_survives():
    assert find_stale([_row(3.9)], 4, now=NOW) == []


def test_boundary_just_over_the_threshold_is_swept():
    assert len(find_stale([_row(4.1)], 4, now=NOW)) == 1


def test_a_row_with_no_started_at_is_left_alone():
    """No started_at means the claim never completed. Not the sweeper's to
    judge — guessing there would delete evidence of a different bug."""
    assert find_stale([{"asset_id": "x", "started_at": None}],
                      DEFAULT_STALE_HOURS, now=NOW) == []


def test_threshold_is_generous_against_the_real_ceiling():
    """4h must stay well clear of the cumulative ceiling (1800s) plus testssl's
    own 1800s wall, or a legitimate long run gets swept mid-flight."""
    assert DEFAULT_STALE_HOURS * 3600 >= 6 * 1800


# ── guardrail 2: threshold-abort ────────────────────────────────────────────

def test_a_handful_of_orphans_sweeps():
    abort, _ = should_abort(3, DEFAULT_MAX_SWEEP)
    assert abort is False


def test_a_flood_aborts_without_writing():
    """🔴 THE DANGEROUS CASE. Dozens of stale rows is not an orphan problem —
    it is a DB outage, mass runner death, or a clock problem. A sweeper that
    mass-fails rows during an incident turns a recoverable outage into lost
    scan history. Write NOTHING and shout."""
    abort, why = should_abort(DEFAULT_MAX_SWEEP + 1, DEFAULT_MAX_SWEEP)
    assert abort is True
    assert "systemic" in why.lower()


def test_abort_boundary_is_inclusive_at_the_limit():
    assert should_abort(DEFAULT_MAX_SWEEP, DEFAULT_MAX_SWEEP)[0] is False
    assert should_abort(DEFAULT_MAX_SWEEP + 1, DEFAULT_MAX_SWEEP)[0] is True


# ── guardrail 1: source-tag ─────────────────────────────────────────────────

def test_swept_rows_are_source_tagged():
    """A human reading the DB must be able to tell a swept row from a genuine
    failure. Untagged automated writes are how a fabricated verdict becomes
    indistinguishable from an observed one."""
    r = _reason(DEFAULT_STALE_HOURS)
    assert SWEEP_TAG in r
    assert "sweep_stale_running_scans.py" in r


def test_the_reason_explains_the_consequence_not_just_the_cause():
    """The row exists to be read later. It should say WHY it mattered — that
    the asset was unscannable — not merely that a timer expired."""
    r = _reason(DEFAULT_STALE_HOURS).lower()
    assert "scannable" in r and "enqueue" in r


# ── guardrail 3: dry-run is the DEFAULT ─────────────────────────────────────

def test_writing_requires_an_explicit_live_flag():
    """Assert on the shipped source: --live must be opt-in, never a default,
    and never inverted to a --dry-run flag that defaults False."""
    src = pathlib.Path(__file__).parent.joinpath(
        "sweep_stale_running_scans.py").read_text()
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    assert '"--live", action="store_true"' in code, (
        "--live must be an opt-in store_true flag")
    assert "if not args.live:" in code, (
        "the dry-run early-return is gone — writes are no longer opt-in")


def test_abort_is_checked_before_any_write():
    """Ordering is the guardrail. If the flood check ran after the writes it
    would report a disaster it had already caused."""
    src = pathlib.Path(__file__).parent.joinpath(
        "sweep_stale_running_scans.py").read_text()
    assert src.index("should_abort(") < src.index("SWEEP_QUEUE_SQL,"), (
        "threshold-abort must be evaluated before the first UPDATE")


def test_sweep_only_touches_rows_still_running():
    """Both UPDATEs re-assert `status = 'running'`. Without it a row that
    completed between the SELECT and the UPDATE would be clobbered to failed."""
    src = pathlib.Path(__file__).parent.joinpath(
        "sweep_stale_running_scans.py").read_text()
    for stmt in ("SWEEP_QUEUE_SQL", "SWEEP_RUN_SQL"):
        i = src.index(stmt + ' = """')
        body = src[i:i + 500]
        assert "and status = 'running'" in body, (
            f"{stmt} lost its status guard — it could clobber a row that "
            f"finished between the read and the write")
