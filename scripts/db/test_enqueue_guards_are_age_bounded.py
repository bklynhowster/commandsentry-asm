#!/usr/bin/env python3
"""4.7 ㊲ — every enqueue guard must AGE-BOUND its 'running' arm.

THE DEFECT. `poll_queue.py` commits the queue claim + scan_run insert
atomically, on the promise that "the liveness sweeper (separate cron, M11)
detects scans stuck in 'running' for > 4h and marks them failed." No such
sweeper was ever built — not in either repo, not in any workflow.

That alone would be untidy. What made it bite is that every enqueue path
treated ANY 'running' row as an active scan, with no age bound. So a row
abandoned by a dead runner excluded its asset from every future enqueue,
permanently and silently.

Found live on PRODEXsentry 2026-09-02: cooked.prodexlabs.com wedged
status='running' since 2026-07-10 — 53.6 days invisible to every fleet sweep.

THE FIX IS AT THE READ LAYER, not a scheduled writer. 4.7 ㊲: a wrong threshold
in a read costs a redundant enqueue (the VPN slot gates it); a wrong threshold
in a writer corrupts state by failing a live scan. The read-side fix also
leaves stale rows in place AS EVIDENCE rather than silently rewriting history.

These are source pins because the guards live in workflow YAML, where no unit
test reaches them. A guard that silently loses its age bound is exactly the
regression that produced the 53-day wedge.

Run: python3 -m pytest test_enqueue_guards_are_age_bounded.py
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"

# Every workflow that gates on scan_queue state. seed-device-class.yml is
# Command-only, so it is checked when present rather than required.
GUARD_FILES = ["enqueue-fleet.yml", "scanner.yml", "seed-device-class.yml"]


def _existing(name: str) -> pathlib.Path | None:
    p = WORKFLOWS / name
    return p if p.exists() else None


@pytest.mark.parametrize("name", GUARD_FILES)
def test_no_unbounded_running_guard(name):
    """🔴 THE REGRESSION PIN. `status in ('queued','running')` treats a dead
    runner's row as an active scan forever."""
    p = _existing(name)
    if p is None:
        pytest.skip(f"{name} not present in this instance")
    text = p.read_text()
    bad = re.findall(r"status\s+in\s*\(\s*'queued'\s*,\s*'running'\s*\)", text)
    assert not bad, (
        f"{name} has {len(bad)} unbounded queued/running guard(s). A 'running' "
        f"row from a dead runner will wedge its asset out of every enqueue — "
        f"that is the cooked.prodexlabs.com 53-day failure. Age-bound it.")


@pytest.mark.parametrize("name", GUARD_FILES)
def test_running_arm_is_age_bounded_wherever_it_appears(name):
    """Every mention of a 'running' status test must sit next to a started_at
    recency comparison. Asserts on CODE — comment lines are stripped, because
    the comments in these files discuss 'running' at length."""
    p = _existing(name)
    if p is None:
        pytest.skip(f"{name} not present in this instance")
    code = "\n".join(ln for ln in p.read_text().splitlines()
                     if not ln.lstrip().startswith("#")
                     and not ln.lstrip().startswith("--"))
    if "status = 'running'" not in code:
        pytest.skip(f"{name} has no running-status guard")
    for m in re.finditer(r"status\s*=\s*'running'", code):
        before = code[max(0, m.start() - 320):m.start()]
        window = code[m.start():m.start() + 220]

        # EXEMPTION, deliberate and narrow: the per-run close-out UPDATE in
        # scanner.yml re-asserts `status = 'running'` so it cannot clobber a row
        # that finished between the read and the write. That guard is scoped by
        # `scan_run_id = <this run>`, so it can never wedge another asset — it
        # is a concurrency guard, not an enqueue gate, and age-bounding it would
        # be wrong (a run legitimately older than the window still needs closing
        # out). Only guards that DECIDE WHETHER TO ENQUEUE need the age bound.
        if "scan_run_id" in before:
            continue

        assert "started_at" in window, (
            f"{name}: a 'running' test at offset {m.start()} is not scoped by "
            f"scan_run_id and has no started_at bound within 220 chars — an "
            f"unbounded enqueue gate is the cooked.prodexlabs.com wedge")


@pytest.mark.parametrize("name", GUARD_FILES)
def test_threshold_is_operator_tunable(name):
    """Per-instance tunability. Command and Prodex have different slot counts
    and drain cadences; the threshold must not be hard-coded."""
    p = _existing(name)
    if p is None:
        pytest.skip(f"{name} not present in this instance")
    text = p.read_text()
    if "status = 'running'" not in text:
        pytest.skip(f"{name} has no running-status guard")
    assert "STALE_RUN_HOURS" in text, (
        f"{name} hard-codes the staleness window — make it ${{STALE_RUN_HOURS:-8}}")


def test_default_threshold_clears_the_longest_real_run():
    """8h was chosen empirically, not by feel: the longest COMPLETED run in 90
    days was 1.00h (Command), and yesterday's cumulative heavy was 0.64h. That
    is an 8x margin.

    If this default is ever lowered, re-derive it from scan_run durations
    first — a threshold under the longest legitimate run causes redundant
    enqueues against a scan that is still alive.
    """
    p = _existing("enqueue-fleet.yml")
    assert p is not None
    m = re.search(r"STALE_RUN_HOURS:-(\d+)", p.read_text())
    assert m, "no STALE_RUN_HOURS default found"
    hours = int(m.group(1))
    assert hours >= 4, f"{hours}h is under 4x the longest observed run (1.00h)"


def test_the_sweeper_is_not_wired_to_a_schedule():
    """4.7 ㊲ kept sweep_stale_running_scans.py as a MANUAL tidy-up tool and
    explicitly rejected it as scheduled automation: an unattended writer on
    production scan history is a bigger risk than the garbage it collects, and
    its threshold-abort guard would make it inert during precisely the
    incidents that produce stale rows.

    Same precedent as asm_autoclose_stale_findings, which is blocked from live
    running for over-closing on a staleness predicate."""
    for wf in WORKFLOWS.glob("*.yml"):
        text = wf.read_text()
        if "sweep_stale_running_scans" in text:
            pytest.fail(
                f"{wf.name} invokes the sweeper. 4.7 ㊲ ruled it manual-only — "
                f"if you are scheduling it, re-open that ruling first.")
