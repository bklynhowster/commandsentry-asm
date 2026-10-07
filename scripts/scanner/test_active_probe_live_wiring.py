#!/usr/bin/env python3
"""(relay 533 item 2) The pin ACTIVE_PROBE_LIVE never had.

⛔ WHY THIS FILE EXISTS. Its sibling ENFORCEMENT_PROBE_LIVE has had
test_enforcement_probe_live_wiring.py since 354a-FIRE. ACTIVE_PROBE_LIVE — armed
on the scheduled path in the SAME commit (0797947a, 2026-09-27, "scanner: arm the
live half on the scheduled path") — had nothing. So when that commit inverted the
fallback, the sibling's test was updated deliberately and in the open, while this
flag's comment block kept claiming "Default false -> run_heavy ships DRY-RUN" and
"Cron/workflow_run triggers carry no input (empty -> 'false' -> dry-run)" for
three days. An unpinned comment is a comment that rots.

⚠ AND IT ROTTED IN THE DIRECTION THAT INVITES A WRONG FIX. Reading those comments
beside a chain ending in the literal 'true', the obvious "correction" is to change
the operator to 'false' — which would restore exactly the defect Howie removed:
github.event.inputs is empty on cron and on workflow_run, so a 'false' fallback
puts the fleet half where the automatic path can never reach it and the probe can
only fire from a hand-dispatch. This file pins the armed shape so that revert
fails here, loudly, instead of quietly muting the fleet again.

⭐ AND IT PINS THE OTHER DIRECTION TOO. Arming the fleet half must not widen the
target set by one host: the per-asset flag assets.active_probe_authorized is the
gate on WHICH hosts are legal, and the two probe phases must AND the two together.

⚠ KNOWN LIMIT, STATED NOT HIDDEN. The sibling asserts end-to-end against the real
pure predicate probe_is_authorised. The active probe has no such function — its
per-asset flag arrives from a DB read inside the phase — so the AND is asserted
against SOURCE TEXT here. That is the weak assertion in this file, and extracting
the active probe's authorization into a pure predicate is what would fix it.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_heavy as h  # noqa: E402

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scanner.yml"
RUNNER = Path(__file__).resolve().parent / "run_heavy.py"
ENV_KEY = "ACTIVE_PROBE_LIVE"
INPUT_NAME = "active_probe_live"


def _wf():
    return yaml.safe_load(WORKFLOW.read_text())


def _on_block(wf):
    # PyYAML (YAML 1.1) parses a bare `on:` key as the boolean True.
    return wf.get("on", wf.get(True))


def _all_steps(wf):
    for job in (wf.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            yield step


def _step_running(fragment):
    hits = [s for s in _all_steps(_wf()) if fragment in (s.get("run") or "")]
    assert len(hits) == 1, f"expected exactly one step running {fragment}, got {len(hits)}"
    return hits[0]


# ── the dispatch input exists and is default-off ─────────────────────────────

def test_the_dispatch_input_exists_and_defaults_false():
    inputs = _on_block(_wf())["workflow_dispatch"]["inputs"]
    assert INPUT_NAME in inputs, f"no {INPUT_NAME} workflow_dispatch input"
    spec = inputs[INPUT_NAME]
    assert spec["type"] == "boolean"
    assert spec["default"] is False, "the go-live input must default to false"
    assert spec.get("required") is False


def test_the_input_description_does_not_claim_cron_is_dry_run():
    """⛔ THE COPY THAT ACTUALLY MISLEADS SOMEBODY. This description is what an
    operator reads in the GitHub dispatch UI at the moment they decide whether to
    tick the box. It used to end "Cron/workflow_run runs never set this -> always
    dry-run there", which is false: they set no INPUT, and the chain then falls
    through to the repo variable and, absent that, to armed. Corrected 2026-09-30."""
    desc = _on_block(_wf())["workflow_dispatch"]["inputs"][INPUT_NAME]["description"]
    assert "never set this -> always dry-run" not in desc, (
        "the description claims scheduled runs are always dry-run; the fallback "
        "below ends in 'true', so they are armed unless the repo variable says otherwise")
    assert "active_probe_authorized" in desc, (
        "the per-asset gate must be named — someone ticking this box needs to know "
        "it alone fires nothing")


# ── THE PIN: the env is on the HEAVY step, the one that runs the probe ───────

def test_the_env_is_wired_on_the_step_that_runs_run_heavy():
    step = _step_running("run_heavy.py")
    assert ENV_KEY in (step.get("env") or {}), (
        f"{ENV_KEY} is not on the step that runs run_heavy.py — both probe phases "
        "execute there, so anywhere else leaves them permanently dry-run")


def test_the_env_is_NOT_on_the_light_step():
    """The mirror of the sibling's mistake: wired onto light, this would look
    configured and fire nothing forever."""
    step = _step_running("run_light.py")
    assert ENV_KEY not in (step.get("env") or {})


def test_the_env_appears_exactly_once_in_the_whole_workflow():
    n = sum(1 for s in _all_steps(_wf()) if ENV_KEY in (s.get("env") or {}))
    assert n == 1, f"{ENV_KEY} wired on {n} steps, expected exactly 1"


def test_the_env_derives_from_input_then_repo_var_then_armed():
    """⭐ THE SHAPE HOWIE CHOSE IN 0797947a. A silent revert to 'false' fails here
    rather than quietly putting the fleet half out of the scheduler's reach."""
    expr = _step_running("run_heavy.py")["env"][ENV_KEY]
    assert f"github.event.inputs.{INPUT_NAME}" in expr, (
        "a manual dispatch must still win over the fleet default")
    assert f"vars.{ENV_KEY}" in expr, (
        f"no repo-variable override. Without vars.{ENV_KEY} the only way to disarm "
        "the fleet is a code change, which is the wrong shape for a kill switch "
        "someone may need in a hurry — and it is the switch actually in use today")
    assert "|| 'true'" in expr, (
        "the fleet half must END armed. github.event.inputs is EMPTY on cron and on "
        "workflow_run, so a 'false' fallback is the 0797947a defect restored: a "
        "switch positioned where the automatic path cannot reach it")


# ── the runner's parse, driven with the exact strings the workflow delivers ──

def test_the_parse_reads_what_each_path_delivers():
    assert h._env_flag_armed("true") is True     # cron, no repo variable
    assert h._env_flag_armed("false") is False    # the repo-var kill switch in use today
    assert h._env_flag_armed(None) is False       # env absent -> dry-run
    assert h._env_flag_armed("") is False


# ── arming the fleet half must not widen the target set ─────────────────────

def test_both_probe_phases_AND_the_per_asset_flag_with_the_fleet_flag():
    """⛔ THE ASSERTION THAT MATTERS MOST. Arming the fleet half must not make one
    extra host legal. Both phases must require per-asset authorization AND the
    fleet flag — an `or` here, or a phase reading only the fleet flag, would probe
    hosts nobody opted in.

    ⚠ Source-level, per this file's stated limit: there is no pure predicate to
    call, so this reads the runner's text."""
    src = RUNNER.read_text()
    ands = re.findall(r"fire\s*=\s*authorized and _ACTIVE_PROBE_LIVE", src)
    assert len(ands) == 2, (
        f"expected both probe phases to AND the two gates, found {len(ands)} — "
        "run_fwbbot_check_probe_phase and run_waf_differential_probe_phase")
    assert not re.search(r"fire\s*=\s*authorized or _ACTIVE_PROBE_LIVE", src)
    assert not re.search(r"fire\s*=\s*_ACTIVE_PROBE_LIVE\s*$", src, re.M)
