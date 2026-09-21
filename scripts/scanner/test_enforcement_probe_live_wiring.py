#!/usr/bin/env python3
"""(354a-FIRE / relay 366) The SECOND live wire: the dispatch input -> the env.

⛔ THE GAP THIS CLOSES. 360 carried the per-asset flag to the descriptor, but
`ENFORCEMENT_PROBE_LIVE` is read from the RUNNER ENV (enforcement_probe.py) and
nothing in scanner.yml ever set it — no dispatch input, no env block. So
probe_is_authorised always saw env-absent and every run stayed dry-run no matter
what the flag said. Same shape as the descriptor gap, one layer out.

⛔ THE ASSERTION THAT MATTERS IS *WHERE*. probe_enforcement runs inside
run_light.py. ACTIVE_PROBE_LIVE — the fwbbot sibling this mirrors — sits on the
HEAVY step because that probe runs in run_heavy.py. Wire this one to the heavy
step and it is still permanently dry-run, silently. So these tests do not ask
"does ENFORCEMENT_PROBE_LIVE appear in scanner.yml" (presence-anywhere, which a
comment or the wrong step would satisfy). They parse the YAML, find the step
that actually invokes run_light.py, and assert the env key is in THAT step.

⛔ AND CRON MUST STAY DRY-RUN. The `|| 'false'` fallback is what makes a
scheduled run safe: github.event.inputs is empty on cron, so the env arrives as
'false'. That value is fed to the REAL probe_is_authorised below and must deny.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import enforcement_probe as EP  # noqa: E402

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scanner.yml"
ENV_KEY = "ENFORCEMENT_PROBE_LIVE"
INPUT_NAME = "enforcement_probe_live"


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
    """The step whose `run:` actually invokes the given script."""
    hits = [s for s in _all_steps(_wf()) if fragment in (s.get("run") or "")]
    assert len(hits) == 1, f"expected exactly one step running {fragment}, got {len(hits)}"
    return hits[0]


# ── the dispatch input exists and is default-off ─────────────────────────────

def test_the_dispatch_input_exists_and_defaults_false():
    inputs = _on_block(_wf())["workflow_dispatch"]["inputs"]
    assert INPUT_NAME in inputs, "no enforcement_probe_live workflow_dispatch input"
    spec = inputs[INPUT_NAME]
    assert spec["type"] == "boolean"
    assert spec["default"] is False, "the go-live input must default to false"
    assert spec.get("required") is False


def test_the_input_description_states_both_gates():
    """Operator-facing text is the only documentation most people read at the
    moment they decide whether to tick the box. It must say the per-asset flag
    is ALSO required, or someone ticks this and expects a capture."""
    desc = _on_block(_wf())["workflow_dispatch"]["inputs"][INPUT_NAME]["description"]
    assert "enforcement_probe_authorized" in desc
    assert "dry-run" in desc.lower()


# ── THE PIN: the env is on the LIGHT step, the one that runs the probe ───────

def test_the_env_is_wired_on_the_step_that_runs_run_light():
    step = _step_running("run_light.py")
    assert ENV_KEY in (step.get("env") or {}), (
        f"{ENV_KEY} is not on the step that runs run_light.py — probe_enforcement "
        "executes there, so anywhere else leaves it permanently dry-run")


def test_the_env_is_NOT_on_the_heavy_step():
    """The sibling ACTIVE_PROBE_LIVE lives on heavy. Putting this one there is
    the specific mistake that would look wired and fire nothing."""
    step = _step_running("run_heavy.py")
    assert ENV_KEY not in (step.get("env") or {})


def test_the_env_appears_exactly_once_in_the_whole_workflow():
    """Not smuggled onto a second step as well."""
    n = sum(1 for s in _all_steps(_wf()) if ENV_KEY in (s.get("env") or {}))
    assert n == 1, f"{ENV_KEY} wired on {n} steps, expected exactly 1"


def test_the_env_derives_from_the_input_with_the_cron_safe_fallback():
    step = _step_running("run_light.py")
    expr = step["env"][ENV_KEY]
    assert f"github.event.inputs.{INPUT_NAME}" in expr, (
        "the env must come from the dispatch input, not a hardcoded value")
    assert "|| 'false'" in expr, (
        "without the fallback, cron sends empty and the value is unset rather "
        "than explicitly false")


# ── end to end against the REAL consumer: cron denies, dispatch allows ───────

def test_the_cron_value_denies_even_for_an_opted_in_asset():
    """⛔ What cron actually delivers. github.event.inputs is empty on a
    schedule, so `|| 'false'` yields the string 'false'. Fed to the real gate
    with the per-asset flag ON, it must still deny."""
    opted_in = {EP.AUTH_FLAG: True}
    for cron_value in ("false", ""):
        assert EP.probe_is_authorised(
            opted_in, env={EP.LIVE_ENV: cron_value}) is False, cron_value


def test_the_dispatch_value_arms_it_only_with_the_per_asset_flag():
    """A ticked box alone is not enough — both gates."""
    assert EP.probe_is_authorised(
        {EP.AUTH_FLAG: True}, env={EP.LIVE_ENV: "true"}) is True
    assert EP.probe_is_authorised(
        {}, env={EP.LIVE_ENV: "true"}) is False


def test_the_env_name_in_the_workflow_matches_the_one_the_code_reads():
    """A rename on either side silently un-wires the probe."""
    step = _step_running("run_light.py")
    assert EP.LIVE_ENV in (step.get("env") or {}), (
        f"code reads {EP.LIVE_ENV}; workflow must set that exact name")
