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

⛔⛔ 2026-10-07 — THIS FILE PINNED THE DEFECT IT WAS WRITTEN TO PREVENT. It
asserted the chain ENDS in 'true' and that the input DEFAULTS to boolean false,
and never asked whether a run could get from one to the other. A
workflow_dispatch that omits an input receives the declared default, so every
dispatched run (portal button, portal heartbeat, and this workflow's own
self-chain, which POSTs only {"ref":"main"}) carried the string 'false', which
is truthy to `||`: the chain stopped at the input, and the repo variable and the
'true' fallback were unreachable on nearly every real scan. Measured: with
ACTIVE_PROBE_LIVE deleted from prodexsentry-asm at 14:31, the uat (14:33) and
prod (14:40) heavy scans both wrote dry_run=true. Two green pins, each true on
its own, jointly guaranteeing the opposite of what both were for: doctrine 278,
the check that cannot fail. The input now defaults to BLANK, and the tests below
RESOLVE the chain the way GitHub does, per trigger path, instead of reading its
pieces separately.
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


# ── the dispatch input exists and defaults BLANK, so the variable decides ──

def test_the_dispatch_input_exists_and_defaults_BLANK():
    """⛔ NOT boolean/false (2026-10-07). A boolean input can never be blank: an
    omitted dispatch receives 'false' and that string beats the repo variable.
    A string input defaulting to '' falls through exactly as cron does."""
    inputs = _on_block(_wf())["workflow_dispatch"]["inputs"]
    assert INPUT_NAME in inputs, f"no {INPUT_NAME} workflow_dispatch input"
    spec = inputs[INPUT_NAME]
    assert spec["type"] == "string", (
        "the go-live input must be a string: a boolean has no blank state, so an "
        "omitted dispatch would carry 'false' and the repo variable would never be read")
    assert spec["default"] == "", "the go-live input must default to BLANK"
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


# ── RESOLVE the chain per trigger path, the way GitHub does (2026-10-07) ────

_CHAIN = re.compile(
    r"^\$\{\{\s*github\.event\.inputs\." + INPUT_NAME
    + r"\s*\|\|\s*vars\." + ENV_KEY + r"\s*\|\|\s*'true'\s*\}\}$")


def _input_spec():
    return _on_block(_wf())["workflow_dispatch"]["inputs"][INPUT_NAME]


def _heavy_expr():
    return _step_running("run_heavy.py")["env"][ENV_KEY]


def _input_as_delivered(spec, path, typed=None):
    """What github.event.inputs.<name> holds on each trigger path.
    schedule / workflow_run: the event carries no inputs, so ''.
    workflow_dispatch that omits the input (portal button, heartbeat, the
    self-chain's {"ref":"main"}): GitHub fills the DECLARED default, rendered as
    a string, so a boolean False arrives as 'false'.
    workflow_dispatch with a value typed by an operator: that value."""
    if path in ("schedule", "workflow_run"):
        return ""
    if typed is not None:
        return typed
    d = spec.get("default", "")
    if isinstance(d, bool):
        return "true" if d else "false"
    return "" if d is None else str(d)


def _resolve(expr, input_value, repo_var):
    """GitHub `a || b || c`: the first truthy operand, and EVERY non-empty
    string is truthy, 'false' included. That last clause is the whole defect."""
    assert _CHAIN.match(expr.strip()), f"the chain's shape changed: {expr!r}"
    for term in (input_value, repo_var or "", "true"):
        if term:
            return term
    raise AssertionError("unreachable: the chain ends in a literal")


def test_an_omitted_input_dispatch_resolves_exactly_like_cron():
    """⭐ THE PIN THAT WOULD HAVE CAUGHT IT. The portal, the heartbeat and the
    self-chain all dispatch without this input; they must arm or disarm exactly
    as a cron run would, for every state of the repo variable."""
    spec, expr = _input_spec(), _heavy_expr()
    for var in (None, "false", "true"):
        cron = _resolve(expr, _input_as_delivered(spec, "schedule"), var)
        dispatched = _resolve(expr, _input_as_delivered(spec, "workflow_dispatch"), var)
        assert dispatched == cron, (
            f"with repo variable {var!r}, cron resolves {cron!r} but an omitted-input "
            f"dispatch resolves {dispatched!r}: the input's default is not blank, so "
            "portal and chained scans never read the variable")


def test_the_repo_variable_decides_every_automatic_path():
    """The kill switch must work wherever a scan can start, and its absence must
    arm wherever a scan can start. Driven through the runner's real parse."""
    spec, expr = _input_spec(), _heavy_expr()
    for path in ("schedule", "workflow_run", "workflow_dispatch"):
        delivered = _input_as_delivered(spec, path)
        assert h._env_flag_armed(_resolve(expr, delivered, "false")) is False, (
            f"{path}: ACTIVE_PROBE_LIVE=false did not disarm it")
        assert h._env_flag_armed(_resolve(expr, delivered, None)) is True, (
            f"{path}: with no repo variable it should be armed and is not")


def test_an_operator_typed_value_still_wins_both_ways():
    spec, expr = _input_spec(), _heavy_expr()
    for var in (None, "false", "true"):
        assert h._env_flag_armed(_resolve(
            expr, _input_as_delivered(spec, "workflow_dispatch", "true"), var)) is True
        assert h._env_flag_armed(_resolve(
            expr, _input_as_delivered(spec, "workflow_dispatch", "false"), var)) is False


def test_the_self_chain_dispatch_does_not_send_this_input():
    """The self-chain is an OMITTED-input dispatch on purpose. If it ever starts
    sending this input, it must not send a value that overrides the variable."""
    step = _step_running("scanner.yml/dispatches")
    assert INPUT_NAME not in (step.get("run") or ""), (
        "the self-chain now sends the go-live input; a hard-coded value there "
        "would override the repo variable on every chained scan")


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
