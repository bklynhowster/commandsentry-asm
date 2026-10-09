#!/usr/bin/env python3
"""test_d056_diag_tools_retired.py — Command's two FortiGate diag tools stay retired.

⛔ D-056 (Howie, ABSOLUTE): no authentication-type attacks. Found 2026-10-08:
`fortigate-recipe-canary.yml` (shell) and `fortigate_threshold_probe.py` (via
fortigate-threshold-probe.yml) fire nuclei templates at Command's FortiGate
with NO login-attack exclusion and NO content check. The canary also fired on
any push that touched its own file. Neither has run since 2026-09-04. Both are
retired until they are rebuilt on run_medium.d056_screen_templates.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

WORKFLOWS = ["fortigate-recipe-canary.yml", "fortigate-threshold-probe.yml"]


def test_the_threshold_probe_refuses_before_sending_anything(monkeypatch, capsys):
    import fortigate_threshold_probe as probe

    def boom(*a, **k):
        raise AssertionError("D-056: the retired probe tried to run a process")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    # It must stop AT the refusal, not merely happen to fail a later precondition.
    monkeypatch.setattr(probe.argparse, "ArgumentParser", boom)
    monkeypatch.setattr(sys, "argv", ["fortigate_threshold_probe.py"])
    assert probe.main() == 2
    assert "D-056" in capsys.readouterr().err, "it must refuse BECAUSE of D-056, not by accident"


@pytest.mark.parametrize("wf", WORKFLOWS)
def test_the_workflow_can_only_be_fired_by_hand(wf):
    d = yaml.safe_load(open(os.path.join(REPO, ".github", "workflows", wf), encoding="utf-8"))
    on = d.get(True, d.get("on"))
    triggers = set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on or [])
    assert triggers == {"workflow_dispatch"}, f"{wf} must be manual-only, has {sorted(triggers)}"


@pytest.mark.parametrize("wf", WORKFLOWS)
def test_every_job_refuses_at_its_first_step(wf):
    d = yaml.safe_load(open(os.path.join(REPO, ".github", "workflows", wf), encoding="utf-8"))
    for name, job in d["jobs"].items():
        first = job["steps"][0]
        assert "D-056-RETIRED" in first.get("name", ""), f"{wf}:{name} first step is {first.get('name')}"
        assert first.get("run", "").rstrip().endswith("exit 1"), f"{wf}:{name} first step must exit 1"
