"""(Obsidian 309, 2026-10-13) The device-class classifier writes on its schedule.

Note 154 (2026-07-22) put the classifier on a 6-hourly cron in DRY-RUN and set the bar
for flipping it to write: clean scheduled runs, manual writes validated, no regression
on the known-good hosts, and a review of every single-signal "suspected" host. The soak
ran eleven weeks; the proposals were identical on every pass from 09-18 (Prodex) and
09-22 (Command) on; the review happened on 2026-10-13. This pins what the flip IS:

  * a schedule trigger (no inputs) runs the runner with --write;
  * a manual dispatch still defaults to dry-run and writes only on mode=write;
  * an unknown mode fails the step instead of silently running something;
  * inputs reach the shell through env, never interpolated into the script body.

The run block is EXECUTED here with bash and a stub `python`, not grepped, so the
pin is on behaviour: the exact argv the runner would get for each trigger.
"""
import os
import re
import subprocess

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
WF = os.path.join(REPO, ".github", "workflows", "device-class-classify.yml")

_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def _doc():
    return yaml.safe_load(open(WF, encoding="utf-8"))


def _step():
    (job,) = _doc()["jobs"].values()
    steps = [s for s in job["steps"] if s.get("name") == "Run device-class classifier"]
    assert len(steps) == 1, "exactly one runner step"
    return steps[0]


def _evaluate(expr: str, event_name: str, inputs: dict) -> str:
    """The two expression shapes this workflow uses, and nothing else:
    `github.event.inputs.<k> || '<default>'`, `github.event_name`, `secrets.<k>`."""
    expr = expr.strip()
    if expr == "github.event_name":
        return event_name
    if expr.startswith("secrets."):
        return "<secret>"
    m = re.fullmatch(r"github\.event\.inputs\.(\w+)(?:\s*\|\|\s*'([^']*)')?", expr)
    assert m, f"unexpected expression in the workflow: {expr!r}"
    key, default = m.group(1), m.group(2) or ""
    # GitHub: a schedule event has no inputs -> the left side is empty -> `||` picks
    # the default. A dispatch sends every declared input (its default if untouched).
    return inputs.get(key, "") or default


def _render(s: str, event_name: str, inputs: dict) -> str:
    return _EXPR.sub(lambda m: _evaluate(m.group(1), event_name, inputs), s)


def _run(event_name: str, inputs: dict):
    """Execute the step's run block under bash with the step's env, a stub python."""
    step = _step()
    env = {k: _render(str(v), event_name, inputs) for k, v in (step.get("env") or {}).items()}
    script = _render(step["run"], event_name, inputs)
    stub = 'python () { printf "RUNNER %s\\n" "$*"; }\n'
    r = subprocess.run(["bash", "-euo", "pipefail", "-c", stub + script],
                       env={**env, "PATH": os.environ.get("PATH", "")},
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


DISPATCH_DEFAULTS = {"mode": "dry-run", "soak_generation": "1"}


def test_schedule_runs_the_runner_in_write_mode():
    rc, out, err = _run("schedule", {})
    assert rc == 0, err
    assert "RUNNER scripts/db/device_class_runner.py --soak-generation 1 --write\n" in out
    assert "::notice::device_class_runner.py --soak-generation 1 --write  (event: schedule)" in out


def test_manual_dispatch_defaults_to_dry_run():
    """A human clicking Run workflow and changing nothing must NOT write."""
    rc, out, err = _run("workflow_dispatch", dict(DISPATCH_DEFAULTS))
    assert rc == 0, err
    assert "RUNNER scripts/db/device_class_runner.py --soak-generation 1\n" in out
    assert "--write" not in out


def test_manual_dispatch_mode_write_writes():
    rc, out, err = _run("workflow_dispatch", {**DISPATCH_DEFAULTS, "mode": "write"})
    assert rc == 0, err
    assert "RUNNER scripts/db/device_class_runner.py --soak-generation 1 --write\n" in out


def test_soak_generation_input_is_passed_through():
    rc, out, _ = _run("workflow_dispatch", {"mode": "dry-run", "soak_generation": "4"})
    assert rc == 0
    assert "RUNNER scripts/db/device_class_runner.py --soak-generation 4\n" in out


def test_unknown_mode_fails_the_step_rather_than_guessing():
    rc, out, _ = _run("workflow_dispatch", {**DISPATCH_DEFAULTS, "mode": "yolo"})
    assert rc == 1
    assert "::error::unknown mode 'yolo'" in out
    assert "RUNNER" not in out, "nothing ran"


def test_dispatch_input_declares_dry_run_as_the_default_and_only_the_two_modes():
    on = _doc()[True] if True in _doc() else _doc()["on"]   # PyYAML reads bare `on:` as True
    mode = on["workflow_dispatch"]["inputs"]["mode"]
    assert mode["default"] == "dry-run"
    assert mode["options"] == ["dry-run", "write"]
    assert on["workflow_dispatch"]["inputs"]["soak_generation"]["default"] == "1"


def test_schedule_is_six_hourly_with_the_per_instance_offset():
    on = _doc()[True] if True in _doc() else _doc()["on"]
    crons = [e["cron"] for e in on["schedule"]]
    assert len(crons) == 1
    assert re.fullmatch(r"(15|45) \*/6 \* \* \*", crons[0]), crons   # Command :15, Prodex :45 (154-Q2)


def test_inputs_reach_the_shell_as_env_not_interpolated_into_the_script():
    step = _step()
    assert "github.event.inputs" not in step["run"], "inputs are env, never script text"
    env = step.get("env") or {}
    assert "MODE" in env and "SOAK_GENERATION" in env and "SUPABASE_DSN" in env
    assert env["MODE"] == "${{ github.event.inputs.mode || 'write' }}"


def test_header_says_what_a_stamp_can_do_to_routing():
    """The old header said 'changes NO routing'. cloud_ip_check.py reads
    assets.device_class to pick the port scope, so a stamp that moves an asset between
    its buckets changes the next scan. The file must say so, next to the switch."""
    text = open(WF, encoding="utf-8").read()
    assert "cloud_ip_check.py reads assets.device_class" in text
    assert "would_reroute" in text
    assert "changes NO routing" not in text


@pytest.mark.parametrize("needle", [
    "WRITE MODE ON THE SCHEDULE since 2026-10-13",
    "Obsidian 309",
])
def test_the_flip_is_dated_and_pointed_at_its_record(needle):
    assert needle in open(WF, encoding="utf-8").read()
