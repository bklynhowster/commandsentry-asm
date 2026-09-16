#!/usr/bin/env python3
"""The set-but-EMPTY env trap — relay 202, 2026-09-16. PRODUCTION.

⛔ WHAT HAPPENED. Every schedule-triggered MEDIUM scan on Command died at import
in 32 seconds:

    File "scripts/scanner/run_medium.py", line 447, in <module>
        PATIENT_BAN_COOLDOWN_S = int(os.environ.get("PATIENT_BAN_COOLDOWN_S", "1800"))
    ValueError: invalid literal for int() with base 10: ''

⛔ THE MECHANISM. scanner.yml passes workflow inputs straight through as env:

    PATIENT_BAN_COOLDOWN_S: ${{ github.event.inputs.patient_ban_cooldown_s }}

    workflow_dispatch -> the input's default "1800" -> env "1800" -> int OK
    schedule          -> github.event.inputs is EMPTY -> env ""     -> int("") CRASH
    var never set     -> .get's default "1800"        ->             int OK

`os.environ.get(key, default)` only defaults when the key is ABSENT. GitHub sets it
PRESENT AND EMPTY. Latent since 2026-05-31 (c4bed301, PATIENT_MODE) — three and a
half months — because until the deep sweep began scheduling mediums, no medium had
ever run on the `schedule` path. Same shape as the `utc_now` defect: a branch that
nothing had executed until the first input reached it.

⚠ THE BLAST RADIUS IS WIDER THAN THE ONE STEP. run_light.py:311 and
run_heavy.py:110 both `from run_medium import (...)`, so run_medium's module-level
constants execute on ANY tier's import. Today only the "Run Medium tier" step sets
PATIENT_BAN_COOLDOWN_S, so only medium crashes — but a numeric input added to the
light or heavy step tomorrow would take down all three. That is why this is swept as
a CLASS and pinned, not fixed as one line.

⛔ THIS IS THE TEST THAT WOULD HAVE CAUGHT IT IN MAY. It derives the key list from
the workflow YAML — never a retyped list, which would go stale exactly like the one
the lane-4 orphan check used to carry.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "scanner.yml"
RUNNERS = ("run_light", "run_medium", "run_heavy")

# Any env key whose value is derived from a workflow input. The `|| 'default'`
# form is included deliberately: it is protected TODAY, but the protection lives
# in the YAML where the runner cannot see it, and this test is about what the
# runner tolerates — not about what the workflow currently happens to send.
_INPUT_ENV = re.compile(
    r'^\s*([A-Z_0-9]+):\s*\$\{\{[^}]*inputs\.[a-z_0-9]+[^}]*\}\}', re.M)

# Two-argument numeric coercion of an env var: the defect shape itself.
_TWO_ARG = re.compile(
    r'(?:int|float)\s*\(\s*\n?\s*os\.environ\.get\(\s*"[A-Z_0-9]+"\s*,', re.M)

# ⛔ THE TOOL'S OWN ARTIFACT. Two lines already carried a belt-and-braces guard —
#   float(os.environ.get("WAF_PROBE_PACING_S", "5") or "5")
# — so the mechanical sweep rewrote the two-arg half and left `or "5" or "5"`.
# Harmless to Python, and precisely the class this fix is about: a mechanical
# edit nobody read back. A pin that cannot catch the edit that produced it is
# not finished, so the near-miss is pinned too.
_DOUBLE_OR = re.compile(r'or\s+("(?:[^"]*)")\s+or\s+\1')


def _input_env_keys() -> list:
    assert WORKFLOW.is_file(), f"workflow not found at {WORKFLOW}"
    keys = sorted(set(_INPUT_ENV.findall(WORKFLOW.read_text(encoding="utf-8"))))
    # A parser regression that silently matched nothing would make every test
    # below vacuously green — the empty-set failure mode that let a mutant
    # survive in the 2b sweep. Assert the set is non-trivial.
    assert len(keys) >= 5, (
        f"only {len(keys)} input-derived env keys parsed from scanner.yml — the "
        f"parser is broken, not the workflow: {keys}")
    return keys


def _scanner_pythonpath() -> str:
    parts = [str(ROOT / "scripts" / d) for d in ("common", "scanner", "db", "normalize", "asm")]
    existing = os.environ.get("PYTHONPATH", "")
    return os.pathsep.join(parts + ([existing] if existing else []))


# ---------------------------------------------------------------------------
# ⭐ THE EXECUTABLE TEST — the schedule-shaped environment, in a subprocess
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", RUNNERS)
def test_runner_imports_under_a_schedule_shaped_environment(module):
    """Every input-derived env key set to "" — exactly what GitHub hands a
    `schedule` trigger — then import the runner.

    PRE-FIX : run_medium (and light/heavy, which import it) raise
              ValueError: invalid literal for int() with base 10: ''
    POST-FIX: all three import cleanly.

    A subprocess, not importlib, because the failure is at MODULE level: once a
    module has been imported successfully in-process, a reload cannot reproduce
    the original import-time environment faithfully."""
    env = dict(os.environ)
    for key in _input_env_keys():
        env[key] = ""                      # present-and-empty, the actual trigger
    env["PYTHONPATH"] = _scanner_pythonpath()
    env["PYTHONDONTWRITEBYTECODE"] = "1"   # see the .pyc note in the 2b relay entry
    env.setdefault("SUPABASE_DSN", "")

    proc = subprocess.run(
        [sys.executable, "-B", "-c", f"import {module}"],
        capture_output=True, text=True, env=env, timeout=180)

    assert proc.returncode == 0, (
        f"{module} failed to import with every workflow-input env var set to \"\" — "
        f"this is the `schedule` trigger's environment:\n{proc.stderr[-2000:]}")


def test_the_empty_string_still_yields_the_documented_default():
    """The fix must DEFAULT on empty, not merely survive it. A bare try/except, or
    an `or 0`, would make the import pass and silently change the scan's pacing."""
    env = dict(os.environ)
    env["PATIENT_BAN_COOLDOWN_S"] = ""
    env["PYTHONPATH"] = _scanner_pythonpath()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("SUPABASE_DSN", "")
    proc = subprocess.run(
        [sys.executable, "-B", "-c",
         "import run_medium; print(run_medium.PATIENT_BAN_COOLDOWN_S)"],
        capture_output=True, text=True, env=env, timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip() == "1800", (
        f"empty env should fall back to the documented 1800, got {proc.stdout.strip()!r}")


def test_an_explicitly_set_value_is_still_honoured():
    """The other direction, so the fix cannot be 'ignore the env var'."""
    env = dict(os.environ)
    env["PATIENT_BAN_COOLDOWN_S"] = "42"
    env["PYTHONPATH"] = _scanner_pythonpath()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("SUPABASE_DSN", "")
    proc = subprocess.run(
        [sys.executable, "-B", "-c",
         "import run_medium; print(run_medium.PATIENT_BAN_COOLDOWN_S)"],
        capture_output=True, text=True, env=env, timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip() == "42"


# ---------------------------------------------------------------------------
# the structural pin — the CLASS, not the instance
# ---------------------------------------------------------------------------

def test_no_two_argument_numeric_env_read_anywhere_under_scripts_scanner():
    """`int(os.environ.get("X", "d"))` is the defect shape. The `or` form is the
    fix, and it was already sitting at run_medium.py:212 with a comment reading
    "Recorded trap: defaults differ by arrival path" — someone met this once and
    fixed ONE line. This pin is so the next person cannot.

    ⚠ Counts the files scanned as well as the violations: a glob that silently
    matched nothing would pass while checking nothing."""
    scanned, offenders, doubled = 0, [], []
    for path in sorted((ROOT / "scripts" / "scanner").glob("*.py")):
        if path.name.startswith("test_"):
            continue
        scanned += 1
        src = path.read_text(encoding="utf-8")
        for m in _TWO_ARG.finditer(src):
            offenders.append(f"{path.name}:{src[:m.start()].count(chr(10)) + 1}")
        for m in _DOUBLE_OR.finditer(src):
            doubled.append(f"{path.name}:{src[:m.start()].count(chr(10)) + 1}  {m.group(0)}")

    assert scanned >= 5, f"only {scanned} scanner modules scanned — the glob is wrong"
    assert not doubled, (
        "duplicated `or \"lit\" or \"lit\"` found — a mechanical sweep re-applied the "
        "guard to a line that already had one. Collapse to a single `or`:\n  "
        + "\n  ".join(doubled))
    assert not offenders, (
        "two-argument numeric env reads found — these crash on a `schedule` trigger, "
        "where GitHub sets workflow inputs PRESENT AND EMPTY. Use "
        '`int(os.environ.get("X") or "d")`:\n  ' + "\n  ".join(offenders))


def test_the_pin_regex_actually_matches_the_defect_shape():
    """A pin whose regex matches nothing is decoration. Prove it fires on the exact
    line that took production down, and not on the fixed form."""
    assert _TWO_ARG.search('PATIENT_BAN_COOLDOWN_S = int(os.environ.get("PATIENT_BAN_COOLDOWN_S", "1800"))')
    assert _TWO_ARG.search('X = int(\n    os.environ.get("X", "2"))'), "multi-line form must match too"
    assert _TWO_ARG.search('Y = float(os.environ.get("Y", "1.5"))')
    assert not _TWO_ARG.search('PATIENT_BAN_COOLDOWN_S = int(os.environ.get("PATIENT_BAN_COOLDOWN_S") or "1800")')
    # and the near-miss regex must fire on the artifact and not on the good form
    assert _DOUBLE_OR.search('float(os.environ.get("WAF_PROBE_PACING_S") or "5" or "5")')
    assert not _DOUBLE_OR.search('float(os.environ.get("WAF_PROBE_PACING_S") or "5")')
    assert not _DOUBLE_OR.search('x = a or "5" or "7"'), "different literals are a real fallback chain, not an artifact"
    assert not _TWO_ARG.search('Z = os.environ.get("Z", "keep")'), \
        "a non-numeric two-arg get is fine — '' is a usable string default"


def test_the_workflow_still_passes_inputs_straight_through():
    """⚠ The fix is RUNNER-SIDE on purpose, and this records why: a `|| '1800'`
    added in the YAML would paper over the class behind one more default the runner
    cannot see. If someone later 'fixes' the workflow instead, this test tells them
    the runner-side guard is the contract — it does not fail, it documents."""
    keys = _input_env_keys()
    assert "PATIENT_BAN_COOLDOWN_S" in keys, (
        "PATIENT_BAN_COOLDOWN_S is no longer fed from a workflow input. If that is "
        "deliberate, this test should be updated in the same change that did it.")
