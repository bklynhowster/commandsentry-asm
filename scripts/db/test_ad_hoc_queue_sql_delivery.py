#!/usr/bin/env python3
"""(relay 371) The ad-hoc queue step delivers its SQL to psql via STDIN — an
EXECUTABLE outcome test, not a shape pin.

⛔ WHAT BROKE. The step parameterised its SQL with psql variables (`:'asset_id'`)
but sent it with `psql -c "..."`. psql performs `:'var'` interpolation on input
read from a file/stdin, NOT on a -c string, so on the runner the literal
`:'asset_id'` reached the server and Scanner #1157 died with
"syntax error at or near ':'". The old pin (test_workflow_shell_guards.py) only
asserted the step TEXT contained `:'asset_id'` and `-v asset_id` — it never ran
the step, so it stayed GREEN while the step was dead. Sixth appearance of the
shape-not-outcome trap (306/312/317/319/320/339/341).

⛔ SO THIS TEST RUNS THE STEP. It extracts the real "Queue ad-hoc scan" run
block from scanner.yml, puts a stub `psql` on PATH that records argv + stdin,
executes the block with an apostrophe-bearing asset_id (the #1157 shape), and
asserts every SQL-bearing invocation delivered its SQL on STDIN via `-f -` — NOT
in a `-c` argument. A discrimination control (below) runs the SAME harness
against a `-c` step and asserts it would FAIL, proving the check reds on the bug.

No Postgres is needed or available: the defect is entirely in HOW psql is
invoked (argv vs stdin), which the stub observes directly. That psql then
interpolates `:'var'` from stdin is documented psql behaviour and was confirmed
in production by run df5beeca (the workaround dispatch that succeeded).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".." / ".github" / "workflows" / "scanner.yml"
STEP_NAME = "Queue ad-hoc scan from workflow_dispatch inputs"

# argv and stdin are base64-encoded per token so multi-line values (a -c SQL
# string carries embedded newlines) survive the log intact — otherwise a -c
# call's SQL would be silently truncated and the check could miss it.
_STUB = """#!/bin/bash
{
  echo "=== INVOCATION ==="
  for a in "$@"; do printf 'ARG:%s\\n' "$(printf '%s' "$a" | base64 | tr -d '\\n')"; done
  printf 'STDIN:%s\\n' "$(base64 | tr -d '\\n')"
} >> "$PSQL_LOG"
"""


def _step_run() -> str:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = [s for j in wf["jobs"].values() for s in (j.get("steps") or [])]
    step = [s for s in steps if s.get("name") == STEP_NAME]
    assert len(step) == 1, f"expected one {STEP_NAME!r} step, got {len(step)}"
    return step[0]["run"]


def _run_with_stub(script: str, asset_id: str):
    """Run `script` with a stub psql on PATH; return the parsed invocations."""
    d = Path(tempfile.mkdtemp())
    (d / "psql").write_text(_STUB)
    (d / "psql").chmod(0o755)
    log = d / "psql.log"
    env = {
        **os.environ,
        "PATH": f"{d}:{os.environ['PATH']}",
        "PSQL_LOG": str(log),
        "SUPABASE_DSN": "postgresql://stub",
        "INPUT_ASSET_ID": asset_id,
        "INPUT_INTENSITY": "light",
        "INPUT_AUTHENTICATED": "false",
        "STALE_RUN_HOURS": "8",
    }
    (d / "step.sh").write_text(script)
    r = subprocess.run(["bash", str(d / "step.sh")], env=env,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    raw = log.read_text() if log.exists() else ""
    shutil.rmtree(d, ignore_errors=True)
    import base64
    def _dec(b64: str) -> str:
        return base64.b64decode(b64).decode("utf-8", "replace") if b64 else ""
    invs = []
    for block in raw.split("=== INVOCATION ===")[1:]:
        argv, stdin = [], ""
        for ln in block.splitlines():
            if ln.startswith("ARG:"):
                argv.append(_dec(ln[4:]))
            elif ln.startswith("STDIN:"):
                stdin = _dec(ln[6:])
        invs.append({"argv": argv, "stdin": stdin})
    return invs, r


def _sql_bearing(inv) -> bool:
    """An invocation whose job is to run one of our parameterised statements."""
    return ":'asset_id'" in inv["stdin"] or any(":'asset_id'" in a for a in inv["argv"])


APOSTROPHE_ASSET = "o'reilly.example.com"


# ── the real step ────────────────────────────────────────────────────────────

def test_the_real_step_runs_and_calls_psql_twice():
    invs, r = _run_with_stub(_step_run(), APOSTROPHE_ASSET)
    assert r.returncode == 0, r.stderr
    assert len(invs) == 2, f"expected 2 psql calls (check + insert), got {len(invs)}"


def test_every_sql_bearing_call_delivers_via_stdin_not_dash_c():
    """⛔ THE OUTCOME. With -c the SQL rides in argv and stdin is empty; the fix
    puts it on stdin behind -f -. This is exactly what reds on the #1157 bug."""
    invs, _ = _run_with_stub(_step_run(), APOSTROPHE_ASSET)
    sql_calls = [i for i in invs if ":'asset_id'" in i["stdin"] or ":'asset_id'" in " ".join(i["argv"])]
    assert sql_calls, "no psql call carried the parameterised SQL at all"
    for i in sql_calls:
        assert ":'asset_id'" in i["stdin"], (
            "the parameterised SQL did not reach psql on STDIN — it is still in "
            f"argv (the -c bug):\nargv={i['argv']}")
        assert "-c" not in i["argv"], f"-c is still the SQL carrier: {i['argv']}"
        assert "-" in i["argv"] and "-f" in i["argv"], f"-f - not used: {i['argv']}"


def test_the_apostrophe_asset_id_is_passed_as_a_psql_var_verbatim():
    """The value goes through -v, so libpq quotes it — the apostrophe never
    touches the SQL text. Both calls that reference asset_id must supply it."""
    invs, _ = _run_with_stub(_step_run(), APOSTROPHE_ASSET)
    for i in invs:
        if ":'asset_id'" in i["stdin"]:
            assert f"asset_id={APOSTROPHE_ASSET}" in i["argv"], (
                f"asset_id not supplied verbatim via -v: {i['argv']}")


def test_the_insert_carries_all_three_inputs_on_its_own():
    invs, _ = _run_with_stub(_step_run(), APOSTROPHE_ASSET)
    ins = [i for i in invs if "insert into public.scan_queue" in i["stdin"]]
    assert len(ins) == 1, "expected exactly one INSERT invocation"
    supplied = {a.split("=", 1)[0] for a in ins[0]["argv"] if "=" in a and not a.startswith("ON_ERROR")}
    for v in ("asset_id", "intensity", "authenticated"):
        assert v in supplied, f"INSERT does not supply -v {v}: {ins[0]['argv']}"


# ── discrimination control: the check REDS on a -c step ──────────────────────

_DASH_C_STEP = r'''
ASSET_ID="$INPUT_ASSET_ID"
psql "$SUPABASE_DSN" -t -A -v ON_ERROR_STOP=1 \
  -v asset_id="$ASSET_ID" -c "
  select 1 from public.scan_queue where asset_id = :'asset_id';
"
'''


def test_the_harness_would_have_caught_the_dash_c_bug():
    """Proof this is an outcome test, not a shape pin: the SAME harness, run
    against the OLD -c form, shows the SQL in argv and NOT on stdin — the
    assertion in test_every_sql_bearing_call... would fail on it."""
    invs, r = _run_with_stub(_DASH_C_STEP, APOSTROPHE_ASSET)
    assert r.returncode == 0
    assert len(invs) == 1
    call = invs[0]
    # The defining symptom of the bug: the -c form carries SQL in argv, so it
    # never reaches psql's stdin. The real check above requires :'asset_id' ON
    # STDIN — run that requirement against this -c call and it FAILS, which is
    # exactly what would have red on Scanner #1157.
    assert "-c" in call["argv"], "control invalid — expected the -c form"
    assert ":'asset_id'" not in call["stdin"], (
        "the -c form leaves stdin empty of the SQL — so the outcome assertion "
        "'SQL on stdin' reds on it, proving this is not a shape pin")
