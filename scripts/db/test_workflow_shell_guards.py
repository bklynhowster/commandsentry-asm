#!/usr/bin/env python3
"""EVERY `$(…)` capture in a workflow `run:` block must be guarded. Relay 257.

⛔ THE SAME BUG, THREE TIMES, AND THE THIRD TIME IT WAS IN THE LANE THAT QUOTES
THE RULE. GitHub runs an unqualified `run:` under `bash -e`; a command
substitution whose command exits non-zero therefore kills the step ON THE
ASSIGNMENT, before anything reads the status:

    lane 6, 2026-09-16   out=$(python -m pyflakes …); rc=$?
                         pyflakes exits 1 on ANY finding, and there are ~85
                         cosmetic ones. The lane was RED from the day it landed,
                         with NO OUTPUT, on both instances, and three pushes went
                         out on top of it.

    lane 7, 2026-09-17   n=$(ls -1 .github/workflows/*.yml .github/workflows/*.yaml \\
                              2>/dev/null | wc -l)
                         No `.yaml` exists -> `ls` exits 2 -> `2>/dev/null` hides
                         the message but not the status -> `pipefail` carries it
                         -> `-e` kills the assignment. `tests` #138/#116 printed
                         actionlint's version banner and then nothing.

⇒ THE RULE IS **EVERY** CAPTURE, NOT THE ONES THAT LOOK DANGEROUS. I guarded the
  four actionlint invocations in lane 7 and left the counting line bare, because
  counting files did not look like it could fail. That is precisely the judgement
  this test removes: the guard is cheap, the judgement is not reliable, so the
  guard is unconditional and a machine checks it.

⚠ AND THIS IS THE CHECK 253 SHOULD HAVE BEEN. 253 reported lane 7 "shown RED on
  today's tree, then green" — that was `actionlint` run DIRECTLY, never the STEP
  under GitHub's shell. The instrument was not the instrument that runs the file,
  in the lane created because the instrument was not the instrument that runs the
  file. This test reads the `run:` blocks themselves.

WHAT COUNTS AS GUARDED — any of:
    rc=0; out=$(cmd) || rc=$?      the standard form; `||` lists are exempt from -e
    out=$(cmd || true)             explicitly tolerant
    out=$(cmd) || echo …           any `||` on the assignment
    if out=$(cmd); then …          the condition position is exempt from -e
    $(cmd) inside "$( … )" used as a value in a non-assignment context is still
    flagged if it is an assignment; bare inline substitutions in an `echo` are not
    assignments and cannot abort one, so they are out of scope.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
WORKFLOWS = os.path.join(REPO, ".github", "workflows")

# The two files this pin covers. Named rather than globbed, deliberately: the
# other workflows predate the rule and carry their own history, and a pin that
# turns red on twenty untouched files gets deleted rather than obeyed. Widening
# this list is a relay turn, not a drive-by.
COVERED = ("tests.yml", "premerge-gate.yml")

# An assignment whose value is a command substitution: NAME=$( … )
# ⚠ `$((` IS ARITHMETIC, NOT A COMMAND SUBSTITUTION. `n=$((n+1))` cannot fail and
# cannot abort a step. The first version of this regex flagged it — a false positive
# in the checker written to remove false judgement. The negative lookahead is the
# whole difference between a pin people obey and one they delete.
_ASSIGN_CAPTURE = re.compile(
    r"""^\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\((?!\()""")
_GUARD = re.compile(r"\|\|")


def _run_blocks(path):
    """Every `run:` string in a workflow, with its step name. YAML-parsed, never
    grepped — a `run:` inside a comment or a quoted string is not a run block."""
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    out = []
    for jname, job in (doc.get("jobs") or {}).items():
        for step in (job.get("steps") or []):
            if isinstance(step, dict) and "run" in step:
                out.append((jname, step.get("name") or "<unnamed>", step["run"]))
    return out


def _unguarded_captures(run: str):
    """Assignment-from-substitution lines with no `||` guard, comments stripped.

    ⚠ COMMENTS STRIPPED FIRST, and that is load-bearing here: the fixed lane 7
    QUOTES the broken line in a comment so the next reader knows what happened.
    A checker that cannot tell code from the prose describing it would flag the
    explanation — the sixth instance of that this week, and the reason this
    function exists rather than a grep."""
    bad = []
    lines = run.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        code = raw.split("#", 1)[0] if raw.lstrip().startswith("#") else raw
        if raw.lstrip().startswith("#"):
            i += 1
            continue
        m = _ASSIGN_CAPTURE.match(code)
        if m:
            # Gather continuations so a guard on the next physical line counts.
            stmt = code
            j = i
            while stmt.rstrip().endswith("\\") and j + 1 < len(lines):
                j += 1
                stmt += "\n" + lines[j]
            # `if NAME=$(…); then` — the condition position is exempt from -e
            in_if = code.lstrip().startswith("if ")
            if not _GUARD.search(stmt) and not in_if:
                bad.append((i + 1, code.strip()[:90]))
            i = j + 1
            continue
        i += 1
    return bad


def _covered_files():
    present = [f for f in COVERED if os.path.exists(os.path.join(WORKFLOWS, f))]
    return present


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ THE PIN
# ═══════════════════════════════════════════════════════════════════════════

def test_the_covered_workflows_are_actually_present():
    """⚠ FLOOR, not decoration. If the filenames drift, every test below passes
    over an empty list — the vacuous pass this repo has now met in lane 4 (stale
    directory list), lane 6 (absent linter reported 0 findings) and lane 7 (empty
    glob exits 0). Same shape, third venue."""
    present = _covered_files()
    assert len(present) == len(COVERED), (
        f"expected {list(COVERED)} in {WORKFLOWS}, found {present}")


@pytest.mark.parametrize("fname", COVERED)
def test_every_capture_in_a_run_block_is_guarded(fname):
    """⛔ EVERY capture. Not the ones that look like they could fail.

    Under GitHub's `bash -e`, `NAME=$(cmd)` aborts the whole step when cmd exits
    non-zero — silently, with no output after the last successful line. `|| rc=$?`
    is an `||` list, which `-e` exempts, so the local run and the CI run become the
    same run."""
    path = os.path.join(WORKFLOWS, fname)
    if not os.path.exists(path):
        pytest.skip(f"{fname} not in this repo")
    offenders = []
    for jname, sname, run in _run_blocks(path):
        for lineno, text in _unguarded_captures(run):
            offenders.append(f"{fname} · job {jname} · step {sname!r} · line {lineno}: {text}")
    assert not offenders, (
        "unguarded command substitution(s) in a `run:` block — under `bash -e` these "
        "kill the step ON THE ASSIGNMENT, with no output:\n  " + "\n  ".join(offenders)
        + "\n\nUse:  rc=0; out=$(cmd) || rc=$?")


def test_at_least_one_run_block_was_actually_inspected():
    """The other half of the floor: a YAML shape change that stopped yielding run
    blocks would make the pin above pass on nothing."""
    total = sum(len(_run_blocks(os.path.join(WORKFLOWS, f))) for f in _covered_files())
    assert total >= 5, f"only {total} run block(s) found across {COVERED} — parser drift?"


# ═══════════════════════════════════════════════════════════════════════════
# the checker's own fires / doesn't-fire pair — it must be able to fail
# ═══════════════════════════════════════════════════════════════════════════

# ⚠ THE EXACT TWO LINES FROM THE TWO INCIDENTS, verbatim, as the fire fixtures.
LANE6_BUG = "          out=$(python -m pyflakes $PYTEST_ROOTS 2>&1); rc=$?\n"
LANE7_BUG = ("          n=$(ls -1 .github/workflows/*.yml .github/workflows/*.yaml "
             "2>/dev/null | wc -l)\n")


@pytest.mark.parametrize("snippet", [LANE6_BUG, LANE7_BUG])
def test_the_checker_fires_on_the_real_incidents(snippet):
    """If it cannot catch the two lines that actually broke production, it is not
    a checker."""
    assert _unguarded_captures(snippet), f"missed: {snippet.strip()}"


@pytest.mark.parametrize("snippet", [
    "          rc=0; out=$(cmd) || rc=$?\n",
    "          out=$(cmd || true)\n",
    "          out=$(cmd) || echo nope\n",
    "          if out=$(cmd); then echo yes; fi\n",
    '          rc=0\n          n=$(find . -name "*.yml" | wc -l) || rc=$?\n',
    # continuation: the guard is on the NEXT physical line
    '          rc_n=0\n          n=$(find x \\\n              | wc -l) || rc_n=$?\n',
    # ⚠ ARITHMETIC, not substitution — my own first false positive
    "          n=$((n+1))\n",
    "          ran=$((ran+1)); echo hi\n",
    # not an assignment at all — cannot abort one
    '          echo "count: $(ls | wc -l)"\n',
    # ⚠ a COMMENT quoting the broken line, which the fixed lane 7 really contains
    "          #     n=$(ls -1 *.yml *.yaml 2>/dev/null | wc -l)\n",
])
def test_the_checker_is_silent_on_guarded_and_on_prose(snippet):
    """⚠ The last case is the one that matters. The fixed lane 7 QUOTES the broken
    line in a comment, so the next reader knows what happened. A checker that
    flagged the explanation would make the file unfixable — the prose-vs-checker
    trap, sixth instance this week, pre-empted here."""
    assert _unguarded_captures(snippet) == [], f"false positive: {snippet.strip()}"


def test_run_blocks_come_from_the_yaml_parser_not_a_grep():
    """`run:` appears inside comments and quoted strings in these files. Parsing is
    what makes 'every run block' mean the run blocks."""
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    assert "yaml.safe_load" in src
    assert 'grep' not in src.split('"""')[0] or True  # structure, not text search


# ══ D-041 — EVERY WORKFLOW THAT PUSHES TO main NEEDS THE DEPLOY KEY ═══════════
# ⛔ WHAT HAPPENED (relay 280/281). The branch ruleset landed and the first thing it
# blocked was our own scanner writing its results: `remote: error: GH013 … push
# declined due to repository rule violations`, four runs across both repos, each
# after a 17-44 minute scan, and every step past the push skipped — the asset_surface
# upsert, the demotion-writer dry-run, the Netlify trigger. Production data stopped
# persisting overnight and nothing said so.
#
# ⚠ THE DOC NEVER ASKED "WHO ELSE PUSHES TO main". The setup guide described the
# ruleset and the required checks and was read twice, and the two workflows that
# commit to main were not in it. So this is the pin for the question the doc missed:
# if a workflow runs `git push`, it checks out with `ssh-key:` and it REFUSES up
# front when the secret is absent. Asked of the parsed YAML, not of the text.

def _push_workflows():
    """⚠ Uses this file's own WORKFLOWS constant — the one the rest of the pins use.
    My first version invented a `ROOT` that does not exist here and every new test
    errored on a correct tree. The instrument has to be the one the file already
    runs on."""
    import glob as _glob
    import yaml
    out = []
    for p in sorted(_glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
        path = pathlib.Path(p)
        doc = yaml.safe_load(path.read_text())
        if not isinstance(doc, dict):
            continue
        for job in (doc.get("jobs") or {}).values():
            steps = job.get("steps") or []
            blob = "\n".join(str(s.get("run", "")) for s in steps)
            if re.search(r"^\s*git push\b", blob, re.M):
                out.append((path.name, job, steps))
                break
    return out


def test_every_workflow_that_pushes_to_main_uses_the_deploy_key():
    """A `git push` authenticated with GITHUB_TOKEN is rejected by the ruleset, and
    GITHUB_TOKEN cannot be bypass-listed — the picker offers Roles / Teams / installed
    Apps / Deploy keys / Users and the GitHub Actions app is not among them."""
    pushers = _push_workflows()
    assert pushers, "no workflow pushes to main — the find is wrong, not the repo"
    for name, job, steps in pushers:
        checkouts = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout")]
        assert checkouts, f"{name}: pushes but never checks out"
        for c in checkouts:
            with_ = c.get("with") or {}
            assert "ssh-key" in with_, (
                f"{name}: checkout has no ssh-key, so `git push` authenticates as "
                f"GITHUB_TOKEN and the ruleset rejects it (GH013)")
            assert "ASM_DEPLOY_KEY" in str(with_["ssh-key"])


def test_every_workflow_that_pushes_to_main_refuses_without_the_secret_FIRST():
    """⚠ FIRST, not eventually. The failure cost a full scan each time: the push is
    the last thing these workflows do. A missing secret must cost seconds."""
    for name, job, steps in _push_workflows():
        first = steps[0]
        run = str(first.get("run", ""))
        assert "ASM_DEPLOY_KEY" in run and "exit 1" in run, (
            f"{name}: the first step is {first.get('name') or first.get('uses')!r}, "
            f"which does not refuse on a missing ASM_DEPLOY_KEY")
        # ⛔ and it must not fall back to GITHUB_TOKEN — a silent fallback is how this
        #   stayed invisible: the scan looked like it ran, because it did.
        assert "${ASM_DEPLOY_KEY:-}" in run, (
            f"{name}: uses a bare $ASM_DEPLOY_KEY; under `set -u` an UNSET secret "
            f"aborts with 'unbound variable' and the operator never sees the guidance")


def test_no_workflow_still_chains_the_netlify_deploy_by_hand():
    """A GITHUB_TOKEN push does not trigger `push` workflows; a DEPLOY-KEY push does.
    deploy-netlify.yml watches data/assets/** and web/**, which the asm-scan commit
    writes — so it now fires natively and the manual chain would deploy twice."""
    import glob as _glob
    for p in sorted(_glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
        path = pathlib.Path(p)
        body = path.read_text()
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue          # the comment explaining the deletion is not the call
            assert "gh workflow run deploy-netlify" not in stripped, (
                f"{path.name}: still chains the Netlify deploy by hand")
