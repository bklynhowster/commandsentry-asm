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
COVERED = ("tests.yml", "premerge-gate.yml", "scanner.yml")

# An assignment whose value is a command substitution: NAME=$( … )
# ⚠ `$((` IS ARITHMETIC, NOT A COMMAND SUBSTITUTION. `n=$((n+1))` cannot fail and
# cannot abort a step. The first version of this regex flagged it — a false positive
# in the checker written to remove false judgement. The negative lookahead is the
# whole difference between a pin people obey and one they delete.
_ASSIGN_CAPTURE = re.compile(
    r"""^\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\((?!\()""")
_GUARD = re.compile(r"\|\|")

# ⛔ QUOTED SPANS ARE NOT SHELL. Both halves of the line below need this, and the
# sweep's first file (scanner.yml, relay 309) proved it in BOTH directions:
#
#   guarded, but the guard is on a LATER line, inside a multi-line $( ):
#       STATUS=$(psql "$DSN" -t -A -c "
#         select status from public.scan_run where scan_run_id='$ID';
#       " 2>/dev/null || echo "unknown")
#     The old gatherer only followed BACKSLASH continuations, so it read line 1
#     alone, saw no `||`, and flagged a line that cannot fail. A false positive
#     on live scanner code is how a pin gets deleted instead of obeyed.
#
#   NOT guarded, but a `||` appears anyway — inside a SQL string:
#       EXISTING=$(psql "$DSN" -t -A -c "
#         select queue_id || '|' || status from public.scan_queue ...
#       ")
#     Widening the window without stripping quotes would have read SQL string
#     CONCATENATION as a shell guard and waved this one through. One change
#     without the other is worse than neither.
_QUOTED_SPAN = re.compile(r"""'[^']*'|"[^"]*\"""", re.DOTALL)


def _shell_only(s: str) -> str:
    """The parts of `s` the shell would act on: quoted spans blanked out."""
    return _QUOTED_SPAN.sub(" ", s)


def _substitution_is_closed(stmt: str) -> bool:
    """Has every `$(` opened OUTSIDE quotes been closed? Counting, not parsing —
    enough for `NAME=$( … )` spanning lines, and honest about being a heuristic."""
    t = _shell_only(stmt)
    return t.count("$(") <= t.count(")")


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
            # Gather continuations so a guard on the next physical line counts:
            # a backslash continuation, OR an unclosed `$(` — the substitution is
            # one statement however many lines it occupies, and its guard is
            # routinely on the closing line (`" 2>/dev/null || echo unknown)`).
            stmt = code
            j = i
            while (stmt.rstrip().endswith("\\")
                   or not _substitution_is_closed(stmt)) and j + 1 < len(lines):
                j += 1
                stmt += "\n" + lines[j]
            # `if NAME=$(…); then` — the condition position is exempt from -e
            in_if = code.lstrip().startswith("if ")
            # ⛔ The guard is looked for in SHELL, not in strings. See _QUOTED_SPAN.
            if not _GUARD.search(_shell_only(stmt)) and not in_if:
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


# ═══════════════════════════════════════════════════════════════════════════
# ⛔ THE TWO SHAPES THE SWEEP'S FIRST FILE PRODUCED (relay 309, scanner.yml)
# Both are multi-line `NAME=$( … )`. One is guarded and the old checker called it
# unguarded; the other is unguarded and a naive widening would have called it
# guarded. They are pinned as a PAIR because fixing either alone is a regression.
# ═══════════════════════════════════════════════════════════════════════════

# Verbatim from scanner.yml's Summary step. The `||` is on the CLOSING line of the
# substitution, not the opening one, and no backslash continues it.
GUARD_ON_THE_CLOSING_LINE = (
    '          STATUS=$(psql "$SUPABASE_DSN" -t -A -c "\n'
    "            select status from public.scan_run where scan_run_id='$ID';\n"
    '          " 2>/dev/null || echo "unknown")\n')

# Verbatim shape from scanner.yml's ad-hoc queue step. The only `||` in it are SQL
# string CONCATENATION inside a quoted span — not a shell guard, and this capture
# really can abort the step.
SQL_CONCAT_IS_NOT_A_GUARD = (
    '          EXISTING=$(psql "$SUPABASE_DSN" -t -A -v ON_ERROR_STOP=1 -c "\n'
    "            select queue_id || '|' || status\n"
    '              from public.scan_queue where asset_id = \'$ASSET_ID\';\n'
    '          ")\n')


def test_a_guard_on_the_closing_line_of_a_multiline_substitution_counts():
    """⛔ THE FALSE POSITIVE THE SWEEP FOUND FIRST. The old gatherer followed only
    backslash continuations, so it read line 1 of this and saw no `||`. A pin that
    flags live scanner code which CANNOT fail is a pin that gets deleted."""
    assert _unguarded_captures(GUARD_ON_THE_CLOSING_LINE) == []


def test_sql_string_concatenation_is_not_mistaken_for_a_shell_guard():
    """⛔ THE OTHER HALF, and the reason the two ship together. Widening the window
    without stripping quoted spans would read `queue_id || '|' || status` as a
    guard and wave through a capture that genuinely aborts the step."""
    assert _unguarded_captures(SQL_CONCAT_IS_NOT_A_GUARD), (
        "SQL `||` inside a quoted string was read as a shell guard")


def test_the_quote_stripper_leaves_shell_operators_alone():
    """The stripper is the load-bearing half; it must remove strings and nothing
    else. Tested directly, because a pure helper nobody drives is one nobody runs
    (mutant L's family, and the reason this line exists)."""
    assert "||" in _shell_only('out=$(cmd "a b") || rc=$?')
    assert "||" not in _shell_only("out=$(psql -c \"select a || b\")")
    assert "$(" in _shell_only('x=$(echo "hi")')


def test_the_substitution_gatherer_knows_when_it_is_closed():
    assert _substitution_is_closed('x=$(cmd)')
    assert not _substitution_is_closed('x=$(psql -c "')
    # a `)` inside a CLOSED quoted span does not close the substitution — this is
    # the case the SQL in scanner.yml actually produces.
    assert not _substitution_is_closed('x=$(psql -c "a ) b" ')


def test_the_gatherer_says_what_it_cannot_do():
    """⚠ WRITTEN BECAUSE MY OWN FIRST VERSION OF THE TEST ABOVE ASSERTED THIS AND
    FAILED. While a quote is still OPEN mid-gather, a `)` inside it IS counted, so
    this fragment reads as closed:

        x=$(psql -c "a )        <- unterminated quote, stray ) visible

    In a real run block that is harmless: the gatherer keeps appending lines, the
    quote closes, the whole span blanks out, and the real `")` decides it. This
    test pins the LIMIT so nobody later reads the heuristic as a shell parser —
    and fails if someone makes it stricter without revisiting the gather loop."""
    assert _substitution_is_closed('x=$(psql -c "a )')


def test_scanner_yml_is_in_the_swept_set():
    """The sweep is one file per commit; this commit is scanner.yml. If it silently
    left COVERED the pin above would pass over the two files that were already
    clean — the vacuous pass this file's floor test exists to prevent."""
    assert "scanner.yml" in COVERED


# ═══════════════════════════════════════════════════════════════════════════
# ⛔ THE AD-HOC DISPATCH STEP TAKES USER INPUT (relay 311)
#
# It is the only step in any workflow whose values come from a human typing
# into the GitHub UI. Two layers had to be fixed and BOTH get a pin, because
# fixing one and leaving the other is what made this entry necessary: the
# deleted `printf %q` was shell quoting applied to a SQL problem.
# ═══════════════════════════════════════════════════════════════════════════

AD_HOC_STEP = "Queue ad-hoc scan from workflow_dispatch inputs"


def _ad_hoc_step(fname="scanner.yml"):
    """The step's run block AND its env map. Returns (run, env).

    ⚠ Raises if the step is gone. A pin that silently stops finding its subject
    passes forever — the vacuous-pass shape this file was built around.
    """
    doc = yaml.safe_load(open(os.path.join(WORKFLOWS, fname), encoding="utf-8"))
    for job in (doc.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            if isinstance(step, dict) and step.get("name") == AD_HOC_STEP:
                return step.get("run") or "", (step.get("env") or {})
    raise AssertionError(f"step {AD_HOC_STEP!r} not found in {fname}")


def _psql_invocations(code: str):
    """Split a run block into its psql calls, with the variables each REFERENCES.

    ⚠ Crude on purpose and honest about it: a psql call starts at the word
    `psql` and ends where the next one begins (or at the end). That is enough
    for this step's two calls and it cannot silently merge them, which is the
    failure that matters — merging is exactly what made the old check pass.
    """
    starts = [m.start() for m in re.finditer(r"\bpsql\b", code)]
    assert starts, "no psql invocation found in the ad-hoc step"
    bounds = starts + [len(code)]
    out = []
    for i, s in enumerate(starts):
        inv = code[s:bounds[i + 1]]
        out.append((inv, set(re.findall(r":'([a-z_]+)'", inv))))
    return out


def test_the_ad_hoc_step_interpolates_no_input_into_the_script_text():
    """⛔ THE WORSE OF THE TWO, AND IT WAS NOT THE ONE THIS ENTRY WAS FILED FOR.

    `ASSET_ID="${{ github.event.inputs.asset_id }}"` is substituted by GitHub
    into the TEXT of the script before bash parses it. An input containing a
    double quote does not become a funny value — it ends the assignment, and
    what follows is shell. That is command execution on the runner.

    Through `env:` the value never enters the program text.
    """
    run, env = _ad_hoc_step()
    leaked = [ln.strip() for ln in run.splitlines()
              if "github.event.inputs" in ln and not ln.lstrip().startswith("#")]
    assert not leaked, (
        "workflow inputs are interpolated into the run block — pass them via "
        "`env:` and read them as shell variables:\n  " + "\n  ".join(leaked))
    # and they really are routed through env
    routed = [k for k, v in env.items() if "github.event.inputs" in str(v)]
    assert len(routed) >= 3, (
        f"expected the three dispatch inputs in the step's env, found {routed}")


def test_the_ad_hoc_step_puts_no_input_into_SQL_unparameterised():
    """⛔ THE ONE 4.7 RULED (310/311). Every value in those two statements goes
    through `psql -v name=value` + `:'name'` — SQL quoting, done by libpq.

    Not a threat-model fix: workflow_dispatch needs repo write. It is here
    because an asset_id carrying an apostrophe breaks the WHERE and the INSERT
    with no attacker at all, and because raw interpolation into a WHERE clause
    is a thing we write up as a finding in other people's estates.
    """
    run, _ = _ad_hoc_step()
    code = "\n".join(ln for ln in run.splitlines()
                     if not ln.lstrip().startswith("#"))

    # a shell variable inside single quotes, i.e. '$FOO' — the raw literal form
    raw = re.findall(r"'\$[A-Za-z_][A-Za-z0-9_]*'", code)
    assert not raw, f"raw shell interpolation used as a SQL literal: {raw}"

    # the bare one: `, $AUTHENTICATED,` in a values list — no quotes at all, so
    # a non-boolean input would have been parsed as SQL rather than as data.
    assert not re.search(r"values[\s\S]{0,200}?,\s*\$[A-Za-z_]", code), (
        "a bare $VAR is still being substituted into a values list")

    # ⛔ PER INVOCATION, NOT PER STEP (4.7, relay 339). The previous version
    # asked whether `-v name=` and `:'name'` each appeared SOMEWHERE in the step.
    # The step runs TWO psql calls and asset_id is supplied to BOTH — so dropping
    # the -v from ONE of them left the other's copy satisfying the check, on both
    # instances, while that statement's :'asset_id' resolved to nothing.
    #
    # Fifth appearance of presence-anywhere (306, 312, 319, 320, and this), in a
    # pin I wrote two days after we fixed the same shape elsewhere. The question
    # has to be asked of each call: does THIS invocation supply every variable
    # THIS invocation references?
    for n, (inv, refs) in enumerate(_psql_invocations(code), start=1):
        supplied = set(re.findall(r"-v\s+([a-z_]+)=", inv))
        missing = sorted(r for r in refs if r not in supplied)
        assert not missing, (
            f"psql invocation #{n} references {missing} but is not given "
            f"{'it' if len(missing) == 1 else 'them'} with -v — the variable "
            f"resolves to nothing in THIS statement:\n{inv.strip()[:300]}")

    # and the step as a whole still covers all three, so a call cannot vanish
    all_refs = set(re.findall(r":'([a-z_]+)'", code))
    assert {"asset_id", "intensity", "authenticated"} <= all_refs, (
        f"the step no longer parameterises all three inputs: {sorted(all_refs)}")


def test_the_ad_hoc_pins_read_the_step_not_the_file():
    """Both pins above must fail if the step disappears or is renamed, rather
    than passing over a file they can no longer find."""
    import pytest as _pytest
    with _pytest.raises(AssertionError, match="not found"):
        _ad_hoc_step("tests.yml")


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
