#!/usr/bin/env python3
"""The invariants are themselves testable — relay 247. 2026-09-17.

⛔ THE INVARIANT FILE IS A CONTROL THAT RUNS AGAINST PRODUCTION WITH A
SERVICE-ROLE CREDENTIAL. Three things have to hold, and none of them can be a
promise in a docstring:

  1. every invariant FIRES on the shape its bug produced, and STAYS SILENT on the
     good shape (an invariant that cannot fail is a comment);
  2. every query is READ-ONLY;
  3. the summary line ruling 21 depends on is actually printed — a job that ran
     nothing must fail, not pass.

`--selftest` proves (1) with fixtures. This file pins (2) and (3) structurally,
and re-runs (1) through pytest so lane 1 carries it too.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner"))

import premerge_invariants as pi  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "premerge_invariants.py"), encoding="utf-8").read()

ANSI_RAW = ("[+] The site \x1b[1;94mhttps://commandcommcentral.com/\x1b[0m is behind "
            "\x1b[1;96mFortiWeb (Fortinet)\x1b[0m WAF.\n")
EMPTY_ENV = json.dumps({"schema": 1, "collected_at": "2026-09-03T20:14:56Z",
                        "hostname": "commandcommcentral.com"})
FULL_ENV = json.dumps({"schema": 1, "hostname": "commandcommcentral.com",
                       "set_cookie_names": ["cookiesession1"],
                       "headers": {"server": "nginx"}, "cert": "CN=*.x"})

# wafw00f output, by what the tool prints. These decide I3's POPULATION (ruling 23).
W_VERDICT = ("[+] The site https://commandcommcentral.com/ is behind "
             "FortiWeb (Fortinet) WAF.\n")
W_NOWAF = "[-] No WAF detected by the generic detection\n"
W_DOWN = "[*] The site https://ftp.sciimage.com/ appears to be down.\n"


def _host(aid, envelope, raw=W_VERDICT):
    return {"asset_id": aid, "envelope": envelope, "wafw00f_raw": raw}


# ═══════════════════════════════════════════════════════════════════════════
# ⛔ READ-ONLY. This is the one that matters most.
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name", ["Q_I1", "Q_I2", "Q_I3", "Q_I4"])
def test_every_query_is_read_only(name):
    """⛔ A SERVICE-ROLE CREDENTIAL RUNS THESE AGAINST PRODUCTION ON EVERY PR.
    A mutating statement here would not be a failing gate, it would be a gate that
    changes the thing it is measuring."""
    q = " ".join(getattr(pi, name).split()).lower()
    assert q.startswith(("select", "with")), f"{name} does not start with SELECT/WITH"
    for verb in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate ",
                 "grant ", "create "):
        assert verb not in q, f"{name} contains {verb!r}"


def test_the_live_path_never_opens_a_write_transaction():
    """autocommit=True on a read-only connection: no BEGIN, nothing to commit, and
    no half-open transaction left behind if the gate is cancelled mid-run."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    body = ast.get_source_segment(SRC, fn)
    assert "autocommit = True" in body
    assert ".commit()" not in body and "execute(\"insert" not in body.lower()


def test_no_module_writes_anywhere_in_the_file():
    """Not just the four named queries — ANY mutating SQL literal in this file."""
    bad = []
    for n in ast.walk(ast.parse(SRC)):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            s = " ".join(n.value.split()).lower()
            if re.match(r"^(insert|update|delete|drop|alter|truncate)\s+\w", s):
                bad.append((n.lineno, s[:60]))
    assert not bad, f"mutating SQL in a read-only control: {bad}"


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ every invariant FIRES and STAYS SILENT
# ═══════════════════════════════════════════════════════════════════════════

def test_i1_fires_on_the_persist_fold_shape():
    """18 of 18 heavy runs wrote the raw and not the parsed verdict."""
    assert len(pi.i1_violations(
        [{"asset_id": "x", "scan_run_id": "a", "has_raw": True, "has_parsed": False}])) == 1


def test_i1_is_silent_on_the_sftp_pair():
    """⚠ THE REASON IT IS AN IMPLICATION. ftp.sciimage.com has no HTTPS surface, so
    a heavy there has NEITHER artifact. 'has both' would fail forever on them and
    the gate would be switched off — the flaky-gate failure mode."""
    assert pi.i1_violations(
        [{"asset_id": "ftp.sciimage.com", "scan_run_id": "b",
          "has_raw": False, "has_parsed": False}]) == []


def test_i2_fires_when_a_named_vendor_is_stored_as_generic():
    v = pi.i2_laundered([{"asset_id": "x", "raw": ANSI_RAW, "stored_kind": "generic"}])
    assert len(v) == 1 and v[0]["raw_says"] == "fortiweb"


def test_i2_is_silent_on_a_genuine_negative():
    """'no WAF found' stored as null is a correct verdict, not laundering."""
    assert pi.i2_laundered([{"asset_id": "x", "stored_kind": None,
                             "raw": "[-] No WAF detected by the generic detection\n"}]) == []


def test_i2_uses_the_scanners_own_parser_not_a_copy():
    """⚠ A second copy of the wafw00f regexes would be a third home for the defect
    family this file exists to catch — ruling 8 (FOLD, not register-a-pair)."""
    assert "_medium._classify_wafw00f_output" in SRC
    # ⚠ THIS ASSERT WAS FIRST WRITTEN AS `"is behind" not in SRC` AND IT FAILED ON A
    # CORRECT TREE — the selftest fixture holds the PRODUCTION wafw00f bytes, which
    # contain "is behind" verbatim. A guard that can be tripped by a fixture is the
    # same mistake as one tripped by a comment (the 233 nikto grep, the order pin
    # that matched a `def`). Check for a REGEX CALL over the wafw00f signature, not
    # for the words appearing anywhere in the file.
    copied = []
    for n in ast.walk(ast.parse(SRC)):
        if isinstance(n, ast.Call) and getattr(getattr(n.func, "value", None), "id", "") == "re":
            s = ast.unparse(n)
            if "is behind" in s or "seems to be behind" in s:
                copied.append((n.lineno, s[:70]))
    assert not copied, f"the wafw00f signature regex has been re-implemented here: {copied}"
    assert pi.kind_from_raw(ANSI_RAW) == "fortiweb"


def test_i2_parser_does_not_leave_the_scanner_log_muted():
    """It borrows the parser, not its narration — and restores in a `finally`."""
    import run_medium as m
    before = m.log
    pi.kind_from_raw(ANSI_RAW)
    assert m.log is before


def test_i3_fires_at_the_measured_post_cutover_ratio():
    """5 of 11 full is what production actually did between 09-02 and 09-17 — with
    every host confirmed to have an HTTP surface in its own run, so the ratio is
    about the COLLECTOR and not about the population."""
    runs = ([_host(f"e{i}", EMPTY_ENV) for i in range(6)] +
            [_host(f"f{i}", FULL_ENV) for i in range(5)])
    r = pi.i3_empty_envelopes(runs)
    assert r["full_pct"] == 45 and r["ok"] is False


def test_i3_passes_at_the_pre_cutover_ratio():
    """130 of 130 full is what it did before. The floor sits between the two."""
    assert pi.i3_empty_envelopes(
        [_host(f"f{i}", FULL_ENV) for i in range(11)])["ok"] is True


def test_i3_tolerates_one_genuinely_banned_run_without_flapping():
    """⚠ A GATE THAT FLAPS GETS BYPASSED — the same failure as one that passes
    vacuously. 10 of 11 (91%) clears a 90% floor; 5 of 11 does not."""
    runs = [_host("e0", EMPTY_ENV)] + [_host(f"f{i}", FULL_ENV) for i in range(10)]
    assert pi.i3_empty_envelopes(runs)["ok"] is True


# ── ruling 23: the POPULATION, which is the half that was wrong ─────────────

def test_i3_is_silent_on_the_sftp_pair():
    """⛔ THE FAILURE premerge-gate #2 ACTUALLY PRODUCED — 80% of 10, naming
    ftp.sciimage.com and ftp.unimacgraphics.com. 443 is open on both and nothing
    HTTP is behind it, so an empty envelope is the TRUE answer and counting it made
    the invariant fail on healthy production. The POPULATION was wrong, not the
    fleet. With them excluded this reads 8/8."""
    runs = ([_host(f"f{i}", FULL_ENV) for i in range(8)] +
            [_host("ftp.sciimage.com", EMPTY_ENV, W_DOWN),
             _host("ftp.unimacgraphics.com", EMPTY_ENV, W_DOWN)])
    r = pi.i3_empty_envelopes(runs)
    assert r["total"] == 8 and r["full_pct"] == 100 and r["ok"] is True
    assert {e["asset_id"] for e in r["excluded"]} == {
        "ftp.sciimage.com", "ftp.unimacgraphics.com"}


def test_the_excluded_hosts_are_returned_not_silently_dropped():
    """An invariant that quietly narrows its own population until it passes is the
    vacuous-pass shape wearing a ratio. The exclusions are reported with reasons."""
    r = pi.i3_empty_envelopes(
        [_host(f"f{i}", FULL_ENV) for i in range(5)] +
        [_host("ftp.sciimage.com", EMPTY_ENV, W_DOWN)])
    assert len(r["excluded"]) == 1 and "no HTTP surface" in r["excluded"][0]["reason"]


def test_a_collapsed_population_FAILS_rather_than_passing():
    """⛔ THE OLD CODE RETURNED ok=True ON total==0. So a predicate bug that
    excluded every host would have read as a clean pass — "nothing to check" and
    "everything checked out" must never look the same."""
    r = pi.i3_empty_envelopes([_host("ftp.sciimage.com", EMPTY_ENV, W_DOWN)])
    assert r["ok"] is False and r["population_too_thin"] is True
    assert pi.i3_empty_envelopes([])["ok"] is False


def test_a_thin_but_FULL_population_still_fails():
    """⛔ MUTANT M3 (4.7, relay 259): `"ok": (not thin) and pct >= floor` →
    `"ok": pct >= floor`. It SURVIVED my tests, because every fixture that
    exercised the floor had pct=0 — an empty list, where `ok` is False with or
    without the floor wired in. A population of 3, all full, read GREEN.

    ⇒ THE FLOOR HAS TO BE TESTED WHERE IT IS THE ONLY THING FAILING. 100% full and
    below the floor: the ratio says perfect, the population says nothing was
    checked, and "nothing to check" must not read as "everything checked out"."""
    r = pi.i3_empty_envelopes([_host(f"f{i}", FULL_ENV) for i in range(3)])
    assert r["full_pct"] == 100, "the ratio alone would pass this"
    assert r["population_too_thin"] is True
    assert r["ok"] is False, (
        "a 3-host population reads GREEN — the floor is not wired to the verdict")


@pytest.mark.parametrize("full,empty,want_pct,want_ok", [
    (9, 1, 90, True),    # ⭐ EXACTLY the design point the docstring claims
    (8, 2, 80, False),   # one step below it
    (10, 0, 100, True),
])
def test_the_ninety_percent_boundary_is_where_the_docstring_says_it_is(
        full, empty, want_pct, want_ok):
    """⛔ MUTANT M6 (4.7): `pct >= floor_pct` → `pct > floor_pct`. SURVIVED — the
    docstring says 90% "passes with room for one genuinely banned run", i.e. 9 of
    10, and no fixture sat on that line. A claim in a docstring that no test
    touches is a comment about what someone intended."""
    runs = ([_host(f"f{i}", FULL_ENV) for i in range(full)] +
            [_host(f"e{i}", EMPTY_ENV) for i in range(empty)])
    r = pi.i3_empty_envelopes(runs)
    assert r["full_pct"] == want_pct
    assert r["ok"] is want_ok, (
        f"{full} full + {empty} empty = {want_pct}% against a "
        f"{r['floor_pct']}% floor -> expected ok={want_ok}")


def test_the_population_floor_is_below_todays_real_count():
    """Grounded, not chosen: the gate's first live run saw 10 hosts, 8 with a real
    HTTP surface. A floor above 8 would fail on healthy production."""
    assert pi.I3_MIN_POPULATION <= 8


@pytest.mark.parametrize("raw,expected", [
    (W_VERDICT, True),      # named vendor — definitely HTTP
    (W_NOWAF, True),        # "no WAF" is still a verdict: the tool reached the host
    (W_DOWN, False),        # ⭐ the SFTP pair
    (None, False), ("", False), ("   \n", False),
    ("Traceback (most recent call last):\n", False),   # tool died — not countable
])
def test_the_population_predicate_both_ways(raw, expected):
    assert pi.wafw00f_saw_http(raw) is expected


def test_the_population_predicate_is_imported_not_reimplemented():
    """⚠ `wafw00f_is_degraded` is the scanner's own shipped test for "did wafw00f
    produce a verdict". A second copy here would be one more home for a judgement
    that must not drift from what a live scan makes."""
    # ⚠ THIS GUARD TOOK THREE GOES, AND THE THIRD IS THE ONE WORTH KEEPING.
    #   v1  `"appears to be down" not in SRC`   — failed: the DOCSTRING explains it
    #   v2  same, docstrings excluded           — failed: the SELFTEST FIXTURE is
    #                                             that string, and a fixture is code
    #   v3  this                                — a FIXTURE holding the phrase is
    #                                             fine; a PREDICATE deciding on it
    #                                             is not. So check for a membership
    #                                             TEST, inside the function whose
    #                                             judgement is at issue.
    #
    # ⇒ "no copy of X" is not a text question. It is "does any code path DECIDE on
    #   X", and that is an operator, not a substring. Sixth prose-vs-checker
    #   instance this week, and the previous fix is forty lines above.
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "wafw00f_saw_http")
    body = ast.get_source_segment(SRC, fn)
    assert "_medium.wafw00f_is_degraded" in body, (
        "wafw00f_saw_http no longer delegates to the scanner's own predicate")
    decided_locally = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare) and any(
                isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
            src = ast.unparse(n)
            if any(k in src for k in ("appears to be down", "is behind",
                                      "No WAF detected", "[+] ")):
                decided_locally.append(src[:70])
    assert not decided_locally, (
        f"wafw00f_saw_http decides on wafw00f's output text itself instead of asking "
        f"the scanner: {decided_locally}")


def test_i3_no_longer_walks_asset_surface_for_port_443():
    """⚠ THE 443 WALK IS GONE, AND WITH IT A SECOND READER of the surface port
    shape that deliberately disagreed with demotion_writer.known_ports() about
    defaulting. One fewer footnote waiting to become a bug."""
    assert "jsonb_array_elements" not in pi.Q_I3
    assert "443" not in pi.Q_I3
    assert "wafw00f_raw" in pi.Q_I3, "the population source must come from the query"


@pytest.mark.parametrize("blob", [None, "not json", "[]", "{}", 42,
                                  json.dumps({"schema": 1}),
                                  json.dumps({"set_cookie_names": [], "headers": {}})])
def test_an_envelope_with_no_collected_field_is_empty(blob):
    """{} / [] / absent / unparseable all mean 'collected nothing'."""
    assert pi.envelope_is_empty(blob) is True


def test_i4_fires_on_an_unmarked_same_class_downgrade():
    assert len(pi.i4_unmarked_downgrades([{
        "asset_id": "api.commandcommcentral.com", "newest_envelope_empty": True,
        "prior_state": {"device_class": "waf", "confidence": "confirmed"}}])) == 1


def test_i4_is_silent_when_the_preserve_marker_is_present():
    """⚠ WHY THE MARKER AND NOT THE ROW'S ABSENCE: a preserve still EMITS the
    TRANSITION_DOWNGRADE audit row — that is how the streak accumulates without a
    migration. Only the marker distinguishes preserved from written."""
    assert pi.i4_unmarked_downgrades([{
        "asset_id": "api.commandcommcentral.com", "newest_envelope_empty": True,
        "prior_state": {"device_class": "waf", "confidence": "confirmed",
                        "preserve": {"reason": "EVIDENCE_AGED"}}}]) == []


def test_i4_ignores_a_downgrade_over_a_FULL_envelope():
    """A capable observation that saw weaker evidence SHOULD write. Not I4's business."""
    assert pi.i4_unmarked_downgrades([{
        "asset_id": "x", "newest_envelope_empty": False,
        "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]) == []


def test_i4_reads_prior_state_whether_it_arrives_as_jsonb_or_text():
    """psycopg returns jsonb as dict; some paths hand it back as a string."""
    ps = {"device_class": "waf", "confidence": "confirmed"}
    for form in (ps, json.dumps(ps)):
        assert len(pi.i4_unmarked_downgrades(
            [{"asset_id": "x", "newest_envelope_empty": True, "prior_state": form}])) == 1


# ═══════════════════════════════════════════════════════════════════════════
# ruling 21 — the summary line, and the selftest as the gate runs it
# ═══════════════════════════════════════════════════════════════════════════

def test_the_selftest_prints_the_summary_line_and_exits_zero():
    """⛔ RULING 21. The gate greps for this prefix. If the step dies early the line
    is absent and the job fails — which is the only cover for the class that killed
    lane 6 (a step that exited silently and read as a pass)."""
    r = subprocess.run([sys.executable, "-B",
                        os.path.join(HERE, "premerge_invariants.py"), "--selftest"],
                       capture_output=True, text=True, env={**os.environ,
                                                            "PYTHONDONTWRITEBYTECODE": "1"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert pi.SUMMARY_PREFIX in r.stdout
    assert "selftest PASS" in r.stdout


def test_the_live_path_also_prints_the_summary_line():
    """Structural: the same prefix on the live path, outside any conditional, so a
    FAILING gate still prints it — a missing line must mean 'the step died', never
    'the step failed'. Those need different responses."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    prints = [n for n in ast.walk(fn)
              if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "print"
              and "SUMMARY_PREFIX" in ast.unparse(n)]
    assert len(prints) == 1, "run_live must print the summary line exactly once"
    body_last = fn.body[-2:]
    assert any(any(p is c for c in ast.walk(stmt)) for stmt in body_last for p in prints), (
        "the summary print is no longer at the end of run_live — a mid-function "
        "return would skip it and the job would read as 'died' instead of 'failed'")


def test_no_argument_means_selftest_never_live():
    """⚠ Running it bare must not touch production. `--live` is opt-in, the same
    shape as device_class_runner's `--write`."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = ast.get_source_segment(SRC, fn)
    assert "if a.selftest or not a.live:" in body
