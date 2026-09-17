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
        [{"asset_id": "down-host", "envelope": EMPTY_ENV, "wafw00f_raw": W_DOWN,
          "wafw00f_present": True}])
    assert len(r["excluded"]) == 1
    assert r["excluded"][0]["reason"] == "wafw00f ran, no verdict"


@pytest.mark.parametrize("present,raw,want", [
    (True,  W_DOWN, "wafw00f ran, no verdict"),
    (True,  "[*] Checking https://x/\n", "wafw00f ran, no verdict"),
    (False, None, "no wafw00f artifact (tool did not run)"),
])
def test_the_two_exclusion_reasons_are_distinct(present, raw, want):
    """⛔ RELAY 263 READ 3. THREE of the four excluded Command hosts had NO wafw00f
    artifact at all, and the line printed "no verdict" over every one of them —
    conflating "we looked and could not tell" with "we did not look". The
    absence-vs-evidence-of-absence error, in the reporting, inside the file built to
    stop it. Two reasons now, and they are checked apart."""
    r = pi.i3_empty_envelopes(
        [_host(f"f{i}", FULL_ENV) for i in range(5)] +
        [{"asset_id": "x", "envelope": EMPTY_ENV, "wafw00f_raw": raw,
          "wafw00f_present": present}])
    assert r["excluded"][0]["reason"] == want


def test_the_third_exclusion_reason_is_dropped_as_impossible():
    """⚠ "not a heavy in window" was specified and CANNOT occur: Q_I3 already filters
    `intensity = 'heavy'` and the window. A reason that can never print is a comment
    pretending to be a branch, so it is absent — and its absence is asserted rather
    than left to be noticed."""
    q = " ".join(pi.Q_I3.split()).lower()
    assert "intensity = 'heavy'" in q and "interval" in q
    src = open(os.path.join(HERE, "premerge_invariants.py"), encoding="utf-8").read()
    assert "not a heavy in window" not in src.split("def i3_empty_envelopes")[1].split("def ")[0]


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
    """A capable observation that saw weaker evidence SHOULD write. Not I4's business.

    ⚠ SINCE R26 THIS IS A POPULATION QUESTION, NOT A PREDICATE ONE — so it is asked of
    `i4_scoped`, which EXCLUDES the row under a named, counted reason. It used to be a
    `continue` inside the predicate, and on Command that silent skip swallowed 15 of 15
    armed rows behind a PASS."""
    rows = [{"asset_id": "x", "newest_envelope": "{}", "newest_envelope_empty": False,
             "asset_basis": json.dumps({"signals": ["fortiweb_cookiesession1"]}),
             "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    s = pi.i4_scoped(rows)
    assert s["violations"] == [] and s["counted"] == []
    assert [e["reason"] for e in s["excluded"]] == [pi._I4_FULL_ENVELOPE]


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
    # ⚠ TWO now, and both are load-bearing: the REFUSED line on an unrecognised
    # project ref (ruling 264/5) and the four-count summary at the end. Both carry
    # the prefix, so the gate's grep cannot tell a refusal from a silent death —
    # which is the point: neither is a pass, and both must be visible.
    assert len(prints) == 2, (
        f"run_live prints the summary prefix {len(prints)}x; expected 2 — the "
        f"unrecognised-ref refusal and the final four-count line")
    body_last = fn.body[-3:]
    assert any(any(p is c for c in ast.walk(stmt)) for stmt in body_last for p in prints), (
        "no summary print near the end of run_live — a mid-function return would "
        "skip it and the job would read as 'died' instead of 'failed'")


def test_the_summary_line_carries_all_four_counts_or_none():
    """⛔ RULING 264/3. `3/4 held` is exactly the phrasing that lets INCONCLUSIVE read
    as fine, so that form is gone. Four counts or none."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    body = ast.get_source_segment(SRC, fn)
    # ⚠ COMMENTS STRIPPED. The first version of this assert searched the whole
    # function body for "/4 held" and found it in the COMMENT that explains why we
    # do NOT use that form. SEVENTH prose-vs-checker instance this week — and I
    # wrote it minutes after writing two comments about this exact class. The rule
    # is not "be careful with substrings"; it is that a check over a region
    # containing prose must strip the prose FIRST, every time, without deciding
    # whether this particular one needs it.
    code = "\n".join(l for l in body.split("\n") if not l.lstrip().startswith("#"))
    final = code.split("SUMMARY_PREFIX")[-1]
    for word in ("held", "inconclusive", "failed", "backlog"):
        assert word in final, f"the summary line omits {word!r}"
    assert "/4 held" not in code, "the N/4 form is back — it hides INCONCLUSIVE"


def test_exit_code_is_zero_unless_something_actually_FAILED():
    """Backlog and inconclusive never block. A gate that cannot go green is a gate
    people learn to bypass, and it arrived on day one."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    body = ast.get_source_segment(SRC, fn)
    assert "return 1 if tally[FAILED] else 0" in body


def test_no_argument_means_selftest_never_live():
    """⚠ Running it bare must not touch production. `--live` is opt-in, the same
    shape as device_class_runner's `--write`."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = ast.get_source_segment(SRC, fn)
    assert "if a.selftest or not a.live:" in body


# ═══════════════════════════════════════════════════════════════════════════
# R25 — armed vs backlog, the anchor, and the instance (relay 262/264)
# ═══════════════════════════════════════════════════════════════════════════

CMD_DSN = "postgresql://postgres:pw@db.hdygktppfvuspnumpfuq.supabase.co:5432/postgres"
PDX_POOL = ("postgresql://postgres.bxcvzpbmxsdtalyfanee:pw@"
            "aws-0-us-east-1.pooler.supabase.com:6543/postgres")


@pytest.mark.parametrize("dsn,want", [
    (CMD_DSN, "command"),
    (PDX_POOL, "prodex"),
    ("postgresql://postgres:pw@db.bxcvzpbmxsdtalyfanee.supabase.co:5432/postgres", "prodex"),
    ("postgresql://postgres.hdygktppfvuspnumpfuq:pw@aws-0-eu-west-1.pooler.supabase.com:6543/x",
     "command"),
])
def test_the_instance_comes_from_the_dsn_both_shapes(dsn, want):
    """⚠ FROM THE DSN, NOT `SUPABASE_URL` (ruling 264/5). Job 4 runs on SUPABASE_DSN
    and may not carry SUPABASE_URL at all; deriving the instance from a variable the
    job might not have is how a gate silently picks the wrong `since` column."""
    assert pi.instance_from_dsn(dsn) == want


@pytest.mark.parametrize("dsn", [
    "postgresql://postgres:pw@db.zzzzzzzzzzzzzzzzzzzz.supabase.co:5432/postgres",
    "postgresql://postgres@localhost:5432/postgres",
    "postgresql://postgres.notaref:pw@aws-0.pooler.supabase.com:6543/postgres",
    "not a dsn", "", None,
])
def test_an_unrecognised_ref_REFUSES_rather_than_guessing(dsn):
    """⛔ A guessed instance picks the wrong `since`, and a wrong `since` produces a
    verdict that LOOKS like a regression. Refusing is the only honest answer."""
    assert pi.instance_from_dsn(dsn) is None


def test_the_dsn_password_is_never_returned_or_logged():
    """It is handed a credential on every gate run."""
    secret = "postgresql://postgres:SUPERSECRET@db.hdygktppfvuspnumpfuq.supabase.co:5432/x"
    assert pi.instance_from_dsn(secret) == "command"
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "instance_from_dsn")
    body = ast.get_source_segment(SRC, fn)
    assert ".password" not in body, "instance_from_dsn reads the password"


def test_the_refusal_path_reads_host_and_user_and_NEVER_the_password():
    """⛔ THE FOURTH ATTEMPT AT THIS ONE ASSERT, AND THE FOURTH IS THE RULE.

        v1  split on "REFUSED", searched AFTER it — hostname/username are read
            BEFORE that word, so it searched the wrong half of its own subject
        v2  searched the right half — failed because the code comment there says
            "never the password", which the assert read as the password being used
        v3  stripped comment LINES — failed again: that comment is TRAILING, on the
            same line as the code
        v4  this — ask the AST whether `.password` is ACCESSED

    ⇒ THE GENERALISATION, and it is the story of this whole week: every guard that
      kept failing was a TEXT check over a region containing prose. Every guard that
      works asks the AST about an OPERATION. "Does any code path read the password"
      is an attribute access, not a substring — the same correction as signals_in,
      as the wafw00f-copy guard, and as the N/4 form."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    reads = {n.attr for n in ast.walk(fn)
             if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
             and n.value.id == "pr"}
    assert "hostname" in reads and "username" in reads, (
        f"the refusal does not report host/user — it reports {sorted(reads)}")
    assert "password" not in reads, "the refusal path READS the DSN password"
    # and the same question of instance_from_dsn itself
    fn2 = next(n for n in ast.walk(ast.parse(SRC))
               if isinstance(n, ast.FunctionDef) and n.name == "instance_from_dsn")
    reads2 = {n.attr for n in ast.walk(fn2)
              if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
              and n.value.id == "parts"}
    assert "password" not in reads2, "instance_from_dsn READS the DSN password"


@pytest.mark.parametrize("ts", [
    "2026-09-17T12:18:32.47312+00:00",      # ⭐ 5 digits — the real trap, twice met
    "2026-09-17T12:18:32.4+00:00",
    "2026-09-17T12:18:32.473120+00:00",
    "2026-09-17T12:18:32+00:00",
])
def test_iso_takes_one_to_six_fractional_digits(ts):
    """Postgres emits 1-6; `fromisoformat` on 3.10 accepts only 3 or 6 and RAISES on
    the rest. Pad — never hand-roll a timestamp parser."""
    assert pi.iso(ts) is not None


def test_armed_split_on_the_real_boundary():
    """⭐ REAL ROWS. f8cc3a3e (Command's I3 fix) is 2026-09-17T12:09:34Z. #3050 STARTED
    12:12:20Z -> armed. ftp.sciimage.com's newest heavy started 2026-09-06 -> backlog."""
    rows = [
        {"asset_id": "commandcommcentral.com", "started_at": "2026-09-17T12:12:20.1+00:00"},
        {"asset_id": "ftp.sciimage.com", "started_at": "2026-09-06T12:11:00+00:00"},
    ]
    armed, backlog = pi.armed_split(rows, "I3", "command")
    assert [r["asset_id"] for r in armed] == ["commandcommcentral.com"]
    assert [r["asset_id"] for r in backlog] == ["ftp.sciimage.com"]


def test_a_row_with_no_anchor_timestamp_is_BACKLOG_not_armed():
    """'Cannot show it ran the fixed code' is not 'did'."""
    armed, backlog = pi.armed_split([{"asset_id": "x", "started_at": None}], "I3", "command")
    assert armed == [] and len(backlog) == 1


def test_the_anchor_is_started_at_and_that_CHANGES_the_answer():
    """⛔ RULING 264/1, AND THE CASE IS REAL. bcbsma.commandcommcentral.com's heavy ran
    2026-09-15T12:00:41 → 12:41:01 — forty minutes. A run that BEGAN on the old code
    ran the old code, whatever it finished on. Under `completed_at` it would be ARMED,
    and a wrongly-armed row looks exactly like a regression."""
    straddle = [{"asset_id": "bcbsma", "started_at": "2026-09-17T12:00:41+00:00",
                 "completed_at": "2026-09-17T12:41:01+00:00"}]
    assert pi.armed_split(straddle, "I3", "command")[0] == []
    assert len(pi.armed_split(straddle, "I3", "command", anchor="completed_at")[0]) == 1
    assert pi.ANCHOR["I3"] == "started_at"


def test_moving_since_one_second_past_a_row_flips_it_to_backlog(monkeypatch):
    """⚠ THE MUTATION 4.7 ASKED FOR, as a test. A `since` one second later than a
    row's anchor must move that row out of the armed set — otherwise the constant is
    decorative and a wrong date would never be noticed."""
    row = [{"asset_id": "x", "started_at": "2026-09-17T12:12:20+00:00"}]
    assert len(pi.armed_split(row, "I3", "command")[0]) == 1
    bumped = dict(pi.SINCE)
    bumped["command"] = dict(pi.SINCE["command"], I3=("deadbeef", "2026-09-17T12:12:21+00:00"))
    monkeypatch.setattr(pi, "SINCE", bumped)
    armed, backlog = pi.armed_split(row, "I3", "command")
    assert armed == [] and len(backlog) == 1


def test_every_invariant_has_a_since_an_anchor_and_a_remedy_in_both_instances():
    assert set(pi.SINCE) == {"command", "prodex"}
    for inst in pi.SINCE:
        assert set(pi.SINCE[inst]) == {"I1", "I2", "I3", "I4"}
        for iid, (sha, when) in pi.SINCE[inst].items():
            assert len(sha) >= 7 and pi.iso(when) is not None
    assert set(pi.ANCHOR) == set(pi.BACKLOG_REMEDY) == {"I1", "I2", "I3", "I4"}


def test_the_two_instances_really_have_different_constants():
    """Both repos ship this file byte-identical, so a copy-paste that left one column
    equal to the other would be invisible — and would silently arm Prodex on
    Command's timeline."""
    for iid in ("I1", "I2", "I3", "I4"):
        assert pi.SINCE["command"][iid] != pi.SINCE["prodex"][iid]


def test_I4_is_anchored_on_its_own_audit_row_not_on_a_scan():
    """I4 is a fact about a CLASSIFY PASS. Anchoring it to a scan's start would arm
    it by something unrelated to when the classifier ran."""
    assert pi.ANCHOR["I4"] == "evaluated_at"
    # ⚠ AND MIND THE OFFSET. The SINCE values carry git's committer offset (-04:00),
    # so Command's I4 cut is 2026-09-17T12:06:14-04:00 = 16:06:14Z. My first version
    # of this row used 12:06:15+00:00 and was FOUR HOURS EARLY — the comparison is
    # correct (both datetimes are aware), but it is easy to misread by eye, and I did.
    rows = [{"asset_id": "x", "evaluated_at": "2026-09-17T16:06:15+00:00",
             "newest_envelope_empty": True, "prior_state": {"device_class": "waf",
                                                            "confidence": "confirmed"}}]
    assert len(pi.armed_split(rows, "I4", "command")[0]) == 1


# ══ i3_state — THE THREE-STATE DECISION, WHICH NOTHING TESTED UNTIL NOW ═══════
# ⛔ 4.7's mutant D (relay 266): the mapping from `population_too_thin` to the word
#   INCONCLUSIVE lived inside `run_live()`, which needs a DSN. `thin -> HELD` passed
#   all 92 tests AND the selftest: a one-host population printed PASS and the summary
#   read `inconclusive 0`. The gate would have been green on nothing — R25's own
#   vacuous-pass shape, sitting one function past where the tests stopped.
#   ⇒ The rule this is the third instance of: A DECISION ONLY A LIVE CREDENTIAL CAN
#     REACH IS A DECISION NOBODY CHECKS. Keep the verdict pure; call it from the DB path.

def _r3(full, empty, floor=90, minpop=pi.I3_MIN_POPULATION):
    env_full = json.dumps({"schema": 1, "headers": {"server": "nginx"},
                           "set_cookie_names": ["c"], "cert": "CN=x"})
    env_empty = json.dumps({"schema": 1, "hostname": "h"})
    w = "[-] No WAF detected by the generic detection\n"
    runs = ([{"asset_id": f"f{i}", "envelope": env_full, "wafw00f_raw": w} for i in range(full)] +
            [{"asset_id": f"e{i}", "envelope": env_empty, "wafw00f_raw": w} for i in range(empty)])
    return pi.i3_empty_envelopes(runs, floor_pct=floor, min_population=minpop)


def test_i3_state_thin_population_is_INCONCLUSIVE_even_at_100_percent():
    """THE mutant-D test. 3 hosts, every one of them full: the percentage is perfect
    and the answer is still not PASS, because 100% of three hosts is not evidence."""
    r = _r3(3, 0)
    assert r["full_pct"] == 100 and r["population_too_thin"] is True
    assert pi.i3_state(r) == pi.INCONCLUSIVE
    assert pi.i3_state(r) != pi.HELD


def test_i3_state_healthy_population_over_the_floor_is_PASS():
    r = _r3(9, 1)
    assert r["full_pct"] == 90 and r["population_too_thin"] is False
    assert pi.i3_state(r) == pi.HELD


def test_i3_state_healthy_population_under_the_floor_is_FAIL():
    r = _r3(8, 2)
    assert r["full_pct"] == 80
    assert pi.i3_state(r) == pi.FAILED


def test_i3_state_empty_population_is_INCONCLUSIVE_not_PASS():
    """`total == 0` used to return ok=True — a predicate bug that excluded every host
    read as a clean pass. It must reach the third word, not the first."""
    assert pi.i3_state(pi.i3_empty_envelopes([])) == pi.INCONCLUSIVE


def test_the_three_states_are_three_distinct_words_and_INCONCLUSIVE_is_not_PASS():
    assert len({pi.HELD, pi.FAILED, pi.INCONCLUSIVE}) == 3
    assert pi.INCONCLUSIVE == "INCONCLUSIVE" and pi.HELD == "PASS"


def test_run_live_uses_i3_state_rather_than_its_own_expression():
    """⛔ THE POINT OF THE EXTRACTION, PINNED — and asked of the AST, not of the text,
    because a text search for "INCONCLUSIVE if" hits this file's own prose (four
    guards died that way; see the password test below). `run_live` must CALL
    i3_state; if the ternary ever migrates back inline, the pure tests above stop
    covering the live path and stop saying so."""
    src = (pi.Path(pi.__file__).read_text())
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "i3_state" in calls, "run_live no longer calls i3_state"
    # and the decision is NOT re-made inline: no IfExp in run_live mentions the flag
    inline = [n for n in ast.walk(fn) if isinstance(n, ast.IfExp)
              for s in ast.walk(n)
              if isinstance(s, ast.Constant) and s.value == "population_too_thin"]
    assert inline == [], "the thin->state decision is inline again in run_live"


# ══ armed_split BOUNDARY AND INSTANCE COLUMN (4.7's surviving mutants A and F) ══

def test_a_row_exactly_AT_the_cut_second_is_armed():
    """⛔ Mutant A survived: `>= cut` -> `> cut` changed no test, because no fixture
    sat ON the cut. The docstring says at/after, so the boundary second is the spec."""
    at = [{"asset_id": "at-the-cut", "started_at": pi.SINCE["command"]["I3"][1]}]
    assert len(pi.armed_split(at, "I3", "command")[0]) == 1
    before = [{"asset_id": "one-before", "started_at": "2026-09-17T08:09:33-04:00"}]
    assert pi.armed_split(before, "I3", "command")[0] == []


def test_the_since_column_follows_the_instance_argument():
    """⛔ Mutant F survived: SINCE[instance] -> SINCE["command"] passed everything,
    because every fixture asked for command. The two columns differ by two seconds in
    production, so a single row placed between them separates them. This is the only
    check that catches a future column swap — and a swap means every armed/backlog
    verdict is computed against the other repo's history."""
    between = [{"asset_id": "between", "started_at": "2026-09-17T08:09:35-04:00"}]
    assert len(pi.armed_split(between, "I3", "command")[0]) == 1
    assert pi.armed_split(between, "I3", "prodex")[0] == []
    # same row, same call, different instance -> different answer. That is the property.
    assert (pi.armed_split(between, "I3", "command")[0]
            != pi.armed_split(between, "I3", "prodex")[0])


# ══ R26 — I4's POPULATION, FROM PRODUCTION ROWS ═══════════════════════════════
# The fixtures below are rows that exist: relay 271's Prodex reads and my own read of
# Command's armed set this turn. ⛔ The reason that matters most is the one nobody
# specified — `newest envelope is full` — because it fires on COMMAND 15 TIMES OUT OF
# 15, so v1's silent `continue` meant I4 printed "PASS 0 unmarked of 12 armed" having
# checked ZERO rows. A predicate that narrows its own input silently cannot report that
# it checked nothing; that is the third instance of this shape (I3's population, R27).

_FULL_ENV = json.dumps({"schema": 1, "hostname": "api.commandcommcentral.com",
                        "set_cookie_names": ["CCC", "cookiesession1"],
                        "headers": {"server": "Microsoft-IIS/10.0"},
                        "cert": {"issuer_o": "GoDaddy.com"}})
_EMPTY_ENV = json.dumps({"schema": 1, "hostname": "api.commandcommcentral.com",
                         "collected_at": "2026-09-03T20:14:56Z"})
# api.commandcommcentral.com's REAL stored basis (read from Command, this turn)
_CMD_BASIS = json.dumps({"signals": ["wafw00f_discovery_confidence",
                                     "fortiweb_cookiesession1",
                                     "cert_issuer_subject_pattern"]})
# demo-tour / azure-demo's REAL basis: the 2026-07-13 cloud-inherited seed
_PDX_BASIS = json.dumps({"signals": [], "inherited_at": "2026-07-13T21:13:42Z",
                         "surface_stale": False, "cloud_provider": "gcp",
                         "inherited_from": "cloud_provider",
                         "cloud_match_tier": "asn", "is_cloud_endpoint": False})


def _row4(**kw):
    r = {"asset_id": "api.commandcommcentral.com", "device_class": "waf",
         "confidence": "suspected", "newest_envelope": _EMPTY_ENV,
         "newest_envelope_empty": True, "asset_basis": _CMD_BASIS,
         "prior_state": {"device_class": "waf", "confidence": "confirmed"}}
    r.update(kw)
    return r


def test_i4_excludes_a_NULL_envelope_because_NULL_IS_NEVER_ASKED():
    """⛔ demo-tour.prodexlabs.com: ONE heavy (2026-07-11), ZERO stack_id_passive
    artifacts ever, so Q_I4's correlated subquery returns NULL. v1 ran
    envelope_is_empty(None) -> True and demanded a preserve marker for an envelope
    nobody ever collected — "not asked" read as "found nothing". Two of Prodex's I4
    FAIL rows were exactly this.

    ⚠ AND THE SAME NULL MEANS THE OPPOSITE IN I3: there, an ARMED heavy with no
    artifact is the collector failing to write, which IS the defect. Identical value,
    opposite meaning, which is why this is a named bucket and not a shared helper."""
    s = pi.i4_scoped([_row4(asset_id="demo-tour.prodexlabs.com", newest_envelope=None,
                            asset_basis=_PDX_BASIS)])
    assert s["counted"] == [] and s["violations"] == []
    assert [e["reason"] for e in s["excluded"]] == [pi._I4_NO_ENVELOPE]


def test_i4_excludes_an_empty_prior_basis_because_R5_WRITES_on_one():
    """Prodex's whole I4 red. Every positive prior there is the 2026-07-13
    cloud-inherited seed with `signals: []`; `apply_r5_confidence_rule` returns WRITE
    on an empty basis BY DESIGN (preserving would build a ratchet), so demanding the
    marker asks for a key the rule forbids."""
    s = pi.i4_scoped([_row4(asset_id="demo-tour.prodexlabs.com", asset_basis=_PDX_BASIS)])
    assert s["counted"] == []
    assert [e["reason"] for e in s["excluded"]] == [pi._I4_NO_BASIS]


def test_the_cloud_inherited_basis_really_yields_no_signals_through_the_imported_reader():
    """`signals_in` is IMPORTED from device_class_runner, not re-implemented — the
    function the 241 crash produced. The cloud-fallback blob is a DICT whose
    `signals` is `[]`; iterating the dict itself would yield its keys."""
    assert pi.signals_in.__module__ == "device_class_runner"
    assert pi.signals_in(_PDX_BASIS) == set()
    assert pi.signals_in(_CMD_BASIS) == {"wafw00f_discovery_confidence",
                                         "fortiweb_cookiesession1",
                                         "cert_issuer_subject_pattern"}


def test_i4_counts_one_violation_when_the_row_is_genuinely_in_the_population():
    s = pi.i4_scoped([_row4()])
    assert len(s["counted"]) == 1 and len(s["violations"]) == 1
    assert s["excluded"] == []


def test_i4_is_silent_on_that_same_row_once_it_carries_the_marker():
    marked = _row4(prior_state={"device_class": "waf", "confidence": "confirmed",
                                "preserve": {"reason": "EVIDENCE_AGED",
                                             "incapable_signals": ["fortiweb_cookiesession1"],
                                             "evidence_age_days": {"set_cookie_names": 57}}})
    s = pi.i4_scoped([marked])
    assert len(s["counted"]) == 1 and s["violations"] == []


def test_i4_prefers_the_basis_on_the_row_over_the_assets_blob():
    """The runner-turn change makes the row self-describing. ⚠ KEY-PRESENT-BUT-EMPTY
    IS NOT KEY-ABSENT (R12's two cap modes, which cut in opposite directions):
    `basis_signals: []` is the runner ANSWERING "empty"; an absent key is no answer
    and falls back to `assets`."""
    # key present and empty -> the row's answer wins over a non-empty assets blob
    r = _row4(prior_state={"device_class": "waf", "confidence": "confirmed",
                           "basis_signals": []})
    s = pi.i4_scoped([r])
    assert [e["reason"] for e in s["excluded"]] == [pi._I4_NO_BASIS]
    assert s["basis_source"] == {"row": 1, "assets": 0}
    # key present and non-empty, assets blob EMPTY -> still in the population
    r2 = _row4(asset_basis=_PDX_BASIS,
               prior_state={"device_class": "waf", "confidence": "confirmed",
                            "basis_signals": ["fortiweb_cookiesession1"]})
    s2 = pi.i4_scoped([r2])
    assert len(s2["counted"]) == 1 and s2["basis_source"] == {"row": 1, "assets": 0}
    # key absent -> assets, and the count says so (that count falling to zero is how
    # we will see the runner change land)
    s3 = pi.i4_scoped([_row4()])
    assert s3["basis_source"] == {"row": 0, "assets": 1}


def test_every_i4_exclusion_reason_is_reachable_and_distinct():
    """The rule I applied to I3's third reason, applied here: a branch that cannot
    execute is a comment pretending to be code. All three of these fire on production
    rows; 4.7's proposed fourth (`basis not recorded on the row`) cannot, because the
    assets fallback always answers and asset_id is an FK to assets."""
    rows = [_row4(newest_envelope=None),                      # NO_ENVELOPE
            _row4(newest_envelope=_FULL_ENV, newest_envelope_empty=False),  # FULL
            _row4(asset_basis=_PDX_BASIS),                    # NO_BASIS
            _row4()]                                          # counted
    s = pi.i4_scoped(rows)
    got = sorted(e["reason"] for e in s["excluded"])
    assert got == sorted([pi._I4_NO_ENVELOPE, pi._I4_FULL_ENVELOPE, pi._I4_NO_BASIS])
    assert len(set(got)) == 3 and len(s["counted"]) == 1


def test_the_full_envelope_reason_is_the_one_that_fires_on_every_command_row():
    """MEASURED, relay 272: all 15 of Command's armed same-class downgrade rows have a
    full envelope — because their preserves fire on 57-DAY-OLD observations while the
    newest heavy (2026-07-22) collected cookies, headers and a cert. So I4's population
    on Command is EMPTY, and under R27 that is INCONCLUSIVE, not PASS."""
    rows = [_row4(newest_envelope=_FULL_ENV, newest_envelope_empty=False) for _ in range(15)]
    s = pi.i4_scoped(rows)
    assert s["counted"] == [] and len(s["excluded"]) == 15
    assert {e["reason"] for e in s["excluded"]} == {pi._I4_FULL_ENVELOPE}
    assert pi.state_for(len(s["counted"]), not s["violations"],
                        pi.INVARIANT_FLOOR["I4"]) == pi.INCONCLUSIVE


# ══ R27 — ZERO CHECKED ROWS IS INCONCLUSIVE FOR EVERY INVARIANT ══════════════

def test_state_for_zero_armed_is_INCONCLUSIVE_whatever_ok_says():
    """Prodex printed `PASS I1 0 violation(s) of 0 armed run(s)`. Nothing was checked
    and the word was PASS."""
    assert pi.state_for(0, True, 1) == pi.INCONCLUSIVE
    assert pi.state_for(0, False, 1) == pi.INCONCLUSIVE


def test_state_for_one_armed_row_arms_I1_I2_I4():
    assert pi.state_for(1, True, 1) == pi.HELD
    assert pi.state_for(1, False, 1) == pi.FAILED


def test_state_for_keeps_I3s_ratio_floor():
    assert pi.state_for(4, True, pi.I3_MIN_POPULATION) == pi.INCONCLUSIVE
    assert pi.state_for(5, True, pi.I3_MIN_POPULATION) == pi.HELD
    assert pi.state_for(5, False, pi.I3_MIN_POPULATION) == pi.FAILED


def test_the_floor_table_covers_every_invariant_and_I3_defers_to_its_ratio():
    assert set(pi.INVARIANT_FLOOR) == {"I1", "I2", "I3", "I4"}
    assert pi.INVARIANT_FLOOR["I1"] == pi.INVARIANT_FLOOR["I2"] == pi.INVARIANT_FLOOR["I4"] == 1
    assert pi.INVARIANT_FLOOR["I3"] is None      # the ratio's own min_population governs


def test_i3_state_still_answers_through_state_for():
    """i3_state is now a thin call into state_for, so mutant D stays dead and I3's
    floor stays a ratio's floor rather than R27's any-row-arms-it."""
    thin = pi.i3_empty_envelopes([])
    assert pi.i3_state(thin) == pi.INCONCLUSIVE


def test_run_live_asks_state_for_for_all_four_invariants():
    """⛔ THE AST PIN, WIDENED. Mutant D survived because the verdict lived inside the
    DB-only path; three of the four invariants still decided inline (`FAILED if v else
    HELD`) after that fix, which is the same defect with a different invariant's name
    on it. Asked of the AST, not the text: a text search for `state_for` matches this
    docstring."""
    tree = ast.parse(pi.Path(pi.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    calls = [n for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id in _VERDICT_FNS]
    assert len(calls) >= 4, f"only {len(calls)} invariant verdicts go through state_for"
    # ...and no invariant re-decides inline any more. ⚠ THE FIRST VERSION OF THIS
    # ASSERTION WAS TOO WIDE: it flagged `return 1 if tally[FAILED] else 0`, the exit
    # code, which is not a verdict — the guard failed on a correct tree and would have
    # been "fixed" by deleting it. The verdict shape is specifically a state CONSTANT
    # as the ternary's value (`FAILED if v else HELD`); FAILED appearing in the TEST
    # (`if tally[FAILED]`) is a different sentence. Ask for the shape, not the word.
    def _is_state_name(node):
        return isinstance(node, ast.Name) and node.id in ("FAILED", "HELD", "INCONCLUSIVE")
    inline = [n for n in ast.walk(fn) if isinstance(n, ast.IfExp)
              and (_is_state_name(n.body) or _is_state_name(n.orelse))]
    assert inline == [], (f"an invariant's verdict is decided inline in run_live at "
                          f"line {inline[0].lineno if inline else '-'}")


# ══ 2b CANNOT REACH I4 — event_for IMPORTED, not re-implemented ══════════════

def test_2b_cannot_produce_a_row_in_I4s_population():
    """Relay 270 §1 leaned on this and nothing asserted it: a computed `unknown`
    against a positive prior IS a TRANSITION_DOWNGRADE, but the two classes DIFFER, so
    Q_I4's `prior_state->>'device_class' = d.device_class` filter drops it. Every row
    I4 ever sees therefore comes from R5's branch — one producer."""
    assert pi.event_for.__module__ == "device_class_runner"
    assert pi.event_for("waf", "confirmed", "unknown", "unknown") == "TRANSITION_DOWNGRADE"
    # ... and the classes differ, which is what the SQL filter tests
    assert "waf" != "unknown"
    # a same-class downgrade is only ever positive-class-both-sides with a rank drop
    assert pi.event_for("waf", "confirmed", "waf", "suspected") == "TRANSITION_DOWNGRADE"
    assert pi.event_for("unknown", "unknown", "waf", "confirmed") == "STAMP"
    assert pi.event_for("waf", "confirmed", "waf", "confirmed") is None
    assert "and d.prior_state->>'device_class' = d.device_class" in pi.Q_I4


def test_Q_I4_reads_the_prior_basis_and_stays_read_only():
    assert "asset_basis" in pi.Q_I4 and "device_class_evidence" in pi.Q_I4
    low = " ".join(pi.Q_I4.split()).lower()
    assert low.startswith("select")
    for verb in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate "):
        assert verb not in low


def test_i4_state_takes_the_SCOPED_result_not_the_fetched_rows():
    """⛔ 4.7's mutation style, turned on my own commit. Having extracted i3_state so
    no verdict lives where tests cannot reach, I wrote I4's as
    `state_for(len(s4["counted"]), …)` INSIDE run_live — and `len(armed)` there passes
    every test while printing PASS over an empty population. The operand choice IS
    part of the decision, so it moved inside the pure function."""
    rows = [_row4(newest_envelope=_FULL_ENV, newest_envelope_empty=False) for _ in range(15)]
    s = pi.i4_scoped(rows)
    assert len(s["excluded"]) == 15 and s["counted"] == []
    assert pi.i4_state(s) == pi.INCONCLUSIVE          # NOT pass, on 15 armed rows
    assert pi.i4_state(pi.i4_scoped([_row4()])) == pi.FAILED
    marked = _row4(prior_state={"device_class": "waf", "confidence": "confirmed",
                                "preserve": {"reason": "EVIDENCE_AGED"}})
    assert pi.i4_state(pi.i4_scoped([marked])) == pi.HELD


_VERDICT_FNS = ("state_for", "invariant_state", "i3_state", "i4_state")


def test_no_verdict_call_site_in_run_live_passes_any_arithmetic():
    """⛔ THE PIN THAT MUTANTS L AND R BOTH NEEDED, GENERALISED.

    L: I4's verdict was `state_for(len(s4["counted"]), …)` in run_live — swap the
       operand for `len(armed)` and every test passed while I4 printed PASS on zero.
    R: 4.7 then found I1's `state_for(len(armed), …)` still inline — `len(armed) + 1`
       passed 118 tests and the selftest, printing PASS on zero armed I1 rows: the
       exact Prodex line R27 exists to kill, inside the commit implementing R27.

    Two instances of one defect: the CALLER doing the arithmetic. So the pin is not
    "I4 calls i4_state" any more, it is: **no verdict call site in run_live may pass
    a len(), a BinOp or a Compare**. The population size and the ok/not-ok decision
    are the pure functions' business; run_live passes a scope and a name.
    ⚠ Asked of the AST, because the text of this very docstring contains `len(`."""
    tree = ast.parse(pi.Path(pi.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    offenders = []
    for call in ast.walk(fn):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id in _VERDICT_FNS):
            continue
        for arg in list(call.args) + [k.value for k in call.keywords]:
            for node in ast.walk(arg):
                if (isinstance(node, ast.BinOp) or isinstance(node, ast.Compare)
                        or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "len")):
                    offenders.append(f"line {call.lineno}: {ast.unparse(call)}")
    assert offenders == [], "run_live computes a verdict operand: " + "; ".join(offenders)


def test_all_four_invariants_take_their_verdict_from_a_pure_function():
    tree = ast.parse(pi.Path(pi.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    got = [n.func.id for n in ast.walk(fn)
           if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
           and n.func.id in _VERDICT_FNS]
    assert len(got) >= 4, f"only {len(got)} verdicts go through a pure function: {got}"


def test_i1_and_i2_scopes_are_pure_and_zero_armed_is_INCONCLUSIVE():
    """R's target, as a value test rather than a shape test: no rows in, no verdict
    out. Prodex's `PASS I1 0 violation(s) of 0 armed run(s)` is what this kills."""
    assert pi.invariant_state(pi.i1_scoped([]), "I1") == pi.INCONCLUSIVE
    assert pi.invariant_state(pi.i2_scoped([]), "I2") == pi.INCONCLUSIVE
    clean = [{"asset_id": "a", "scan_run_id": "s", "has_raw": True, "has_parsed": True}]
    assert pi.invariant_state(pi.i1_scoped(clean), "I1") == pi.HELD
    dirty = [{"asset_id": "a", "scan_run_id": "s", "has_raw": True, "has_parsed": False}]
    assert pi.invariant_state(pi.i1_scoped(dirty), "I1") == pi.FAILED
    assert pi.i1_scoped(dirty)["counted"] == dirty and len(pi.i1_scoped(dirty)["violations"]) == 1


def test_floor_for_resolves_I3s_ratio_floor_and_leaves_the_others_at_one():
    assert pi.floor_for("I3") == pi.I3_MIN_POPULATION
    assert pi.floor_for("I1") == pi.floor_for("I2") == pi.floor_for("I4") == 1


def test_run_live_gets_I4s_verdict_from_i4_state_and_does_no_arithmetic_itself():
    """The AST pin for the operand choice: run_live must not compute I4's population
    size. If `len(armed)` ever appears as an argument to a verdict call again, this
    fails — which is the only thing that would have caught mutant L."""
    tree = ast.parse(pi.Path(pi.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_live")
    verdict_calls = [n for n in ast.walk(fn)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id in ("state_for", "i3_state", "i4_state")]
    assert any(c.func.id == "i4_state" for c in verdict_calls), "I4's verdict is not i4_state's"
    # I1/I2 legitimately pass len(armed) — they have no exclusions. I4 must not.
    for c in verdict_calls:
        if c.func.id != "state_for":
            continue
        src = ast.unparse(c)
        assert "INVARIANT_FLOOR['I4']" not in src, f"I4 verdict computed inline: {src}"
