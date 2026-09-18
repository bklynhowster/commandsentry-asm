#!/usr/bin/env python3
"""Production INVARIANTS — the regression suite for bugs that DO NOT CRASH.
Relay 246/247, ruling from Howie's "why do these keep happening". 2026-09-17.

⛔ WHY THIS FILE EXISTS, AND IT IS NOT "MORE TESTS".
Six production breaks in one week. A pre-merge dry-run gate catches exactly ONE of
them — b3a96e90, which raised an AttributeError 1m51s in. The other four exited
CLEAN, with plausible numbers, and were found days later by reading the data:

    the persist fold      heavy wrote the raw wafw00f artifact and not the parsed
                          one. 18 of 18 runs. rc=0, no error, verdict discarded.
    the ANSI parse        wafw00f colourised the vendor name, so 32 FortiWeb
                          identifications were stored as "generic". A positive
                          claim of a weaker fact — worse than absence.
    the collector order   nikto earned a FortiGate ban 35s before the passive
                          collector ran, which then collected nothing and wrote
                          a well-formed EMPTY envelope.
    the capability gap    a light scan's empty evidence counted as "we looked and
                          found nothing", so real labels were downgradable.

⇒ A GATE THAT ONLY ASKS "DID IT CRASH" GOES GREEN ON ALL FOUR. These are not
  exceptions; they are FACTS ABOUT PRODUCTION THAT STOPPED BEING TRUE. So the check
  has to be a fact about production, asserted on real data, every time.

⚠ EACH INVARIANT IS STATED SO THAT IT WOULD HAVE FAILED ON THE TREE THAT HAD THE
  BUG. That is the acceptance test for an invariant, and `--selftest` proves it
  both ways: every invariant is run against a fixture of the BAD shape (must fail)
  and the GOOD shape (must pass). An invariant that cannot fail is not an
  invariant, it is a comment — the same rule as a mutation-tested guard.

⚠ THE LIST GROWS BY ONE EVERY TIME A WRONG-ANSWER BUG IS FIXED. That is the point:
  the tests cannot see this class, because the fixtures are built from the shape
  the code expects. Production is the only place the real shape lives.

READ-ONLY. Every query is a SELECT. This runs against the live DB from the
pre-merge gate and must never write.

    python3 scripts/db/premerge_invariants.py --selftest    # no DB, fixtures both ways
    SUPABASE_DSN=... python3 scripts/db/premerge_invariants.py --live
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover — --selftest needs no DB driver
    psycopg = None

# The wafw00f parse, IMPORTED — never re-implemented. A second copy of those
# regexes would be a third home for the defect family this file exists to catch
# (4.7 ruling 8: FOLD, not register-a-pair).
import run_medium as _medium  # noqa: E402

# `signals_in` and `event_for` are IMPORTED, never re-implemented (4.7 ruling 8 / R26).
# `signals_in` is the one reader of `evidence`'s two shapes — the function the 241
# hotfix created precisely because a second isinstance check is a second home for the
# defect. `event_for` is the event taxonomy I4's population relies on; asserting a
# property of a COPY of it would assert nothing.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_class_runner as _dcr  # noqa: E402

signals_in = _dcr.signals_in
event_for = _dcr.event_for
signal_capable = _dcr.signal_capable          # R5's OWN capability test, imported
_SIG2OBS = None                                # built lazily from the same YAML R5 reads


def fresh_days() -> int:
    """The runner's own `evidence_freshness_days`, read from its own thresholds file —
    never a number copied into this file. A constant duplicated into the checker is a
    second source of truth that agrees only until someone edits one of them."""
    return int(_dcr.load_thresholds()["evidence_freshness_days"])


def sig2obs():
    """signal -> observations, from device_fingerprints.yaml, via the runner's own
    `signal_observation_map` — the same map R5 hands to `signal_capable`."""
    global _SIG2OBS
    if _SIG2OBS is None:
        _SIG2OBS = _dcr.signal_observation_map(_dcr.load_fingerprints())
    return _SIG2OBS

WINDOW_DAYS = 30
RECENT_HOURS = 24
PASSIVE_FIELDS = ("set_cookie_names", "headers", "cert")

# ══ R25 — AN INVARIANT IS A REGRESSION DETECTOR, NOT AN AUDIT (relay 262/264) ══
#
# ⛔ WHAT THE GATE'S FIRST REAL PR PROVED. premerge-gate #3/#2 went red on both
# repos and NOT ONE of the four failures was caused by the PR's code:
#
#   Command  I3 FAIL 83% of 6 — ftp.sciimage.com's newest heavy is 2026-09-06,
#            eleven days BEFORE the collector-first fix. A pre-fix empty envelope.
#   Prodex   I1 FAIL 15 · I2 FAIL 11 — the deferred Prodex backfill, i.e. debt the
#            gate correctly found on its first run and cannot be fixed by a PR.
#   Prodex   I4 FAIL 6 of 12 — a 24h window straddling 2c's landing.
#
# The invariants were written as statements about PRODUCTION. Read over 30 days of
# history they are statements about the BACKLOG, so they block every PR — including
# the ones that would clear the backlog — until the fleet is re-scanned end to end.
# ⇒ A GATE THAT CANNOT GO GREEN IS A GATE PEOPLE LEARN TO BYPASS, and it arrived on
#   day one. Same species as ruling 23 (I3's population) one level up.
#
# ⇒ Each invariant is ARMED only for rows at/after the fix IT guards. Older rows are
#   counted and printed as BACKLOG with a named remedy, and never block.
#
# ⚠ THE ANCHOR IS `started_at`, NOT `completed_at` (ruling 264/1). A run that BEGAN
# on the old code ran the old code, whatever it finished on. Not hypothetical:
# bcbsma.commandcommcentral.com's heavy ran 2026-09-15T12:00:41 → 12:41:01 — forty
# minutes, which straddles a commit easily. `completed_at` would arm a run that
# executed the pre-fix code, and a wrongly-armed row looks exactly like a regression.
#
# ⚠ DEFERRED, AND IT WOULD DELETE ALL OF THIS TIME ARITHMETIC: `scan_run` already has
# a `matrix_version_sha` column and it is NULL on every heavy. Populated from
# GITHUB_SHA at run start, `since` becomes a sha-MEMBERSHIP test with no timestamps
# at all. When that lands the timestamp path is DELETED, not kept as a fallback —
# two ways to decide the same thing is the second-reader defect (ruling 264/2).

# The instance each project ref belongs to. Both repos ship this file byte-identical
# (the push script's one-stamp check asserts it), so the column is chosen at RUNTIME.
_PROJECT_REFS = {
    "hdygktppfvuspnumpfuq": "command",
    "bxcvzpbmxsdtalyfanee": "prodex",
}

# ⚠ EVERY PAIR BELOW CAME FROM `git log -1 --format='%H %cI' <sha>` IN ITS OWN REPO.
# Not retyped from an entry, not inferred from a date. The commits are the fixes each
# invariant guards; a row from before its own fix cannot be a regression in it.
#
#   I1  the persist fold           Cmd ea74b16a  ·  Pdx 3353667
#   I2  the ANSI strip             Cmd 5d6703e8  ·  Pdx 675cb97
#   I3  collector runs first       Cmd f8cc3a3e  ·  Pdx 4ee5f4a
#   I4  the 2c evidence-shape fix  Cmd 2edf0770  ·  Pdx b45c5b4
#
# ⚠ THE VALUES CARRY GIT'S COMMITTER OFFSET (-04:00), NOT UTC. That is deliberate —
# it is the provenance, unaltered — but it is easy to misread by eye, and it caught
# me while writing the tests: a fixture row at 12:06:15+00:00 is FOUR HOURS BEFORE a
# cut at 12:06:14-04:00. The comparison itself is safe (both datetimes are aware).
# UTC equivalents, for reading only:
#   I1  22:05:40Z  ·  I2  23:34:01Z  ·  I3  12:09:34Z  ·  I4  16:06:14Z
SINCE = {
    "command": {
        "I1": ("ea74b16a", "2026-09-16T18:05:40-04:00"),
        "I2": ("5d6703e8", "2026-09-16T19:34:01-04:00"),
        "I3": ("f8cc3a3e", "2026-09-17T08:09:34-04:00"),
        "I4": ("2edf0770", "2026-09-17T12:06:14-04:00"),
    },
    "prodex": {
        "I1": ("3353667", "2026-09-16T18:05:42-04:00"),
        "I2": ("675cb97", "2026-09-16T19:34:02-04:00"),
        "I3": ("4ee5f4a", "2026-09-17T08:09:36-04:00"),
        "I4": ("b45c5b4", "2026-09-17T12:06:16-04:00"),
    },
}

# Which timestamp each invariant is armed by. I1-I3 are facts about a SCAN, so the
# anchor is when the scan started. I4 is a fact about a CLASSIFY PASS, so it is the
# audit row's own evaluated_at.
ANCHOR = {"I1": "started_at", "I2": "started_at", "I3": "started_at",
          "I4": "evaluated_at"}

# The remedy printed on a BACKLOG line — because a count with no next step is a
# number someone learns to scroll past. They do not clear the same way:
BACKLOG_REMEDY = {
    "I1": "backfill_stack_id_wafw00f.py --write            (only the backfill clears these)",
    "I2": "backfill_stack_id_wafw00f.py --write --reparse-generic",
    "I3": "clears itself as the sweep re-covers each host with a post-fix heavy",
    "I4": "self-clearing: the 24h window rolls past the fix within a day",
}

HELD, FAILED, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"

_FRAC = re.compile(r"\.(\d{1,6})")


def iso(ts):
    """Postgres emits 1-6 fractional digits; `datetime.fromisoformat` on 3.10 accepts
    ONLY 3 or 6 and raises on the rest. Met twice in this session's read scripts
    (`.47312`). Pad — never hand-roll a timestamp parser."""
    if ts is None:
        return None
    if not isinstance(ts, str):
        return ts                                   # psycopg already gave a datetime
    return datetime.fromisoformat(_FRAC.sub(lambda m: "." + m.group(1).ljust(6, "0"), ts))


def instance_from_dsn(dsn):
    """Which instance this credential points at, or None.

    ⚠ FROM THE DSN, NOT FROM `SUPABASE_URL` (ruling 264/5). Job 4 runs on
    `SUPABASE_DSN` and may not carry `SUPABASE_URL` at all — deriving the instance
    from a variable the job might not have is how a gate silently picks the wrong
    column. Both DSN shapes are in use:

        postgresql://postgres:…@db.<ref>.supabase.co:5432/postgres     direct
        postgresql://postgres.<ref>:…@aws-0-….pooler.supabase.com:…    pooler

    ⚠ The password is never read, never logged. urlsplit exposes hostname/username
    without it."""
    if not dsn:
        return None
    try:
        parts = urllib.parse.urlsplit(dsn)
    except Exception:
        return None
    host = (parts.hostname or "")
    if host.startswith("db.") and host.endswith(".supabase.co"):
        ref = host[len("db."):-len(".supabase.co")]
        if ref in _PROJECT_REFS:
            return _PROJECT_REFS[ref]
    user = (parts.username or "")
    if "." in user:
        ref = user.split(".", 1)[1]
        if ref in _PROJECT_REFS:
            return _PROJECT_REFS[ref]
    return None


def armed_split(rows, iid, instance, anchor=None):
    """(armed, backlog) — rows at/after this invariant's own fix, and rows before it.

    A row with no anchor timestamp is BACKLOG, not armed: we cannot show it ran the
    fixed code, and 'cannot show' is not 'did'."""
    field = anchor or ANCHOR[iid]
    cut = iso(SINCE[instance][iid][1])
    armed, backlog = [], []
    for r in rows:
        when = iso(r.get(field))
        (armed if (when is not None and when >= cut) else backlog).append(r)
    return armed, backlog
# ⚠ I3's population floor. The gate's first live run counted 10 hosts, of which
# 8 had a real HTTP surface. A population below this is a PREDICATE BUG, not a
# pass — see i3_empty_envelopes for why "nothing to check" must not look like
# "everything checked out".
I3_MIN_POPULATION = 5
SUMMARY_PREFIX = "premerge-invariants:"     # ruling 21 — the line the gate asserts


# ══ PURE DECISIONS — every invariant's verdict, with no DB in sight ════════
# The queries feed these; --selftest drives them directly with fixtures. Keeping
# the decision pure is what makes "would it have failed on the bad tree?" a test
# rather than a claim.

def i1_violations(runs) -> list:
    """I1 — THE PERSIST FOLD. A heavy that produced a raw `wafw00f` artifact must
    also have produced the parsed `stack_id_wafw00f`.

    ⚠ STATED AS AN IMPLICATION, NOT A CONJUNCTION. A host with no HTTP surface in
    that run legitimately has NEITHER artifact — `ftp.unimacgraphics.com`'s newest
    heavy is the read case (entry 263): the wafw00f artifact holds only
    `[*] Checking …` and no verdict. "has both" would fail on such hosts forever and
    the gate would be turned off. "has the parsed one IF it has the raw one" is the
    actual rule.

    ⛔ AND NOT "THE SFTP PAIR" — that phrase was false and this docstring was still
    carrying it. `ftp.sciimage.com` ANSWERS HTTP: its 09-06 heavy's wafw00f made four
    requests and got different responses by user-agent (entry 263, read from the DB).
    The pair was never a pair; the two hosts differ in the only way that matters here.
    Ruling 264 killed the claim in the fixtures and it survived in the prose one
    function away — a fact that has only ever been repeated has never been checked.

    BAD TREE (pre-217): 18 of 18 heavy runs -> 18 violations -> FAIL."""
    return [r for r in runs if r.get("has_raw") and not r.get("has_parsed")]


def i2_laundered(rows) -> list:
    """I2 — THE ANSI PARSE. No stored verdict may say generic/null when the RAW
    text it came from names a vendor.

    ⚠ NOT "at least one named vendor exists in the fleet" — that is a fact about
    the fleet, not about the parser, and it would pass on a broken parser the
    moment someone backfilled one row. This re-parses the raw with the SCANNER'S
    OWN parser and compares. It is exactly the bug or it is nothing.

    BAD TREE (pre-222): 32 FortiWeb identifications stored as 'generic' -> 32
    violations -> FAIL. Post-fix and post-backfill: 0."""
    out = []
    for r in rows:
        fresh = kind_from_raw(r.get("raw"))
        if fresh in (None, "generic"):
            continue                       # raw names no vendor — nothing to launder
        if r.get("stored_kind") in (None, "generic"):
            out.append({**r, "raw_says": fresh})
    return out


def kind_from_raw(raw):
    """The scanner's parser against a duck-typed ctx — the backfill's approach,
    and the only one that cannot drift from what a live scan decides."""
    if not raw or not str(raw).strip():
        return None
    import types
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    saved = getattr(_medium, "log", None)
    _medium.log = lambda *_a, **_k: None          # borrow the parser, not its narration
    try:
        _medium._classify_wafw00f_output(ctx, raw, 0)
    finally:
        if saved is not None:
            _medium.log = saved
    return ctx.waf_kind


def wafw00f_saw_http(raw) -> bool:
    """Did THIS RUN find an HTTP surface to collect from? (Ruling 23.)

    ⛔ WHY I3 NEEDED THIS AT ALL. Its first population was "hosts with 443 open",
    from asset_surface. The gate's first live run (premerge-gate #2) failed I3 at
    80% of 10 — and the two "failures" were `ftp.sciimage.com` and
    `ftp.unimacgraphics.com`: 443 open, nothing HTTP behind it, so an empty
    envelope is the TRUE answer there. The invariant's POPULATION was wrong, not
    production. Exactly the pair excluded from the 233 fixture, walking back in
    through a different door.

    ⇒ 443 OPEN IS NOT AN HTTP SURFACE. naabu sees the port, not the protocol.
      And "httpx OK" would be circular — httpx is one of the things the ban kills.

    ⚠ IMPORTED, NOT WRITTEN. `wafw00f_is_degraded` is the scanner's own shipped
    predicate for "did wafw00f produce a verdict", and it already excludes the
    down case by construction: a host that only prints "appears to be down" has no
    `[+] `, no "No WAF detected by the generic detection" and no "is behind", so it
    reads degraded. Ruling 23 said "does not report the site down"; this is that,
    expressed as the tool's own positive test — strictly stronger, because a run
    whose wafw00f died for some *other* reason is also excluded rather than
    counted. Flagged in the relay entry as a deliberate strengthening.

    wafw00f runs FIRST, on a fresh egress, before anything noisy — which is what
    makes its verdict the cleanest in-run evidence that there was something to
    collect from. rc=0 for the same reason verdict_from_raw passes it: the artifact
    exists, so the tool produced output."""
    if not raw or not str(raw).strip():
        return False
    try:
        degraded, _reason = _medium.wafw00f_is_degraded(str(raw), 0)
    except Exception:
        return False
    return not degraded


def envelope_is_empty(blob) -> bool:
    """A `stack_id_passive` envelope that carries none of the three collected
    fields. THE 09-03 SHAPE: {schema, collected_at, hostname} — well-formed,
    present, and empty, which is why nothing complained for two weeks."""
    if blob is None:
        return True
    if isinstance(blob, str):
        try:
            blob = json.loads(blob)
        except Exception:
            return True
    if not isinstance(blob, dict):
        return True
    return not any(blob.get(f) for f in PASSIVE_FIELDS)


def i3_empty_envelopes(runs, floor_pct: int = 90,
                       min_population: int = I3_MIN_POPULATION) -> dict:
    """I3 — THE COLLECTOR ORDER. Of the newest heavies on hosts THAT ANSWERED HTTP
    IN THAT SAME RUN, at least `floor_pct`% must carry a non-empty passive envelope.

    ⚠ A RATIO, NOT AN ABSOLUTE, and the floor is measured rather than chosen: the
    post-cutover reality was 5 of 11 full (45%) and the pre-cutover reality was
    130 of 130 (100%). 90% fails the first and passes the second with room for one
    genuinely banned run, so the gate reports a real regression instead of flapping
    on a single bad night. A gate that flaps gets bypassed, which is the same
    failure as a gate that passes vacuously.

    ⛔ AND THE POPULATION IS THE HALF THAT WAS WRONG (ruling 23). A host with no
    HTTP surface has nothing to collect, so its empty envelope is CORRECT and
    counting it makes the invariant fail on healthy production — which is what
    premerge-gate #2 did, at 80% of 10. Excluded hosts are
    RETURNED, not silently dropped: an invariant that quietly narrows its own
    population until it passes is the vacuous-pass shape wearing a ratio.

    ⚠ HENCE `min_population`. With `total == 0` the ratio is undefined and the old
    code returned ok=True — so a predicate bug that excluded everything would have
    read as a clean pass. A population below the floor is now a FAILURE with its
    own reason, because "nothing to check" and "everything checked out" must never
    look the same.

    BAD TREE (post-93e8acea, pre-233): 45% -> FAIL."""
    # ⚠ TWO REASONS, NOT ONE — and the difference is a fact, not a nicety.
    #   `no wafw00f artifact (tool did not run)`  geisinger, test.commandcommcentral,
    #                                             portal-tims: pre-08-29 plans that
    #                                             never invoked wafw00f at all
    #   `wafw00f ran, no verdict`                 ftp.unimacgraphics: the artifact is
    #                                             there and holds only "[*] Checking …"
    # ⚠ A THIRD REASON WAS SPECIFIED AND IS DROPPED AS IMPOSSIBLE HERE: "not a heavy
    #   in window" cannot occur, because Q_I3 already filters `intensity = 'heavy'`
    #   and the window. A reason that can never print is a comment pretending to be
    #   a branch. Said out loud rather than left in as reassurance.
    counted, excluded = [], []
    for r in runs:
        if wafw00f_saw_http(r.get("wafw00f_raw")):
            counted.append(r)
        else:
            excluded.append({
                "asset_id": r.get("asset_id"),
                "reason": ("wafw00f ran, no verdict" if r.get("wafw00f_present")
                           else "no wafw00f artifact (tool did not run)")})
    total = len(counted)
    empty = [r for r in counted if envelope_is_empty(r.get("envelope"))]
    pct = round(100 * (total - len(empty)) / total) if total else 0
    thin = total < min_population
    return {"total": total, "empty": empty, "excluded": excluded, "full_pct": pct,
            "ok": (not thin) and pct >= floor_pct,
            "floor_pct": floor_pct, "min_population": min_population,
            "population_too_thin": thin}


# ⛔ R27 — ZERO ARMED ROWS IS INCONCLUSIVE FOR EVERY INVARIANT, NOT JUST I3.
# Prodex's gate #3 printed `PASS I1 0 violation(s) of 0 armed run(s)`. Nothing was
# checked and the word was PASS — the same vacuous pass R25 was written against,
# wearing PASS's coat one level in. I3 had a floor because it is a RATIO; the other
# three have one now because "no rows" and "no violations" must never read alike.
#
#   I1 / I2 / I4  floor 1   any armed row arms it; zero is INCONCLUSIVE
#   I3            floor 5   a ratio needs a population (I3_MIN_POPULATION)
INVARIANT_FLOOR = {"I1": 1, "I2": 1, "I3": None, "I4": 1}   # None -> I3_MIN_POPULATION


def state_for(armed_n: int, ok: bool, floor: int) -> str:
    """The three-state verdict for ANY invariant — PURE, so the WORD is testable.

    ⛔ WHY THIS FUNCTION EXISTS AT ALL (4.7's mutation D, entry 266). This decision
    used to be an expression inside `run_live()`, which needs a live DSN, so neither
    pytest nor --selftest ever executed it. 4.7 mutated it to

        state = HELD if r3["population_too_thin"] else …

    and **every test and the whole selftest still passed.** Under that mutant a
    population of one host prints PASS, the summary reads `inconclusive 0`, and the
    gate is green on nothing — the exact vacuous pass R25 was written to name. The
    word INCONCLUSIVE was enforced by nothing but the fact that I had typed it.

    ⚠ The lesson is the file's own header turned on itself: keeping the decision pure
    is what makes "would it have failed?" a test. The decision had drifted one
    function downstream of where the tests stop, so the guard stopped covering it.
    A verdict that only a DB connection can reach is a verdict nobody checks.

    THIN WINS OVER `ok`, unconditionally. A thin population's percentage is not
    evidence either way — 100% of one host is not a pass, and 0% of one host is not
    a regression. R27 generalises that from I3's ratio to all four: `armed_n` is the
    number of rows THE CHECK ACTUALLY RAN ON, after every named exclusion — not the
    number of armed rows fetched. ⚠ THAT DISTINCTION IS THE WHOLE POINT and it is
    measured: Command has 15 armed same-class downgrade rows and I4 excludes all 15
    (full envelopes), so counting the fetched rows would print PASS on a population
    of zero — which is what it did."""
    if armed_n < floor:
        return INCONCLUSIVE
    return HELD if ok else FAILED


def i3_state(r3) -> str:
    """I3 in R27's terms. Kept as a named function because the AST pin asks whether
    `run_live` CALLS the decision rather than re-deciding inline, and because I3's
    floor is a ratio's floor rather than R27's 'any row arms it'."""
    return state_for(0 if r3["population_too_thin"] else r3["total"],
                     r3["ok"], r3["min_population"])


def floor_for(iid: str) -> int:
    """The floor for one invariant. I3's entry is None because its floor is a RATIO's
    minimum population, which lives with the ratio."""
    f = INVARIANT_FLOOR[iid]
    return I3_MIN_POPULATION if f is None else f


def i1_scoped(rows) -> dict:
    """I1's scope. No exclusions — every armed row is checked — but it is returned in
    the SAME shape as I4's so the verdict function is the same function.

    ⛔ WHY THIS TRIVIAL WRAPPER EXISTS: `run_live` used to compute I1's population
    size itself (`state_for(len(armed), not v, INVARIANT_FLOOR["I1"])`). 4.7 mutated
    that to `len(armed) + 1` and **118 tests and the selftest all passed**, printing
    PASS on zero armed I1 rows — the exact Prodex line R27 was written to kill,
    surviving inside the commit that implements R27. I had declared "the caller gets
    no arithmetic" 270 lines above and then not applied it here.
    ⇒ NO CALLER DOES ARITHMETIC FOR ANY OF THE FOUR. The scope is built by a pure
      function, the verdict is taken from a pure function, and `run_live` prints."""
    return {"counted": list(rows), "violations": i1_violations(rows)}


def i2_scoped(rows) -> dict:
    """I2's scope — same shape, same reason as i1_scoped."""
    return {"counted": list(rows), "violations": i2_laundered(rows)}


def invariant_state(scope, iid: str) -> str:
    """The verdict for a scoped invariant — PURE, and the ONLY place the operand
    choice is made. `counted` is what the check ran on; `violations` is what it
    found; the floor comes from the table. Every caller passes a scope and a name and
    computes nothing."""
    return state_for(len(scope["counted"]), not scope["violations"], floor_for(iid))


def i4_state(s4) -> str:
    """I4's verdict, from the SCOPED result — PURE.

    ⛔ WHY THIS EXISTS, AND IT IS MUTANT D ALL OVER AGAIN. Having extracted `i3_state`
    to stop `run_live` from deciding a verdict where no test could reach it, I then
    wrote I4's verdict as `state_for(len(s4["counted"]), …)` — INSIDE `run_live`. 4.7's
    mutation style applied to my own commit: change that argument to `len(armed)` and
    **every one of the 99 tests and the whole selftest still pass**, while I4 prints
    PASS over a population of zero. That is the precise defect this commit exists to
    remove, re-created by the fix for it, one function to the left.

    ⇒ THE RULE, THIRD STATEMENT AND NOW A HABIT: the CHOICE OF ARGUMENT is part of
      the decision. A pure function called with the wrong operand from an untestable
      caller is an untested decision wearing a tested function's name. So the operand
      choice moves inside the pure function too, and the caller gets no arithmetic."""
    return invariant_state(s4, "I4")


# ══ I4 v3 — R5's OWN AXIS, NOT A PROXY FOR IT (relay 277f, deviation stated) ══
#
# ⛔ WHAT v2 MEASURED AND WHY IT COULD NOT WORK. v2's population was "the newest heavy's
# passive envelope is EMPTY". Measured on Command this week: all 15 armed same-class
# downgrade rows were EXCLUDED as full-envelope — because api.commandcommcentral.com's
# newest heavy is 2026-07-22 and that envelope carries cookies, headers and a cert.
# The preserve fires because those observations are 57 days OLD. So v2 asked "was the
# envelope empty" while R5 asks "was the evidence COLLECTIBLE IN-WINDOW" — different
# axes, and I4's population was empty on the one instance with preserves to check.
#
# ⚠ DEVIATION FROM RULING 277f, WITH THE MEASUREMENT THAT DROVE IT. 4.7 ruled the
# population as "the newest HEAVY predates evidence_freshness_days". That is a proxy,
# and `_capability_rows` joins `scan_run` with NO intensity filter — a MEDIUM run can
# carry `stack_id_wafw00f` (api.commandcommcentral.com's newest is a medium, 2026-06-11).
# So a recent non-heavy run can make a signal capable while the newest heavy is old:
# R5 legitimately writes with no marker and the proxy would call it a violation. A gate
# that goes red on correct behaviour is the failure mode we have spent three days
# removing, so I4 v3 imports `signal_capable` and asks R5's own question with R5's own
# freshness constant. On today's three hosts BOTH give the same answer — the deviation
# changes nothing now and removes a class of false red later. Reject it and I will
# rebuild on the heavy-date proxy.
_I4_NO_BASIS = "no recorded prior basis (R5: write, not preserve)"
_I4_ALL_CAPABLE = "every prior signal was collectible in-window (R5: a real observation)"
_I4_NO_CURSOR = "capability unreadable (no DB cursor)"


def basis_signals_of_row(r) -> set:
    """The signals the asset's stored class rested on, for THIS row.

    Prefers `prior_state.basis_signals` — the runner-turn change that makes the row
    self-describing — and falls back to `assets.device_class_evidence` read at gate
    time. ⚠ KEY-PRESENT-BUT-EMPTY IS NOT KEY-ABSENT (R12's `_CAP_JSON_KEY_PRESENT`
    vs `_CAP_JSON_NONEMPTY`, the distinction that cut in opposite directions there):
    `basis_signals: []` is the runner SAYING the basis was empty, which is an answer;
    an absent key is no answer and sends us to `assets`.

    ⚠ THE FALLBACK IS A TIME-OF-CHECK READ. `assets.device_class_evidence` is the
    basis NOW; the row was evaluated up to 24h ago, and a `--write` pass rewrites
    that blob. 4.7 corrected me on the blast radius (271): `--write` is OFF on BOTH
    instances, so today the two are identical and the read is exact. The caveat is
    printed on the line anyway, because "exact today" is a property of the
    configuration, not of the code."""
    prior = _as_dict(r.get("prior_state"))
    if "basis_signals" in prior:
        return signals_in(prior.get("basis_signals"))
    return signals_in(r.get("asset_basis"))


def _as_dict(v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except Exception:
            return {}
    return v if isinstance(v, dict) else {}


def i4_scoped(rows, cur=None) -> dict:
    """I4's population and its NAMED exclusions (R26) — pure.

    ⛔ WHY EXCLUSIONS AND NOT `continue`. v1 skipped two shapes silently:
    a full envelope, and a NULL one. Measured on Command's live rows this turn:
    **15 of 15 armed same-class downgrade rows have a FULL envelope**, so the check
    ran on ZERO rows and printed `PASS I4 0 unmarked of 12 armed`. A pass over an
    empty population, announced with the count of the rows it had thrown away. Same
    species as I3's population (ruling 23) and R27's zero-armed — third time.

    The three reasons, each counted on the line:

      no passive envelope on record   NULL. demo-tour.prodexlabs.com's only heavy is
                                      2026-07-11 and it has never had a
                                      stack_id_passive artifact, so `newest_envelope`
                                      is NULL and `envelope_is_empty(None)` read it
                                      as "collected nothing". ⛔ NULL IS "NEVER
                                      ASKED". For I3 the same NULL on an ARMED heavy
                                      IS a defect (the collector should have written)
                                      — the identical value means opposite things in
                                      the two invariants, which is why it is a named
                                      bucket here rather than a shared helper.
      newest envelope is full         nothing was uncollected in that run, so R5 has
                                      nothing to preserve and no marker is owed.
      no recorded prior basis         R5's own documented WRITE path: an empty basis
                                      cannot be preserved (it would build a ratchet),
                                      so demanding a marker asks for a key the rule
                                      forbids. Every positive prior on Prodex is the
                                      2026-07-13 cloud-inherited seed with
                                      `signals: []` — the whole of its I4 red.

    ⚠ 4.7 NAMED A FOURTH — `basis not recorded on the row (pre-fix)` — AND IT CANNOT
    FIRE, so it is not here. With the `assets` fallback, an absent key is not an
    absent answer; and `device_class_dryrun.asset_id` is an FK to `assets`, so the
    asset is always readable. A branch that cannot execute is a comment pretending to
    be code (the same call I made on I3's third reason). What IS reported instead is
    where each basis came from — `basis from row` / `basis from assets (current)` —
    so the runner-turn migration is visible as those counts move.

    BAD TREE (pre-2c): api/edelivery/testapi.commandcommcentral.com, cookie and cert
    evidence 55-57d old, downgrade with no marker -> 3 violations -> FAIL."""
    counted, excluded = [], []
    src = {"row": 0, "assets": 0}
    for r in rows:
        if "basis_signals" in _as_dict(r.get("prior_state")):
            src["row"] += 1
        else:
            src["assets"] += 1
        basis = basis_signals_of_row(r)
        if not basis:
            excluded.append({"asset_id": r.get("asset_id"), "reason": _I4_NO_BASIS})
            continue
        # ⛔ R5's OWN QUESTION, ASKED WITH R5's OWN FUNCTION. `incapable_of` returns the
        #   prior signals that could NOT have been collected in-window. R5 preserves iff
        #   that set is non-empty — so a row with an empty set is one R5 was RIGHT to
        #   write, and asking it for a marker would fail the gate on correct behaviour.
        incapable = incapable_of(basis, r, cur)
        if incapable is None:
            excluded.append({"asset_id": r.get("asset_id"), "reason": _I4_NO_CURSOR})
            continue
        if not incapable:
            excluded.append({"asset_id": r.get("asset_id"), "reason": _I4_ALL_CAPABLE})
            continue
        r = dict(r, incapable_signals=sorted(incapable))
        counted.append(r)
    return {"counted": counted, "excluded": excluded,
            "violations": i4_unmarked_downgrades(counted),
            "basis_source": src}


def incapable_of(basis, row, cur):
    """Which of this row's prior-basis signals could NOT have been collected in-window.

    ⛔ IMPORTED, NEVER RE-IMPLEMENTED: `signal_capable` is R5's own predicate, handed the
    runner's own signal->observation map and the runner's own `evidence_freshness_days`.
    A copy of R5's capability logic living in the checker would agree with R5 until the
    day someone edited one of them — and this file exists because facts stop being true.

    Returns None when there is no cursor (fixtures, --selftest): the answer is then
    UNKNOWN, and unknown is an exclusion with a name, never a silent pass.

    ⚠ TIME OF CHECK. Capability is evaluated NOW; the row was evaluated up to 24h ago
    (I4's window), so a scan that landed in between can flip a signal from incapable to
    capable. That bounds the skew at one window and it is stated on the line, the same
    way the basis read is."""
    if cur is None:
        return None
    asset = row.get("asset_id")
    if not asset:
        return None
    try:
        m, days = sig2obs(), fresh_days()
        return {s for s in basis if not signal_capable(cur, asset, s, m, days)}
    except Exception as exc:                      # a capability read that fails is not a pass
        print(f"          · capability unreadable for {asset}: {exc}")
        return None


def i4_unmarked_downgrades(rows) -> list:
    """I4 — THE CAPABILITY GAP. A SAME-CLASS confidence downgrade written for an
    asset whose newest heavy collected an EMPTY envelope must carry the R5 preserve
    marker in `prior_state.preserve`.

    ⚠ WHY THE MARKER AND NOT THE ROW'S ABSENCE. A preserve still EMITS a
    TRANSITION_DOWNGRADE audit row every pass — that is how the streak accumulates
    without a migration. So "no downgrade row exists" cannot distinguish preserved
    from written; only the marker can. The marker is the field 2c added for exactly
    this audit trail, and this is the consumer that makes it load-bearing.

    ⚠ SCOPED TO SAME-CLASS (prior class == computed class). A move to `unknown` is
    2b's territory and has its own, untouched audit shape.

    BAD TREE (pre-2c): api/edelivery/testapi.commandcommcentral.com, whose cookie
    evidence is 55-57d old, downgrade with no marker -> 3 violations -> FAIL.

    ⛔ THE MARKER TEST ALONE, SINCE R26. The population questions — is there an
    envelope, is it empty, does the prior have a basis — belong to `i4_scoped`, which
    NAMES and COUNTS each exclusion. They used to be `continue`s in here, and that is
    how I4 came to print PASS over an empty population: a predicate that narrows its
    own input silently cannot tell you it checked nothing."""
    out = []
    for r in rows:
        prior = _as_dict(r.get("prior_state"))
        if not (prior.get("preserve") or {}).get("reason"):
            out.append(r)
    return out


# ══ THE QUERIES — read-only, bounded, one per invariant ════════════════════

Q_I1 = """
select r.scan_run_id::text as scan_run_id, r.asset_id, r.started_at, r.completed_at,
       exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f') as has_raw,
       exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f') as has_parsed
  from scan_run r
 where r.intensity = 'heavy'
   and r.completed_at > now() - interval '%s days'
 order by r.completed_at desc
 limit 100
"""

Q_I2 = """
select r.scan_run_id::text as scan_run_id, r.asset_id, r.started_at,
       (select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text)
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f' limit 1) as raw,
       (select a.content_jsonb->>'wafw00f_kind'
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f' limit 1) as stored_kind
  from scan_run r
 where r.completed_at > now() - interval '%s days'
   and exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f')
 order by r.completed_at desc
 limit 200
"""

# ⚠ THE POPULATION IS DECIDED IN PYTHON, FROM THE RUN'S OWN wafw00f OUTPUT —
# not in SQL from asset_surface. The previous version keyed on "443 open" via a
# jsonb walk over subdomains[].services[] and hosts[].services[], and it was wrong
# in fact: naabu sees the port, not the protocol. Ruling 23.
#
# ⇒ THE 443 WALK IS GONE, AND SO IS THE SECOND READER IT CREATED. It duplicated
#   demotion_writer.known_ports()'s traversal with deliberately different
#   defaulting, which was a footnote waiting to become a bug. One fewer home.
Q_I3 = """
select distinct on (r.asset_id)
       r.asset_id, r.scan_run_id::text as scan_run_id, r.started_at, r.completed_at,
       (select a.content_jsonb::text from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_passive'
         order by a.artifact_id desc limit 1) as envelope,
       (select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text)
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f'
         order by a.artifact_id desc limit 1) as wafw00f_raw,
       -- ⚠ SEPARATE FROM THE RAW, ON PURPOSE (ruling 264/4). A NULL raw cannot tell
       -- "the tool never ran" from "it ran and said nothing", and READ 3 in relay 263
       -- found THREE of four excluded hosts in the first class while the line printed
       -- the second. Absence vs evidence of absence, in the reporting, inside the file
       -- built to stop it.
       exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f')
         as wafw00f_present
  from scan_run r
 where r.intensity = 'heavy'
   and r.completed_at > now() - interval '%s days'
 order by r.asset_id, r.completed_at desc
"""

Q_I4 = """
select d.asset_id, d.device_class, d.confidence, d.prior_state, d.evaluated_at,
       -- ⛔ THE ENVELOPE SUBQUERY IS GONE (I4 v3). v2 asked "is the newest heavy's
       -- passive envelope empty"; R5 asks "was the prior basis COLLECTIBLE in-window".
       -- Measured: all 15 of Command's armed rows had a FULL envelope (their preserves
       -- fire on 57-day-old observations), so v2's population was empty on the only
       -- instance with preserves to check. Capability is now read through R5's own
       -- `signal_capable`, per row, with the cursor this query already has.
       -- R26: the prior BASIS, which the audit row does not carry. Read-only, same
       -- credential, and `signals_in` (imported) is the only thing that reads it.
       -- ⚠ This is the basis NOW, not as-of the row — exact only while `--write` is
       -- off, which it is on both instances. The line says so when it prints.
       (select a2.device_class_evidence::text
          from public.assets a2 where a2.asset_id = d.asset_id) as asset_basis
  from public.device_class_dryrun d
 where d.event_type = 'TRANSITION_DOWNGRADE'
   and d.evaluated_at > now() - interval '%s hours'
   and d.device_class <> 'unknown'
   and d.prior_state->>'device_class' = d.device_class
 order by d.evaluated_at desc
 limit 200
"""


def _rows(cur, sql, arg):
    cur.execute(sql % int(arg))
    return cur.fetchall() or []


def run_live(dsn: str) -> int:
    # ⛔ REFUSE ON AN UNRECOGNISED PROJECT REF (ruling 264/5). Guessing an instance
    # would silently pick the wrong `since` column, and a wrong `since` produces a
    # verdict that LOOKS like a regression. The ref is printed so the fix is obvious.
    instance = instance_from_dsn(dsn)
    if instance is None:
        try:
            pr = urllib.parse.urlsplit(dsn)
            seen = f"host={pr.hostname!r} user={pr.username!r}"   # never the password
        except Exception:
            seen = "unparseable DSN"
        print(f"{SUMMARY_PREFIX} REFUSED — unrecognised project ref ({seen}). "
              f"Known: {sorted(_PROJECT_REFS)}. Add it to _PROJECT_REFS with its "
              f"own SINCE column; do not guess.")
        return 1
    print(f"instance: {instance}   (from the DSN, never from SUPABASE_URL)")
    for iid in ("I1", "I2", "I3", "I4"):
        sha, when = SINCE[instance][iid]
        print(f"  armed {iid}: rows with {ANCHOR[iid]} >= {when}  ({sha})")
    print()

    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=15)
    conn.autocommit = True                      # read-only; never opens a write txn
    tally = {HELD: 0, FAILED: 0, INCONCLUSIVE: 0}
    backlog_total = 0
    try:
        with conn.cursor() as cur:
            # ── I1 ──────────────────────────────────────────────────────────
            armed, back = armed_split(_rows(cur, Q_I1, WINDOW_DAYS), "I1", instance)
            s1, s1b = i1_scoped(armed), i1_scoped(back)
            v, vb = s1["violations"], s1b["violations"]
            backlog_total += _report(
                "I1", "heavy with a raw wafw00f and no parsed verdict",
                invariant_state(s1, "I1"),
                f"{len(v)} violation(s) of {len(armed)} armed run(s)",
                [f"{x['asset_id']} {x['scan_run_id'][:8]}" for x in v[:5]],
                vb, [x["asset_id"] for x in vb[:5]], tally)

            # ── I2 ──────────────────────────────────────────────────────────
            armed, back = armed_split(_rows(cur, Q_I2, WINDOW_DAYS), "I2", instance)
            s2, s2b = i2_scoped(armed), i2_scoped(back)
            v, vb = s2["violations"], s2b["violations"]
            backlog_total += _report(
                "I2", "stored verdict generic/null while the raw names a vendor",
                invariant_state(s2, "I2"),
                f"{len(v)} laundered of {len(armed)} armed run(s)",
                [f"{x['asset_id']} raw={x['raw_says']} stored={x['stored_kind']}" for x in v[:5]],
                vb, [f"{x['asset_id']} raw={x['raw_says']}" for x in vb[:5]], tally)

            # ── I3 ──────────────────────────────────────────────────────────
            armed, back = armed_split(_rows(cur, Q_I3, WINDOW_DAYS), "I3", instance)
            r3 = i3_empty_envelopes(armed)
            state = i3_state(r3)        # pure — tested; see i3_state's docstring
            ex = r3["excluded"]
            by_reason = {}
            for e in ex:
                by_reason[e["reason"]] = by_reason.get(e["reason"], 0) + 1
            detail = (f"{r3['full_pct']}% full of {r3['total']} armed host(s) "
                      f"(floor {r3['floor_pct']}%, min population {r3['min_population']})")
            if state is INCONCLUSIVE:
                detail += f" — UNARMED: {len(back)} host(s) still on a pre-fix heavy"
            lines = [f"EMPTY {x['asset_id']}" for x in r3["empty"][:5]]
            lines += [f"excluded {n}x: {reason}" for reason, n in sorted(by_reason.items())]
            backlog_total += _report(
                "I3", "newest heavy on a host that answered HTTP carries a full envelope",
                state, detail, lines,
                [r for r in back if envelope_is_empty(r.get("envelope"))],
                [r["asset_id"] for r in back
                 if envelope_is_empty(r.get("envelope"))][:5], tally)

            # ── I4 ──────────────────────────────────────────────────────────
            raw4 = _rows(cur, Q_I4, RECENT_HOURS)
            armed, back = armed_split(raw4, "I4", instance)
            s4, s4b = i4_scoped(armed, cur), i4_scoped(back, cur)
            v, vb = s4["violations"], s4b["violations"]
            by_reason4 = {}
            for e in s4["excluded"]:
                by_reason4[e["reason"]] = by_reason4.get(e["reason"], 0) + 1
            detail4 = (f"{len(v)} unmarked of {len(s4['counted'])} checked "
                       f"(of {len(armed)} armed row(s), floor {INVARIANT_FLOOR['I4']})")
            lines4 = [x["asset_id"] for x in v[:5]]
            lines4 += [f"excluded {n}x: {reason}" for reason, n in sorted(by_reason4.items())]
            if s4["basis_source"]["assets"]:
                # ⚠ SAID ON THE LINE, NOT IN A COMMENT. The basis for these rows was read
                # from `assets` as it is NOW; it is as-of the row only because --write is
                # off. When the runner starts writing `prior_state.basis_signals`, this
                # count falls to zero and that is the signal the migration landed.
                lines4.append(f"basis from assets (current, not as-of the row — exact "
                              f"while --write is off): {s4['basis_source']['assets']}")
            if s4["basis_source"]["row"]:
                lines4.append(f"basis from the row itself: {s4['basis_source']['row']}")
            backlog_total += _report(
                "I4", "same-class downgrade on evidence R5 could not collect carries the marker",
                i4_state(s4),                 # pure: the operand choice is inside it
                detail4, lines4,
                vb, [x["asset_id"] for x in vb[:5]], tally)
    finally:
        conn.close()

    # ⛔ RULING 21 + 264/3 — THE SUMMARY LINE, WITH ALL FOUR COUNTS OR NONE.
    # `3/4 held` is exactly the phrasing that lets INCONCLUSIVE read as fine, so that
    # form is gone. INCONCLUSIVE is a third word, never a shade of PASS. The line is
    # printed on the pass AND the fail path, so its ABSENCE means the step died rather
    # than failed — and the gate greps only for the prefix, because the counts vary.
    print(f"{SUMMARY_PREFIX} held {tally[HELD]} · inconclusive {tally[INCONCLUSIVE]} "
          f"· failed {tally[FAILED]} · backlog {backlog_total}")
    return 1 if tally[FAILED] else 0


def _report(iid, title, state, measured, examples, backlog_rows, backlog_names, tally):
    """One invariant's three-state line, plus its BACKLOG line if it has one.
    Returns the backlog count so the caller can total it."""
    mark = {HELD: "PASS        ", FAILED: "⛔ FAIL      ",
            INCONCLUSIVE: "⚠ INCONCLUSIVE"}[state]
    print(f"  {mark}  {iid}  {title}")
    print(f"          measured: {measured}")
    for e in examples:
        print(f"          · {e}")
    n = len(backlog_rows)
    if n:
        # ⚠ A BACKLOG COUNT WITH NO NEXT STEP IS A NUMBER PEOPLE SCROLL PAST.
        print(f"  BACKLOG       {iid}  {n} pre-fix row(s) — NOT blocking")
        for b in backlog_names:
            print(f"          · {b}")
        print(f"          clears with: {BACKLOG_REMEDY[iid]}")
    tally[state] += 1
    return n


# ══ SELFTEST — every invariant, BAD shape then GOOD shape ══════════════════
# An invariant that cannot fail is a comment. Each fixture below is the shape the
# bad tree actually produced, not an invented counterexample.

def _selftest() -> int:
    ok = True

    # I1 — the persist fold. Bad: raw without parsed (18 of 18). Good: both, and a
    # host with NEITHER artifact, which must not count as a violation.
    bad1 = [{"asset_id": "commandcommcentral.com", "scan_run_id": "a", "has_raw": True, "has_parsed": False}]
    good1 = [{"asset_id": "commandcommcentral.com", "scan_run_id": "a", "has_raw": True, "has_parsed": True},
             {"asset_id": "ftp.sciimage.com", "scan_run_id": "b", "has_raw": False, "has_parsed": False}]
    ok &= len(i1_violations(bad1)) == 1
    ok &= i1_violations(good1) == []
    print(f"  I1 fires on raw-without-parsed, silent on a host with NEITHER artifact: "
          f"{'ok' if len(i1_violations(bad1)) == 1 and not i1_violations(good1) else 'FAIL'}")

    # I2 — the ANSI parse. The raw is the PRODUCTION bytes, escapes and all.
    ansi_raw = ("[+] The site \x1b[1;94mhttps://commandcommcentral.com/\x1b[0m is behind "
                "\x1b[1;96mFortiWeb (Fortinet)\x1b[0m WAF.\n"
                "[*] The site https://commandcommcentral.com/ seems to be behind a WAF or "
                "some sort of security solution\n")
    bad2 = [{"asset_id": "commandcommcentral.com", "raw": ansi_raw, "stored_kind": "generic"}]
    good2 = [{"asset_id": "commandcommcentral.com", "raw": ansi_raw, "stored_kind": "fortiweb"},
             {"asset_id": "x", "raw": "[-] No WAF detected by the generic detection\n",
              "stored_kind": None}]
    ok &= len(i2_laundered(bad2)) == 1
    ok &= i2_laundered(good2) == []
    ok &= kind_from_raw(ansi_raw) == "fortiweb"            # the parser really de-ANSIs
    print(f"  I2 fires on a laundered FortiWeb, silent on a genuine negative: "
          f"{'ok' if len(i2_laundered(bad2)) == 1 and not i2_laundered(good2) else 'FAIL'}")

    # I3 — the collector order. The empty envelope is the real 09-03 key set, and
    # the POPULATION is what ruling 23 corrected after the gate's first live run.
    empty_env = json.dumps({"schema": 1, "collected_at": "2026-09-03T20:14:56Z",
                            "hostname": "commandcommcentral.com"})
    full_env = json.dumps({"schema": 1, "hostname": "commandcommcentral.com",
                           "set_cookie_names": ["cookiesession1"],
                           "headers": {"server": "nginx"}, "cert": "CN=*.x"})
    # wafw00f output, by what the tool actually prints.
    W_VERDICT = ("[+] The site https://commandcommcentral.com/ is behind "
                 "FortiWeb (Fortinet) WAF.\n")
    W_NOWAF   = "[-] No WAF detected by the generic detection\n"
    W_DOWN    = "[*] The site https://ftp.sciimage.com/ appears to be down.\n"
    ok &= wafw00f_saw_http(W_VERDICT) and wafw00f_saw_http(W_NOWAF)
    ok &= not wafw00f_saw_http(W_DOWN)
    ok &= not wafw00f_saw_http(None) and not wafw00f_saw_http("")
    print(f"  I3 population (ruling 23): a verdict counts, "
          f"'appears to be down' does NOT: "
          f"{'ok' if wafw00f_saw_http(W_NOWAF) and not wafw00f_saw_http(W_DOWN) else 'FAIL'}")

    # ⭐ FIRES: banned egress, HTTP surface confirmed in the same run -> 45%
    bad3 = ([{"asset_id": f"e{i}", "envelope": empty_env, "wafw00f_raw": W_VERDICT}
             for i in range(6)] +
            [{"asset_id": f"g{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT}
             for i in range(5)])
    r_bad = i3_empty_envelopes(bad3)
    ok &= r_bad["ok"] is False and r_bad["full_pct"] == 45
    # ⭐ SILENT: two hosts that were DOWN in that run — empty envelope, but no HTTP
    #   surface, so EXCLUDED. The shape that failed premerge-gate #2 at 80% of 10.
    #   ⚠ NOT "the SFTP pair": ftp.sciimage.com answers HTTP when it is up (entry 263).
    #   Here both rows carry "appears to be down", which is the property being tested —
    #   the hostnames are incidental and must not be read as a standing fact.
    good3 = ([{"asset_id": f"g{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT}
              for i in range(8)] +
             [{"asset_id": "ftp.sciimage.com", "envelope": empty_env, "wafw00f_raw": W_DOWN},
              {"asset_id": "ftp.unimacgraphics.com", "envelope": empty_env, "wafw00f_raw": W_DOWN}])
    r_good = i3_empty_envelopes(good3)
    ok &= r_good["ok"] is True and r_good["total"] == 8 and r_good["full_pct"] == 100
    ok &= len(r_good["excluded"]) == 2
    print(f"  I3 fires at 45% on a banned egress, and is SILENT on hosts that were "
          f"down in that run (8/8, 2 excluded): "
          f"{'ok' if not r_bad['ok'] and r_good['ok'] and r_good['total'] == 8 else 'FAIL'}")
    # ⛔ AND A POPULATION THAT COLLAPSES IS A FAILURE, NOT A PASS. The old code
    #   returned ok=True on total==0, so a predicate bug that excluded everything
    #   read as clean. "Nothing to check" and "everything checked out" must differ.
    r_thin = i3_empty_envelopes(
        [{"asset_id": "ftp.sciimage.com", "envelope": empty_env, "wafw00f_raw": W_DOWN}])
    ok &= r_thin["ok"] is False and r_thin["population_too_thin"] is True
    ok &= i3_empty_envelopes([])["ok"] is False
    print(f"  I3 population below the floor FAILS (and [] fails too): "
          f"{'ok' if not r_thin['ok'] and not i3_empty_envelopes([])['ok'] else 'FAIL'}")
    # ⛔ MUTANTS M3 AND M6 (4.7, relay 259) SURVIVED THE SELFTEST while dying in
    #   pytest — so the line this function prints ("proven to fire AND to stay
    #   silent") was claiming more than it had checked. Mirrored here so the claim
    #   and the coverage are the same thing.
    #   M3: floor not wired to the verdict. Every earlier floor fixture had pct=0,
    #       where ok is False either way. 3 hosts, ALL FULL, must still fail.
    r_m3 = i3_empty_envelopes([{"asset_id": f"f{i}", "envelope": full_env,
                                "wafw00f_raw": W_VERDICT} for i in range(3)])
    ok &= r_m3["full_pct"] == 100 and r_m3["population_too_thin"] is True and r_m3["ok"] is False
    #   M6: >= floor vs > floor. The docstring's design point is 9 of 10; nothing
    #       sat on it.
    _b = lambda nf, ne: i3_empty_envelopes(
        [{"asset_id": f"f{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT} for i in range(nf)] +
        [{"asset_id": f"e{i}", "envelope": empty_env, "wafw00f_raw": W_VERDICT} for i in range(ne)])
    ok &= _b(9, 1)["full_pct"] == 90 and _b(9, 1)["ok"] is True
    ok &= _b(8, 2)["ok"] is False
    print(f"  I3 floor is wired to the verdict (3 full hosts -> FAIL) and 90% is the "
          f"boundary (9/10 pass, 8/10 fail): "
          f"{'ok' if not r_m3['ok'] and _b(9,1)['ok'] and not _b(8,2)['ok'] else 'FAIL'}")
    # ⛔ MUTANT D (4.7, relay 266) — THE WORD ITSELF WAS UNGUARDED. The mapping from
    #   `population_too_thin` to the word INCONCLUSIVE lived inside run_live(), which
    #   needs a DSN, so `thin -> HELD` passed every test AND this selftest: a thin
    #   population printed PASS and the summary read `inconclusive 0`. R25's own
    #   vacuous pass, one function downstream of where the tests stopped.
    ok &= i3_state(r_m3) is INCONCLUSIVE               # 3 hosts, 100% full -> still thin
    ok &= i3_state(_b(9, 1)) is HELD                   # 10 hosts, 90%      -> PASS
    ok &= i3_state(_b(8, 2)) is FAILED                 # 10 hosts, 80%      -> FAIL
    ok &= i3_state(i3_empty_envelopes([])) is INCONCLUSIVE      # nothing at all
    # ⚠ THE VERDICT IS COMPUTED INTO A NAME FIRST. My first version split the
    #   condition across two concatenated f-strings, which python 3.10 cannot parse —
    #   an f-string expression may not straddle two literals. It failed at IMPORT, so
    #   the whole test file errored on collection rather than one test failing: a
    #   syntax error in the reporting line takes down the thing it reports on.
    _d_ok = (i3_state(r_m3) is INCONCLUSIVE and i3_state(_b(9, 1)) is HELD
             and i3_state(_b(8, 2)) is FAILED)
    print(f"  i3_state: thin -> INCONCLUSIVE EVEN AT 100% full (mutant D), "
          f"10 hosts 90% -> PASS, 80% -> FAIL: {'ok' if _d_ok else 'FAIL'}")
    # ⚠ AND THE SUMMARY LINE'S OWN FORMAT, exercised with a non-zero inconclusive —
    #   the count that used to be unreachable is now printed here.
    _tally = {HELD: 2, FAILED: 0, INCONCLUSIVE: 1}
    _summary = (f"{SUMMARY_PREFIX} held {_tally[HELD]} · inconclusive "
                f"{_tally[INCONCLUSIVE]} · failed {_tally[FAILED]} · backlog 15")
    _fmt_ok = "inconclusive 1" in _summary and "/4" not in _summary
    ok &= _fmt_ok
    print(f"  the summary line carries all four counts and no N/4 form: "
          f"{'ok' if _fmt_ok else 'FAIL'}")
    print(f"          {_summary}")
    ok &= envelope_is_empty(empty_env) and not envelope_is_empty(full_env)
    ok &= envelope_is_empty(None) and envelope_is_empty("not json") and envelope_is_empty("[]")

    # I4 — the capability gap. Same asset, same row, with and without the marker.
    base4 = {"asset_id": "api.commandcommcentral.com", "device_class": "waf",
             "confidence": "suspected", "newest_envelope_empty": True}
    bad4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    good4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed",
                                       "preserve": {"reason": "EVIDENCE_AGED",
                                                    "evidence_age_days": {"set_cookie_names": 56}}}},
             # a FULL envelope is not this invariant's business, marker or not
             {**base4, "newest_envelope_empty": False,
              "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    # I4 — the capability gap. ⚠ THE FIXTURES CARRY A BASIS, NOT AN ENVELOPE, SINCE v3:
    #   the population is "some prior signal was NOT collectible in-window", which is
    #   R5's own condition, so an envelope on the fixture would be decoration.
    #   `_BASIS3` is api.commandcommcentral.com's REAL stored basis, read from Command.
    _BASIS3 = json.dumps({"signals": ["wafw00f_discovery_confidence",
                                      "fortiweb_cookiesession1",
                                      "cert_issuer_subject_pattern"]})
    base4 = {"asset_id": "api.commandcommcentral.com", "device_class": "waf",
             "confidence": "suspected", "asset_basis": _BASIS3}
    bad4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    good4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed",
                                       "preserve": {"reason": "EVIDENCE_AGED",
                                                    "evidence_age_days": {"set_cookie_names": 56}}}}]

    # ══ R26/I4 v3 — THE POPULATION IS R5's OWN AXIS. The rows below are production
    #    (relay 271's Prodex reads + my Command read); the capability answer is None
    #    here because a fixture has no cursor, which is itself an exclusion WITH A NAME.
    _PDX_CLOUD_BASIS = json.dumps({"signals": [], "inherited_at": "2026-07-13T21:13:42Z",
                                   "surface_stale": False, "cloud_provider": "gcp",
                                   "inherited_from": "cloud_provider",
                                   "cloud_match_tier": "asn", "is_cloud_endpoint": False})
    _CMD_BASIS = json.dumps({"signals": ["wafw00f_discovery_confidence",
                                         "fortiweb_cookiesession1",
                                         "cert_issuer_subject_pattern"]})
    _scope4 = [
        # demo-tour / azure-demo: the 2026-07-13 cloud-inherited seed, signals: [] ->
        # R5 WRITES on an empty basis by design, so no marker is owed. Prodex's whole red.
        {"asset_id": "demo-tour.prodexlabs.com", "device_class": "cloud_endpoint",
         "confidence": "suspected", "asset_basis": _PDX_CLOUD_BASIS,
         "prior_state": {"device_class": "cloud_endpoint", "confidence": "confirmed"}},
        {"asset_id": "azure-demo.prodexlabs.com", "device_class": "cdn",
         "confidence": "suspected", "asset_basis": _PDX_CLOUD_BASIS,
         "prior_state": {"device_class": "cdn", "confidence": "confirmed"}},
        # a real basis, but no cursor in a fixture -> capability UNKNOWN, named, not passed
        {"asset_id": "api.commandcommcentral.com", "device_class": "waf",
         "confidence": "suspected", "asset_basis": _CMD_BASIS,
         "prior_state": {"device_class": "waf", "confidence": "confirmed"}},
    ]
    _s4 = i4_scoped(_scope4)                       # no cursor
    _r4 = sorted({e["reason"] for e in _s4["excluded"]})
    ok &= _s4["counted"] == [] and _r4 == sorted([_I4_NO_BASIS, _I4_NO_CURSOR])
    print(f"  I4 v3 population: empty basis -> excluded (R5 writes), no cursor -> "
          f"UNKNOWN not pass: {'ok' if _r4 == sorted([_I4_NO_BASIS, _I4_NO_CURSOR]) else 'FAIL'}")

    # ⛔ AND THE CAPABILITY AXIS ITSELF, with a stub cursor standing in for the DB.
    #    R5 preserves IFF some prior signal was incapable; I4 v3 asks exactly that.
    class _Cur:                                   # only signal_capable's inputs matter
        def __init__(self, incapable): self.incapable = incapable
    def _fake_capable(cur, asset, sig, m, days): return sig not in cur.incapable
    _real = globals()["signal_capable"]
    globals()["signal_capable"] = _fake_capable
    try:
        _row = dict(_scope4[2])
        _all_cap = i4_scoped([_row], _Cur(set()))
        ok &= _all_cap["counted"] == [] and [e["reason"] for e in _all_cap["excluded"]] == [_I4_ALL_CAPABLE]
        _one_incap = i4_scoped([_row], _Cur({"fortiweb_cookiesession1"}))
        ok &= len(_one_incap["counted"]) == 1 and len(_one_incap["violations"]) == 1
        _marked = dict(_row, prior_state={"device_class": "waf", "confidence": "confirmed",
                                          "preserve": {"reason": "EVIDENCE_AGED"}})
        ok &= i4_scoped([_marked], _Cur({"fortiweb_cookiesession1"}))["violations"] == []
        # the named fixtures, through the same axis: fires, and stays silent
        ok &= len(i4_scoped(bad4, _Cur({"fortiweb_cookiesession1"}))["violations"]) == 1
        ok &= i4_scoped(good4, _Cur({"fortiweb_cookiesession1"}))["violations"] == []
        ok &= len(i4_scoped([{**base4, "prior_state": json.dumps(bad4[0]["prior_state"])}],
                            _Cur({"fortiweb_cookiesession1"}))["violations"]) == 1   # jsonb as text
        print(f"  I4 v3 capability axis: every prior signal collectible -> EXCLUDED; one "
              f"incapable + no marker -> VIOLATION; with the marker -> silent: "
              f"{'ok' if len(_one_incap['violations']) == 1 and not _all_cap['counted'] else 'FAIL'}")
    finally:
        globals()["signal_capable"] = _real

    # ⛔ R27 — ZERO CHECKED ROWS IS INCONCLUSIVE, NOT PASS. Prodex printed
    #   "PASS I1 0 violation(s) of 0 armed run(s)" and Command's I4 checked nothing
    #   behind a PASS. Both are the vacuous pass in PASS's coat.
    ok &= state_for(0, True, 1) is INCONCLUSIVE
    ok &= state_for(0, False, 1) is INCONCLUSIVE          # no rows -> no verdict, either way
    ok &= state_for(1, True, 1) is HELD
    ok &= state_for(1, False, 1) is FAILED
    ok &= state_for(4, True, 5) is INCONCLUSIVE           # I3's ratio floor
    ok &= state_for(5, True, 5) is HELD
    _empty4 = i4_scoped([_scope4[0]])                     # only the NULL-envelope row
    ok &= i4_state(_empty4) is INCONCLUSIVE
    # ⛔ AND I4's VERDICT TAKES THE SCOPED RESULT, NOT THE FETCHED ROWS. 15 full
    #   envelopes = 15 armed rows and ZERO checked: PASS there is the vacuous pass.
    # ⛔ MUTANT R (4.7, relay 273) — I1/I2 WERE STILL DECIDED IN run_live. `len(armed)
    #   + 1` there passed 118 tests and this selftest, printing PASS on zero armed I1
    #   rows: R27's own target, inside R27's own commit. Mirrored here so the selftest
    #   claims no more than it checks.
    ok &= invariant_state(i1_scoped([]), "I1") is INCONCLUSIVE
    ok &= invariant_state(i2_scoped([]), "I2") is INCONCLUSIVE
    ok &= invariant_state(i1_scoped(good1), "I1") is HELD
    ok &= invariant_state(i1_scoped(bad1), "I1") is FAILED
    ok &= invariant_state(i2_scoped(good2), "I2") is HELD
    ok &= invariant_state(i2_scoped(bad2), "I2") is FAILED
    ok &= floor_for("I3") == I3_MIN_POPULATION and floor_for("I1") == 1
    print(f"  I1/I2 verdicts are PURE too (mutant R): zero armed -> INCONCLUSIVE, "
          f"clean -> PASS, dirty -> FAIL: "
          f"{'ok' if invariant_state(i1_scoped([]), 'I1') is INCONCLUSIVE else 'FAIL'}")

    _all_full = i4_scoped([{**base4, "newest_envelope": full_env,
                            "newest_envelope_empty": False,
                            "prior_state": {"device_class": "waf", "confidence": "confirmed"}}
                           for _ in range(15)])
    ok &= len(_all_full["excluded"]) == 15 and _all_full["counted"] == []
    ok &= i4_state(_all_full) is INCONCLUSIVE
    print(f"  R27 zero CHECKED rows is INCONCLUSIVE for every invariant (floor 1 for "
          f"I1/I2/I4, 5 for I3): "
          f"{'ok' if state_for(0, True, 1) is INCONCLUSIVE and state_for(1, True, 1) is HELD else 'FAIL'}")

    # ⛔ 2b CANNOT PRODUCE AN I4 ROW, and event_for is IMPORTED to prove it. A computed
    #   `unknown` against a positive prior IS a TRANSITION_DOWNGRADE, but its classes
    #   DIFFER, so Q_I4's `prior_state->>device_class = device_class` filter drops it —
    #   which means every row I4 ever sees comes from R5's branch. §1 of relay 270
    #   leaned on that and nothing asserted it.
    ok &= event_for("waf", "confirmed", "unknown", "unknown") == "TRANSITION_DOWNGRADE"
    ok &= event_for("waf", "confirmed", "waf", "suspected") == "TRANSITION_DOWNGRADE"
    ok &= event_for("unknown", "unknown", "waf", "confirmed") == "STAMP"      # prior first
    ok &= event_for("waf", "confirmed", "waf", "confirmed") is None
    print(f"  2b cannot reach I4: unknown-target downgrades have DIFFERENT classes, so "
          f"the same-class filter excludes them (event_for imported): "
          f"{'ok' if event_for('waf', 'confirmed', 'unknown', 'unknown') == 'TRANSITION_DOWNGRADE' else 'FAIL'}")

    # ══ R25 — the instance resolution, the anchor, and the armed split ══════
    # ⚠ BOTH DSN SHAPES ARE IN USE and the refusal is the important case.
    _dsns = [
        ("postgresql://postgres:pw@db.hdygktppfvuspnumpfuq.supabase.co:5432/postgres", "command"),
        ("postgresql://postgres.bxcvzpbmxsdtalyfanee:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres", "prodex"),
        ("postgresql://postgres:pw@db.bxcvzpbmxsdtalyfanee.supabase.co:5432/postgres", "prodex"),
        ("postgresql://postgres.hdygktppfvuspnumpfuq:pw@aws-0-eu-west-1.pooler.supabase.com:6543/postgres", "command"),
        # ⛔ the refusals — an unknown ref must NEVER resolve to a guess
        ("postgresql://postgres:pw@db.zzzzzzzzzzzzzzzzzzzz.supabase.co:5432/postgres", None),
        ("postgresql://postgres@localhost:5432/postgres", None),
        ("not a dsn at all", None), ("", None), (None, None),
    ]
    for dsn, want in _dsns:
        got = instance_from_dsn(dsn)
        ok &= got == want
        if got != want:
            print(f"  ⛔ instance_from_dsn mis-resolved: want {want}, got {got}")
    print(f"  R25 instance from the DSN (both shapes, both instances, 5 refusals): "
          f"{'ok' if all(instance_from_dsn(d) == w for d, w in _dsns) else 'FAIL'}")
    # ⚠ and it must never surface the password, whatever it is handed
    _secret = "postgresql://postgres:SUPERSECRET@db.hdygktppfvuspnumpfuq.supabase.co:5432/postgres"
    ok &= instance_from_dsn(_secret) == "command"

    # The fractional-seconds parser — 1 to 6 digits, all of which Postgres emits.
    for _t in ("2026-09-17T12:18:32.47312+00:00", "2026-09-17T12:18:32.4+00:00",
               "2026-09-17T12:18:32.473120+00:00", "2026-09-17T12:18:32+00:00"):
        ok &= iso(_t) is not None
    ok &= iso(None) is None
    print(f"  iso() takes 1-6 fractional digits (the '.47312' trap): "
          f"{'ok' if iso('2026-09-17T12:18:32.47312+00:00') else 'FAIL'}")

    # ⭐ THE ARMED SPLIT, ON THE REAL BOUNDARY. f8cc3a3e is Command's I3 fix at
    #   2026-09-17T08:09:34-04:00 = 12:09:34Z. #3050 STARTED 12:12:20Z -> armed.
    #   ftp.sciimage.com's newest heavy started 2026-09-06 -> backlog.
    _rows3 = [
        {"asset_id": "commandcommcentral.com", "started_at": "2026-09-17T12:12:20.1+00:00"},
        {"asset_id": "ftp.sciimage.com",       "started_at": "2026-09-06T12:11:00+00:00"},
        {"asset_id": "no-timestamp",           "started_at": None},
    ]
    _a, _b = armed_split(_rows3, "I3", "command")
    ok &= [r["asset_id"] for r in _a] == ["commandcommcentral.com"]
    ok &= len(_b) == 2
    print(f"  armed_split on the real f8cc3a3e boundary (#3050 armed, 09-06 backlog, "
          f"NULL anchor -> backlog): {'ok' if len(_a) == 1 and len(_b) == 2 else 'FAIL'}")

    # ⚠ THE ANCHOR IS started_at. A run that STARTED before the fix and COMPLETED
    #   after it ran the OLD code — bcbsma's real 40-minute window. Under
    #   completed_at it would be armed, and a wrongly-armed row looks like a
    #   regression. This is the case that makes the ruling concrete.
    _straddle = [{"asset_id": "bcbsma", "started_at": "2026-09-17T12:00:41+00:00",
                  "completed_at": "2026-09-17T12:41:01+00:00"}]
    ok &= armed_split(_straddle, "I3", "command")[0] == []
    ok &= len(armed_split(_straddle, "I3", "command", anchor="completed_at")[0]) == 1
    print(f"  a run STARTING pre-fix and FINISHING post-fix is BACKLOG on started_at "
          f"and would be armed on completed_at: "
          f"{'ok' if not armed_split(_straddle, 'I3', 'command')[0] else 'FAIL'}")

    # ⛔ MUTANT A (4.7, relay 266): `>= cut` -> `> cut` SURVIVED — nothing sat exactly
    #   ON the cut second. The docstring says "at/after", so the boundary row is the
    #   spec, and a spec with no fixture is a sentence.
    _at_cut = [{"asset_id": "exactly-at-the-cut",
                "started_at": SINCE["command"]["I3"][1]}]           # the cut, verbatim
    ok &= len(armed_split(_at_cut, "I3", "command")[0]) == 1
    _one_before = [{"asset_id": "one-second-before",
                    "started_at": "2026-09-17T08:09:33-04:00"}]
    ok &= armed_split(_one_before, "I3", "command")[0] == []
    _a_ok = (len(armed_split(_at_cut, "I3", "command")[0]) == 1
             and not armed_split(_one_before, "I3", "command")[0])
    print(f"  a row exactly AT the cut second is ARMED, one second before is BACKLOG "
          f"(mutant A): {'ok' if _a_ok else 'FAIL'}")

    # ⛔ MUTANT F (4.7, relay 266): SINCE[instance] -> SINCE["command"] SURVIVED,
    #   because every fixture asked for "command". The instance columns differ by two
    #   seconds in production, so ONE row placed between them separates them — and
    #   this is the only check that would catch a future column swap. If job 4 ever
    #   reads the wrong instance's `since`, it arms the wrong rows and every verdict
    #   after that is about a different repo's history.
    _between = [{"asset_id": "between-the-two-cuts",
                 "started_at": "2026-09-17T08:09:35-04:00"}]        # Cmd 08:09:34, Pdx 08:09:36
    ok &= len(armed_split(_between, "I3", "command")[0]) == 1        # armed on Command
    ok &= armed_split(_between, "I3", "prodex")[0] == []             # backlog on Prodex
    _f_ok = (len(armed_split(_between, "I3", "command")[0]) == 1
             and not armed_split(_between, "I3", "prodex")[0])
    print(f"  the SINCE column FOLLOWS the instance: one row between Command's cut "
          f"and Prodex's is armed on command, backlog on prodex (mutant F): "
          f"{'ok' if _f_ok else 'FAIL'}")

    # Per-repo columns, and every invariant present in both.
    ok &= set(SINCE) == {"command", "prodex"}
    for _inst in SINCE:
        ok &= set(SINCE[_inst]) == {"I1", "I2", "I3", "I4"} == set(ANCHOR) == set(BACKLOG_REMEDY)
        for _iid, (_sha, _when) in SINCE[_inst].items():
            ok &= iso(_when) is not None and len(_sha) >= 7
    ok &= SINCE["command"]["I3"][1] != SINCE["prodex"]["I3"][1]   # they really differ
    print(f"  SINCE has both instances x 4 invariants, all parseable, Cmd != Pdx: "
          f"{'ok' if set(SINCE) == {'command','prodex'} else 'FAIL'}")

    # ⚠ FIXTURE SCOPE CORRECTED (ruling 264/8, from relay 263's byte-read):
    #   ftp.sciimage.com ANSWERS HTTP — its wafw00f produced a generic verdict off
    #   four requests — so it is a COUNTED host, not an excluded one. The old fixture
    #   called it part of "the SFTP pair with no HTTPS surface", which was false and
    #   was repeated across four entries before anyone read the bytes.
    _scoped = [
        # ⚠ VERBATIM FROM THE DB — scan_run e6360fac, 2026-09-06, relay 263 READ 1.
        # My first hand-typed version of this fixture dropped the
        # "[+] Generic Detection results:" line, and WITHOUT it wafw00f_saw_http
        # returns False, because that `[+] ` IS the verdict marker. The selftest
        # caught it: the code was right and the fixture I typed was not. The ANSI
        # rule again — a fixture a human composed is not the bytes a tool emits.
        {"asset_id": "ftp.sciimage.com", "envelope": full_env, "wafw00f_present": True,
         "wafw00f_raw": ("[*] Checking https://ftp.sciimage.com/\n"
                         "[+] Generic Detection results:\n"
                         "[*] The site https://ftp.sciimage.com/ seems to be behind a WAF "
                         "or some sort of security solution\n"
                         "[~] Reason: The response was different when the request "
                         "wasn't made from a browser.\n")},
        {"asset_id": "ftp.unimacgraphics.com", "envelope": empty_env,
         "wafw00f_raw": "[*] Checking https://ftp.unimacgraphics.com/\n", "wafw00f_present": True},
        {"asset_id": "geisinger.commandcommcentral.com", "envelope": full_env,
         "wafw00f_raw": None, "wafw00f_present": False},
    ]
    _rs = i3_empty_envelopes(_scoped, min_population=1)
    ok &= [c["asset_id"] for c in _scoped if wafw00f_saw_http(c["wafw00f_raw"])] == ["ftp.sciimage.com"]
    _reasons = sorted(e["reason"] for e in _rs["excluded"])
    ok &= _reasons == ["no wafw00f artifact (tool did not run)", "wafw00f ran, no verdict"]
    print(f"  fixture scope: ftp.sciimage.com COUNTED (it answers HTTP); the two "
          f"exclusion reasons are distinct: {'ok' if len(_reasons) == 2 else 'FAIL'}")

    # ⛔ AND THE ARITHMETIC PIN RUNS HERE TOO. Mutant R died in pytest (the AST pin)
    #   and the selftest still exited 0 — so a dead `unit` lane would hide it, which is
    #   lane 6's whole lesson. The gate runs --selftest in its own job, so the pin has
    #   to be reachable from both. Asked of the AST: this comment contains `len(`.
    import ast as _ast
    _tree = _ast.parse(Path(__file__).read_text())
    _fn = next(n for n in _ast.walk(_tree)
               if isinstance(n, _ast.FunctionDef) and n.name == "run_live")
    _bad = []
    for _c in _ast.walk(_fn):
        if not (isinstance(_c, _ast.Call) and isinstance(_c.func, _ast.Name)
                and _c.func.id in ("state_for", "invariant_state", "i3_state", "i4_state")):
            continue
        for _a in list(_c.args) + [k.value for k in _c.keywords]:
            for _n in _ast.walk(_a):
                if (isinstance(_n, (_ast.BinOp, _ast.Compare))
                        or (isinstance(_n, _ast.Call) and isinstance(_n.func, _ast.Name)
                            and _n.func.id == "len")):
                    _bad.append(_c.lineno)
    ok &= not _bad
    print(f"  no verdict call site in run_live passes arithmetic (mutants L and R): "
          f"{'ok' if not _bad else 'FAIL at line ' + str(_bad[0])}")

    # ⛔ THE QUERIES MUST BE READ-ONLY. Stated as a test rather than a promise:
    # this runs against production with a service-role credential.
    # ⚠ THIS LINE USED TO REPORT THE CUMULATIVE `ok`, so an unrelated failure earlier
    # in the selftest made it announce that the QUERIES were not read-only. A control
    # that misattributes a failure sends the next reader to the wrong file — and it
    # did exactly that to me one run ago.
    _ro_ok = True
    for name, q in (("Q_I1", Q_I1), ("Q_I2", Q_I2), ("Q_I3", Q_I3), ("Q_I4", Q_I4)):
        low = " ".join(q.split()).lower()
        bad = [v for v in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate ")
               if v in low]
        _sw = low.startswith("select") or low.startswith("with")
        ok &= not bad; ok &= _sw
        _ro_ok = _ro_ok and (not bad) and _sw
        if bad:
            print(f"  ⛔ {name} contains {bad}")
    print(f"  all four queries are read-only and start with SELECT/WITH: "
          f"{'ok' if _ro_ok else 'FAIL'}")

    print(f"{SUMMARY_PREFIX} selftest {'PASS' if ok else 'FAIL'} "
          f"(4 invariants, each proven to fire AND to stay silent)")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true", help="fixtures only, no DB")
    ap.add_argument("--live", action="store_true", help="run against SUPABASE_DSN (read-only)")
    a = ap.parse_args()
    if a.selftest or not a.live:
        return _selftest()
    if psycopg is None:
        sys.exit("psycopg required for --live")
    dsn = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
    if not dsn:
        sys.exit("set SUPABASE_DSN")
    print(f"premerge invariants — LIVE, read-only, window {WINDOW_DAYS}d / {RECENT_HOURS}h")
    return run_live(dsn)


if __name__ == "__main__":
    sys.exit(main())
