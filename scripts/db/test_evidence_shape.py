#!/usr/bin/env python3
"""`evidence` has TWO shapes and the readers assumed one. Relay 241. 2026-09-17.

⛔ THE OUTAGE. classify #242, Command, dry-run on b3a96e90, 1m51s, FAILURE:

    File "scripts/db/device_class_runner.py", line 1153, in <setcomp>
      still_firing = {e.get("signal") for e in (res.get("evidence") or [])}
    AttributeError: 'str' object has no attribute 'get'

`classify_asset` has two return paths that do not agree on what `evidence` is:

    fingerprint path   [{"signal": "wafw00f_high_confidence", …}, …]      LIST of rows
    cloud fallback     {"signals": [], "inherited_from": "cloud_provider", …}   DICT

Iterating the dict yields its KEYS — strings. `.get` on a str raises. Command has
12 cloud_endpoint + 7 cdn assets on that path; the pass died on the first one.
Every 6-hourly dry-run classify on BOTH instances failed until this landed.

⚠ NOTHING WAS CORRUPTED — dry-run cannot write `assets`. The soak was paused, not
damaged. That is luck about the mode, not a property of the code.

⭐ WHY THIS KEPT NOT BEING CAUGHT, WHICH IS THE REAL LESSON.
`_has_wafw00f` handled the dict correctly — `isinstance(evidence, list) and …`.
The right answer was already in the file. But the guard lived IN THE READER, so it
was a private habit rather than a rule, and the two readers added afterwards
inherited nothing:

    _has_wafw00f          guarded          survived
    :797  cap-print       UNGUARDED        survived only because `nc == "waf"` is
                                           never a cloud-fallback result — luck
    :1153 R5 still_firing UNGUARDED        crashed the pass

⇒ A SHAPE THAT NEEDS A GUARD NEEDS ONE READER, NOT A CONVENTION. `signals_in()`
is that reader; this file pins that all three go through it.

⚠ AND THE FIXTURES NEVER CARRIED THE DICT. Every 2c fixture was built from the
shape the new code expected, not from what production returns — the same miss as
utc_now, PATIENT_BAN_COOLDOWN_S and the ANSI bytes. CLOUD_EVIDENCE below is copied
from `_cloud_fallback`'s own return statement, not retyped from memory, and a test
asserts it still matches that statement.
"""

from __future__ import annotations

import ast
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "normalize"))

import device_class_runner as dcr  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()

# ── VERBATIM from _cloud_fallback's return. The keys are the test. ──────────
CLOUD_EVIDENCE = {
    "signals": [],
    "inherited_from": "cloud_provider",
    "cloud_provider": "akamai",
    "cloud_match_tier": "asn",
    "is_cloud_endpoint": True,
    "surface_stale": False,
    "inherited_at": "2026-09-17T12:15:00Z",
}

FINGERPRINT_EVIDENCE = [
    {"signal": "wafw00f_high_confidence", "weight": "high",
     "evidence_class": "vendor_identifying"},
    {"signal": "fortiweb_cookiesession1", "weight": "high",
     "evidence_class": "vendor_identifying"},
]


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ THE CRASH, REPRODUCED — red on the pre-fix tree
# ═══════════════════════════════════════════════════════════════════════════

def test_the_cloud_fallback_dict_does_not_raise():
    """⛔ THE OUTAGE, in one line. PRE-FIX the old set-comp raised AttributeError
    on this exact value; the whole classify pass died on the first cloud asset."""
    assert dcr.signals_in(CLOUD_EVIDENCE) == set()


def test_the_old_setcomp_really_does_raise_on_this_fixture():
    """Guards the fixture itself. If CLOUD_EVIDENCE were ever 'tidied' into a list,
    the test above would pass while testing nothing — the vacuous-fixture failure.
    This asserts the value is genuinely the shape that broke production."""
    with pytest.raises(AttributeError):
        {e.get("signal") for e in CLOUD_EVIDENCE}          # noqa: B015 — the bug, verbatim


def test_cloud_inherited_evidence_rests_on_no_fingerprint_signal():
    """Empty is the TRUE answer here, not a fallback. A cloud-inherited class is
    derived from cloud_provider (ASN/CNAME), which is not a fingerprint signal and
    never enters the tally. So R5 sees an empty prior basis and WRITES — no
    ratchet, and no preserve justified by evidence that was never signal-based."""
    assert dcr.signals_in(CLOUD_EVIDENCE) == set()
    assert dcr.apply_r5_confidence_rule(
        "cdn", "confirmed", "cdn", "suspected",
        dcr.prior_signals_of(CLOUD_EVIDENCE), ["anything"]) == dcr._DECISION_WRITE


def test_the_fixture_still_matches_the_producer():
    """⚠ The fixture is copied from `_cloud_fallback`'s return statement. If that
    statement grows or renames a key, this fails and the fixture gets updated —
    rather than the fixture quietly describing a shape production stopped emitting.
    Keys only: the VALUES are per-asset."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "_cloud_fallback")
    body = ast.get_source_segment(SRC, fn)
    ev = next(n for n in ast.walk(ast.parse(body))
              if isinstance(n, ast.Assign)
              and any(getattr(t, "id", "") == "ev" for t in n.targets))
    keys = {k.value for k in ev.value.keys if isinstance(k, ast.Constant)}
    assert keys == set(CLOUD_EVIDENCE), (
        f"_cloud_fallback's evidence keys are now {sorted(keys)}; the fixture says "
        f"{sorted(CLOUD_EVIDENCE)}. Update the fixture from the producer.")


# ═══════════════════════════════════════════════════════════════════════════
# the other shapes signals_in must take
# ═══════════════════════════════════════════════════════════════════════════

def test_the_list_of_rows_still_works():
    assert dcr.signals_in(FINGERPRINT_EVIDENCE) == {
        "wafw00f_high_confidence", "fortiweb_cookiesession1"}


def test_a_json_string_is_parsed():
    """assets.device_class_evidence comes back as text on some drivers."""
    assert dcr.signals_in(json.dumps(FINGERPRINT_EVIDENCE)) == {
        "wafw00f_high_confidence", "fortiweb_cookiesession1"}
    assert dcr.signals_in(json.dumps(CLOUD_EVIDENCE)) == set()


def test_a_dict_with_actual_signals_yields_them():
    """`signals` may carry rows or bare names — neither is invented here, both are
    accepted rather than guessed at."""
    assert dcr.signals_in({"signals": [{"signal": "a"}, {"signal": "b"}]}) == {"a", "b"}
    assert dcr.signals_in({"signals": ["a", "b"]}) == {"a", "b"}


@pytest.mark.parametrize("junk", [None, "", "not json", 42, [], {}, [None, 7],
                                  [{"no_signal_key": 1}], {"signals": None}])
def test_junk_yields_an_empty_set_and_never_raises(junk):
    """⚠ THE POINT OF THE WHOLE EXERCISE: a reader of a value with more than one
    producer must not be able to take down the pass."""
    assert dcr.signals_in(junk) == set()


def test_rows_without_a_signal_key_are_skipped_not_counted():
    assert dcr.signals_in([{"signal": "a"}, {"weight": "high"}, {"signal": ""}]) == {"a"}


# ═══════════════════════════════════════════════════════════════════════════
# prior_signals_of — same rule, and ORDER preserved
# ═══════════════════════════════════════════════════════════════════════════

def test_prior_signals_keeps_producer_order():
    """⚠ Membership comes from signals_in; the ORDER is this function's own job. The
    R5 log line names the incapable signals, and a set would reorder them between
    passes — turning a stable audit line into noise."""
    assert dcr.prior_signals_of(FINGERPRINT_EVIDENCE) == [
        "wafw00f_high_confidence", "fortiweb_cookiesession1"]
    assert dcr.prior_signals_of(list(reversed(FINGERPRINT_EVIDENCE))) == [
        "fortiweb_cookiesession1", "wafw00f_high_confidence"]


def test_prior_signals_on_the_cloud_dict_is_empty_by_rule_not_by_accident():
    """It returned [] before too — by iterating the dict's KEYS and having the
    isinstance filter drop them. Right answer, no rule behind it."""
    assert dcr.prior_signals_of(CLOUD_EVIDENCE) == []


def test_prior_signals_dedupes():
    assert dcr.prior_signals_of(
        [{"signal": "a"}, {"signal": "a"}, {"signal": "b"}]) == ["a", "b"]


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ THE PIN — enumerated from the AST, never a hand-written list
# ═══════════════════════════════════════════════════════════════════════════

def _evidence_producing_returns():
    """Every `return` in classify_asset / _resolve / _cloud_fallback that yields an
    evidence-bearing result, found by walking the tree. A hand list is the thing
    that went stale twice in 24 hours in lane 4."""
    tree = ast.parse(SRC)
    out = []
    for name in ("classify_asset", "_resolve", "_cloud_fallback"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == name)
        for n in ast.walk(fn):
            if isinstance(n, ast.Return) and n.value is not None:
                out.append((name, n.lineno, ast.unparse(n.value)))
    return out


def test_every_evidence_producing_return_is_accounted_for():
    """⚠ THE MISS, PINNED. classify_asset has TWO return shapes and the 2c fixtures
    only ever carried one. This enumerates the return sites so a THIRD shape cannot
    be added without someone reading this test.

    Anything returning None / a literal dict is checked here; anything delegating
    to another of the three is covered by that one's own returns."""
    sites = _evidence_producing_returns()
    # 10 = classify_asset 2 · _resolve 3 · _cloud_fallback 5 (1 literal + 4 None).
    # ⚠ I first wrote 9 here, from memory rather than from the count, and this
    # assert failed on a correct tree — the pin catching its own author. The number
    # is derived above; it is not a guess.
    assert len(sites) == 10, (
        f"the return sites of classify_asset/_resolve/_cloud_fallback changed "
        f"({len(sites)} now, 10 at relay 241):\n  " +
        "\n  ".join(f"{n}:{ln}  {src}" for n, ln, src in sites) +
        "\nIf a new shape was added, signals_in() must accept it and this count moves.")
    # the ONE site that literally constructs an evidence value
    literal = [s for s in sites if "'evidence': ev" in s[2] or '"evidence": ev' in s[2]]
    assert len(literal) == 1, "the cloud-fallback evidence literal moved or multiplied"


def test_all_three_evidence_readers_go_through_signals_in():
    """⛔ THE ACTUAL FIX. Three readers, one shape. If any of them grows its own
    set-comp again, this fails — which is what did not happen last time, because
    the guard was a habit in one reader instead of a rule with one home."""
    tree = ast.parse(SRC)
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.SetComp, ast.ListComp, ast.GeneratorExp)):
            continue
        s = ast.unparse(node)
        if ".get('signal')" in s or '.get("signal")' in s:
            bad.append((node.lineno, s[:90]))
    assert not bad, (
        "an evidence comprehension is reading `.get('signal')` directly again "
        f"instead of going through signals_in(): {bad}")
    for reader in ("_has_wafw00f",):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == reader)
        assert "signals_in" in ast.get_source_segment(SRC, fn), (
            f"{reader} no longer uses the shared reader")


def test_the_run_loop_uses_signals_in_at_both_sites():
    """The cap-print (:797-shaped) and R5's still_firing. Both were set-comps; the
    first survived on luck, so both are pinned."""
    fn = next(n for n in ast.walk(ast.parse(SRC))
              if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(SRC, fn)
    code = "\n".join(l for l in body.split("\n") if not l.lstrip().startswith("#"))
    assert code.count("signals_in(") == 2, (
        f"run() calls signals_in {code.count('signals_in(')}x; both the cap-print "
        f"and R5's still_firing must use it")
    assert 'e.get("signal") for e in' not in code and "e.get('signal') for e in" not in code
