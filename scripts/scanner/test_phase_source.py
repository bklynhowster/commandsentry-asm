#!/usr/bin/env python3
"""test_phase_source.py — the declared-tier source mechanism (spec 190 / 191 Q1).

Two jobs: (1) the module maps tiers to the canonical sources the autocloser keys
on, incl. the standard→medium alias; (2) a REGRESSION PIN that no runner ever
re-derives source from ctx.intensity (the bug this whole change removes). The pin
asserts the ABSENCE of the bad thing, per the wiring-test lesson — a test that
only checks the good value passes even if the old code path is still present.

Run: python3 test_phase_source.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from phase_source import (source_for_tier, all_tier_sources,  # noqa: E402
                          LIGHT, MEDIUM, HEAVY)

HERE = pathlib.Path(__file__).parent


# ── mapping ────────────────────────────────────────────────────────────────

def test_each_tier_maps_to_its_canonical_source():
    assert source_for_tier(LIGHT) == "commandsentry_light"
    assert source_for_tier(MEDIUM) == "commandsentry_medium"
    assert source_for_tier(HEAVY) == "commandsentry_heavy"


def test_standard_intensity_normalizes_to_medium():
    """run_medium accepts intensity='standard' (run_medium.py:3939). It MUST map
    to commandsentry_medium, never an un-autocloseable commandsentry_standard."""
    assert source_for_tier("standard") == "commandsentry_medium"


def test_unknown_tier_raises_loud():
    """A typo must fail at call time, not silently mint a bad source."""
    try:
        source_for_tier("havy")
    except ValueError:
        return
    raise AssertionError("unknown tier did not raise")


def test_all_tier_sources_is_the_three():
    assert all_tier_sources() == frozenset(
        {"commandsentry_light", "commandsentry_medium", "commandsentry_heavy"})


# ── no-op proof: new value == old f-string result for the live intensities ───

def test_new_source_equals_old_fstring_for_live_intensities():
    """The fix is a no-op on existing data ONLY if the constant equals what
    f"commandsentry_{intensity}" produced for every intensity that actually
    runs (light, medium — verified: zero 'standard' rows exist)."""
    for intensity in ("light", "medium"):
        assert source_for_tier(intensity) == f"commandsentry_{intensity}"


# ── regression pin: no runner re-derives source from ctx.intensity ───────────

def test_no_runner_derives_source_from_intensity():
    """The bad pattern was `f"commandsentry_{ctx.intensity}"`. Assert it is GONE
    from every runner — absence of the bad thing, not presence of the good."""
    bad = 'f"commandsentry_{ctx.intensity}"'
    for name in ("run_light.py", "run_medium.py", "run_heavy.py"):
        src = (HERE / name).read_text()
        assert bad not in src, f"{name} still derives source from ctx.intensity"


def test_light_and_medium_call_source_for_tier():
    """Positive wiring pin: the writers actually call the shared helper."""
    light = (HERE / "run_light.py").read_text()
    medium = (HERE / "run_medium.py").read_text()
    assert "source_for_tier(LIGHT)" in light
    assert "source_for_tier(MEDIUM)" in medium


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 6, f"expected >=6 tests, collected {len(tests)}"
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{len(tests) - failed} / {len(tests)} passed")
    sys.exit(1 if failed else 0)
