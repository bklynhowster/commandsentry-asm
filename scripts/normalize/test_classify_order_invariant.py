"""classify() must be ORDER-INVARIANT (4.7 ruling, relay 116/121, 2026-09-14).

⛔ WHY THIS EXISTS. `classify()` picked the winning device_class with max() over a
plain dict whose insertion order comes from `matched` — i.e. from fingerprint FILE
ORDER. Two classes with identical (high, medium, low) tallies were separated by
whichever happened to be matched first. Reproduced on live data
(commandmarketinginnovations.com, 2026-09-14):

    as-produced -> waf / vendor_product {}
    reversed    -> cdn / vendor_product {'vendor': 'Automattic'}

Same observations. Same signals. Only the list order changed. A re-sort of
device_fingerprints.yaml would have flipped classifications fleet-wide with no
code change, and device_class feeds routing (146 R2).

⭐ THIS IS A PROPERTY, NOT A FIXTURE. A fixture pins one arrangement; the defect
lives in the arrangements nobody wrote down. The permutation sweep exercises
orderings the live fleet does not currently produce but will, as light-tier
posture collection adds header signals to more assets (4.7 relay 121: the tie
population is growing *because* of the coverage fix we shipped).
"""
import itertools
import pathlib

import pytest
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import derive_device_class as d  # noqa: E402

FPS = d.load_fingerprints()
TH = d.load_thresholds()

# The real CMI shape: a CDN vendor tell + a WAF presence tell + an origin tell.
# This is the arrangement that produced the live coin flip.
CMI_OBS = {
    "http_headers": "x-ac: true\nserver: nginx\nx-nananana: true\ncache-control: true",
    "waf_present": True,
}
# A second, independent shape — cert + cookie + header, different class mix.
MIXED_OBS = {
    "http_headers": "server: nginx\ncf-ray: abc123\nx-powered-by: PHP",
    "set_cookie_names": ["cookiesession1"],
    "waf_present": True,
}


def _verdicts_over_all_permutations(obs):
    """Run the SHIPPED classify() with `matched` presented in every order."""
    matched = d.match_signals(obs, FPS, TH)
    assert matched, "fixture matched nothing — the test would pass vacuously"
    seen = {}
    original = d.match_signals
    try:
        for perm in itertools.permutations(matched):
            d.match_signals = lambda *a, _p=perm, **k: list(_p)
            r = d.classify(obs, FPS, TH)
            key = (r["device_class"], r["confidence"],
                   r["device_class_confidence"], r["vendor_product_confidence"],
                   tuple(sorted((r["vendor_product"] or {}).items())))
            seen.setdefault(key, 0)
            seen[key] += 1
    finally:
        d.match_signals = original
    return matched, seen


def test_cmi_shape_is_order_invariant():
    """⭐ THE REGRESSION. This shape produced two different verdicts before the fix."""
    matched, seen = _verdicts_over_all_permutations(CMI_OBS)
    assert len(matched) >= 2, f"need >=2 signals to permute, got {len(matched)}"
    assert len(seen) == 1, (
        f"classify() is ORDER-DEPENDENT: {len(seen)} distinct verdicts across "
        f"{sum(seen.values())} permutations of the same {len(matched)} signals -> {seen}")


def test_mixed_shape_is_order_invariant():
    """A second, structurally different shape — one fixture is not a property."""
    matched, seen = _verdicts_over_all_permutations(MIXED_OBS)
    assert len(seen) == 1, (
        f"ORDER-DEPENDENT on the mixed shape: {len(seen)} verdicts -> {seen}")


def test_the_whole_verdict_is_asserted_not_just_device_class():
    """⚠ vendor_product regressed independently of device_class in the live bug:
    the winner-scoped `win["vendor"]` dropped Automattic while the class was also
    wrong. Asserting only device_class would have missed half of it."""
    _, seen = _verdicts_over_all_permutations(CMI_OBS)
    key = next(iter(seen))
    assert len(key) == 5, "verdict key must cover class + both confidences + vendor_product"


def test_tiebreak_table_is_total_over_every_class_in_the_corpus():
    """⛔ A partial ranking reintroduces the bug for any class it omits. Every
    device_class present in device_fingerprints.yaml must have an explicit rank."""
    src = (HERE / "derive_device_class.py").read_text()
    assert "_CLASS_TIEBREAK" in src, "the deterministic tie-break is gone"
    corpus_classes = {fp.get("device_class") for fp in FPS} - {None}
    import re
    m = re.search(r"_CLASS_TIEBREAK = \{([^}]*)\}", src)
    assert m, "could not read _CLASS_TIEBREAK"
    ranked = set(re.findall(r'"([a-z_]+)":', m.group(1)))
    missing = corpus_classes - ranked
    assert not missing, f"device_class values with no explicit tie-break rank: {missing}"


def test_ranking_is_documented_as_status_quo_not_precedence():
    """⭐ The comment is load-bearing. Without it a later reader inherits an
    accidental precedence model as though it had been ratified."""
    src = (HERE / "derive_device_class.py").read_text()
    assert "NOT** A CLAIM THAT A WAF OUTRANKS A CDN" in src or \
           "NOT A CLAIM THAT A WAF OUTRANKS A CDN" in src, \
        "the 'this is not a precedence claim' warning has been removed"


# ── ⛔ KNOWN DEFECT, EXECUTABLE — same-class vendor collision (4.7 relay 123) ──
# The tie-break above made CLASS selection deterministic. VENDOR selection WITHIN
# a class is still last-wins:
#     derive_device_class.py:370   g["vendor"].update(m["vendor_product"])
#     derive_device_class.py:380   slot["vendor"].update(g["vendor"])
# `dict.update()` takes the last writer, and the iteration order comes from
# `matched` — so two vendor_identifying signals in the SAME class with DIFFERENT
# vendors resolve to whichever the loop reaches last.
#
# MEASURED 2026-09-14 on the fixture below: 6 permutations -> 2 verdicts, 3 each.
# ⛔ AND vendor_product_confidence reads `confirmed` in BOTH. The system asserts
# CONFIRMED confidence in a vendor name chosen by list order. That is worse than
# the class-level bug, which at least only produced `suspected`.
#
# ⚠ xfail(strict=True) ON PURPOSE. The defect is real and unfixed; leaving the
# test plain-red would break CI and get muted. strict=True means that when the
# vendor-merge work (② / relay 117) fixes this, the test XPASSes and pytest FAILS
# — forcing whoever fixes it to delete this marker and read the note. A silently
# self-healing xfail would let the fix land with no one noticing the contract
# changed.
@pytest.mark.xfail(strict=True, reason="same-class vendor collision is last-wins; "
                                       "fixed by the vendor-merge work (relay 117 item 2)")
def test_same_class_vendor_collision_is_order_invariant():
    """Cloudflare in front of a Pressable/Automattic origin — a real shape, and
    both tells read the SAME observation (http_headers), so they genuinely
    co-occur rather than being a synthetic pairing."""
    obs = {"http_headers": "x-ac: 1.atl _atomic_dfw MISS\n"
                           "cf-ray: 8a1b2c3d4e5f-EWR\n"
                           "server: nginx"}
    matched, seen = _verdicts_over_all_permutations(obs)
    vendors = {dict(k[4]).get("vendor") for k in seen}
    assert len(seen) == 1, (
        f"vendor is decided by list order: {len(seen)} verdicts across "
        f"{sum(seen.values())} permutations, vendors seen = {vendors}")
