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
import json
import pathlib
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
            # json.dumps(sort_keys=True), NOT tuple(sorted(items())): vendor_product
            # may now hold a `vendors` LIST (② multi-vendor shape), and a list inside
            # a tuple is unhashable. The first version of this harness raised
            # TypeError on the multi-vendor case — which xfail(strict) silently
            # swallowed as "still failing". A harness that cannot represent the
            # fixed output cannot detect the fix.
            key = (r["device_class"], r["confidence"],
                   r["device_class_confidence"], r["vendor_product_confidence"],
                   json.dumps(r["vendor_product"] or {}, sort_keys=True))
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


def test_the_preexisting_four_keep_their_relative_order():
    """⛔ (relay 414) Adding hosting_edge must not move any EXISTING pair.

    The ranks were renumbered to slot hosting_edge between edge_firewall and
    cdn; what must be invariant is the ORDER of the four that were already
    there, because that order is the recorded status quo and moving it would
    silently reclassify assets fleet-wide with no code change of intent.
    """
    import re
    src = (HERE / "derive_device_class.py").read_text()
    m = re.search(r"_CLASS_TIEBREAK = \{(.*?)\}", src, re.S)
    assert m, "could not read _CLASS_TIEBREAK"
    ranks = {k: int(v) for k, v in re.findall(r'"([a-z_]+)":\s*(\d+)', m.group(1))}
    for cls in ("waf", "edge_firewall", "cdn", "origin_host"):
        assert cls in ranks, f"{cls} lost its explicit rank"
    assert ranks["waf"] < ranks["edge_firewall"] < ranks["cdn"] < ranks["origin_host"], (
        f"the pre-existing precedence moved: {ranks}")
    # and the new class sits where 414 documented it: below waf, above cdn.
    assert ranks["edge_firewall"] < ranks["hosting_edge"] < ranks["cdn"], (
        f"hosting_edge is not between edge_firewall and cdn: {ranks}")


# ── (relay 424) THE SCOPED PROMOTION: presence-only waf vs a NAMED hosting edge ──
# 4.7's ruling: a hosting_edge identified by a VENDOR tell outranks a waf backed
# ONLY by presence-only evidence — but a VENDOR-IDENTIFIED waf still wins. The
# asymmetry is the point: masking a real, configured security control is a worse
# error than over-showing one.

def test_presence_only_waf_loses_to_a_NAMED_hosting_edge():
    """⭐ (a) x-ac + presence-only wafw00f -> hosting_edge.

    The live mislabel from relay 424: www.commandcompanies.com and
    www.unimacgraphics.com read `waf` off an anonymous "something filtered us"
    while their own apex domains read `hosting_edge` from the same
    infrastructure. On a named Pressable edge that something IS the edge.
    """
    r = d.classify({"http_headers": "x-ac: 3.dca _dfw\nserver: nginx",
                   "waf_present": True}, FPS, TH)
    assert r["device_class"] == "hosting_edge", (
        f"presence-only waf still outranks a named hosting edge: {r['device_class']}")
    assert (r["vendor_product"] or {}).get("vendor") == "Automattic"


def test_a_VENDOR_IDENTIFIED_waf_still_outranks_a_hosting_edge():
    """⛔ (b) x-ac + a NAMED waf -> waf. The scope limit, and the one that
    matters for safety: a real configured policy must never be hidden behind a
    hosting-edge label. wafw00f naming Cloudflare is vendor_identifying, so the
    reconciliation must NOT fire."""
    r = d.classify({"http_headers": "x-ac: 3.dca _dfw\nserver: nginx",
                   "waf_vendor": "Cloudflare"}, FPS, TH)
    assert r["device_class"] == "waf", (
        f"a vendor-identified WAF was masked by the hosting edge: {r['device_class']}")


def test_the_promotion_does_not_need_the_tallies_to_tie():
    """⚠ Several presence-only waf tells on a NAMED edge are still symptoms of
    that ONE edge, not evidence of N devices — so the rule deliberately carries
    no count condition. Pinned so the choice is tested rather than argued."""
    r = d.classify({"http_headers": "x-ac: 3.dca _dfw\nserver: nginx",
                   "waf_present": True, "waf_present_differential": True}, FPS, TH)
    assert r["device_class"] == "hosting_edge", (
        f"the promotion wrongly requires an equal tally: {r['device_class']}")


def test_a_PRESENCE_ONLY_hosting_edge_does_NOT_win_either():
    """⛔ ISOLATE THE SECOND GATE (relay 312 lesson: each gate tested alone).

    The promotion's whole justification is "the edge we have NAMED" — on a
    named Pressable edge the anonymous waf tell is a SYMPTOM of it. A
    hosting_edge asserted only by PRESENCE-ONLY evidence has named nothing, so
    it has no standing to displace the waf and the reconciliation must not fire.

    No such registry row exists today (both Automattic rows are
    vendor_identifying), so this is pinned against a SYNTHETIC fingerprint set —
    otherwise the guard is unfalsifiable and a future presence-only hosting_edge
    row would silently start winning. A mutation dropping the vendor-identified
    check on the hosting_edge side survives every other test in this file.
    """
    fps = [
        {"signal": "synthetic_presence_only_hosting_edge",
         "observation": "http_headers", "match_substrings": ["x-synthetic-edge:"],
         "device_class": "hosting_edge", "evidence_class": "presence_only",
         "vendor_product": {}},
        {"signal": "waf_present_wafw00f",
         "observation": "waf_present", "match_bool": True,
         "device_class": "waf", "evidence_class": "presence_only",
         "vendor_product": {}},
    ]
    th = json.loads(json.dumps(TH))
    th["weight"]["synthetic_presence_only_hosting_edge"] = "high"
    r = d.classify({"http_headers": "x-synthetic-edge: 1", "waf_present": True}, fps, th)
    assert r["device_class"] == "waf", (
        "a hosting_edge with NO vendor-identifying evidence displaced the waf — "
        f"the 'named edge' condition is gone: {r['device_class']}")


def test_a_presence_only_waf_ALONE_is_still_a_waf():
    """⛔ The reconciliation must not invent a hosting edge that no tell named.
    With no Automattic evidence there is nothing to reconcile to."""
    r = d.classify({"waf_present": True}, FPS, TH)
    assert r["device_class"] == "waf"


def test_ranking_is_documented_as_status_quo_not_precedence():
    """⭐ The comment is load-bearing. Without it a later reader inherits an
    accidental precedence model as though it had been ratified."""
    src = (HERE / "derive_device_class.py").read_text()
    assert "NOT** A CLAIM THAT A WAF OUTRANKS A CDN" in src or \
           "NOT A CLAIM THAT A WAF OUTRANKS A CDN" in src, \
        "the 'this is not a precedence claim' warning has been removed"


# ── same-class vendor collision — WAS a known defect, FIXED by ② (relay 129) ──
# History, kept because the marker's self-retirement is the interesting part:
#   2026-09-14 pinned as xfail(strict=True) — vendor selection within a class was
#   last-wins via dict.update(), and the coin-flipped vendor carried
#   vp_conf=confirmed because two signals had fired. Measured: 6 permutations,
#   2 verdicts, 3 each.
#   Same day, ② landed per-vendor attribution -> the test XPASSed -> strict turned
#   that into a FAILURE -> this marker was removed and the test promoted to a
#   permanent guard. That is exactly the retirement path the strict flag exists
#   to force; a non-strict xfail would have self-healed silently.
# ⚠ One detour worth recording: the first harness built its verdict key with
#   tuple(sorted(items())), which cannot hash the new `vendors` list. It raised
#   TypeError — and xfail swallowed that as "still failing". The fix was invisible
#   to the instrument until the instrument could represent the fixed output.
def test_same_class_vendor_collision_is_order_invariant():
    """Cloudflare in front of a Pressable/Automattic origin — a real shape, and
    both tells read the SAME observation (http_headers), so they genuinely
    co-occur rather than being a synthetic pairing."""
    obs = {"http_headers": "x-ac: 1.atl _atomic_dfw MISS\n"
                           "cf-ray: 8a1b2c3d4e5f-EWR\n"
                           "server: nginx"}
    matched, seen = _verdicts_over_all_permutations(obs)
    assert len(seen) == 1, (
        f"vendor is decided by list order: {len(seen)} verdicts across "
        f"{sum(seen.values())} permutations -> {seen}")
    (_, _, _, vp_conf, vp_json), = seen
    vp = json.loads(vp_json)
    # ② contract: BOTH vendors emitted, each with its OWN confidence, sorted by name.
    assert "vendors" in vp and [e["vendor"] for e in vp["vendors"]] == ["Automattic", "Cloudflare"], vp
    # ⛔ THE CLAIM-EXCEEDS-EVIDENCE GUARD: one signal per vendor -> each is `suspected`.
    # Before ②, ONE of these was published at `confirmed` on the strength of the OTHER.
    assert all(e["confidence"] == "suspected" for e in vp["vendors"]), vp
    # top-level vp_conf is the NOT-APPLICABLE sentinel, never an aggregate (relay 129)
    assert vp_conf == d.VP_CONF_MULTI_VENDOR == "unknown"
