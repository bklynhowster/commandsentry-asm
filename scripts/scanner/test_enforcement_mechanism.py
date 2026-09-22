"""relay 414 (Axis 2) — the mechanism rule, and its MIRROR pin to the portal.

⛔ THE POINT OF THE MIRROR PIN (relay 352): enforcement_mechanism.py and the
portal's src/lib/enforcement-mechanism.mjs implement ONE rule in TWO languages,
in two repos that cannot import each other. A shared rule with no shared test is
precisely how the vendor digest and the vendor chip came to carry the same bug.
So the fixture table is asserted HERE and THERE, and both suites assert the
COUNT as well as the cases — adding a case to one side alone reds the other.

    python3 scripts/scanner/test_enforcement_mechanism.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enforcement_mechanism import (  # noqa: E402
    MECHANISM_FIXTURES,
    fixture_vendor_product,
    MECHANISM_NONE,
    MECHANISM_RATE,
    MECHANISM_SIGNATURE,
    enforcement_applies,
    is_rate_based_vendor,
    resolve_enforcement_mechanism,
)

MIRROR = "commandsentry-portal/src/lib/enforcement-mechanism.mjs"

# the SHARED builder — honours the __STR__ bare-string encoding (relay 424)
_vp = fixture_vendor_product


# ── the fixture table itself ────────────────────────────────────────────────

def test_every_fixture_case():
    for cls, vendor, product, expected, why in MECHANISM_FIXTURES:
        got = resolve_enforcement_mechanism(cls, _vp(vendor, product))
        assert got == expected, (
            f"{cls!r} + vendor={vendor!r}/{product!r} -> {got!r}, expected "
            f"{expected!r}\n       reason on record: {why}")




def test_fixture_count_is_pinned_for_the_mirror():
    # ⛔ THE COUNT IS THE MIRROR PIN. If you add or remove a case here you MUST
    # make the identical edit in the portal, whose suite asserts this same
    # number. That is what keeps one rule from becoming two.
    # 17 -> 21 in relay 424: four vendor-SHAPE cases (bare string vs dict).
    assert len(MECHANISM_FIXTURES) == 21, (
        f"fixture count is {len(MECHANISM_FIXTURES)}, pinned at 21 — if that was "
        f"deliberate, make the SAME edit in {MIRROR} and update both counts")


def test_bare_string_vendor_resolves_like_the_dict():
    # ⭐ (relay 424) 4.7's finding. The string path used to fall through to
    # `signature`, which would have routed a Pressable host into a probe it
    # cannot answer. Both shapes are now asserted AGAINST EACH OTHER.
    for name in ("Automattic", "Fortinet", "fortinet", "FortiWeb"):
        assert resolve_enforcement_mechanism("waf", name) == MECHANISM_RATE, name
        assert resolve_enforcement_mechanism("waf", {"vendor": name}) == MECHANISM_RATE, name
        assert is_rate_based_vendor(name) is True, name
    # …and the fix must NOT over-match: a non-rate vendor stays signature.
    assert resolve_enforcement_mechanism("waf", "Cloudflare") == MECHANISM_SIGNATURE
    assert is_rate_based_vendor("Cloudflare") is False
    # non-str non-dict still fails closed to "no vendor".
    for junk in (123, True, [], None, ""):
        assert is_rate_based_vendor(junk) is False, junk




def test_fixtures_cover_all_three_mechanisms():
    got = {f[3] for f in MECHANISM_FIXTURES}
    assert got == {MECHANISM_SIGNATURE, MECHANISM_RATE, MECHANISM_NONE}, (
        f"fixtures only exercise {sorted(got)} — a table that never produces one "
        f"of the three outcomes cannot falsify that outcome's rule")




# ── the rules that mutations must not be able to break ──────────────────────

def test_rule_order_class_none_beats_vendor():
    # ⛔ THE DECISIVE ORDERING. A CDN fronted by a rate-based vendor is STILL a
    # CDN. If the vendor rule ran first, every Automattic/Fortinet CDN would be
    # dragged into the enforcement population and read "not verified" forever
    # on a thing whose job was never to enforce.
    assert resolve_enforcement_mechanism("cdn", {"vendor": "Automattic"}) == MECHANISM_NONE
    assert resolve_enforcement_mechanism("cdn", {"vendor": "Fortinet"}) == MECHANISM_NONE
    assert resolve_enforcement_mechanism("origin_host", {"vendor": "Fortinet"}) == MECHANISM_NONE




def test_vendor_rule_survives_a_wrong_class():
    # ⭐ THE LIVE DRIFT (relay 414 O1). www.commandcompanies.com and
    # www.unimacgraphics.com dry-run to `waf` because presence-only wafw00f
    # outranks the vendor-identifying Automattic tell. The mechanism must still
    # route them AWAY from the signature differential — otherwise a wrong class
    # silently produces a wrong enforcement verdict.
    assert resolve_enforcement_mechanism("waf", {"vendor": "Automattic"}) == MECHANISM_RATE
    assert resolve_enforcement_mechanism("waf", {"vendor": "Fortinet",
                                                 "product": "FortiWeb"}) == MECHANISM_RATE




def test_signature_edges_are_not_swept_into_rate():
    # The 405 guard, restated: Cloud Armor must stay `signature`, or a clean
    # single-signature pass stops meaning anything and www.prodexlabs.com's
    # real "not enforcing" finding evaporates.
    assert resolve_enforcement_mechanism(
        "waf", {"vendor": "Google Cloud", "product": "Google Cloud Armor"}) == MECHANISM_SIGNATURE
    assert resolve_enforcement_mechanism("waf", {"vendor": "Cloudflare"}) == MECHANISM_SIGNATURE
    assert resolve_enforcement_mechanism("waf", None) == MECHANISM_SIGNATURE




def test_is_rate_based_vendor_is_substring_and_case_insensitive():
    for vp in ({"vendor": "Fortinet"}, {"product": "FortiWeb"}, {"vendor": "fortinet"},
               {"vendor": "Automattic"}, {"vendor": "automattic"}):
        assert is_rate_based_vendor(vp) is True, vp
    # (424) "Fortinet" as a BARE STRING is now True — see the shape test above.
    assert is_rate_based_vendor("Fortinet") is True
    for vp in ({"vendor": "Google Cloud", "product": "Google Cloud Armor"},
               {"vendor": "Cloudflare"}, {}, None):
        assert is_rate_based_vendor(vp) is False, vp




# ── the derived population ──────────────────────────────────────────────────

def test_enforcement_applies_is_derived_not_hardcoded():
    # Everything that used to be in PROTECTIVE_CLASSES still applies …
    for cls in ("waf", "edge_firewall", "adc_lb"):
        assert enforcement_applies(cls) is True, cls
    # … plus the new hosting edge …
    assert enforcement_applies("hosting_edge", {"vendor": "Automattic"}) is True
    # … and nothing else got dragged in.
    for cls in ("cdn", "origin_host", "cloud_endpoint", "unknown", "unreadable", None, ""):
        assert enforcement_applies(cls) is False, cls




def test_population_grows_by_hosting_edge_ONLY():
    # ⛔ BLAST-RADIUS PIN. Against the OLD hardcoded list, the only membership
    # change this relay may cause is the addition of hosting_edge. If any other
    # class enters or leaves, the taxonomy change was not confined.
    old = ("waf", "edge_firewall", "adc_lb")
    every_class = ("waf", "edge_firewall", "adc_lb", "cdn", "origin_host",
                   "cloud_endpoint", "hosting_edge", "unknown", "unreadable")
    entered, left = [], []
    for cls in every_class:
        was = cls in old
        now = enforcement_applies(cls)
        if now and not was:
            entered.append(cls)
        if was and not now:
            left.append(cls)
    assert entered == ["hosting_edge"], f"unexpected entrants: {entered}"
    assert left == [], f"classes silently dropped out of the population: {left}"




if __name__ == "__main__":
    # ⚠ Standalone runner ONLY. A module-level sys.exit() breaks pytest at
    # COLLECTION time (SystemExit during import = INTERNALERROR), which would
    # take the whole scanner lane down with it. Guarded so pytest imports the
    # test_* functions natively and the file still runs on its own.
    _failed = []
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn()
                print(f"  ok   {_name}")
            except AssertionError as _e:
                _failed.append(_name)
                print(f"  FAIL {_name}")
                print(f"       {str(_e).splitlines()[0]}")
    print("enforcement-mechanism check (relay 414):",
          "PASS" if not _failed else f"{len(_failed)} FAILURE(S)")
    sys.exit(0 if not _failed else 1)
