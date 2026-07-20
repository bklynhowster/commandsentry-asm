"""Unit tests for the cookie / generic-WAF signals (4.7 Q1/Q2/Q4/Q8e, Obsidian 146).
Exercises exact cookie matching, the R4 citation gate, and the two-bar outcomes
against the REAL registry (device_fingerprints.yaml + cookie_signatures.yaml)."""
import derive_device_class as d


def _classify(obs):
    return d.classify(obs, d.load_fingerprints(), d.load_thresholds())


# ── exact cookie-name matching (4.7 Q8e) ────────────────────────────────────
def test_cookiesession1_exact_match_fires_fortiweb():
    r = _classify({"set_cookie_names": [".AspNetCore.Antiforgery.x", ".SCI.Session", "cookiesession1"]})
    assert r["device_class"] == "waf"
    assert r["vendor_product"].get("vendor") == "Fortinet"
    assert r["vendor_product"].get("product") == "FortiWeb"
    assert r["vendor_product_confidence"] == "suspected"   # lone cookie -> suspected


def test_cookiesession1_is_exact_not_substring():
    # cookies whose names merely CONTAIN the string must NOT match (Q8e).
    r = _classify({"set_cookie_names": ["cookiesession1234", "cookiesession1_backup"]})
    assert r["device_class"] == "unknown"
    assert r["vendor_product"] == {}


# ── generic WAF presence (4.7 Q1) ───────────────────────────────────────────
def test_generic_waf_presence_only():
    r = _classify({"waf_present": True})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "suspected"     # one high presence signal
    assert r["vendor_product_confidence"] == "unknown"     # names no vendor
    assert r["vendor_product"] == {}


# ── the ccc outcome: generic wafw00f + the passive cookiesession1 ────────────
def test_ccc_generic_plus_cookie_confirms_class_suspects_vendor():
    # wafw00f=generic (waf_present) + passive cookiesession1 = 2 INDEPENDENT
    # device-class tells -> confirmed WAF; 1 vendor tell -> suspected FortiWeb.
    r = _classify({"waf_present": True, "set_cookie_names": ["cookiesession1"]})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "suspected"
    assert r["vendor_product"].get("vendor") == "Fortinet"


# ── R4-revised independence: cookie + wafw00f-fortiweb -> confirmed vendor ───
def test_cookie_plus_wafw00f_fortiweb_confirms_vendor():
    # cookiesession1 (Fortinet-doc) + wafw00f kind=fortiweb (keys on FORTIWAFSID /
    # block page, never cookiesession1) = independent artifacts = 2 vendor tells.
    r = _classify({"set_cookie_names": ["cookiesession1"], "waf_vendor": "fortiweb"})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "confirmed"
    assert r["vendor_product"].get("vendor") == "Fortinet"


# ── R4 citation gate (4.7 Q2/Q8b) ───────────────────────────────────────────
def test_real_registry_passes_citation_gate():
    assert d.validate_cookie_citations(d.load_fingerprints()) == []


def test_uncited_cookie_row_is_rejected():
    bad = [{"signal": "x", "observation": "set_cookie_names", "match_values": ["totallymadeup"],
            "device_class": "waf", "evidence_class": "vendor_identifying",
            "vendor_product": {"vendor": "Acme"}}]
    errs = d.validate_cookie_citations(bad)
    assert errs and "no cookie_signatures.yaml entry" in errs[0]


def test_cookie_row_vendor_must_match_corpus():
    # cookiesession1 is Fortinet in the corpus; a row claiming Cloudflare is rejected.
    bad = [{"signal": "x", "observation": "set_cookie_names", "match_values": ["cookiesession1"],
            "device_class": "waf", "evidence_class": "vendor_identifying",
            "vendor_product": {"vendor": "Cloudflare"}}]
    errs = d.validate_cookie_citations(bad)
    assert errs and "!= row vendor" in errs[0]


def test_corpus_cookiesession1_is_vendor_primary_cited():
    sigs = d.load_cookie_signatures()
    cit = sigs["cookiesession1"]["citation"]
    assert cit["source_type"] == "vendor_primary_documentation"
    assert "fortinet.com" in cit["url"] and cit["quote"]
