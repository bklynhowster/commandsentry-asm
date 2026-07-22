"""Unit tests for the artifact-signature corpus + citation gate (4.7 Q1/Q2/Q4/Q5/
Q8e, Obsidian 146). Generalizes the former test_cookie_signals.py: exact cookie
matching, the R4 citation gate (now over any cited artifact — cookies AND the
fwbbot_check challenge-endpoint), and the two-bar outcomes against the REAL registry
(device_fingerprints.yaml + artifact_signatures.yaml)."""
import derive_device_class as d


def _classify(obs):
    return d.classify(obs, d.load_fingerprints(), d.load_thresholds())


# ── exact cookie-name matching (4.7 Q8e) ────────────────────────────────────
def test_cookiesession1_exact_match_fires_fortiweb():
    r = _classify({"set_cookie_names": [".AspNetCore.Antiforgery.x", ".SCI.Session", "cookiesession1"]})
    assert r["device_class"] == "waf"
    assert r["vendor_product"].get("vendor") == "Fortinet"
    assert r["vendor_product"].get("product") == "FortiWeb"
    assert r["vendor_product_confidence"] == "suspected"


def test_cookiesession1_is_exact_not_substring():
    r = _classify({"set_cookie_names": ["cookiesession1234", "cookiesession1_backup"]})
    assert r["device_class"] == "unknown"
    assert r["vendor_product"] == {}


# ── generic WAF presence (4.7 Q1) + ccc outcome ─────────────────────────────
def test_generic_waf_presence_only():
    r = _classify({"waf_present": True})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "suspected"
    assert r["vendor_product_confidence"] == "unknown"
    assert r["vendor_product"] == {}


def test_ccc_generic_plus_cookie_confirms_class_suspects_vendor():
    r = _classify({"waf_present": True, "set_cookie_names": ["cookiesession1"]})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "suspected"
    assert r["vendor_product"].get("vendor") == "Fortinet"


def test_cookie_plus_wafw00f_fortiweb_confirms_vendor():
    r = _classify({"set_cookie_names": ["cookiesession1"], "waf_vendor": "fortiweb"})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "confirmed"
    assert r["vendor_product"].get("vendor") == "Fortinet"


# ── the fwbbot_check row confirms ccc (once the observation is wired, Phase D) ─
def test_fwbbot_check_is_independent_second_fortiweb_tell():
    # cookiesession1 (cookie) + fwbbot_check (challenge endpoint) = 2 independent
    # vendor tells -> confirmed FortiWeb. (Directly sets obs; the active-probe
    # collector that emits `fwbbot_check` lands in Phase B/D.)
    r = _classify({"set_cookie_names": ["cookiesession1"], "fwbbot_check": True})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "confirmed"
    assert r["vendor_product"].get("vendor") == "Fortinet"


def test_fwbbot_check_alone_names_fortiweb_at_suspected():
    r = _classify({"fwbbot_check": True})
    assert r["device_class"] == "waf"
    assert r["vendor_product"].get("vendor") == "Fortinet"
    assert r["vendor_product_confidence"] == "suspected"


# ── R4 citation gate (4.7 Q2/Q5/Q8b), now over any cited artifact ───────────
def test_real_registry_passes_citation_gate():
    # cookiesession1 AND the fwbbot_check row are both cited in the real corpus.
    assert d.validate_artifact_citations(d.load_fingerprints()) == []


def test_uncited_cookie_artifact_is_rejected():
    bad = [{"signal": "x", "observation": "set_cookie_names", "match_values": ["totallymadeup"],
            "device_class": "waf", "evidence_class": "vendor_identifying",
            "vendor_product": {"vendor": "Acme"}}]
    errs = d.validate_artifact_citations(bad)
    assert errs and "no artifact_signatures.yaml entry" in errs[0]


def test_uncited_challenge_endpoint_is_rejected():
    # a vendor_identifying fwbbot_check row with an EMPTY corpus must be rejected.
    row = [{"signal": "x", "observation": "fwbbot_check", "match_bool": True,
            "device_class": "waf", "evidence_class": "vendor_identifying",
            "vendor_product": {"vendor": "Fortinet"}}]
    errs = d.validate_artifact_citations(row, sigs={})
    assert errs and "fwbbot_check" in errs[0] and "no artifact_signatures.yaml entry" in errs[0]


def test_artifact_row_vendor_must_match_corpus():
    bad = [{"signal": "x", "observation": "set_cookie_names", "match_values": ["cookiesession1"],
            "device_class": "waf", "evidence_class": "vendor_identifying",
            "vendor_product": {"vendor": "Cloudflare"}}]
    errs = d.validate_artifact_citations(bad)
    assert errs and "!= row vendor" in errs[0]


# ── corpus provenance ───────────────────────────────────────────────────────
def test_corpus_cookiesession1_is_vendor_primary_cited():
    sigs = d.load_artifact_signatures()
    cit = sigs["cookiesession1"]["citation"]
    assert cit["source_type"] == "vendor_primary_documentation"
    assert "fortinet.com" in cit["url"] and cit["quote"]
    assert sigs["cookiesession1"]["artifact_type"] == "set_cookie_name"


def test_corpus_fwbbot_check_cited_with_independence_dependency():
    sigs = d.load_artifact_signatures()
    e = sigs["fwbbot_check"]
    assert e["artifact_type"] == "challenge_endpoint_path"
    assert e["vendor"] == "Fortinet" and e["product"] == "FortiWeb"
    assert "fortinet.com" in e["citation"]["url"] and e["citation"]["quote"]
    # 4.7 Q2/Q8c: independence on wafw00f NOT probing /fwbbot_check is recorded.
    assert e["independence_dependencies"]["wafw00f_fortiweb_plugin_does_not_probe_fwbbot_check"] is True


# ── Automattic x-ac edge-cache header (4.7 2026-07-22, Obsidian 153) ─────────
def test_x_ac_header_fires_automattic_suspected():
    # Pressable/Automattic edge-cache header. One vendor_identifying high -> suspected.
    r = _classify({"http_headers": "x-ac: True\nserver: nginx"})
    assert r["device_class"] == "cdn"
    assert r["vendor_product"].get("vendor") == "Automattic"
    assert r["vendor_product_confidence"] == "suspected"


def test_x_ac_is_colon_anchored_not_x_accel():
    # LOAD-BEARING (4.7 Q5): the cited token is "x-ac:" — a bare "x-ac" substring
    # would false-match nginx's x-accel-* headers. If someone drops the colon
    # anchor, this test catches it. A delete-this-test PR must never merge.
    r = _classify({"http_headers": "x-accel-buffering: True\nserver: nginx"})
    assert r["device_class"] == "unknown"
    assert r["vendor_product"] == {}


def test_x_ac_does_not_fire_on_x_account():
    r = _classify({"http_headers": "x-account-id: 42\nserver: nginx"})
    assert r["vendor_product"] == {}


def test_corpus_x_ac_is_vendor_primary_cited():
    sigs = d.load_artifact_signatures()
    e = sigs["x-ac:"]
    assert e["artifact_type"] == "response_header_token"
    assert e["vendor"] == "Automattic"
    assert e["citation"]["source_type"] == "vendor_primary_documentation"
    assert "pressable.com" in e["citation"]["url"] and e["citation"]["quote"]
