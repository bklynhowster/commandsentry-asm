"""Unit tests for P0.5 / R5 (Obsidian 146): the two-bar confidence split in
derive_device_class.classify().

The load-bearing invariant: presence_only signals can drive device_class_confidence
to 'confirmed' ("a WAF is present") WITHOUT ever raising vendor_product_confidence
above 'unknown' ("...but we have not earned the right to name Fortinet"). P2 gates
CVE attribution on vendor_product_confidence == 'confirmed', so this split is what
stops fabricated CVE findings on presence-only-confirmed assets.

Pure — inline fingerprint/threshold fixtures, no DB/network/YAML.
"""
import derive_device_class as d


# ── fixtures ────────────────────────────────────────────────────────────────
# waf class only. Mix of presence_only (confirm the class, never name a vendor)
# and vendor_identifying (the only signals allowed to move vendor_product_confidence).
FPS = [
    {"signal": "wafw00f", "observation": "waf_present", "match_bool": True,
     "device_class": "waf", "evidence_class": "presence_only", "vendor_product": {}},
    {"signal": "block_page", "observation": "block_page", "match_bool": True,
     "device_class": "waf", "evidence_class": "presence_only", "vendor_product": {}},
    {"signal": "vendor_cookie", "observation": "http_headers",
     "match_substrings": ["cookiesession1"], "device_class": "waf",
     "evidence_class": "vendor_identifying",
     "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}},
    {"signal": "vendor_header", "observation": "http_headers",
     "match_substrings": ["fortiwebid"], "device_class": "waf",
     "evidence_class": "vendor_identifying",
     "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}},
    {"signal": "cert_o", "observation": "cert_issuer",
     "match_substrings": ["fortinet"], "device_class": "waf",
     "evidence_class": "vendor_identifying", "vendor_product": {"vendor": "Fortinet"}},
    {"signal": "minor", "observation": "minor", "match_bool": True,
     "device_class": "waf", "evidence_class": "presence_only", "vendor_product": {}},
]
TH = {"weight": {"wafw00f": "high", "block_page": "high", "vendor_cookie": "high",
                 "vendor_header": "high", "cert_o": "medium", "minor": "low"}}


def _classify(obs):
    return d.classify(obs, FPS, TH)


# ── the core invariant ──────────────────────────────────────────────────────
def test_presence_only_confirms_class_but_never_names_vendor():
    # Two high presence_only signals: device_class 'confirmed', but vendor stays unknown.
    r = _classify({"waf_present": True, "block_page": True})
    assert r["device_class"] == "waf"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "unknown"   # <-- the load-bearing gate
    assert r["vendor_product"] == {}                     # no vendor named, ever


def test_one_vendor_signal_names_vendor_at_suspected_while_class_confirmed():
    # vendor_cookie (VI high) + wafw00f (presence high): class confirmed on the pair,
    # but vendor_product_confidence rides ONLY the single VI signal -> 'suspected'.
    r = _classify({"http_headers": "set-cookie: cookiesession1=x", "waf_present": True})
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "suspected"
    assert r["vendor_product"] == {"vendor": "Fortinet", "product": "FortiWeb"}


def test_two_vendor_signals_confirm_vendor():
    # Two VI high signals in the same header blob -> vendor_product_confidence confirmed.
    r = _classify({"http_headers": "set-cookie: cookiesession1=x; server: fortiwebid"})
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "confirmed"
    assert r["vendor_product"]["vendor"] == "Fortinet"


def test_presence_confirmed_plus_one_vendor_medium_is_vendor_unknown():
    # Class confirmed via 2 presence highs; the only VI signal is a single medium
    # (cert_o) -> _confidence(0 high, 1 medium) == 'unknown'. Class known, vendor not.
    r = _classify({"waf_present": True, "block_page": True, "cert_issuer": "CN=Fortinet Inc"})
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "unknown"


# ── backward-compat / routing-stability ─────────────────────────────────────
def test_confidence_key_preserved_and_equals_device_class_confidence():
    # The routing/write path (device_class_runner) reads result['confidence'].
    # It must remain byte-identical to the old single confidence == device_class_confidence.
    r = _classify({"waf_present": True, "block_page": True})
    assert "confidence" in r
    assert r["confidence"] == r["device_class_confidence"]


# ── shape on the no-decision paths ──────────────────────────────────────────
def test_no_match_carries_both_new_keys():
    r = _classify({})
    assert r["device_class"] == d.DEFAULT_CLASS
    assert r["confidence"] == "unknown"
    assert r["device_class_confidence"] == "unknown"
    assert r["vendor_product_confidence"] == "unknown"


def test_only_low_weight_stays_unknown_with_both_keys():
    # A single low-weight presence signal can't clear 'suspected' -> unknown path.
    r = _classify({"minor": True})
    assert r["confidence"] == "unknown"
    assert r["device_class_confidence"] == "unknown"
    assert r["vendor_product_confidence"] == "unknown"


def test_evidence_class_threaded_onto_records():
    # match_signals must carry evidence_class so classify can score the VI-only bar.
    recs = d.match_signals({"waf_present": True, "http_headers": "cookiesession1"}, FPS, TH)
    by_sig = {r["signal"]: r for r in recs}
    assert by_sig["wafw00f"]["evidence_class"] == "presence_only"
    assert by_sig["vendor_cookie"]["evidence_class"] == "vendor_identifying"
