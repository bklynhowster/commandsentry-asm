"""Unit tests for P1 (Obsidian 146): wiring the two persisted stack-id artifacts
into gather_observations via the pure extractors, and proving those observations
light up the RATIFIED-BUT-DORMANT device_fingerprints.yaml rows.

Two layers:
  1. pure extractors (no DB): waf_vendor_from_wafw00f / http_headers_from_passive
  2. end-to-end contract: the emitted observation actually fires the real registry
     row (wafw00f_high_confidence / product_http_header) — the guard that the
     wiring<->registry handshake stays intact if either side is edited.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))

import device_class_runner as r
from derive_device_class import classify, load_fingerprints, load_thresholds


# ── waf_vendor_from_wafw00f (E1 stack_id_wafw00f -> waf_vendor observation) ───
def test_wafw00f_fortiweb_emits_kind():
    assert r.waf_vendor_from_wafw00f(
        {"schema": 1, "wafw00f_detected": True, "wafw00f_kind": "fortiweb"}) == "fortiweb"


def test_wafw00f_generic_emits_generic_but_names_no_vendor_downstream():
    # 'generic' IS emitted (runner stays dumb) — the registry has no row matching
    # it, so it can never produce a false brand. Verified downstream below.
    assert r.waf_vendor_from_wafw00f(
        {"wafw00f_detected": True, "wafw00f_kind": "generic"}) == "generic"


def test_wafw00f_not_detected_is_none():
    assert r.waf_vendor_from_wafw00f({"wafw00f_detected": False, "wafw00f_kind": None}) is None


def test_wafw00f_missing_or_bad_input_is_none():
    assert r.waf_vendor_from_wafw00f(None) is None
    assert r.waf_vendor_from_wafw00f({"wafw00f_detected": True}) is None   # no kind
    assert r.waf_vendor_from_wafw00f("nope") is None


# ── http_headers_from_passive (P0 stack_id_passive -> http_headers observation) ─
def test_passive_headers_serialized_name_value():
    assert r.http_headers_from_passive({"headers": {"server": "FortiWeb"}}) == "server: FortiWeb"


def test_passive_headers_list_value_joined():
    out = r.http_headers_from_passive({"headers": {"via": ["a", "b"]}})
    assert out == "via: a, b"


def test_passive_headers_multiline():
    out = r.http_headers_from_passive({"headers": {"server": "forti", "x-cache": "hit"}})
    assert "server: forti" in out and "x-cache: hit" in out and "\n" in out


def test_passive_no_headers_or_bad_input_is_none():
    assert r.http_headers_from_passive({"set_cookie_names": ["cookiesession1"]}) is None
    assert r.http_headers_from_passive({"headers": {}}) is None
    assert r.http_headers_from_passive(None) is None
    assert r.http_headers_from_passive("nope") is None


# ── end-to-end: emitted observation lights up the real dormant registry row ───
def test_waf_vendor_observation_fires_wafw00f_row():
    fps, th = load_fingerprints(), load_thresholds()
    obs = {"waf_vendor": r.waf_vendor_from_wafw00f(
        {"wafw00f_detected": True, "wafw00f_kind": "fortiweb"})}
    res = classify(obs, fps, th)
    assert res["device_class"] == "waf"
    assert res["vendor_product"].get("vendor") == "Fortinet"
    # one vendor_identifying HIGH signal -> vendor bar 'suspected' (needs a 2nd tell
    # for 'confirmed'); device_class bar likewise 'suspected' off the single signal.
    assert res["vendor_product_confidence"] == "suspected"


def test_http_headers_observation_fires_product_header_row():
    fps, th = load_fingerprints(), load_thresholds()
    obs = {"http_headers": r.http_headers_from_passive({"headers": {"server": "FortiWeb"}})}
    res = classify(obs, fps, th)
    assert res["device_class"] == "edge_firewall"
    assert res["vendor_product"].get("vendor") == "Fortinet"
    assert res["vendor_product_confidence"] == "suspected"


def test_generic_wafw00f_names_no_vendor_end_to_end():
    # The dumb-runner claim, proven: 'generic' emitted, but classify names nothing.
    fps, th = load_fingerprints(), load_thresholds()
    obs = {"waf_vendor": r.waf_vendor_from_wafw00f(
        {"wafw00f_detected": True, "wafw00f_kind": "generic"})}
    res = classify(obs, fps, th)
    assert res["device_class"] == "unknown"        # no row matched 'generic'
    assert res["vendor_product"] == {}
    assert res["vendor_product_confidence"] == "unknown"
