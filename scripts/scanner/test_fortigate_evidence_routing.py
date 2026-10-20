"""FortiGate safe-only routing keys on per-asset EVIDENCE (rule 4b).

Two branches: the scan's own runtime wafw00f verdict (a) and the recorded
Fortinet vendor read off the poll descriptor (b). These tests pin branch b
end-to-end: a descriptor carrying the columns fires, and one without them does
not — so a broken SQL->descriptor pipe is caught as a red test, not silent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from run_medium import is_fortigate_target, ScanContext  # noqa: E402


def _ctx(asset: dict) -> ScanContext:
    ctx = ScanContext.__new__(ScanContext)
    ctx.waf_kind = None
    ctx.descriptor = {"asset": asset}
    return ctx


def _asset(**kw) -> dict:
    a = {"device_class": "unknown", "device_class_confidence": "unknown",
         "vendor_product": None, "vendor_product_confidence": "unknown"}
    a.update(kw)
    return a


def test_recorded_fortinet_vendor_confirmed_routes_safe_only():
    ctx = _ctx(_asset(vendor_product={"vendor": "Fortinet", "product": "FortiWeb"},
                      vendor_product_confidence="confirmed"))
    assert is_fortigate_target(ctx) is True


def test_recorded_fortinet_vendor_suspected_routes_safe_only():
    ctx = _ctx(_asset(vendor_product={"vendor": "FortiWeb"},
                      vendor_product_confidence="suspected"))
    assert is_fortigate_target(ctx) is True


def test_fortinet_vendor_unknown_confidence_does_not_route():
    # Pins the confidence gate (rule 4b / note 146 R6): a Fortinet vendor whose
    # confidence is outside {suspected, confirmed} must not route — presence-only
    # evidence names a role, not a vendor, so it cannot open the safe-only plan.
    ctx = _ctx(_asset(vendor_product={"vendor": "Fortinet", "product": "FortiWeb"},
                      vendor_product_confidence="unknown"))
    assert is_fortigate_target(ctx) is False


def test_non_fortinet_vendor_does_not_route():
    ctx = _ctx(_asset(vendor_product={"vendor": "Google Cloud", "product": "Cloud Armor"},
                      vendor_product_confidence="confirmed"))
    assert is_fortigate_target(ctx) is False


def test_empty_vendor_does_not_route():
    ctx = _ctx(_asset(vendor_product={}, vendor_product_confidence="suspected"))
    assert is_fortigate_target(ctx) is False


def test_descriptor_without_vendor_columns_does_not_route():
    ctx = _ctx({})
    assert is_fortigate_target(ctx) is False


def test_runtime_waf_kind_branch_still_fires():
    ctx = _ctx({})
    ctx.waf_kind = "fortiweb"
    assert is_fortigate_target(ctx) is True