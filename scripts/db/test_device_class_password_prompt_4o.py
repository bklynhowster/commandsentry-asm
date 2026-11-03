"""(KB 12 job 4o, 2026-11-02) A password prompt is not a firewall.

ftp.unimacgraphics.com and ftp.commandmi.com run Globalscape EFT, which answers any request
not made from a browser with HTTP 401 Basic. wafw00f's generic check reads that as "seems to
be behind a WAF" ("The response was different when the request wasn't made from a browser.
Normal response code is "200", while the response code to a modified request is "401""), and
the classifier turned it into "A web application firewall we could not name" on the page.
Howie, 17:00: "it's misleading".

Pins:
  * a generic wafw00f verdict whose stated reason is a 401 to a non-browser request adds
    NO waf_present observation;
  * any other generic reason (an attack string answered 403) still does;
  * a generic verdict written before 4o (no reason recorded) is unchanged until the next deep
    scan writes the reason (nothing is guessed from an artifact that does not say);
  * a named vendor is untouched;
  * end to end, the EFT shape no longer classifies as a WAF.
"""
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
from derive_device_class import classify, load_fingerprints, load_thresholds  # noqa: E402
from test_device_class_differential_310 import Cur  # noqa: E402

NOW = datetime(2026, 11, 2, 23, 0, tzinfo=timezone.utc)
EFT_REASON = {"text": "The response was different when the request wasn't made from a browser. "
                      "Normal response code is \"200\", while the response code to a modified request is \"401\"",
              "non_browser": True, "normal_code": 200, "modified_code": 401}
ATTACK_REASON = {"text": "The server returns a different response code when an attack string is used. "
                         "Normal response code is \"200\", while the response code to cross-site scripting attack is \"403\"",
                 "non_browser": False, "normal_code": 200, "modified_code": 403}


def _wafw00f(kind="generic", reason=None):
    v = {"schema": 1, "wafw00f_detected": True, "wafw00f_kind": kind}
    if reason is not None:
        v["wafw00f_generic_reason"] = reason
    return json.dumps(v)


def _obs(blob):
    return dcr.gather_observations(Cur({"stack_id_wafw00f": [(blob, NOW)]}),
                                   "ftp.unimacgraphics.com", 30, "^nuclei:fortinet")


def test_the_pure_rule():
    assert dcr._wafw00f_saw_only_a_password_prompt({"wafw00f_generic_reason": EFT_REASON})
    assert not dcr._wafw00f_saw_only_a_password_prompt({"wafw00f_generic_reason": ATTACK_REASON})
    assert not dcr._wafw00f_saw_only_a_password_prompt(
        {"wafw00f_generic_reason": dict(EFT_REASON, modified_code=403)})
    # an attack string answered 401 is a refusal, not the browser check: still presence
    assert not dcr._wafw00f_saw_only_a_password_prompt(
        {"wafw00f_generic_reason": dict(ATTACK_REASON, modified_code=401)})
    assert not dcr._wafw00f_saw_only_a_password_prompt({})
    assert not dcr._wafw00f_saw_only_a_password_prompt(None)


def test_a_password_prompt_adds_no_presence_signal():
    obs = _obs(_wafw00f(reason=EFT_REASON))
    assert "waf_present" not in obs and "waf_vendor" not in obs


def test_an_attack_string_refused_still_counts():
    assert _obs(_wafw00f(reason=ATTACK_REASON)).get("waf_present") is True


def test_a_pre_4o_generic_verdict_is_unchanged():
    assert _obs(_wafw00f()).get("waf_present") is True


def test_a_named_vendor_is_untouched():
    obs = _obs(_wafw00f(kind="fortiweb", reason=EFT_REASON))
    assert obs.get("waf_vendor") == "fortiweb" and "waf_present" not in obs


def test_end_to_end_the_eft_shape_is_not_a_waf():
    fps, th = load_fingerprints(), load_thresholds()
    before = classify(_obs(_wafw00f()), fps, th)
    after = classify(_obs(_wafw00f(reason=EFT_REASON)), fps, th)
    assert before["device_class"] == "waf"
    assert after["device_class"] != "waf"
