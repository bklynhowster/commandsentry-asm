"""(Obsidian 310, 2026-10-13) The differential WAF probe's MEASUREMENT reaches the classifier.

The test case is real and recorded: uat.prodexlabs.com. wafw00f has named "Google Cloud
App Armor" on it since July (one tool, one dedupe key -> waf/suspected). On 2026-10-12
19:58Z the heavy tier's differential probe measured 0 of 3 attack-payload classes blocked;
on 2026-10-13 18:39Z it measured all 3 blocked behind a Google 403 page. Same name both
days; enforcement only on the second. Before this change the classifier never read the
measurement, so the label could not move and the asset page said "attack blocked" and "no
enforcing WAF" two inches apart.

Pins:
  * the artifact's three values mean three things: null = did not look, false = measured
    pass-through, true = measured block; the NEWEST artifact WITH A VERDICT decides;
  * capability is "a verdict exists" (NOT_NULL): a dry-run after a block cannot strip
    it (R5 preserves), a measured pass-through after a block CAN (it is a real negative);
  * wafw00f's name + the measured block = waf/CONFIRMED, vendor still 'suspected' from the
    name alone (the differential never names a vendor — 4.7 Q3/Q8 unchanged);
  * read depth is one shared constant for the gather and for capability.
"""
import ast
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
from derive_device_class import classify, load_fingerprints, load_thresholds  # noqa: E402

NOW = datetime(2026, 10, 13, 18, 45, tzinfo=timezone.utc)
ART = "stack_id_waf_differential"


def _diff(verdict, blocked=()):
    return json.dumps({"schema": 1, "probe_class": "waf_differential",
                       "waf_present_differential": verdict, "blocked": list(blocked),
                       "reason": "", "details": {"live_flag": verdict is not None}})


def _wafw00f(kind="google_cloud_app_armor"):
    return json.dumps({"schema": 1, "wafw00f_kind": kind, "wafw00f_detected": True})


class Cur:
    """Serves gather_observations AND the capability probes from one artifact table,
    keyed on the tool_name parameter (never on SQL text)."""

    def __init__(self, artifacts):
        self.artifacts = artifacts          # {tool: [(blob, completed_at), ...]}
        self._r = []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if "scan_run_artifacts" not in s or not params:
            self._r = []
            return
        tool = params[1]
        rows = []
        for name, entries in self.artifacts.items():
            ok = name.startswith(tool[:-1]) if tool.endswith("%") else name == tool
            if not ok:
                continue
            for blob, when in entries:
                rows.append({"raw": blob, "blob": blob, "completed_at": when})
        rows.sort(key=lambda r: r["completed_at"], reverse=True)
        limit = int(s.rsplit("limit", 1)[1].strip()) if "limit" in s else len(rows)
        self._r = rows[:limit]

    def fetchall(self):
        return self._r

    def fetchone(self):
        return self._r[0] if self._r else None


def _obs(arts):
    return dcr.gather_observations(Cur(arts), "uat.prodexlabs.com", 30, "^nuclei:fortinet")


# ── the three values ──────────────────────────────────────────────────────────
def test_a_measured_block_emits_the_observation():
    obs = _obs({ART: [(_diff(True, ["lfi", "sqli", "xss"]), NOW)]})
    assert obs.get("waf_differential_block") is True


def test_a_measured_pass_through_emits_nothing():
    obs = _obs({ART: [(_diff(False), NOW)]})
    assert "waf_differential_block" not in obs


def test_a_dry_run_emits_nothing_and_is_not_a_measurement():
    obs = _obs({ART: [(_diff(None), NOW)]})
    assert "waf_differential_block" not in obs


# ── the newest MEASUREMENT decides, not the newest artifact ──────────────────
def test_a_dry_run_after_a_block_does_not_erase_the_block():
    """The heavy tier writes the artifact on every run; a run that did not fire the
    probe (verdict null) must not read as 'nothing blocked'."""
    obs = _obs({ART: [(_diff(None), NOW), (_diff(True, ["lfi", "sqli", "xss"]), NOW - timedelta(days=1))]})
    assert obs.get("waf_differential_block") is True


def test_a_measured_pass_through_after_a_block_erases_it():
    """UAT in reverse: a later live run where everything passes is a real negative."""
    obs = _obs({ART: [(_diff(False), NOW), (_diff(True, ["lfi", "sqli", "xss"]), NOW - timedelta(days=1))]})
    assert "waf_differential_block" not in obs


def test_a_block_after_a_pass_through_wins_the_uat_case():
    """uat.prodexlabs.com: 10-12 pass-through, 10-13 block."""
    obs = _obs({ART: [(_diff(True, ["lfi", "sqli", "xss"]), NOW),
                      (_diff(False), NOW - timedelta(days=1))]})
    assert obs.get("waf_differential_block") is True


def test_only_the_newest_n_are_read_and_a_verdict_beyond_that_is_not_seen():
    """Depth is bounded and shared with capability; a block older than the window of
    N artifacts, behind N dry-runs, is not read — and capability says the same."""
    arts = {ART: [(_diff(None), NOW - timedelta(hours=h)) for h in range(dcr._DIFFERENTIAL_DEPTH)]
            + [(_diff(True, ["lfi", "sqli", "xss"]), NOW - timedelta(days=2))]}
    assert "waf_differential_block" not in _obs(arts)
    assert dcr.observation_capable(Cur(arts), "uat.prodexlabs.com", "waf_differential_block", 30) is False


# ── capability: a verdict exists ─────────────────────────────────────────────
def test_capability_is_true_for_a_measured_pass_through_and_false_for_a_dry_run():
    """false IS a verdict (the probe looked and saw nothing blocked) -> capable, so a
    measured pass-through may lower a confirmed class (R5 writes). null = did not look ->
    not capable, so a dry-run pass preserves the prior (R5 EVIDENCE_AGED)."""
    assert dcr.observation_capable(Cur({ART: [(_diff(False), NOW)]}), "x", "waf_differential_block", 30) is True
    assert dcr.observation_capable(Cur({ART: [(_diff(None), NOW)]}), "x", "waf_differential_block", 30) is False
    assert dcr.observation_capable(Cur({}), "x", "waf_differential_block", 30) is False


def test_capability_mode_is_not_null_and_depth_is_the_shared_constant():
    cap = dcr.OBSERVATION_CAPABILITY["waf_differential_block"]
    assert cap.mode == dcr._CAP_JSON_KEY_NOT_NULL
    assert cap.sources == (ART,)
    assert cap.field == "waf_present_differential"
    assert cap.depth == dcr._DIFFERENTIAL_DEPTH
    src = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "gather_observations")
    code = "\n".join(l for l in ast.get_source_segment(src, fn).split("\n") if not l.lstrip().startswith("#"))
    assert "limit=_DIFFERENTIAL_DEPTH" in code


def test_the_registry_row_is_fed_and_no_longer_dormant():
    fps = load_fingerprints()
    rows = [r for r in fps if r.get("signal") == "waf_present_differential"]
    assert len(rows) == 1 and rows[0]["observation"] == "waf_differential_block"
    assert rows[0]["evidence_class"] == "presence_only" and not rows[0].get("vendor_product")
    assert "waf_differential_block" not in dcr.DORMANT_OBSERVATIONS
    assert dcr.validate_capability_coverage(fps) == []


# ── the composition that makes UAT 'confirmed' ───────────────────────────────
def test_wafw00f_name_plus_measured_block_is_confirmed_with_vendor_still_suspected():
    fps, th = load_fingerprints(), load_thresholds()
    before = classify({"waf_vendor": "google_cloud_app_armor"}, fps, th)
    after = classify({"waf_vendor": "google_cloud_app_armor", "waf_differential_block": True}, fps, th)
    assert (before["device_class"], before["device_class_confidence"]) == ("waf", "suspected")
    assert (after["device_class"], after["device_class_confidence"]) == ("waf", "confirmed")
    assert after["vendor_product"].get("product") == "Google Cloud Armor"
    assert after["vendor_product_confidence"] == "suspected", "the measurement names no vendor"
    assert dcr.event_for("waf", "suspected", "waf", "confirmed") == "TRANSITION_UPGRADE"


def test_end_to_end_through_the_gather_for_both_uat_days():
    fps, th = load_fingerprints(), load_thresholds()
    day1 = _obs({ART: [(_diff(False), NOW - timedelta(days=1))], "stack_id_wafw00f": [(_wafw00f(), NOW - timedelta(days=1))]})
    day2 = _obs({ART: [(_diff(True, ["lfi", "sqli", "xss"]), NOW), (_diff(False), NOW - timedelta(days=1))],
                 "stack_id_wafw00f": [(_wafw00f(), NOW)]})
    r1, r2 = classify(day1, fps, th), classify(day2, fps, th)
    assert (r1["device_class"], r1["device_class_confidence"]) == ("waf", "suspected")
    assert (r2["device_class"], r2["device_class_confidence"]) == ("waf", "confirmed")
    assert any(e.get("signal") == "waf_present_differential" for e in r2["evidence"])
