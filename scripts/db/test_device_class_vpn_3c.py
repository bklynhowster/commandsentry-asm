"""KB 12 job 3c — the light tier's VPN-gateway checks reach the device classifier.

The case is real: vpn.sciimage.com and vpn2.sciimage.com sat at device_class
'unknown' while httpx named a Cisco ASA CPE on every scan and the passive collector
saw the ASA's `webvpn` cookie (2026-10-21). The plan's claim 3: vpn.sciimage.com is
a Cisco ASA, not the FortiGate the job-2 hand list called it.

Pins:
  * the AnyConnect hello and the WebVPN login page are two INDEPENDENT tells (two
    artifacts) -> edge_firewall / Cisco ASA CONFIRMED; either alone -> suspected;
  * the version the hello read lands in vendor_product (NVD spelling + the raw one),
    and only when the winner IS Cisco ASA;
  * a FortiGate landing names Fortinet FortiGate and carries the firmware build date;
  * capability is NOT-NULL: a pass with no answer cannot demote, a real negative can;
  * the registry, weights and capability map stay consistent (the startup guards).
"""
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
from derive_device_class import (classify, load_fingerprints, load_thresholds,  # noqa: E402
                                 validate_fingerprints, validate_artifact_citations)

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
HELLO, PORTAL = "stack_id_vpn_hello", "stack_id_vpn_portal"


def _hello(matched=True, version="9.16.4.48", raw="9.16(4)48", none=False):
    return json.dumps({"schema": 1, "hostname": "vpn.sciimage.com",
                       "asa_hello": None if none else {"matched": matched, "status": 200,
                                                       "version": version if matched else None,
                                                       "version_raw": raw if matched else None}})


def _portal(asa=True, fgt=False, release="2024-02-20", none=False):
    return json.dumps({"schema": 1, "hostname": "h",
                       "asa_logon": None if none else {"matched": asa, "status": 200},
                       "fortigate_sslvpn": None if none else {"matched": fgt, "status": 200, "port": 443,
                                                              "release_date": release if fgt else None}})


class Cur:
    """Serves gather_observations and the capability probes from one artifact table."""

    def __init__(self, artifacts):
        self.artifacts = artifacts
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
            if ok:
                rows += [{"raw": b, "blob": b, "completed_at": w} for b, w in entries]
        rows.sort(key=lambda r: r["completed_at"], reverse=True)
        limit = int(s.rsplit("limit", 1)[1].strip()) if "limit" in s else len(rows)
        self._r = rows[:limit]

    def fetchall(self):
        return self._r

    def fetchone(self):
        return self._r[0] if self._r else None


def _obs(arts):
    return dcr.gather_observations(Cur(arts), "vpn.sciimage.com", 30, "^nuclei:fortinet")


def _classify(arts):
    obs = _obs(arts)
    return dcr.attach_appliance_details(classify(obs, load_fingerprints(), load_thresholds()), obs)


# ── the observations ─────────────────────────────────────────────────────────
def test_hello_and_login_page_emit_two_observations_and_the_version():
    obs = _obs({HELLO: [(_hello(), NOW)], PORTAL: [(_portal(), NOW)]})
    assert obs["asa_vpn_hello"] is True and obs["asa_logon_page"] is True
    assert obs[dcr.APPLIANCE_DETAILS] == {"cisco/asa": {"version": "9.16.4.48", "version_raw": "9.16(4)48"}}


def test_negatives_and_nulls_emit_nothing():
    for arts in ({HELLO: [(_hello(matched=False), NOW)], PORTAL: [(_portal(asa=False), NOW)]},
                 {HELLO: [(_hello(none=True), NOW)], PORTAL: [(_portal(none=True), NOW)]},
                 {}):
        obs = _obs(arts)
        for k in ("asa_vpn_hello", "asa_logon_page", "fortigate_sslvpn_page", dcr.APPLIANCE_DETAILS):
            assert k not in obs


# ── the verdicts ─────────────────────────────────────────────────────────────
def test_both_asa_tells_confirm_cisco_asa_edge_firewall_with_version():
    r = _classify({HELLO: [(_hello(), NOW)], PORTAL: [(_portal(), NOW)]})
    assert r["device_class"] == "edge_firewall"
    assert r["device_class_confidence"] == "confirmed"
    assert r["vendor_product_confidence"] == "confirmed"
    assert r["vendor_product"] == {"vendor": "Cisco", "product": "ASA",
                                   "version": "9.16.4.48", "version_raw": "9.16(4)48"}


def test_one_asa_tell_alone_is_suspected():
    for arts in ({HELLO: [(_hello(), NOW)]}, {PORTAL: [(_portal(), NOW)]}):
        r = _classify(arts)
        assert r["device_class"] == "edge_firewall"
        assert r["vendor_product_confidence"] == "suspected"
        assert r["vendor_product"]["vendor"] == "Cisco"


def test_fortigate_landing_names_fortigate_with_its_build_date():
    r = _classify({PORTAL: [(_portal(asa=False, fgt=True), NOW)]})
    assert r["device_class"] == "edge_firewall"
    assert r["vendor_product"] == {"vendor": "Fortinet", "product": "FortiGate", "release_date": "2024-02-20"}
    assert r["vendor_product_confidence"] == "suspected"      # one tell; confirm needs another


def test_details_attach_only_to_the_product_they_name():
    obs = {dcr.APPLIANCE_DETAILS: {"cisco/asa": {"version": "9.16.4.48"}}}
    other = {"vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}}
    assert dcr.attach_appliance_details(other, obs)["vendor_product"] == {"vendor": "Fortinet", "product": "FortiWeb"}
    multi = {"vendor_product": {"vendors": [{"vendor": "Cisco", "product": "ASA"}]}}
    assert "version" not in json.dumps(dcr.attach_appliance_details(multi, obs))
    none = {"vendor_product": {}}
    assert dcr.attach_appliance_details(none, obs)["vendor_product"] == {}


# ── capability: NOT-NULL ─────────────────────────────────────────────────────
def _cap_ok(obs_name, blob):
    return dcr._cap_satisfied(dcr.OBSERVATION_CAPABILITY[obs_name], {"raw": blob})


def test_no_answer_is_not_capable_a_real_negative_is():
    assert not _cap_ok("asa_vpn_hello", _hello(none=True))
    assert _cap_ok("asa_vpn_hello", _hello(matched=False))
    assert not _cap_ok("asa_logon_page", _portal(none=True))
    assert _cap_ok("asa_logon_page", _portal(asa=False))
    assert not _cap_ok("fortigate_sslvpn_page", _portal(none=True))
    assert _cap_ok("fortigate_sslvpn_page", _portal(fgt=False))


def test_capability_reads_the_same_artifacts_the_gather_reads():
    caps = dcr.OBSERVATION_CAPABILITY
    assert caps["asa_vpn_hello"].sources == (HELLO,)
    assert caps["asa_logon_page"].sources == (PORTAL,)
    assert caps["fortigate_sslvpn_page"].sources == (PORTAL,)
    for name in ("asa_vpn_hello", "asa_logon_page", "fortigate_sslvpn_page"):
        assert caps[name].mode == dcr._CAP_JSON_KEY_NOT_NULL
    assert HELLO in dcr.EVIDENCE_ARTIFACT_PATTERNS and PORTAL in dcr.EVIDENCE_ARTIFACT_PATTERNS


# ── the startup guards stay green ───────────────────────────────────────────
def test_registry_guards_pass():
    fps = load_fingerprints()
    th = load_thresholds()
    assert validate_fingerprints(fps) == []
    assert validate_artifact_citations(fps) == []
    assert dcr.validate_capability_coverage(fps) == []
    sig = {r["signal"] for r in fps}
    for s in ("cisco_asa_anyconnect_hello", "cisco_asa_webvpn_login_page", "fortigate_sslvpn_landing"):
        assert s in sig
        assert th["weight"][s] == "high"


def test_soak_generation_reset_for_the_new_signals():
    root = os.path.dirname(os.path.dirname(HERE))
    wf = open(os.path.join(root, ".github", "workflows", "device-class-classify.yml"), encoding="utf-8").read()
    assert "default: '2'" in wf and "soak_generation || '2'" in wf


def test_details_never_attach_to_a_result_carrying_a_vendors_list():
    obs = {dcr.APPLIANCE_DETAILS: {"cisco/asa": {"version": "9.16.4.48"}}}
    both = {"vendor_product": {"vendor": "Cisco", "product": "ASA",
                               "vendors": [{"vendor": "Cisco", "product": "ASA"}]}}
    assert "version" not in dcr.attach_appliance_details(both, obs)["vendor_product"]


def test_the_runner_attaches_details_on_the_path_it_writes():
    import ast
    import inspect
    src = inspect.getsource(dcr.classify_asset)
    tree = ast.parse(src.lstrip())
    calls = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "attach_appliance_details"]
    assert calls == ["attach_appliance_details(classify(obs, fps, th), obs)"]
