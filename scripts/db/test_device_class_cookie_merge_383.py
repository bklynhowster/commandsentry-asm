"""(383, 2026-10-30) A DEEP SCAN'S FORTIWEB COOKIE IS NOT HIDDEN BY A NEWER QUICK SCAN.

Seen live on Command, 2026-10-30. One heavy scan of commandcommcentral.com (scan_run
ccbdc959, 20:48-21:04 UTC) wrote BOTH passive reads:
  stack_id_passive     (heavy, browser-UA curl)  .AspNetCore.Antiforgery.., .SCI.Session,
                                                  CCC, cookiesession1
  light_stack_passive  (httpx's GET, reused)      .AspNetCore.Antiforgery..
The light read cannot see cookiesession1 (heavy #1061, 2026-07-19: httpx's GET measured
cookies=0 on this host while cookiesession1 was served). gather_observations took the
newest read whose cookie LIST was non-empty, whole — so on www.commandcommcentral.com
(heavy 10-21, light 10-28) and enrollment2.edelivery-bessemer.com (heavy 10-19, light
10-26) the light read hid the cookie, FortiWeb fell from confirmed to suspected, and the
first pass after push-382 would have written that with nothing about either host changed.

Pins:
  * a cookie name counts if ANY fresh passive read carried it (per name, not per list);
  * end to end on the recorded shape: FortiWeb CONFIRMED (wafw00f + cookiesession1), not
    suspected — the case that fails on the pre-383 gather;
  * nothing is invented: a light read alone never yields cookiesession1;
  * absence stays absence: empty lists / junk contribute nothing and write no key;
  * headers still take the newest read that carries them (unchanged).
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
from derive_device_class import classify, load_fingerprints, load_thresholds  # noqa: E402

NOW = datetime(2026, 10, 30, 21, 30, tzinfo=timezone.utc)
ANTIFORGERY = ".AspNetCore.Antiforgery.1vbe_3U2uwM"
HEAVY_COOKIES = [ANTIFORGERY, ".SCI.Session", "CCC", "cookiesession1"]


def _ago(days):
    return NOW - timedelta(days=days)


def _passive(cookies, headers=None):
    o = {"schema": 1, "hostname": "www.commandcommcentral.com"}
    if headers is not None:
        o["headers"] = headers
    if cookies is not None:
        o["set_cookie_names"] = cookies
    return json.dumps(o)


def _wafw00f(kind="fortiweb"):
    return json.dumps({"schema": 1, "wafw00f_kind": kind, "wafw00f_detected": True})


class Cur:
    """Serves scan_run_artifacts rows by tool name, newest first, honouring the limit.
    Freshness is SQL's job and is not modelled: every row here is inside the window."""

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
    return dcr.gather_observations(Cur(arts), "www.commandcommcentral.com", 30, "^nuclei:fortinet")


def _www_1028():
    """www.commandcommcentral.com as the 2026-10-30 dry-run saw it: heavy 10-21, light 10-28."""
    return {
        "stack_id_wafw00f": [(_wafw00f(), _ago(9))],
        "stack_id_passive": [(_passive(HEAVY_COOKIES, {"server": ""}), _ago(9))],
        "light_stack_passive": [(_passive([ANTIFORGERY], {"server": ""}), _ago(2))],
    }


# ── the merge ─────────────────────────────────────────────────────────────────
def test_a_newer_quick_scan_does_not_hide_the_deep_scans_cookie():
    """FAILS on the pre-383 gather: the light list (newer, non-empty) won whole."""
    obs = _obs(_www_1028())
    assert "cookiesession1" in obs["set_cookie_names"]


def test_every_name_counts_once_newest_read_first():
    obs = _obs(_www_1028())
    assert obs["set_cookie_names"] == [ANTIFORGERY, ".SCI.Session", "CCC", "cookiesession1"]


def test_both_reads_from_one_scan_run_give_the_cookie_either_way_round():
    """The 10-30 apex run: both reads share completed_at. Pre-383 the tie happened to
    favour the heavy read (tool order + a stable sort); now the order cannot matter."""
    same = _ago(0)
    for light_first in (False, True):
        arts = {"stack_id_passive": [(_passive(HEAVY_COOKIES), same)],
                "light_stack_passive": [(_passive([ANTIFORGERY]),
                                         same + timedelta(seconds=1 if light_first else -1))]}
        assert "cookiesession1" in _obs(arts)["set_cookie_names"], light_first


def test_a_quick_scan_alone_never_produces_the_cookie():
    """Nothing invented: the light read is all there is, and it never carried it."""
    obs = _obs({"light_stack_passive": [(_passive([ANTIFORGERY]), _ago(2))]})
    assert obs["set_cookie_names"] == [ANTIFORGERY]


def test_empty_and_junk_contribute_nothing_and_write_no_key():
    arts = {"stack_id_passive": [(_passive([]), _ago(5)), (_passive(None), _ago(6))],
            "light_stack_passive": [(json.dumps({"set_cookie_names": "cookiesession1"}), _ago(1)),
                                    (json.dumps({"set_cookie_names": [None, "", 7]}), _ago(2))]}
    assert "set_cookie_names" not in _obs(arts)


def test_the_helper_is_pure_and_tolerates_bad_candidates():
    assert dcr._passive_cookie_names(None) == []
    assert dcr._passive_cookie_names([None, "x", {}, {"set_cookie_names": None}]) == []
    assert dcr._passive_cookie_names([{"set_cookie_names": ["a", "b"]},
                                      {"set_cookie_names": ["b", "c"]}]) == ["a", "b", "c"]


def test_headers_still_take_the_newest_read_that_carries_them():
    """Unchanged: only cookies merge per name."""
    arts = {"stack_id_passive": [(_passive(None, {"server": "old-heavy"}), _ago(9))],
            "light_stack_passive": [(_passive(None, {"server": "new-light"}), _ago(2))]}
    assert _obs(arts).get("http_headers") == _obs(
        {"light_stack_passive": [(_passive(None, {"server": "new-light"}), _ago(2))]}).get("http_headers")


# ── end to end through the real registry ─────────────────────────────────────
def test_www_reads_fortiweb_confirmed_not_suspected():
    """The recorded case. FAILS on the pre-383 gather (vendor confidence 'suspected':
    wafw00f alone is one detection)."""
    r = classify(_obs(_www_1028()), load_fingerprints(), load_thresholds())
    assert r["device_class"] == "waf"
    assert r["vendor_product"] == {"vendor": "Fortinet", "product": "FortiWeb"}
    assert r["vendor_product_confidence"] == "confirmed"
    sigs = {m["signal"] for m in r["evidence"]}
    assert {"wafw00f_high_confidence", "fortiweb_cookiesession1"} <= sigs


def test_without_any_deep_read_fortiweb_stays_suspected():
    """The other side: wafw00f + a light read only — one FortiWeb detection, a guess."""
    arts = {"stack_id_wafw00f": [(_wafw00f(), _ago(9))],
            "light_stack_passive": [(_passive([ANTIFORGERY]), _ago(2))]}
    r = classify(_obs(arts), load_fingerprints(), load_thresholds())
    assert r["vendor_product_confidence"] == "suspected"
