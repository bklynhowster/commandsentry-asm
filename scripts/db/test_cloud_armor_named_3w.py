"""KB 12 job 3w (2026-10-30) — Google Cloud Armor, named from what it does.

Howie, 2026-10-30: 10:03 "Why aren't we identifying what the damn thing is? … Can we give
our audience more specificity if we have it and we have high confidence in it?"; 10:13 "I
agree about the narrow rule"; 11:12 the call is Sentry's evidence ("only you can make that
determination by fingerprinting it"); 11:38 "A": named only when TWO separate deep scans
each show all three signs.

The case is real: uat.prodexlabs.com, heavy scan 2026-10-30 06:54Z. The benign request got
the site (200, 10,533 B); sqli, xss and lfi each got `HTTP/2 403`, 134 B, `via: 1.1 google`,
Google's own page. Read 2026-10-30 (Prodex, read-only): 12 Google-hosted sites show that on
their newest deep scan AND an earlier one; 13 sit behind Google's front door and let the
attack strings through.

Pins:
  * the rule needs all three signs in ONE capture, and says nothing on any one missing;
  * wafw00f's "Google Cloud App Armor" (the Via header alone) is not the second piece: the
    newest capture shares its dedupe_key, so wafw00f + one capture stays SUSPECTED;
  * newest + an earlier, separate scan = CONFIRMED, with or without wafw00f;
  * the earlier scan must be a DIFFERENT, OLDER scan run; the newest must qualify;
  * gather_observations reads both from the artifacts, and the registry cites Google.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
import block_page_signatures as bps  # noqa: E402
from derive_device_class import (classify, load_fingerprints, load_thresholds,  # noqa: E402
                                 load_artifact_signatures, validate_artifact_citations,
                                 validate_registry)

ART = "stack_id_waf_differential"
HOST = "uat.prodexlabs.com"
T = datetime(2026, 10, 30, 6, 54, tzinfo=timezone.utc)
GOOGLE_403 = ('<!doctype html><meta charset="utf-8"><meta name=viewport content="width=device-width, '
              'initial-scale=1"><title>403</title>403 Forbidden')
GOOGLE_HDR = ("HTTP/2 403 \ncontent-type: text/html; charset=UTF-8\ncontent-length: 134\nvia: 1.1 google\n"
              "date: Fri, 30 Oct 2026 06:53:30 GMT\n")
CLOUD_ARMOR = {"vendor": "Google Cloud", "product": "Google Cloud Armor"}


def uat_fired(**over):
    """The real uat capture (2026-10-30 06:54Z); `over` swaps one deny's fields."""
    fired = [{"cls": "benign", "status": 200, "size": 10533}]
    for c in ("sqli", "xss", "lfi"):
        fired.append({"cls": c, "status": 403, "size": 134, "body_head": GOOGLE_403, "raw_headers": GOOGLE_HDR})
    if over:
        fired[1] = dict(fired[1], **over)
    return fired


def passthrough_fired():
    """staging.prodexlabs.com's newest scan: Google's front door, everything served."""
    return [{"cls": c, "status": 200, "size": 10533} for c in ("benign", "sqli", "xss", "lfi")]


# ── the rule, one capture ───────────────────────────────────────────────────────────────
def test_the_real_uat_capture_shows_all_three_signs():
    assert bps.cloud_armor_edge_deny(uat_fired())


def test_each_sign_missing_names_nothing():
    no_door = uat_fired(raw_headers="HTTP/2 403 \ncontent-type: text/html\nserver: nginx\n")
    not_googles_page = uat_fired(body_head="<html><title>Access denied</title>Blocked by the site</html>")
    a_404 = uat_fired(status=404)                       # an owner's deny-404: the safe direction
    baseline_redirected = [dict(uat_fired()[0], status=301)] + uat_fired()[1:]
    one_class = uat_fired()[:2] + [{"cls": c, "status": 200, "size": 10533} for c in ("xss", "lfi")]
    for name, fired in [("no Google front door", no_door), ("not Google's page", not_googles_page),
                        ("a 404 deny", a_404), ("ordinary request not served", baseline_redirected),
                        ("only one class denied", one_class), ("nothing denied", passthrough_fired()),
                        ("empty", []), ("none", None)]:
        assert not bps.cloud_armor_edge_deny(fired), name


def test_the_page_match_ignores_whitespace_and_case_only():
    assert bps.cloud_armor_edge_deny(uat_fired(body_head="\n " + GOOGLE_403.upper().replace(" ", "\n  ") + "\r\n"))
    assert not bps.cloud_armor_edge_deny(uat_fired(body_head=GOOGLE_403 + "<p>see support</p>"))


def test_the_via_header_must_be_its_own_line():
    assert not bps.cloud_armor_edge_deny(uat_fired(raw_headers="HTTP/2 403 \nx-note: via: 1.1 google\n"))
    assert bps.cloud_armor_edge_deny(uat_fired(raw_headers="HTTP/2 403\r\nVia: 1.1 google\r\n"))


# ── two separate deep scans (Howie 11:38, "A") ──────────────────────────────────────────
def _art(fired, verdict=True):
    return {"waf_present_differential": verdict, "details": {"fired": fired}}


def test_newest_and_an_earlier_separate_scan_both_pass():
    runs = [("r3", T, _art(uat_fired())), ("r2", T - timedelta(days=7), _art(passthrough_fired(), False)),
            ("r1", T - timedelta(days=14), _art(uat_fired()))]
    assert dcr.earlier_edge_deny(runs)


def test_only_the_newest_is_not_enough():
    assert not dcr.earlier_edge_deny([("r2", T, _art(uat_fired())),
                                      ("r1", T - timedelta(days=7), _art(passthrough_fired(), False))])
    assert not dcr.earlier_edge_deny([("r1", T, _art(uat_fired()))])


def test_an_older_block_does_not_count_when_the_newest_lets_it_through():
    """staging and demo, 2026-10-30: they blocked on earlier scans, not on their newest."""
    assert not dcr.earlier_edge_deny([("r3", T, _art(passthrough_fired(), False)),
                                      ("r2", T - timedelta(days=7), _art(uat_fired())),
                                      ("r1", T - timedelta(days=14), _art(uat_fired()))])


def test_the_same_scan_run_twice_is_one_piece_of_evidence():
    assert not dcr.earlier_edge_deny([("r1", T, _art(uat_fired())), ("r1", T - timedelta(minutes=1), _art(uat_fired()))])
    assert not dcr.earlier_edge_deny([(None, T, _art(uat_fired())), (None, T - timedelta(days=7), _art(uat_fired()))])
    assert not dcr.earlier_edge_deny([("r2", T, _art(uat_fired())), ("r1", T, _art(uat_fired()))]), "not older"


# ── the registry: how strong each piece is ──────────────────────────────────────────────
FPS, TH = load_fingerprints(), load_thresholds()
WAFW00F_GOOGLE = {"waf_vendor": "google_cloud_app_armor"}


def _vp(obs):
    r = classify(obs, FPS, TH)
    return r["vendor_product"], r["vendor_product_confidence"], r["device_class"]


def test_wafw00f_alone_is_unchanged_suspected():
    """The 13 sites behind Google's front door that let everything through: as today."""
    assert _vp(WAFW00F_GOOGLE) == (CLOUD_ARMOR, "suspected", "waf")


def test_wafw00f_plus_one_capture_is_still_one_piece_suspected():
    obs = dict(WAFW00F_GOOGLE, cloud_armor_edge_deny=True, waf_differential_block=True)
    assert _vp(obs)[1] == "suspected", "wafw00f's tell is the same Via header: they count once"


def test_two_separate_captures_confirm_with_or_without_wafw00f():
    two = {"cloud_armor_edge_deny": True, "cloud_armor_edge_deny_earlier": True, "waf_differential_block": True}
    assert _vp(dict(WAFW00F_GOOGLE, **two)) == (CLOUD_ARMOR, "confirmed", "waf")
    assert _vp(two) == (CLOUD_ARMOR, "confirmed", "waf")


def test_the_rows_are_cited_to_google_and_the_registry_loads():
    assert validate_registry() == []
    assert validate_artifact_citations(FPS) == []
    sigs = load_artifact_signatures()
    for name in ("cloud_armor_edge_deny", "cloud_armor_edge_deny_earlier"):
        e = sigs[name]
        assert e["vendor"] == "Google Cloud" and e["product"] == "Google Cloud Armor"
        assert e["citation"]["url"].startswith("https://docs.cloud.google.com/armor/")
        assert "deny-403" in e["citation"]["quote"]
    rows = {r["signal"]: r for r in FPS if r["signal"].startswith("cloud_armor_edge_block")}
    assert rows["cloud_armor_edge_block"]["observation"] == "cloud_armor_edge_deny"
    assert rows["cloud_armor_edge_block"]["dedupe_key"] == "wafw00f_detection"
    assert rows["cloud_armor_edge_block_repeat"]["observation"] == "cloud_armor_edge_deny_earlier"
    assert rows["cloud_armor_edge_block_repeat"].get("dedupe_key") in (None, "cloud_armor_edge_block_repeat")


def test_an_uncited_behavior_row_is_refused():
    sigs = load_artifact_signatures()
    sigs.pop("cloud_armor_edge_deny_earlier")
    errs = validate_artifact_citations(FPS, sigs)
    assert any("cloud_armor_edge_deny_earlier" in e for e in errs)


# ── gather_observations, from the artifacts ─────────────────────────────────────────────
class Cur:
    """Serves stack_id_waf_differential artifacts newest first, with their scan run ids."""

    def __init__(self, arts):
        self.arts = arts                                 # [(run_id, completed_at, obj)]
        self._r = []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self._r = []
        if "scan_run_artifacts" not in s or not params or params[1] != ART:
            return
        rows = [{"run": r, "completed_at": at, "blob": json.dumps(o), "raw": json.dumps(o)}
                for r, at, o in self.arts]
        if "is not null" in s:
            rows = [x for x in rows if json.loads(x["blob"]).get("waf_present_differential") is not None]
        rows.sort(key=lambda x: x["completed_at"], reverse=True)
        limit = int(s.rsplit("limit", 1)[1].strip()) if "limit" in s else len(rows)
        self._r = rows[:limit]

    def fetchall(self):
        return self._r

    def fetchone(self):
        return self._r[0] if self._r else None


def _obs(arts):
    return dcr.gather_observations(Cur(arts), HOST, 30, "^nuclei:fortinet")


def test_gather_reads_the_newest_and_the_earlier_scan():
    o = _obs([("r2", T, _art(uat_fired())), ("r1", T - timedelta(days=7), _art(uat_fired()))])
    assert o.get("waf_differential_block") and o.get("cloud_armor_edge_deny") and o.get("cloud_armor_edge_deny_earlier")


def test_gather_says_nothing_when_the_newest_lets_it_through():
    o = _obs([("r2", T, _art(passthrough_fired(), False)), ("r1", T - timedelta(days=7), _art(uat_fired()))])
    assert "cloud_armor_edge_deny" not in o and "cloud_armor_edge_deny_earlier" not in o


def test_a_dry_run_after_the_blocks_keeps_the_measurement():
    o = _obs([("r3", T, _art([], None)), ("r2", T - timedelta(days=1), _art(uat_fired())),
              ("r1", T - timedelta(days=8), _art(uat_fired()))])
    assert o.get("cloud_armor_edge_deny") and o.get("cloud_armor_edge_deny_earlier")


def test_the_capability_map_knows_both_observations():
    assert dcr.validate_capability_coverage(FPS) == []
    cap = dcr.OBSERVATION_CAPABILITY["cloud_armor_edge_deny_earlier"]
    assert cap.depth == dcr._EDGE_DENY_DEPTH and cap.field == "waf_present_differential"
