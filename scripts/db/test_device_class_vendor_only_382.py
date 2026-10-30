"""(382, KB 12 job 3w) A vendor verdict that moves while the class stands still is written.

Found in the 3w read-back, 2026-10-30: push-381 taught the classifier to name Google Cloud
Armor (vendor_product_confidence = confirmed) on 12 Prodex sites. All 12 were already
waf/confirmed, so `event_for` returned None and the loop skipped them before the audit row
and the assets UPDATE: the 18:45 UTC pass computed the new vendor verdict and wrote nothing
(events all 0), and the daily, which names a product only at vendor confidence confirmed,
named none.

These tests run `run()` end to end against a fake database and a stubbed `classify_asset`,
so the real loop, the real write gate and the real SQL strings are what is exercised. The
first one is the failing-first test: on the pre-382 runner the UPDATE never happens.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import device_class_runner as dcr  # noqa: E402

ARMOR = {"vendor": "Google Cloud", "product": "Google Cloud Armor", "cloud_provider": "gcp"}
# Same content, different key order: what psycopg hands back is not guaranteed to match
# what derive_device_class built, and order alone must never read as a move.
ARMOR_REORDERED = {"cloud_provider": "gcp", "product": "Google Cloud Armor", "vendor": "Google Cloud"}


class _Cur:
    def __init__(self, assets):
        self.assets = assets
        self.executed = []
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))
        s = " ".join(sql.split()).lower()
        if s.startswith("select asset_id, device_class, device_class_confidence"):
            self._result = [dict(r) for r in self.assets]
        else:
            self._result = []

    def fetchall(self):
        return self._result

    def fetchone(self):
        return self._result[0] if self._result else None


class _Conn:
    def __init__(self, cur):
        self.cur = cur
        self.autocommit = True

    def cursor(self):
        return self.cur

    def commit(self):
        pass

    def close(self):
        pass


class _Psycopg:
    def __init__(self, cur):
        self.cur = cur

    def connect(self, *a, **k):
        return _Conn(self.cur)


def _asset(asset_id="bitec.prodexlabs.com", cls="waf", conf="confirmed",
           vp=ARMOR, vpc="suspected"):
    return {"asset_id": asset_id, "device_class": cls, "device_class_confidence": conf,
            "device_class_evidence": [], "discovery_status": "confirmed_live",
            "vendor_product": vp, "vendor_product_confidence": vpc}


def _run(monkeypatch, asset, res, write=True):
    cur = _Cur([asset])
    monkeypatch.setattr(dcr, "psycopg", _Psycopg(cur))
    monkeypatch.setattr(dcr, "classify_asset", lambda *a, **k: (dict(res), False))
    rc = dcr.run("postgresql://fake", write, soak_generation=7)
    assert rc == 0
    updates = [p for s, p in cur.executed if s.lower().startswith("update public.assets set device_class")]
    audits = [p for s, p in cur.executed if s.lower().startswith("insert into public.device_class_dryrun")]
    return updates, audits


def _res(cls="waf", conf="confirmed", vp=ARMOR_REORDERED, vpc="confirmed"):
    return {"device_class": cls, "confidence": conf, "evidence": [],
            "vendor_product": vp, "vendor_product_confidence": vpc}


# ── the failing-first test ──────────────────────────────────────────────────

def test_a_vendor_verdict_that_moves_alone_is_written(monkeypatch, capsys):
    """bitec.prodexlabs.com on 2026-10-30: waf/confirmed before and after, vendor
    suspected -> confirmed. PRE-382: nothing written (this test FAILS). 382: one UPDATE
    carrying vendor confidence 'confirmed', one audit row, event CHANGE, with the prior
    vendor in prior_state."""
    updates, audits = _run(monkeypatch, _asset(), _res())
    assert len(updates) == 1, updates
    nc, ncf, vpc, _evidence, vp, asset_id = updates[0]
    assert (nc, ncf, vpc, asset_id) == ("waf", "confirmed", "confirmed", "bitec.prodexlabs.com")
    assert json.loads(vp)["product"] == "Google Cloud Armor"
    assert len(audits) == 1
    a = audits[0]
    assert a[0] == "bitec.prodexlabs.com" and a[1] == "CHANGE" and a[4] == "confirmed"
    prior = json.loads(a[7])
    assert prior["device_class"] == "waf" and prior["confidence"] == "confirmed"
    assert prior["vendor"] == {"vendor_product": ARMOR, "confidence": "suspected"}
    out = capsys.readouterr().out
    assert "[vendor only: suspected -> confirmed]" in out
    assert "vendor only (class unchanged, vendor verdict moved): 1" in out
    # the class tally is untouched: a vendor move is not a class event
    assert "events: STAMP=0 CHANGE=0 UPGRADE=0 DOWNGRADE=0" in out


def test_a_vendor_that_drops_is_written_too(monkeypatch):
    """The other direction: the earlier deep scan ages out of 3w's 30 days, the vendor
    verdict falls back to suspected, and the stored 'confirmed' must not outlive it."""
    updates, audits = _run(monkeypatch, _asset(vpc="confirmed"), _res(vpc="suspected"))
    assert len(updates) == 1 and updates[0][2] == "suspected"
    assert len(audits) == 1 and audits[0][1] == "CHANGE"


# ── nothing moved, nothing written ─────────────────────────────────────────

def test_nothing_moved_writes_nothing(monkeypatch):
    """Same class, same confidence, same vendor (only the key order differs): no UPDATE
    and no audit row, so a settled asset costs nothing pass after pass."""
    updates, audits = _run(monkeypatch, _asset(vpc="confirmed"), _res(vpc="confirmed"))
    assert updates == [] and audits == []


def test_a_cloud_fallback_with_no_vendor_is_not_a_move(monkeypatch):
    """Cloud-fallback results carry no vendor confidence; the runner defaults it to
    'unknown'. A stored 'unknown' with the same cloud_provider blob is not a move."""
    asset = _asset(cls="cloud_endpoint", conf="confirmed", vp={"cloud_provider": "aws"}, vpc="unknown")
    res = {"device_class": "cloud_endpoint", "confidence": "confirmed", "evidence": [],
           "vendor_product": {"cloud_provider": "aws"}}
    updates, audits = _run(monkeypatch, asset, res)
    assert updates == [] and audits == []


# ── the write gate still decides ───────────────────────────────────────────

def test_a_vendor_difference_under_a_no_write_decision_is_not_audited(monkeypatch):
    """unknown before and after (the 2b matrix says NO_WRITE for an unknown prior), with
    a stale stored vendor. Without the gate the row would be audited every pass forever,
    because assets is never updated and the difference never closes."""
    asset = _asset(asset_id="cooked.prodexlabs.com", cls="unknown", conf="unknown",
                   vp={"vendor": "Stale"}, vpc="suspected")
    res = {"device_class": "unknown", "confidence": "unknown", "evidence": [],
           "vendor_product": {}, "vendor_product_confidence": "unknown"}
    updates, audits = _run(monkeypatch, asset, res)
    assert updates == [] and audits == []


def test_dry_run_audits_the_vendor_move_but_writes_nothing(monkeypatch):
    """Dry-run (the pre-merge gate, a manual check): the audit row lands, assets does not
    change, exactly as for any other event in dry-run."""
    updates, audits = _run(monkeypatch, _asset(), _res(), write=False)
    assert updates == []
    assert len(audits) == 1 and audits[0][1] == "CHANGE"


def test_a_class_move_is_still_a_class_event_and_carries_no_vendor_key(monkeypatch):
    """waf/suspected -> waf/confirmed with the vendor moving too: the class event wins
    (TRANSITION_UPGRADE), it is counted in the class tally, and prior_state has no
    'vendor' key, so nothing about pre-382 rows or readers changes."""
    updates, audits = _run(monkeypatch, _asset(conf="suspected"), _res())
    assert len(updates) == 1 and updates[0][2] == "confirmed"
    assert len(audits) == 1 and audits[0][1] == "TRANSITION_UPGRADE"
    assert "vendor" not in json.loads(audits[0][7])


# ── the pure pieces ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("a,b", [
    (None, {}), (None, "null"), ({}, "null"), (None, "not json"),
    (ARMOR, ARMOR_REORDERED), (ARMOR, json.dumps(ARMOR_REORDERED)),
])
def test_vendor_state_treats_equivalent_shapes_as_equal(a, b):
    assert dcr.vendor_state(a, "confirmed") == dcr.vendor_state(b, "confirmed")


def test_vendor_state_defaults_a_missing_confidence_to_unknown():
    assert dcr.vendor_state(None, None) == dcr.vendor_state({}, "unknown")


def test_vendor_only_move_needs_no_class_event_a_write_and_a_difference():
    f, t = dcr.vendor_state(ARMOR, "suspected"), dcr.vendor_state(ARMOR, "confirmed")
    assert dcr.vendor_only_move(None, dcr._DECISION_WRITE, f, t) is True
    assert dcr.vendor_only_move("TRANSITION_UPGRADE", dcr._DECISION_WRITE, f, t) is False
    assert dcr.vendor_only_move(None, dcr._DECISION_PRESERVE, f, t) is False
    assert dcr.vendor_only_move(None, dcr._DECISION_NO_WRITE, f, t) is False
    assert dcr.vendor_only_move(None, dcr._DECISION_WRITE, t, t) is False
