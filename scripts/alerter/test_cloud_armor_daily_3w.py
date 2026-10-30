"""KB 12 job 3w (2026-10-30) — the daily and #on-call name Google Cloud Armor.

Howie, 2026-10-30 10:03, on the daily's "something is standing guard … still working out
which product": "Why aren't we identifying what the damn thing is?". 11:12: "once they are
identified, yes, they should totally be disclosed in the slack communique or in the
morning email." 11:58, the words, "Perfect, book it":

    Google Cloud Armor, Google's web firewall, is blocking our probes on uat and bitec.
    That's good news: it's switched on and doing its job.

Pins:
  * a measured block is NAMED only when its own capture shows the three signs AND the
    classifier holds the asset at Google Cloud Armor, CONFIRMED (two deep scans, "A");
  * a named block leaves "unrecognized" and is one good-news line for all its sites, in
    the booked words, in the email and in #on-call;
  * said once: a named site is not also "started blocking", nor a closed firewall finding;
  * a block that is not (yet) named keeps today's words; old rows are never named.
"""
from __future__ import annotations

import copy
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import run_alerter as ra  # noqa: E402
import digest_daily as dd  # noqa: E402
import digest_slack as ds  # noqa: E402
import digest_voice as dv  # noqa: E402

UTC = timezone.utc
T30 = datetime(2026, 10, 30, 12, 3, tzinfo=UTC)
BRAND = dict(dd.DEFAULT_BRAND, short_name="Prodex")
BOOKED = ("Google Cloud Armor, Google's web firewall, is blocking our probes on bitec and uat. "
          "That's good news: it's switched on and doing its job.")
GOOGLE_403 = ('<!doctype html><meta charset="utf-8"><meta name=viewport content="width=device-width, '
              'initial-scale=1"><title>403</title>403 Forbidden')
GOOGLE_HDR = "HTTP/2 403 \ncontent-type: text/html; charset=UTF-8\ncontent-length: 134\nvia: 1.1 google\n"
CA = {"vendor": "Google Cloud", "product": "Google Cloud Armor", "cloud_provider": "gcp"}


def _fired(google=True):
    out = [{"cls": "benign", "status": 200, "size": 10533}]
    for c in ("sqli", "xss", "lfi"):
        out.append({"cls": c, "status": 403, "size": 134, "body_head": GOOGLE_403,
                    "raw_headers": GOOGLE_HDR if google else "HTTP/2 403 \nserver: nginx\n"})
    return out


def _row(host, when, conf="confirmed", vp=CA, google=True):
    """A SQL_MEASURED_BLOCKS_IN_WINDOW row: asset, name, org, measured_at, fired, vendor_product, confidence."""
    return (host, host.split(".")[0], "prodex", when, _fired(google), vp, conf)


UAT = _row("uat.prodexlabs.com", datetime(2026, 10, 30, 6, 54, tzinfo=UTC))
BITEC = _row("bitec.prodexlabs.com", datetime(2026, 10, 30, 1, 20, tzinfo=UTC))


# ── the alerter: named or unrecognized ──────────────────────────────────────────────────
def test_a_confirmed_cloud_armor_block_is_named_and_not_unrecognized():
    out = ra.measured_block_pages([UAT, BITEC])
    assert [(r[0], r[5]) for r in out] == [("uat.prodexlabs.com", "Google Cloud Armor"),
                                           ("bitec.prodexlabs.com", "Google Cloud Armor")]
    assert ra.unrecognized_block_pages([UAT]) != [], "the library alone still does not know the page"


def test_one_deep_scan_is_not_enough_the_block_stays_unrecognized():
    """The classifier gives 'suspected' until a second deep scan shows the same: today's words."""
    out = ra.measured_block_pages([_row("l3h-ss.prodexlabs.com", T30, conf="suspected")])
    assert len(out) == 1 and len(out[0]) == 5, "unrecognized, as before"


def test_a_page_that_is_not_googles_front_door_is_never_named():
    out = ra.measured_block_pages([_row("x.prodexlabs.com", T30, google=False)])
    assert all(len(r) == 5 for r in out)


def test_old_five_column_rows_are_never_named():
    assert ra.named_guard(UAT[:5]) is None


def test_the_multi_vendor_shape_reads_each_vendors_own_confidence():
    multi = {"vendors": [dict(CA, confidence="confirmed"), {"vendor": "Defiant", "product": "Wordfence",
                                                            "confidence": "suspected"}]}
    assert ra.named_guard(_row("m.prodexlabs.com", T30, conf="unknown", vp=multi)) == "Google Cloud Armor"
    multi["vendors"][0]["confidence"] = "suspected"
    assert ra.named_guard(_row("m.prodexlabs.com", T30, conf="unknown", vp=multi)) is None


def test_the_sql_reads_the_classifiers_two_columns():
    s = " ".join(ra.SQL_MEASURED_BLOCKS_IN_WINDOW.split())
    assert "a.vendor_product, a.vendor_product_confidence FROM" in s


# ── the daily: one line, the booked words, said once ────────────────────────────────────
def _model(pages, flips=(), fixed=()):
    return dd.build_model(window_start=T30.replace(day=29), window_end=T30, new_findings=[], confirmed=[],
                          regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=[],
                          canary_violations=[], baseline={}, brand=BRAND, fixed=list(fixed),
                          enforcement_flips=list(flips), unrecognized_pages=pages, told={})


def _flip(host):
    return (host, host.split(".")[0], "o", T30, True, False, datetime(2026, 10, 22, tzinfo=UTC), [])


def _fixed_waf(host):
    return (f"{host}:w", host, "WAF detected but not blocking", "MODERATE-HIGH", "remediated",
            "commandsentry_heavy", T30)


def test_the_booked_words_in_the_email_and_on_slack_and_they_pass_the_check():
    m = _model(ra.measured_block_pages([UAT, BITEC]))
    assert [d["kind"] for d in m["done"]] == ["guard"] and m["ticket"] == []
    f = dv.facts(m, slack=ds.select(m, [], {}, T30), company="Prodex", day="Friday, October 30")
    fb = dv.fallback(f)
    assert dv.check(fb, f) == []
    assert [e["text"] for e in fb["fixed"]] == [BOOKED]
    assert [e["text"] for e in fb["slack"]["changed"]] == [BOOKED]
    assert "still working out" not in str(fb)


def test_said_once_not_also_started_blocking_nor_a_closed_firewall_finding():
    """uat flipped to blocking and bitec's 'only watching' finding closed the same morning:
    the named line says both, once (Howie 08:26: "you say the same line twice")."""
    m = _model(ra.measured_block_pages([UAT, BITEC]),
               flips=[_flip("uat.prodexlabs.com"), _flip("prod.prodexlabs.com")],
               fixed=[_fixed_waf("bitec.prodexlabs.com")])
    kinds = [(d["kind"], d.get("sites")) for d in m["done"]]
    assert kinds[0] == ("guard", ["bitec.prodexlabs.com", "uat.prodexlabs.com"])
    assert [k for k, _ in kinds] == ["guard", "blocking"], "prod (not named) still 'started blocking'"
    blocking = [d for d in m["done"] if d["kind"] == "blocking"][0]
    assert "uat" not in blocking["title"] and all("uat" not in ln for ln in blocking["lines"])
    f = dv.facts(m, slack=ds.select(m, [], {}, T30), company="Prodex", day="Friday, October 30")
    fb = dv.fallback(f)
    assert dv.check(fb, f) == []
    assert sum("bitec" in e["text"] for e in fb["fixed"]) == 1


def test_a_block_not_yet_named_keeps_todays_words():
    pages = ra.measured_block_pages([_row("l3h-ss.prodexlabs.com", T30, conf="suspected")])
    m = _model(pages)
    assert [t["kind"] for t in m["ticket"]] == ["blockpage"] and m["done"] == []
    fb = dv.fallback(dv.facts(m, slack=ds.select(m, [], {}, T30), company="Prodex", day="Friday"))
    assert "still working out which product" in fb["email"][0]["text"]


def test_the_writer_is_told_to_say_the_product_when_the_item_names_it():
    assert 'UNLESS its item names the product' in dv.SYSTEM
    f = dv.facts(_model(ra.measured_block_pages([UAT])), company="Prodex", day="Friday")
    guard = [it for it in f["items"] if it["kind"] == "guard"][0]
    assert guard["what"].startswith("Google Cloud Armor") and guard["why"].startswith("That's good news")
    assert guard["hosts"] == ["uat.prodexlabs.com"]


def test_a_writer_line_that_drops_a_named_host_is_refused():
    m = _model(ra.measured_block_pages([UAT, BITEC]))
    f = dv.facts(m, slack=ds.select(m, [], {}, T30), company="Prodex", day="Friday")
    out = copy.deepcopy(dv.fallback(f))
    out["fixed"] = [{"id": "f1", "text": "Google Cloud Armor is blocking our probes on uat. Good news."}]
    assert any("does not name bitec" in p for p in dv.check(out, f))
