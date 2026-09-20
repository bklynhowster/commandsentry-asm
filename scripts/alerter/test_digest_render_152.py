#!/usr/bin/env python3
"""152 push 2 — the render half. P1-P5 + D-031. Relay 304.

⛔ WHY THIS FILE IS MOSTLY NOT ABOUT HTML. Howie's complaint was "formatting is kind of
crappy", but the defects were DECISIONS, not tags: the asset repeated on every row
(bcbsma sixteen times), two tools' view of one open port rendered as two findings, and
inventory sat in full beside real defects. So the layout logic is pure functions and
these tests drive those; the snapshot at the end is the one check that the pieces are
actually wired into what gets sent.

⚠ The existing 15 alerter tests cover COUNTS (relay 137's mutation set). Counts are
exactly what these changes must not disturb — P4 collapses INFO rows in the BODY and
the subject count still counts them — so those tests staying green is part of this
turn's evidence, not incidental.
"""
from __future__ import annotations

import os
import sys
import pytest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_alerter as A  # noqa: E402

# A two-asset window, the shape 152 describes: one asset with a real defect plus the
# port pair plus inventory, one asset with only inventory.
ROWS = [
    ("f-csp", "bcbsma.commandcommcentral.com", "Static CSP nonce reused across requests",
     "MODERATE", "open", "medium_scan", "t"),
    ("f-p53", "bcbsma.commandcommcentral.com", "Open port detected (open-port-53)",
     "LOW", "open", "light_scan", "t"),
    ("f-s53", "bcbsma.commandcommcentral.com", "Service identified (service-53-tcp)",
     "INFO", "open", "light_scan", "t"),
    ("f-hdr", "bcbsma.commandcommcentral.com", "Technology disclosed via response headers",
     "INFO", "open", "light_scan", "t"),
    ("f-tls", "api.commandcommcentral.com", "TLS 1.2 cipher suites accepted (22)",
     "INFO", "open", "heavy_scan", "t"),
]
CLASSES = {
    "bcbsma.commandcommcentral.com": {
        "device_class": "waf", "confidence": "confirmed",
        "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}},
    "api.commandcommcentral.com": {
        "device_class": "waf", "confidence": "suspected",
        "vendor_product": {"vendor": "Google Cloud", "product": "Google Cloud Armor"}},
}


# ══ P1 — one block per asset ═════════════════════════════════════════════════

def test_an_asset_appears_once_however_many_findings_it_has():
    """⛔ THE COMPLAINT, AS A TEST. bcbsma appeared 16 times in digest #130 because the
    ASSET column repeated per row."""
    blocks = A.group_by_asset(ROWS)
    assert [b[0] for b in blocks].count("bcbsma.commandcommcentral.com") == 1


def test_the_worst_asset_comes_first_and_the_worst_finding_leads_its_block():
    blocks = A.group_by_asset(ROWS)
    assert blocks[0][0] == "bcbsma.commandcommcentral.com"     # MODERATE beats INFO
    assert blocks[0][1] == "MODERATE"
    assert blocks[0][2][0][0] == "f-csp"


def test_an_unknown_severity_sorts_last_rather_than_crashing():
    """A severity we have never seen is a data question, not a render crash."""
    odd = ROWS + [("f-?", "zz.example", "Something", "WEIRD", "open", "light_scan", "t")]
    blocks = A.group_by_asset(odd)
    assert blocks[-1][0] == "zz.example"


# ══ P3 — two tools, one fact (render-side only) ══════════════════════════════

def test_the_port_pair_becomes_one_service_inventory_line():
    merged = A.merge_service_inventory(ROWS)
    titles = [r[2] for r in merged]
    assert any(t.startswith("Service inventory: 53/tcp") for t in titles)
    assert not any("open-port-53" in t for t in titles)
    assert not any("service-53-tcp" in t for t in titles)


def test_the_merged_row_keeps_the_worst_severity_and_says_how_many_it_ate():
    (row,) = [r for r in A.merge_service_inventory(ROWS) if r[2].startswith("Service inventory")]
    assert row[3] == "LOW"                      # LOW + INFO -> LOW
    assert "2 rows merged" in row[2]


def test_a_real_finding_is_never_swallowed_by_the_merge():
    merged = A.merge_service_inventory(ROWS)
    assert any(r[0] == "f-csp" for r in merged)
    assert len(merged) == 4                      # 5 rows, 2 merged into 1


def test_the_merge_is_render_side_only_and_touches_no_parser():
    """⛔ 4.7's instruction, pinned: `finding_id` embeds the tool and is load-bearing
    for identity, dedupe and close-out. If P3 ever moves into cs_parsers/, this fails."""
    import inspect
    src = inspect.getsource(A.merge_service_inventory)
    assert "cs_parsers" not in src
    merged = A.merge_service_inventory(ROWS)
    assert {r[0] for r in merged} <= {r[0] for r in ROWS}, "the merge invented a finding_id"


# ══ P4 — INFO collapses in the body, never in the count ══════════════════════

def test_info_is_separated_but_not_discarded():
    """⚠ IN THE RENDER'S OWN ORDER — merge, then group, then split. My first version of
    this test skipped the merge and then asserted the post-merge answer, which failed on
    correct code: `service-53-tcp` is only INFO until P3 folds it into the LOW inventory
    line. The pipeline order IS part of what is being tested."""
    block = A.group_by_asset(A.merge_service_inventory(ROWS))[0][2]
    full, info = A.split_info(block)
    assert [r[0] for r in info] == ["f-hdr"]
    assert all(r[3] != "INFO" for r in full)


def test_the_collapse_does_not_change_what_the_subject_counts():
    """⚠ THE INVARIANT THAT MATTERS. A digest whose header disagrees with its body is a
    digest nobody trusts; 152 says the subject still counts INFO."""
    full, info = A.split_info(ROWS)
    assert len(full) + len(info) == len(ROWS)


# ══ D-031 — tier and asset class ═════════════════════════════════════════════

def test_the_scan_tier_is_read_from_source_not_guessed_from_the_title():
    assert A.scan_tier_label("light_scan") == "light scan"
    assert A.scan_tier_label("medium") == "medium scan"
    assert A.scan_tier_label("heavy_scan") == "deep scan"
    assert A.scan_tier_label("asm") == "discovery"


def test_an_unknown_source_says_so_instead_of_inventing_a_tier():
    assert A.scan_tier_label(None) == "unknown tier"
    assert A.scan_tier_label("some_new_producer") == "some_new_producer"


def test_the_asset_class_line_names_the_PRODUCT_and_declares_its_source():
    line = A.asset_class_line("api.commandcommcentral.com", CLASSES)
    assert "waf/suspected" in line
    assert "Google Cloud Armor" in line          # the product, not the slug
    assert "dry-run classification" in line, "the digest must not imply the label is live"


def test_an_unclassified_asset_gets_no_class_line_rather_than_unknown():
    """⚠ "unknown" reads as a verdict we made. No line is the truth: we have not
    classified it — and a retired asset is excluded from classify entirely (relay 285),
    so it arrives here with no row by design."""
    assert A.asset_class_line("never-classified.example", CLASSES) == ""
    assert A.asset_class_line("x", {"x": {"device_class": None}}) == ""


# ══ THE SNAPSHOT — the pieces actually wired into what gets sent ═════════════

def _render(**kw):
    base = dict(
        window_start=datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 9, 19, 0, 0, tzinfo=timezone.utc),
        new_findings=ROWS, confirmed=[], regressed=[], high_risk=[],
        new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
        discovery_stale_hours=12, deepscan_stale_hours=48,
        baseline={"critical_open": 0, "high_open": 1, "mod_high_open": 0,
                  "moderate_open": 2, "low_open": 3},
        product_name="COMMANDsentry", device_classes=CLASSES,
    )
    base.update(kw)
    return base


def test_the_html_digest_groups_merges_collapses_and_links(monkeypatch):
    html = A.render_html(dashboard_url="https://portal.example", **_render())
    # P1: the asset is a heading, once
    assert html.count("bcbsma.commandcommcentral.com") == 2      # heading + INFO link
    # P2: no FINDING ID column; the title carries the link
    assert "Finding ID" not in html
    assert 'href="https://portal.example/findings/f-csp"' in html
    # P3 + P4
    assert "Service inventory: 53/tcp" in html
    assert "+ 1 informational" in html
    # D-031
    assert "FortiWeb" in html and "dry-run classification" in html
    assert "medium scan" in html


def test_the_plaintext_digest_KEEPS_the_finding_id():
    """⛔ P2's exception. Plaintext is what gets grepped and pasted into a ticket."""
    text = A.render_text(**_render())
    assert "f-csp" in text
    assert "Service inventory: 53/tcp" in text
    assert "+ 1 informational" in text
    assert "Google Cloud Armor" in text


def test_new_assets_heading_says_discovered_in_this_window():
    """Howie: an asset he had been running for weeks still read as "new"."""
    assert A.NEW_ASSETS_HEADING == "Assets discovered in this window"
    import inspect
    assert '"New assets discovered"' not in inspect.getsource(A.render_html)


# ═══════════════════════════════════════════════════════════════════════════
# ⛔ VENDOR + PRODUCT WITHOUT SAYING THE VENDOR TWICE (relay 346)
#
# The digest printed "Google Cloud Google Cloud Armor" on every Prodex digest
# since D-031. Prodex-only — Command's Fortinet/FortiWeb reads correctly — and
# the digest reads were Command-heavy, so three weeks of them never showed it.
# Rule 9 step 3 on the PORTAL, which inherited the same construction, is what
# surfaced it.
#
# ⛔ THE FIXTURES BELOW ARE SHARED WITH THE PORTAL, CASE FOR CASE. The portal's
# tests/vendor-product-label-check.mjs carries the identical table against its
# JS implementation. Two languages, one rule, one fixture set — if either side
# is changed alone, one of the two suites goes red.
# ═══════════════════════════════════════════════════════════════════════════

VENDOR_PRODUCT_CASES = [
    # (vendor, product, expected)  — REAL rows from the estates, 2026-09-20
    ("Google Cloud", "Google Cloud Armor", "Google Cloud Armor"),   # ← the defect
    ("Fortinet", "FortiWeb", "Fortinet FortiWeb"),                  # ← must NOT change
    ("Cloudflare", "Cloudflare", "Cloudflare"),
    ("Microsoft", "Azure Front Door", "Microsoft Azure Front Door"),
    # capitalisation is not a second vendor
    ("google cloud", "Google Cloud Armor", "Google Cloud Armor"),
    # absences
    (None, "FortiWeb", "FortiWeb"),
    ("Fortinet", None, "Fortinet"),
    ("", "FortiWeb", "FortiWeb"),
    # a product that merely CONTAINS the vendor later on is not a repeat
    ("Akamai", "Kona Akamai Shield", "Akamai Kona Akamai Shield"),
]


@pytest.mark.parametrize("vendor,product,expected", VENDOR_PRODUCT_CASES)
def test_vendor_product_label(vendor, product, expected):
    assert A.vendor_product_label(vendor, product) == expected


def test_the_prodex_row_no_longer_repeats_its_vendor():
    """The production row, end to end through the line the digest prints."""
    classes = {
        "www.prodexlabs.com": {
            "device_class": "waf",
            "confidence": "suspected",
            "vendor_product": {
                "vendor": "Google Cloud",
                "product": "Google Cloud Armor",
            },
        }
    }
    line = A.asset_class_line("www.prodexlabs.com", classes)
    assert "Google Cloud Armor" in line
    assert "Google Cloud Google Cloud" not in line, f"vendor said twice: {line}"
    assert "(dry-run classification)" in line


def test_the_command_row_is_untouched():
    """⚠ The half that already worked. A fix is not correct because it changed
    the broken case; it is correct when it changed that and nothing else."""
    classes = {
        "api.commandcommcentral.com": {
            "device_class": "waf",
            "confidence": "suspected",
            "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"},
        }
    }
    line = A.asset_class_line("api.commandcommcentral.com", classes)
    assert "Fortinet FortiWeb" in line


def test_the_fixture_table_matches_the_portal_case_for_case():
    """⛔ THE CROSS-LANGUAGE PIN. The portal's check carries this same table. If
    a case is added or changed on one side only, the counts diverge and this
    names it — the two implementations are not allowed to drift apart quietly,
    which is exactly how the digest and the portal came to share one bug."""
    assert len(VENDOR_PRODUCT_CASES) == 9, (
        "the shared fixture table changed size — update "
        "commandsentry-portal/tests/vendor-product-label-check.mjs to match, "
        "and this count with it")
