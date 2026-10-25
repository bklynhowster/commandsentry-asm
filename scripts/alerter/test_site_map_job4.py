"""(KB 12 job 4, push B, 2026-10-25) The digests fold a www name into its site only on evidence.

Howie, 2026-10-24 21:44: "it's the same damn box it's the same site." Ruled 2026-10-25 08:46
(D1): one site only on evidence seen on both names (site_members, through v_site_of, migration
20261025b) — never because of the names. Pinned here: the map moves exactly the names the
evidence moves; the three Unimac www.<sub> names (wildcard DNS) stop folding; a site that is not
a live asset leaves the name alone; an empty map folds nothing; a failed read (None) keeps the old
name rule, so it never un-merges a site; run_alerter loads the map before either digest reads its
sites, from v_site_of, and a failed read gives None.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import run_alerter as ra  # noqa: E402

SAME = ["commandcommcentral.com", "commandcompanies.com", "commandmarketinginnovations.com",
        "unimacgraphics.com", "prodexlabs.com"]
UNIMAC = ["portal.unimacgraphics.com", "firewall.unimacgraphics.com", "zoetislabs.unimacgraphics.com"]
NAMES = set(SAME) | {"www." + s for s in SAME} | set(UNIMAC) | {"www." + u for u in UNIMAC}
EVIDENCE = [("www." + s, s) for s in SAME]          # what v_site_of returns after the read-back


@pytest.fixture(autouse=True)
def _no_map_leaks():
    dd.set_site_map(None)
    yield
    dd.set_site_map(None)


def test_without_the_evidence_the_old_name_rule_stands():
    assert dd.site_of("www.commandcompanies.com", NAMES) == "commandcompanies.com"
    assert dd.site_of("www.portal.unimacgraphics.com", NAMES) == "portal.unimacgraphics.com"
    assert dd.site_of("www.only.example", NAMES) == "www.only.example"


def test_with_the_evidence_the_five_sites_fold_and_the_unimac_names_stand_alone():
    dd.set_site_map(EVIDENCE)
    for s in SAME:
        assert dd.site_of("www." + s, NAMES) == s
        assert dd.site_of(s, NAMES) == s
    for u in UNIMAC:
        assert dd.site_of("www." + u, NAMES) == "www." + u, u
        assert dd.site_of(u, NAMES) == u


def test_a_site_that_is_not_a_live_asset_leaves_the_name_alone():
    dd.set_site_map(EVIDENCE)
    assert dd.site_of("www.prodexlabs.com", {"www.prodexlabs.com"}) == "www.prodexlabs.com"


def test_an_empty_map_folds_nothing_and_none_restores_the_name_rule():
    dd.set_site_map([])
    assert dd.site_of("www.commandcompanies.com", NAMES) == "www.commandcompanies.com"
    dd.set_site_map(None)
    assert dd.site_of("www.commandcompanies.com", NAMES) == "commandcompanies.com"


def test_site_bands_follow_the_evidence():
    rows = [("portal.unimacgraphics.com", "LOW", True, "LOW"),
            ("www.portal.unimacgraphics.com", "HIGH", True, "HIGH"),
            ("prodexlabs.com", "LOW", True, "LOW"), ("www.prodexlabs.com", "HIGH", True, "HIGH")]
    now_old, _ = dd.site_bands(rows)
    assert set(now_old) == {"portal.unimacgraphics.com", "prodexlabs.com"}
    dd.set_site_map([("www.prodexlabs.com", "prodexlabs.com")])
    now_new, _ = dd.site_bands(rows)
    assert set(now_new) == {"portal.unimacgraphics.com", "www.portal.unimacgraphics.com", "prodexlabs.com"}
    assert now_new["prodexlabs.com"] == "high" and now_new["portal.unimacgraphics.com"] == "low"


def test_the_map_reads_v_site_of_and_only_the_names_that_move():
    sql = " ".join(ra.SQL_SITE_MAP.split())
    assert sql == ("SELECT asset_id, site_asset_id FROM public.v_site_of "
                   "WHERE asset_id <> site_asset_id ORDER BY asset_id")


def test_a_failed_read_gives_none():
    class Boom:
        def transaction(self):
            raise RuntimeError("relation public.v_site_of does not exist")
    assert ra._read_site_map(Boom()) is None


def test_both_digests_load_the_map_before_they_read_their_sites():
    src = open(os.path.join(HERE, "run_alerter.py"), encoding="utf-8").read()
    weekly = src[src.index("def _weekly_model("):src.index("def main(")]
    assert weekly.index("_dd.set_site_map(_read_site_map(conn))") < weekly.index("SQL_SITE_RATINGS")
    daily = src[src.index("def main("):]
    i = daily.index("_dd.set_site_map(_read_site_map(conn))")
    assert i < daily.index('sites = _soft("site ratings", SQL_SITE_RATINGS')
    assert i < daily.index("model = _digest_model(")
    assert len(re.findall(r"_dd\.set_site_map\(", src)) == 2
