"""(KB 12 job 3l round 5, 2026-10-27) The #on-call post: who gets which nudge, the floor, the
cap, the merge, the record, and the post itself.

Howie, 08:44: developers "need to know if there's something new that's happening: a site went
down, a site came up, or a new vulnerability was found." 08:46: Moderate and up; a post only
when there is news. 09:01: what changed + a nudge on the 30-day timer. 09:53: developer-fixable
things to Slack; firewalls, DNS, certificates, hosts going dark stay in the email. Review M1/M2:
an allow-list (key "" titles included), a floor, a unit, a cap, no double-telling.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_daily as dd  # noqa: E402
import digest_slack as ds  # noqa: E402
import digest_words as dw  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 27, 12, 3, tzinfo=UTC)
OLD = NOW - timedelta(days=116)       # July 3
NEWISH = NOW - timedelta(days=5)


def _row(fid, host, title, sev="MODERATE", first=OLD, source="commandsentry_light"):
    return (fid, host, title, sev, "detected", source, NOW, "", [], first)


def _items(rows):
    names = {r[1] for r in rows}
    items = dd.group_problems(rows, names)
    first = {r[0]: r[9] for r in rows}
    for g in items:
        g["since"] = min(first[f] for f in g["finding_ids"])
    return items


# Today's Prodex open Moderate+ population, as the review listed it (M1, Reproduced 8)
ROWS = (
    [_row(f"{h}:csp", f"{h}.prodexlabs.com", "Missing security header: Content-Security-Policy")
     for h in ("www", "cooked", "preview", "azure-demo", "atlantis-gcp")]
    + [_row(f"{h}:sts", f"{h}.prodexlabs.com", "Missing security header: Strict-Transport-Security")
       for h in ("www", "cooked", "preview", "azure-demo", "atlantis-gcp")]
    + [_row(f"{h}:hstslow", f"{h}.prodexlabs.com", "HSTS not enabled", sev="LOW") for h in ("www", "cooked")]
    + [_row(f"{h}:3des", f"{h}.prodexlabs.com", "Obsolete 3DES/IDEA ciphers offered", source="commandsentry_heavy")
       for h in ("cooked", "preview", "www", "tour", "valorep")]
    + [_row(f"{h}:beast", f"{h}.prodexlabs.com", "TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA", source="commandsentry_heavy")
       for h in ("cooked", "preview", "www", "tour", "valorep")]
    + [_row(f"{h}:breach", f"{h}.prodexlabs.com", "BREACH attack vulnerability check — potentially VULNERABLE, gzip", source="commandsentry_heavy")
       for h in ("bitec", "cooked", "dass")]
    + [_row("www:dmarc", "www.prodexlabs.com", "DNS missing DMARC record"),
       _row("www:spf", "www.prodexlabs.com", "DNS missing SPF record"),
       _row("www:hdr2", "www.prodexlabs.com", "Security headers missing or weak")]
    + [_row(f"{h}:waf", f"{h}.prodexlabs.com", "No enforcing WAF in front of live application", source="commandsentry_heavy", first=NOW - timedelta(days=18))
       for h in ("cooked", "gov", "sandbox")]
    + [_row(f"{h}:wafw", f"{h}.prodexlabs.com", "WAF detected but not blocking attacks", sev="MODERATE-HIGH", source="commandsentry_heavy", first=NEWISH)
       for h in ("bitec", "demo", "highcom")]
)


def test_the_allow_list_is_the_developer_side_and_everything_else_is_the_emails():
    assert ds.is_developer("Missing security header: Content-Security-Policy", "")
    assert ds.is_developer("Security headers missing or weak", "")
    assert ds.is_developer("Obsolete 3DES/IDEA ciphers offered", "")
    assert ds.is_developer("TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA", "")
    assert ds.is_developer("BREACH attack vulnerability check — potentially VULNERABLE", "")
    assert ds.is_developer("Runs PHP 8.1.2: out of date — 3 published flaws", "out-of-date")
    assert ds.is_developer("HSTS not enabled", "hsts")
    for t, fam in (("DNS missing DMARC record", ""), ("DNS missing SPF record", ""),
                   ("No enforcing WAF in front of live application", "waf-absent"),
                   ("WAF detected but not blocking attacks", "waf-not-blocking"),
                   ("Certificate revocation checking unavailable", "cert-revocation"),
                   ("No CAA DNS record", "caa"), ("A brand new title nobody has seen", "")):
        assert not ds.is_developer(t, fam), t
    # the 14 real keys all have a side
    keys = {f["key"] for f in dw.FAMILIES}
    assert keys >= {"waf-absent-signin", "waf-absent", "waf-not-blocking", "waf-partial", "out-of-date",
                    "version-unknown", "cert-revocation", "cert-lifespan", "cert-chain", "cert-expiring",
                    "ocsp", "caa", "hsts", "auth-bypass"}
    assert {k for k in keys if ds.is_developer("", k)} == {"out-of-date", "hsts", "auth-bypass"}


def test_the_nudge_has_a_floor_a_unit_a_cap_and_merges_same_condition_pairs():
    items = _items(ROWS)
    n = ds.nudge_items(items, None, NOW)
    titles = [i["title"] for i in n]
    assert len(n) <= ds.NUDGE_MAX == 3
    assert "Old weak ciphers" in titles[0] and titles[1].startswith("Security headers missing: Content-Security-Policy, Strict-Transport-Security")
    assert titles[2].startswith("BREACH"), "worst, then most hosts (5, 5, 3), then oldest"
    headers = n[1]
    assert headers["sites"] == sorted({f"{h}.prodexlabs.com" for h in ("www", "cooked", "preview", "azure-demo", "atlantis-gcp")})
    assert not any(f.endswith(":hstslow") for f in headers["finding_ids"]), "HSTS is LOW: below the floor"
    assert not any("dmarc" in f or "spf" in f or ":waf" in f for i in n for f in i["finding_ids"]), "the email's items never nudge the channel"
    assert "www:hdr2" in headers["finding_ids"], "'Security headers missing or weak' is the same condition: merged"
    more = ROWS + [_row("php:ood", "php.prodexlabs.com", "Runs PHP 8.1.2: out of date — 3 published flaws fixed in later versions; update it", source="advisory_watch")]
    n4 = ds.nudge_items(_items(more), None, NOW)
    assert len(n4) == 3 and not any("php:ood" in i["finding_ids"] for i in n4), "a fourth group waits for a later post"


def test_the_nudge_waits_30_days_and_comes_back_on_the_timer():
    items = _items(ROWS)
    hdr = [r[0] for r in ROWS if r[2].startswith(("Missing security header", "Security headers missing"))]
    told = {f: {"last_full_at": NOW - timedelta(days=10)} for f in hdr}
    n = ds.nudge_items(items, told, NOW)
    assert not any(i["title"].startswith("Security headers") for i in n), "told 10 days ago: quiet"
    told = {f: {"last_full_at": NOW - timedelta(days=31)} for f in hdr}
    n = ds.nudge_items(items, told, NOW)
    assert any(i["title"].startswith("Security headers") for i in n), "31 days: due again"
    young = _items([_row("y:csp", "y.prodexlabs.com", "Missing security header: Content-Security-Policy", first=NEWISH)])
    assert ds.nudge_items(young, None, NOW) == [], "younger than 30 days is news, not a nudge"
    low_only = _items([_row("l:hsts", "l.prodexlabs.com", "HSTS not enabled", sev="LOW")])
    assert ds.nudge_items(low_only, None, NOW) == [], "below the floor: never a nudge, even with room"


def test_section_one_and_the_exclusions():
    m = {"do": [{"kind": "coverage", "title": "Sentry lost sight of 1 host", "lines": ["a: x"], "sites": []},
               {"kind": "not_responding", "title": "1 host is not responding", "lines": ["valorep.prodexlabs.com: no answer since Oct 22"], "sites": []},
               {"kind": "finding", "severity": "HIGH", "title": "A proven thing", "family": "auth-bypass", "sites": ["a.prodexlabs.com"], "finding_ids": ["a:ab"]}],
         "ticket": [{"kind": "finding", "severity": "MODERATE", "title": "Missing security header: Content-Security-Policy", "family": "", "sites": ["q.prodexlabs.com"], "finding_ids": ["q:csp"]},
                    {"kind": "blockpage", "severity": "", "title": "Something unrecognized is blocking in front of x", "sites": ["x.prodexlabs.com"]},
                    {"kind": "finding", "severity": "LOW", "title": "low thing", "family": "", "sites": ["z"], "finding_ids": ["z:l"]}],
         "done": [{"kind": "fixed", "title": "Fixed on b.prodexlabs.com: a thing.", "lines": []}]}
    sel = ds.select(m, _items(ROWS + [_row("q:csp", "q.prodexlabs.com", "Missing security header: Content-Security-Policy")]), None, NOW)
    kinds = [(i["kind"], i.get("slack_color")) for i in sel["changed"]]
    assert kinds == [("not_responding", ds.RED), ("finding", ds.RED), ("finding", ds.RED), ("fixed", ds.GREEN)]
    assert not any(i["kind"] in ("coverage", "blockpage") for i in sel["changed"]), "Sentry's own and the block pages are not developer news"
    assert not any("q:csp" in i["finding_ids"] for i in sel["nudge"]), "today's news is not also a nudge"
    recs = ds.records(sel, {"cooked:3des": "MODERATE"})
    assert ("cooked:3des", "MODERATE") in recs and not any(f.endswith(":csp") for f, _s in recs), \
        "a condition that is news today on one host is not nudged on the others the same day"
    assert not any(f == "a:ab" for f, _s in ds.records(sel)), "section 1 is news, not a telling"


def test_a_host_that_stopped_answering_is_news_once_the_day_it_crossed_the_line():
    ws, we = NOW - timedelta(hours=24), NOW
    rows = [("valorep.prodexlabs.com", NOW - timedelta(hours=30), "no_answer", NOW - timedelta(hours=6), None),   # crossed 6 h ago
            ("tour.prodexlabs.com", NOW - timedelta(days=5), "name_gone", NOW - timedelta(days=4), None),        # on the roster for days
            ("never.prodexlabs.com", None, "never_answered", NOW - timedelta(hours=2), None),                      # never answered; notice stamped today
            ("old.prodexlabs.com", None, "never_answered", NOW - timedelta(days=3), None),
            ("edge.prodexlabs.com", NOW - timedelta(hours=48), "no_answer", None, None)]                           # crossed exactly at window_start: yesterday's
    assert ds.quiet_news(rows, ws, we) == {"valorep.prodexlabs.com", "never.prodexlabs.com"}
    assert ds.quiet_news([], ws, we) == set() and ds.quiet_news(None, ws, we) == set()
    item = {"kind": "not_responding", "severity": "", "title": "3 hosts are not responding",
            "lines": ["valorep.prodexlabs.com: no answer since Oct 26, 1:03 AM.", "tour.prodexlabs.com: no answer since Oct 22. Its name no longer exists on the internet.",
                      "never.prodexlabs.com: no answer from Sentry's checks."], "sites": []}
    got = ds.changed_items({"do": [item]}, quiet_news={"valorep.prodexlabs.com", "never.prodexlabs.com"})
    assert len(got) == 1 and got[0]["sites"] == ["valorep.prodexlabs.com", "never.prodexlabs.com"]
    assert got[0]["title"] == "2 hosts are not responding" and len(got[0]["lines"]) == 2 and "tour" not in str(got[0]["lines"])
    assert ds.changed_items({"do": [item]}, quiet_news=set()) == [], "all three were told on earlier days"
    assert ds.changed_items({"do": [item]}, quiet_news={"valorep.prodexlabs.com"})[0]["title"] == "1 host is not responding"
    assert len(ds.changed_items({"do": [item]})[0]["sites"]) == 3, "no window given: the whole roster (the old shape)"


def test_the_post_has_the_approved_shape_and_none_when_empty():
    sel = {"changed": [{"kind": "not_responding", "slack_color": ds.RED}, {"kind": "fixed", "slack_color": ds.GREEN}],
           "nudge": [{"kind": "finding"}]}
    out = {"slack": {"changed": [{"id": "k1", "text": "valorep stopped answering."}, {"id": "k2", "text": "b is fixed."}],
                     "nudge": [{"id": "n1", "text": "Two <headers> missing."}], "closing": "Neither one is urgent."}}
    p = ds.payload(out, sel, product_name="PRODEXsentry", day_label="Tuesday, October 27")
    assert p["blocks"][0]["type"] == "header" and p["blocks"][0]["text"]["text"].startswith("PRODEXsentry")
    colors = [a["color"] for a in p["attachments"]]
    assert colors == [ds.RED, ds.GREEN, ds.YELLOW]
    assert "*What changed since yesterday*\n• valorep stopped answering." in p["attachments"][0]["blocks"][0]["text"]["text"]
    assert "Two &lt;headers&gt; missing." in p["attachments"][2]["blocks"][0]["text"]["text"]
    assert p["attachments"][2]["blocks"][1]["type"] == "context"
    assert "fired" not in str(p).lower()
    assert ds.payload({"slack": {"changed": [], "nudge": [], "closing": "x"}}, {"changed": [], "nudge": []},
                      product_name="P", day_label="d") is None
    assert "What changed since yesterday" in ds.preview_text(p) and ds.preview_text(None) == ""
