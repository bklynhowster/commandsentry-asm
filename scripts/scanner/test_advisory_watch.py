"""(KB 12 job 3d, 2026-10-21) advisory_watch — new advisories against what our hosts run.

Howie's rulings (handoff 004): a finding on the asset; MODERATE "confirm it's patched",
HIGH when on CISA's exploited list; NVD critical (30 d) + KEV (90 d); sources pluggable.
Core rule: proved by a harmless reaction — nothing is sent to a host; no version, no
"vulnerable" claim.
"""
from datetime import datetime, timezone

import pytest

import advisory_watch as aw

NOW = datetime(2026, 10, 21, 10, 25, tzinfo=timezone.utc)


def php2shell(cve_id="CVE-2026-109618", score=9.8, kev=False):
    """Shaped like NVD's record for PHP2Shell (checker read it 2026-10-21): CPE a:php:php,
    one range per branch."""
    rec = {
        "id": cve_id, "published": "2026-10-21T14:17:00.000",
        "descriptions": [{"lang": "en", "value": "PHP out-of-memory handling leaves request state partly set."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}],
                    "cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": min(score, 9.2)}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "8.2.0", "versionEndExcluding": "8.2.35"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "8.3.0", "versionEndExcluding": "8.3.36"},
        ]}]}],
    }
    if kev:
        rec["cisaExploitAdd"] = "2026-10-20"
    return rec


def adv(rec, kev=False):
    return aw._advisory(rec, {rec["id"]} if kev else set())


# ── identity, parts list ────────────────────────────────────────────────────────────
def test_finding_id_is_the_standard_formula():
    from cs_parsers.common import stable_finding_id
    assert aw.finding_id("a.example.com", "php") == \
        stable_finding_id("a.example.com", aw.SOURCE, "advisory:php", "a.example.com")


def test_products_keep_names_without_a_version():
    tech = {"tech": ["PHP", "WordPress", "Nginx:1.31.6", "jQuery UI:1.12.1", "HSTS", "Microsoft ASP.NET"]}
    assert aw.products_from_tech(tech) == {"php": None, "wordpress": None, "nginx": "1.31.6",
                                           "microsoft asp.net": None}


def test_a_version_seen_anywhere_wins_and_lists_are_read():
    tech = [{"tech": ["PHP"]}, {"tech": ["PHP:8.3.10"]}]
    assert aw.products_from_tech(tech) == {"php": "8.3.10"}


def test_inventory_adds_only_confirmed_appliances_and_marks_scan_presence():
    inv = aw.build_inventory(
        [{"asset_id": "w.example.com", "tech": {"tech": ["PHP"]}}],
        [{"asset_id": "fw.example.com", "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}},
         {"asset_id": "x.example.com", "vendor_product": {"vendor": "Acme"}}])
    assert inv["w.example.com"].products == {"php": None} and inv["w.example.com"].scanned
    assert inv["fw.example.com"].products == {"fortiweb": None} and not inv["fw.example.com"].scanned
    assert "x.example.com" not in inv


def test_the_inventory_query_reads_owned_hosts_latest_tech_list_only():
    s = " ".join(aw.INVENTORY_SQL.split())
    assert "tool_name = 'httpx_tech'" in s and "a.ownership = 'owned'" in s
    assert "DISTINCT ON (sr.asset_id)" in s and "ORDER BY sr.asset_id, sra.created_at DESC" in s
    assert s.startswith("SELECT") and "UPDATE" not in s
    assert "vendor_product_confidence = 'confirmed'" in aw.CONFIRMED_APPLIANCE_SQL


# ── versions and ranges ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("version,expected", [
    ("8.3.10", True), ("8.3.36", False), ("8.3.35", True), ("8.4.1", False),
    ("8.2.0", True), ("7.4.33", False), ("8.3", True), ("8.3.x", None),
])
def test_version_in_php2shell_ranges(version, expected):
    ms = aw.cpe_matches(php2shell(), {"a:php:php"})
    got = [aw.version_in_range(version, m) for m in ms]
    result = None if None in got else any(got)
    assert result is expected


def test_exact_and_wildcard_criteria():
    assert aw.version_in_range("2.4.1", {"criteria": "cpe:2.3:a:x:y:2.4.1:*:*:*:*:*:*:*"}) is True
    assert aw.version_in_range("2.4.2", {"criteria": "cpe:2.3:a:x:y:2.4.1:*:*:*:*:*:*:*"}) is False
    assert aw.version_in_range("9.9", {"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}) is True


def test_affects_keeps_unknown_versions_and_drops_patched_ones():
    rec = php2shell()
    assert aw.affects(rec, {"a:php:php"}, None) is True
    assert aw.affects(rec, {"a:php:php"}, "8.3.10") is True
    assert aw.affects(rec, {"a:php:php"}, "8.3.36") is False
    assert aw.affects({"id": "X"}, {"a:php:php"}, "8.3.36") is True     # no ranges: can't rule out


def test_cvss_takes_the_highest_primary_score():
    assert aw.cvss(php2shell()) == 9.8
    # job 3c (the 330 read-back's Proposed item): NVD's own score wins when present...
    both = {"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5}},
                                          {"type": "Secondary", "cvssData": {"baseScore": 10}}]}}
    assert aw.cvss(both) == 7.5


def test_cvss_falls_back_to_the_vendors_score_when_nvd_has_none():
    # ...and a CVE only its reporting vendor has scored is no longer "score not re-read"
    # (nor skipped by the 30-day CVSS >= 9.0 filter).
    assert aw.cvss({"metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 10}}]}}) == 10
    assert aw.cvss({"metrics": {}}) is None


# ── sources ─────────────────────────────────────────────────────────────────────────
def test_nvd_urls_name_the_product_and_the_windows():
    u = aw.nvd_url("a:php:php", "recent", NOW)
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aphp%3Aphp" in u and "noRejected" in u
    assert "pubStartDate=2026-09-21T10%3A25%3A00.000%2B00%3A00" in u and "pubEndDate=2026-10-21" in u
    k = aw.nvd_url("a:php:php", "kev", NOW)
    assert "kevStartDate=2026-07-23" in k and "kevEndDate=2026-10-21" in k


class FakeGet:
    def __init__(self, pages):
        self.pages, self.urls = pages, []

    def __call__(self, url):
        self.urls.append(url)
        for frag, ans in self.pages:
            if frag in url:
                if isinstance(ans, Exception):
                    raise ans
                return ans
        return {"totalResults": 0, "vulnerabilities": []}


def test_recent_keeps_critical_only_and_kev_window_marks_kev():
    low = php2shell("CVE-2026-1", score=7.5)
    get = FakeGet([("pubStartDate", {"totalResults": 2, "vulnerabilities": [{"cve": php2shell()}, {"cve": low}]}),
                   ("kevStartDate", {"totalResults": 1, "vulnerabilities": [{"cve": php2shell("CVE-2025-9", 6.1)}]})])
    sleeps = []
    src = aw.Sources(get=get, sleep=sleeps.append, now=NOW)
    found = aw.advisories_for(src, ("a:php:php",), set())
    assert set(found) == {"CVE-2026-109618", "CVE-2025-9"}
    assert found["CVE-2025-9"].kev and not found["CVE-2026-109618"].kev
    assert sleeps == [aw.NVD_DELAY_S]          # paced between NVD calls, not before the first


def test_a_failed_nvd_query_raises():
    src = aw.Sources(get=FakeGet([("pubStartDate", aw.SourceError("boom"))]), sleep=lambda s: None, now=NOW)
    with pytest.raises(aw.SourceError):
        aw.advisories_for(src, ("a:php:php",), set())


def test_pages_are_followed():
    p1 = {"totalResults": 2, "vulnerabilities": [{"cve": php2shell("CVE-1")}]}
    p2 = {"totalResults": 2, "vulnerabilities": [{"cve": php2shell("CVE-2")}]}
    get = FakeGet([("startIndex=0", p1), ("startIndex=1", p2)])
    src = aw.Sources(get=get, sleep=lambda s: None, now=NOW)
    assert [c["id"] for c in src.nvd_query("a:php:php", "recent")] == ["CVE-1", "CVE-2"]


# ── deciding ────────────────────────────────────────────────────────────────────────
def host(products, scanned=True, asset="w.example.com"):
    return {asset: aw.Host(asset, products, scanned)}


def test_version_not_shown_is_moderate_confirm_its_patched():
    a = adv(php2shell())
    (act,) = aw.plan(host({"php": None}), {"php": {a.cve_id: a}}, set(), {}, {})
    assert act.kind == "upsert" and act.fields["severity"] == "MODERATE"
    assert "version not shown" in act.fields["title"] and "confirm it’s patched" in act.fields["title"]
    assert act.fields["cve"] == ["CVE-2026-109618"] and act.fields["category"] == "supply_chain"
    assert "Nothing was sent to the site" in act.fields["description"]


def test_on_cisas_exploited_list_is_high():
    a = adv(php2shell(), kev=True)
    (act,) = aw.plan(host({"php": None}), {"php": {a.cve_id: a}}, set(), {}, {})
    assert act.fields["severity"] == "HIGH" and "cisa-kev" in act.fields["tags"]


def test_a_version_outside_every_range_raises_nothing_inside_says_so():
    a = adv(php2shell())
    assert aw.plan(host({"php": "8.3.36"}), {"php": {a.cve_id: a}}, set(), {}, {}) == []
    (act,) = aw.plan(host({"php": "8.3.10"}), {"php": {a.cve_id: a}}, set(), {}, {})
    assert act.fields["title"].startswith("PHP 8.3.10 is in the affected range")


def _existing(status="open", cve=("CVE-2026-109618",), key="php", asset="w.example.com"):
    return {aw.finding_id(asset, key): dict(asset_id=asset, key=key, status=status, cve=list(cve))}


def test_a_failed_lookup_changes_nothing():
    assert aw.plan(host({"php": None}), {}, {"php"}, _existing(), {}) == []


def test_product_gone_from_a_scanned_host_closes_unscanned_host_does_not():
    (act,) = aw.plan(host({"wordpress": None}), {"wordpress": {}}, set(), _existing(), {})
    assert act.kind == "close" and "no longer seen" in act.reason
    assert aw.plan(host({}, scanned=False), {}, set(), _existing(), {}) == []
    assert aw.plan({}, {}, set(), _existing(), {}) == []


def test_a_person_closed_row_is_never_touched():
    a = adv(php2shell())
    for st in ("false_positive", "wont_fix", "accepted_risk", "closed_reclassified", "detector_retired"):
        assert aw.plan(host({"php": None}), {"php": {a.cve_id: a}}, set(), _existing(st), {}) == [], st
        assert aw.plan(host({}), {}, set(), _existing(st), {}) == [], st


def test_watcher_closed_reopens_only_on_a_new_match():
    a = adv(php2shell())
    (act,) = aw.plan(host({"php": None}), {"php": {a.cve_id: a}}, set(), _existing("remediated"), {})
    assert act.kind == "upsert" and act.reopen
    assert aw.plan(host({"php": None}), {"php": {}}, set(), _existing("remediated"), {}) == []


def test_listed_cves_stay_after_the_window_and_keep_their_kev_flag():
    (act,) = aw.plan(host({"php": None}), {"php": {}}, set(), _existing(cve=("CVE-2024-4577",)), {},
                     kev_ids={"CVE-2024-4577"})
    assert act.fields["cve"] == ["CVE-2024-4577"] and act.fields["severity"] == "HIGH"
    assert "outside today's look-back window" in act.fields["description"]


def test_a_newly_shown_patched_version_drops_listed_cves_and_closes():
    a = adv(php2shell())
    (act,) = aw.plan(host({"php": "8.3.36"}), {"php": {}}, set(), _existing(), {a.cve_id: a})
    assert act.kind == "close" and "outside every listed advisory" in act.reason
    # the recheck failed -> keep, no close
    (keep,) = aw.plan(host({"php": "8.3.36"}), {"php": {}}, set(), _existing(), {a.cve_id: None})
    assert keep.kind == "upsert"


def test_an_in_window_cve_the_shown_version_rules_out_is_dropped_not_kept():
    # code review MUST-FIX 1 (GLM-5.3, 2026-10-21): the run's own record says 8.3.36 is
    # outside every range, so the listed CVE goes and the row closes; never re-titled.
    a = adv(php2shell())
    acts = aw.plan(host({"php": "8.3.36"}), {"php": {a.cve_id: a}}, set(), _existing(), {})
    assert [x.kind for x in acts] == ["close"]
    assert not any("is in the affected range" in (x.fields.get("title") or "") for x in acts)


def test_the_fortiweb_cpe_is_the_application_entry():
    # code review MUST-FIX 2: NVD lists FortiWeb only as a:fortinet:fortiweb.
    assert aw.cpes_for("fortiweb")[1] == ("a:fortinet:fortiweb",)


def test_kev_listed_is_left_to_cve_scoring():
    a = adv(php2shell(), kev=True)
    (act,) = aw.plan(host({"php": None}), {"php": {a.cve_id: a}}, set(), {}, {})
    assert "kev_listed" not in act.fields and "kev_listed" not in aw.UPSERT_SQL


# ── writing ─────────────────────────────────────────────────────────────────────────
def test_sql_never_touches_a_person_closed_row_and_only_its_own_source():
    up = " ".join(aw.UPSERT_SQL.split())
    assert "WHERE public.findings.current_status::text IN ('detected','confirmed','open','regressed','remediated')" in up
    assert "'regressed'::finding_status_t" in up and "%(source)s::finding_source_t" in up
    cl = " ".join(aw.CLOSE_SQL.split())
    assert "source::text = %(source)s" in cl and "current_status::text IN ('detected','confirmed','open','regressed')" in cl
    assert "last_seen_scan_run" not in up        # no scan run owns these rows


class Cur:
    def __init__(self, store):
        self.s = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.s["calls"].append((" ".join(sql.split())[:40], params))
        self.last = sql

    def fetchall(self):
        if "httpx_tech" in self.last:
            return self.s["tech"]
        if "vendor_product_confidence" in self.last:
            return []
        return self.s["existing"]

    def fetchone(self):
        return {"finding_id": "x", "severity": "MODERATE"}


class Conn:
    def __init__(self, tech, existing=()):
        self.s = {"tech": tech, "existing": list(existing), "calls": []}

    def cursor(self):
        return Cur(self.s)


def _src():
    get = FakeGet([("php%3Aphp&noRejected&pubStartDate", {"totalResults": 1, "vulnerabilities": [{"cve": php2shell()}]}),
                   ("known_exploited", {"vulnerabilities": [{"cveID": "CVE-2021-1"}]})])
    return aw.Sources(get=get, sleep=lambda s: None, now=NOW)


def test_run_dry_run_writes_nothing():
    conn = Conn([{"asset_id": "w.example.com", "tech": {"tech": ["PHP", "WordPress"]}}])
    n = aw.run(conn, _src(), dry_run=True, log=lambda *a: None, Json=lambda x: x)
    assert n["planned"] == 1
    assert not [c for c, _ in conn.s["calls"] if c.startswith("INSERT") or c.startswith("UPDATE")]


def test_run_writes_one_finding_per_asset_and_product():
    conn = Conn([{"asset_id": "w.example.com", "tech": {"tech": ["PHP"]}}])
    n = aw.run(conn, _src(), log=lambda *a: None, Json=lambda x: x)
    assert n["upsert"] == 1 and n["close"] == 0
    (ins,) = [p for c, p in conn.s["calls"] if c.startswith("INSERT INTO public.findings")]
    assert ins["finding_id"] == aw.finding_id("w.example.com", "php") and ins["source"] == "advisory_watch"


def test_the_watcher_contacts_only_nvd_and_cisa():
    get = FakeGet([])
    src = aw.Sources(get=get, sleep=lambda s: None, now=NOW)
    conn = Conn([{"asset_id": "w.example.com", "tech": {"tech": ["PHP", "Nginx:1.31.6"]}}])
    aw.run(conn, src, dry_run=True, log=lambda *a: None, Json=lambda x: x)
    assert get.urls and all(u.startswith((aw.NVD_API, aw.KEV_FEED)) for u in get.urls)


# ── job 3c: edge security devices (Howie 2026-10-22, "Yes to all four.") ──────────
def asa_cve(cve_id="CVE-2025-20333", kev=True, published="2025-09-25T16:15:00.000",
            start="9.16.0", end="9.16.4.85", cpe="o:cisco:adaptive_security_appliance_software"):
    rec = {"id": cve_id, "published": published,
           "descriptions": [{"lang": "en", "value": "Cisco ASA WebVPN flaw."}],
           "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 9.9}}]},
           "configurations": [{"nodes": [{"cpeMatch": [
               {"vulnerable": True, "criteria": f"cpe:2.3:{cpe}:*:*:*:*:*:*:*:*",
                "versionStartIncluding": start, "versionEndExcluding": end}]}]}]}
    if kev:
        rec["cisaExploitAdd"] = "2025-09-25"
    return rec


def test_asa_is_read_under_both_nvd_names():
    disp, cpes = aw.cpes_for("cisco_asa")
    assert cpes == ("o:cisco:adaptive_security_appliance_software",
                    "a:cisco:adaptive_security_appliance_software")
    assert aw.cpes_for("fortigate")[1] == ("o:fortinet:fortios",)
    assert aw.SECURITY_DEVICES == {"fortiweb", "cisco_asa", "fortigate"}


def test_inventory_carries_the_version_or_the_build_date_never_both():
    inv = aw.build_inventory([], [
        {"asset_id": "vpn.example.com", "vendor_product": {"vendor": "Cisco", "product": "ASA",
                                                          "version": "9.16.4.48", "version_raw": "9.16(4)48"}},
        {"asset_id": "fgt.example.com", "vendor_product": {"vendor": "Fortinet", "product": "FortiGate",
                                                          "release_date": "2024-02-20"}},
        {"asset_id": "odd.example.com", "vendor_product": {"vendor": "Cisco", "product": "ASA",
                                                          "version": "9.16(4)48", "release_date": "20240220"}},
        {"asset_id": "both.example.com", "vendor_product": {"vendor": "Fortinet", "product": "FortiGate",
                                                           "version": "7.2.7", "release_date": "2024-02-20"}}])
    assert inv["both.example.com"].products == {"fortigate": "7.2.7"}
    assert inv["both.example.com"].release_dates == {}                    # a version wins over a date
    assert inv["vpn.example.com"].products == {"cisco_asa": "9.16.4.48"}
    assert inv["vpn.example.com"].release_dates == {}
    assert inv["fgt.example.com"].products == {"fortigate": None}
    assert inv["fgt.example.com"].release_dates == {"fortigate": "2024-02-20"}
    assert inv["odd.example.com"].products == {"cisco_asa": None}       # unparseable: never guessed
    assert inv["odd.example.com"].release_dates == {}


def test_security_devices_ask_for_every_kev_entry_others_the_90_day_window():
    get = FakeGet([])
    src = aw.Sources(get=get, sleep=lambda s: None, now=NOW)
    aw.advisories_for(src, ("o:fortinet:fortios",), set(), all_kev=True)
    aw.advisories_for(src, ("a:php:php",), set())
    fortios = [u for u in get.urls if "fortios" in u]
    php = [u for u in get.urls if "php" in u]
    assert any("hasKev" in u and "kevStartDate" not in u for u in fortios)
    assert not any("hasKev" in u for u in php) and any("kevStartDate" in u for u in php)


def test_kev_on_a_security_device_is_critical_even_without_a_version():
    a = adv(asa_cve(), kev=True)
    (act,) = aw.plan(host({"cisco_asa": None}, scanned=False, asset="vpn.example.com"),
                     {"cisco_asa": {a.cve_id: a}}, set(), {}, {})
    assert act.fields["severity"] == "CRITICAL"
    assert "security-device" in act.fields["tags"] and "cisa-kev" in act.fields["tags"]
    assert "No attack was sent" in act.fields["description"]
    assert "Nothing was sent to the site" not in act.fields["description"]


def test_a_shown_asa_version_in_range_is_high_without_kev_and_out_of_range_is_nothing():
    a = adv(asa_cve(kev=False), kev=False)
    inv = host({"cisco_asa": "9.16.4.48"}, scanned=False, asset="vpn.example.com")
    (act,) = aw.plan(inv, {"cisco_asa": {a.cve_id: a}}, set(), {}, {})
    assert act.fields["severity"] == "HIGH" and "9.16.4.48 is in the affected range" in act.fields["title"]
    patched = host({"cisco_asa": "9.16.4.85"}, scanned=False, asset="vpn.example.com")
    assert aw.plan(patched, {"cisco_asa": {a.cve_id: a}}, set(), {}, {}) == []


def test_severity_ladder():
    assert aw.severity_for("cisco_asa", None, True) == "CRITICAL"
    assert aw.severity_for("fortiweb", None, True) == "CRITICAL"          # the D4 widening
    assert aw.severity_for("fortigate", "7.2.1", False) == "HIGH"
    assert aw.severity_for("fortigate", None, False) == "MODERATE"
    assert aw.severity_for("php", None, True) == "HIGH"                   # 3d unchanged
    assert aw.severity_for("php", "8.3.10", False) == "MODERATE"


def test_build_date_keeps_only_advisories_published_after_it():
    old = adv(asa_cve("CVE-2023-27997", published="2023-06-13T09:15:00.000",
                      cpe="o:fortinet:fortios", start="7.2.0", end="7.2.5"), kev=True)
    new = adv(asa_cve("CVE-2024-21762", published="2024-02-09T09:15:00.000",
                      cpe="o:fortinet:fortios", start="7.2.0", end="7.2.7"), kev=True)
    newer = adv(asa_cve("CVE-2025-1", published="2025-01-14T09:15:00.000", kev=False,
                        cpe="o:fortinet:fortios", start="7.2.0", end="7.2.11"), kev=False)
    inv = {"fgt.example.com": aw.Host("fgt.example.com", {"fortigate": None}, False,
                                      {"fortigate": "2024-01-31"})}
    found = {"fortigate": {a.cve_id: a for a in (old, new, newer)}}
    (act,) = aw.plan(inv, found, set(), {}, {})
    assert act.fields["cve"] == ["CVE-2024-21762", "CVE-2025-1"]
    t = act.fields["title"]
    assert t.startswith("Fortinet FortiGate (FortiOS) firmware built Jan 2024 — 2 advisories published since")
    assert "1 on CISA’s exploited list" in t and t.endswith("confirm it’s patched")
    assert act.fields["severity"] == "CRITICAL" and "firmware-build-date" in act.fields["tags"]
    assert "2024-01-31" in act.fields["description"]


def test_a_newer_build_drops_listed_advisories_published_before_it():
    a = adv(asa_cve("CVE-2024-21762", published="2024-02-09T09:15:00.000",
                    cpe="o:fortinet:fortios", start="7.2.0", end="7.2.7"), kev=True)
    inv = {"fgt.example.com": aw.Host("fgt.example.com", {"fortigate": None}, False,
                                      {"fortigate": "2025-06-01"})}
    cur = {aw.finding_id("fgt.example.com", "fortigate"):
           {"asset_id": "fgt.example.com", "key": "fortigate", "status": "open", "cve": ["CVE-2024-21762"]}}
    (act,) = aw.plan(inv, {"fortigate": {a.cve_id: a}}, set(), cur, {})
    assert act.kind == "close" and "firmware built 2025-06-01 is newer" in act.reason


def test_published_after_keeps_unknown_dates():
    a = aw.Advisory("CVE-X", None, None, False, "")
    assert aw.published_after(a, "2024-01-31") is True
    a.published = "2024-01-31T23:00:00.000"
    assert aw.published_after(a, "2024-01-31") is False


def test_fortiweb_now_reads_every_kev_entry_and_is_critical():
    # the D4 widening, live on the four confirmed FortiWeb hosts
    a = adv(asa_cve("CVE-2025-64446", cpe="a:fortinet:fortiweb", start="7.0.0", end="7.0.12"), kev=True)
    (act,) = aw.plan(host({"fortiweb": None}, scanned=False, asset="api.example.com"),
                     {"fortiweb": {a.cve_id: a}}, set(), {}, {})
    assert act.fields["severity"] == "CRITICAL"
    assert "Runs Fortinet FortiWeb, version not shown" in act.fields["title"]


def test_run_asks_for_every_kev_entry_for_a_confirmed_security_device():
    class ApplianceCur(Cur):
        def fetchall(self):
            if "httpx_tech" not in self.last and "vendor_product_confidence" in self.last:
                return [{"asset_id": "vpn.example.com",
                         "vendor_product": {"vendor": "Cisco", "product": "ASA"}}]
            return super().fetchall()

    class ApplianceConn(Conn):
        def cursor(self):
            return ApplianceCur(self.s)

    get = FakeGet([])
    aw.run(ApplianceConn([]), aw.Sources(get=get, sleep=lambda s: None, now=NOW),
           dry_run=True, log=lambda *a: None, Json=lambda x: x)
    asa = [u for u in get.urls if "adaptive_security_appliance_software" in u]
    assert any("hasKev" in u and "kevStartDate" not in u for u in asa)
    assert {("%3Ao%3Acisco" in u) or ("%3Aa%3Acisco" in u) for u in asa} == {True}
