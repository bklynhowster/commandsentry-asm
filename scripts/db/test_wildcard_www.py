"""test_wildcard_www.py — KB 12 job 4 step 5 (plan v4.1 C2, 2026-11-08): a www name that only
the zone's wildcard DNS answers is never made a live asset by discovery.

Pins, offline (an autouse guard makes any real DNS lookup fail the test):
  1. the pure rule, on the four real shapes measured by site_members.py on Command
     (2026-11-08): the three unimacgraphics ghosts are wildcard-only; www.unimacgraphics.com
     (same wildcard addresses, but the plain name is on the same host) is NOT; a zone with no
     wildcard is not; a failed lookup is never evidence;
  2. which buckets are asked at all (www.<sub> only, never www.<apex>, never a plain name) and
     that a bucket discovery read no address for costs no lookup;
  3. importer_status never raises and changes nothing on a failed check;
  4. the real import_one, through a fake cursor: a wildcard-only bucket is written 'retired',
     its alive clock is bumped as before, and it is never resurrected; a real www.<sub> name is
     untouched; the apex path makes no lookup.
"""
from __future__ import annotations

import os
import socket
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import import_asm_to_surface as m  # noqa: E402
import wildcard_www as w  # noqa: E402

# The addresses site_members.py read on Command, 2026-11-08 (documentation only; the fakes
# below answer from these tables, nothing is looked up).
WILD = ["199.16.172.68", "199.16.173.113"]          # *.unimacgraphics.com (Pressable)
ZONE_OK = ("ok", WILD)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a test reached the real resolver")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    yield


class FakeDNS:
    """RESOLVE stand-in: answers by name; any made-up sentry-site-check-* name gets `zone`."""
    def __init__(self, table: dict, zone=ZONE_OK):
        self.table, self.zone, self.asked = table, zone, []

    def __call__(self, name):
        self.asked.append(name)
        if name.startswith(w.site_members.CONTROL_PREFIX):
            if isinstance(self.zone, Exception):
                raise self.zone
            return self.zone
        return self.table.get(name, ("nxdomain", []))


def _subs(name, addrs):
    return [{"name": name, "hosts": [{"ip": a} for a in addrs]}]


# ── 1. the pure rule ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("plain", [("ok", ["208.199.0.130"]),        # www.firewall.
                                   ("ok", ["40.71.11.138"]),         # www.portal., www.zoetislabs.
                                   ("nxdomain", []), ("v6only", [])])
def test_the_ghost_shapes_are_wildcard_only(plain):
    assert w.wildcard_only(WILD, plain, ZONE_OK) is True


def test_a_real_www_name_on_a_wildcard_zone_is_not():
    """www.unimacgraphics.com: same wildcard addresses, but so is the plain name (one host)."""
    assert w.wildcard_only(WILD, ("ok", list(reversed(WILD))), ZONE_OK) is False


def test_no_wildcard_means_no():
    assert w.wildcard_only(WILD, ("ok", ["1.1.1.1"]), ("nxdomain", [])) is False
    assert w.wildcard_only(WILD, ("ok", ["1.1.1.1"]), ("ok", [])) is False
    # only an answered lookup counts: addresses on a non-ok reading are not a wildcard
    for status in ("error", "nxdomain", "v6only"):
        assert w.wildcard_only(WILD, ("ok", ["1.1.1.1"]), (status, WILD)) is False, status


def test_records_of_its_own_mean_no():
    """The www name resolves somewhere the made-up name does not: it has its own records."""
    assert w.wildcard_only(["5.5.5.5"], ("ok", ["1.1.1.1"]), ZONE_OK) is False
    assert w.wildcard_only(WILD + ["5.5.5.5"], ("ok", ["1.1.1.1"]), ZONE_OK) is False
    assert w.wildcard_only(WILD[:1], ("ok", ["1.1.1.1"]), ZONE_OK) is False


def test_a_failed_lookup_is_never_evidence():
    assert w.wildcard_only(WILD, ("error", []), ZONE_OK) is False
    assert w.wildcard_only(WILD, ("ok", ["1.1.1.1"]), ("error", [])) is False
    assert w.wildcard_only([], ("ok", ["1.1.1.1"]), ZONE_OK) is False


# ── 2. who is asked ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bucket,apex,want", [
    ("www.portal.unimacgraphics.com", "unimacgraphics.com", True),
    ("WWW.Portal.unimacgraphics.com", "unimacgraphics.com", True),
    ("www.unimacgraphics.com", "unimacgraphics.com", False),      # routed to the apex anyway
    ("www.unimacgraphics.com", "UNIMACGRAPHICS.COM", False),
    ("portal.unimacgraphics.com", "unimacgraphics.com", False),
    ("wwwportal.unimacgraphics.com", "unimacgraphics.com", False),
    ("www.", "x.com", False), ("", "x.com", False), (None, "x.com", False),
])
def test_only_www_sub_names_are_candidates(bucket, apex, want):
    assert w.is_candidate(bucket, apex) is want


def test_bucket_addrs_reads_ipv4_from_discovery_only():
    subs = [{"name": "a", "hosts": [{"ip": "1.2.3.4"}, {"ip": "2001:db8::1"}, {"ip": None}, "junk"]},
            {"name": "b", "hosts": [{"ip": " 1.2.3.4 "}, {"ip": "9.9.9.9"}]}, "junk", {"hosts": None}]
    assert w.bucket_addrs(subs) == ["1.2.3.4", "9.9.9.9"]
    assert w.bucket_addrs([]) == [] and w.bucket_addrs(None) == []


def test_check_makes_no_lookup_when_discovery_read_no_address(monkeypatch):
    dns = FakeDNS({})
    monkeypatch.setattr(w, "RESOLVE", dns)
    assert w.check("www.portal.unimacgraphics.com", _subs("www.portal.unimacgraphics.com", []))[0] is False
    assert dns.asked == []


def test_check_asks_the_made_up_name_then_the_plain_name(monkeypatch):
    dns = FakeDNS({"portal.unimacgraphics.com": ("ok", ["40.71.11.138"])})
    monkeypatch.setattr(w, "RESOLVE", dns)
    wild, reading = w.check("www.portal.unimacgraphics.com",
                            _subs("www.portal.unimacgraphics.com", WILD), token="t0k3n")
    assert wild is True
    assert dns.asked == ["sentry-site-check-t0k3n.portal.unimacgraphics.com", "portal.unimacgraphics.com"]
    assert reading == {"www": sorted(WILD), "zone": ["ok", WILD], "plain": ["ok", ["40.71.11.138"]]}


@pytest.mark.parametrize("zone", [("nxdomain", []), ("error", []), ("ok", ["7.7.7.7"])])
def test_check_stops_after_one_lookup_unless_the_wildcard_matches(monkeypatch, zone):
    dns = FakeDNS({}, zone=zone)
    monkeypatch.setattr(w, "RESOLVE", dns)
    assert w.check("www.shop.example.com", _subs("www.shop.example.com", ["5.5.5.5"]))[0] is False
    assert len(dns.asked) == 1


# ── 3. importer_status ──────────────────────────────────────────────────────────────────────
def test_importer_status_retires_a_ghost_and_says_why(monkeypatch):
    monkeypatch.setattr(w, "RESOLVE", FakeDNS({"firewall.unimacgraphics.com": ("ok", ["208.199.0.130"])}))
    lines = []
    got = w.importer_status("www.firewall.unimacgraphics.com", "unimacgraphics.com",
                            _subs("www.firewall.unimacgraphics.com", WILD), "confirmed_live", logfn=lines.append)
    assert got == "retired" == w.STATUS
    assert len(lines) == 1 and "wildcard-only" in lines[0] and "www.firewall.unimacgraphics.com" in lines[0]
    assert "firewall.unimacgraphics.com is at 208.199.0.130" in lines[0]


@pytest.mark.parametrize("disc", ["confirmed_live", "dns_only", "ct_ghost"])
def test_importer_status_leaves_a_real_name_alone_silently(monkeypatch, disc):
    monkeypatch.setattr(w, "RESOLVE", FakeDNS({"shop.unimacgraphics.com": ("ok", WILD)}))
    lines = []
    assert w.importer_status("www.shop.unimacgraphics.com", "unimacgraphics.com",
                             _subs("www.shop.unimacgraphics.com", WILD), disc, logfn=lines.append) == disc
    assert lines == []


def test_importer_status_never_raises(monkeypatch):
    monkeypatch.setattr(w, "RESOLVE", FakeDNS({}, zone=RuntimeError("resolver blew up")))
    lines = []
    got = w.importer_status("www.portal.unimacgraphics.com", "unimacgraphics.com",
                            _subs("www.portal.unimacgraphics.com", WILD), "confirmed_live", logfn=lines.append)
    assert got == "confirmed_live"
    assert len(lines) == 1 and "non-fatal" in lines[0]


def test_importer_status_skips_non_candidates_without_a_lookup(monkeypatch):
    dns = FakeDNS({})
    monkeypatch.setattr(w, "RESOLVE", dns)
    for b in ("www.unimacgraphics.com", "portal.unimacgraphics.com"):
        assert w.importer_status(b, "unimacgraphics.com", _subs(b, WILD), "confirmed_live") == "confirmed_live"
    assert dns.asked == []


def test_resolve_is_site_members_own_lookup():
    """One DNS reading for both jobs: the importer asks exactly what site_members.py asks."""
    assert w.RESOLVE is w.site_members.resolve


# ── 4. the real import_one ──────────────────────────────────────────────────────────────────
class _Cur:
    def __init__(self, conn):
        self.conn, self.last = conn, ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.last = " ".join(str(sql).split())
        self.conn.calls.append((self.last, params))

    def fetchone(self):
        u = self.last
        if u.startswith("SELECT aliases"):
            return ([],)
        if "SELECT surface_data" in u:
            return (None,)
        if "cloud_source" in u:
            return ("derived", False, None)
        if "resurrection_count" in u:
            return None
        if "RETURNING" in u:
            return ("x", True, False)
        return None

    def fetchall(self):
        return []


class _Conn:
    def __init__(self):
        self.calls = []

    def cursor(self):
        return _Cur(self)

    def commit(self):
        pass

    def rollback(self):
        pass


def _sub(name, addrs):
    return {
        "name": name, "alive": True, "is_root": False, "discovered_via": "subfinder",
        "first_discovered": "2026-11-08T12:00:00Z", "last_seen": "2026-11-08T12:00:00Z",
        "tags": [], "reachability": {"live": True, "http_status": None, "title": None},
        "probe_status": {},
        "hosts": [{"ip": a, "asn": "AS1", "asn_org": "X", "country": "US", "region": "NY",
                   "city": "NYC", "reverse_dns": None, "is_private": False} for a in addrs],
        "services": [{"port": 443, "protocol": "tcp", "service": "https"}],
        "dns": {"a": addrs, "aaaa": [], "cname": None, "mx": [], "ns": [], "txt": [],
                "spf": None, "dnssec": False},
        "fingerprint": {"server": None, "platform_label": None, "tech": []},
        "waf": {"detected": False, "vendor": None, "confidence": "unknown"},
    }


def _doc(subs):
    return {
        "schema_version": 1,
        "asset": {"value": "unimacgraphics.com", "type": "domain", "organization": "Test"},
        "scan": {"started_at": "2026-11-08T11:00:00Z", "finished_at": "2026-11-08T12:00:00Z"},
        "registration": {},
        "summary": {"subdomain_count": len(subs), "live_subdomain_count": len(subs),
                    "host_count": 2, "service_count": 1, "newest_cert_expiry_days": None,
                    "top_hosting_org": "X", "platforms": []},
        "subdomains": subs, "phantom_subdomains": [], "deltas": {}, "history": [],
    }


def _status_written(conn, asset_id):
    out = [p["discovery_status"] for s, p in conn.calls
           if isinstance(p, dict) and p.get("asset_id") == asset_id and "discovery_status" in p
           and s.startswith("INSERT INTO public.assets")]
    assert len(out) == 1, out
    return out[0]


def _stmts_for(conn, asset_id, needle):
    return [s for s, p in conn.calls if needle in s and (
        (isinstance(p, tuple) and asset_id in p) or (isinstance(p, dict) and asset_id in p.values()))]


def test_import_one_writes_a_ghost_retired_and_never_resurrects_it(monkeypatch, capsys):
    dns = FakeDNS({"portal.unimacgraphics.com": ("ok", ["40.71.11.138"]),
                   "zoetislabs.unimacgraphics.com": ("ok", ["40.71.11.138"])})
    monkeypatch.setattr(w, "RESOLVE", dns)
    conn = _Conn()
    doc = _doc([_sub("unimacgraphics.com", WILD), _sub("www.unimacgraphics.com", WILD),
                _sub("www.portal.unimacgraphics.com", WILD), _sub("portal.unimacgraphics.com", ["40.71.11.138"]),
                _sub("www.shop.unimacgraphics.com", ["5.5.5.5"])])
    res = m.import_one(conn, doc, "test", dry_run=False, skip_events=True)
    assert res["status"] == "ok"

    assert _status_written(conn, "www.portal.unimacgraphics.com") == "retired"
    assert _status_written(conn, "portal.unimacgraphics.com") == "confirmed_live"
    assert _status_written(conn, "www.shop.unimacgraphics.com") == "confirmed_live"   # own records
    assert _status_written(conn, "unimacgraphics.com") == "confirmed_live"

    # discovery saw a service answer: the alive clock moves as it always has
    assert _stmts_for(conn, "www.portal.unimacgraphics.com", "SET last_alive_at = GREATEST")
    # ...but a wildcard-only name is never brought back from dark
    assert not _stmts_for(conn, "www.portal.unimacgraphics.com", "resurrection_count")
    assert _stmts_for(conn, "portal.unimacgraphics.com", "resurrection_count")

    # lookups: a made-up name for each of the two www.<sub> buckets, the plain name only for
    # the one whose addresses are the wildcard's; nothing for the apex, www.<apex> or portal.
    controls = [n for n in dns.asked if n.startswith(w.site_members.CONTROL_PREFIX)]
    plains = [n for n in dns.asked if not n.startswith(w.site_members.CONTROL_PREFIX)]
    assert [c.split(".", 1)[1] for c in controls] == ["portal.unimacgraphics.com", "shop.unimacgraphics.com"]
    assert plains == ["portal.unimacgraphics.com"], dns.asked
    out = capsys.readouterr().out
    assert out.count("wildcard-only:") == 1 and "wildcard-only: www.portal.unimacgraphics.com" in out


def test_import_one_is_unchanged_when_the_lookup_breaks(monkeypatch):
    monkeypatch.setattr(w, "RESOLVE", FakeDNS({}, zone=OSError("no resolver")))
    conn = _Conn()
    res = m.import_one(conn, _doc([_sub("unimacgraphics.com", WILD),
                                   _sub("www.portal.unimacgraphics.com", WILD)]),
                       "test", dry_run=False, skip_events=True)
    assert res["status"] == "ok"
    assert _status_written(conn, "www.portal.unimacgraphics.com") == "confirmed_live"
    assert _stmts_for(conn, "www.portal.unimacgraphics.com", "resurrection_count")


def test_the_importer_wires_it_once_on_the_non_apex_path_only():
    src = open(os.path.join(HERE, "import_asm_to_surface.py")).read()
    assert src.count("wildcard_www.importer_status(") == 1
    i_disc = src.index("disc = asset_liveness.discovery_status_from_service_count(")
    i_hook = src.index("wildcard_www.importer_status(")
    i_upsert = src.index("cur.execute(UPSERT_NEW_SUBDOMAIN_ASSET, {")
    assert i_disc < i_hook < i_upsert
    assert "if not is_apex:" in src[i_disc:i_hook]
    assert 'if disc_seen == "confirmed_live":' in src
