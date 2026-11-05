"""Job 5a (plan v3 B, C, D): the one DNS change pipeline in surface_diff, and the replay gate.

What these pin, from the plan review (2026-11-05 13:44):
  * must-fix 2 — a record is compared only when BOTH readings observed it (ok, not carried);
    a failed lookup, NODATA, a dead CNAME target and one NXDOMAIN are never "gone";
  * must-fix 3 — cloud rotation never counts; a CNAME to the same target never counts; a move
    silences BOTH port directions for that name; the move carries both addresses' ports;
  * the REPLAY GATE — six months of real saved discovery copies (fixtures/dns_history_5a.json,
    extracted read-only from the Command scanner repo's git history) give exactly the moves
    test.commandcommcentral.com really made, and nothing for the rotating cloud names.

Run:  pytest scripts/db/test_dns_changes_5a.py -q
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import surface_diff as sd  # noqa: E402

T0, T1 = "2026-11-04T00:48:08Z", "2026-11-04T06:41:24Z"


def rec(values=(), health="ok", ttl=5, carried=False):
    r = {"health": health, "values": list(values), "ttl": ttl}
    if carried:
        r["carried"] = True
    return r


def reading(name="test.example.com", a=("24.38.70.8",), status="exists", streak=0, at=T0, owners=None, **recs):
    records = {"a": rec(a), "aaaa": rec(), "cname": rec(), "ns": rec(), "mx": rec(), "txt": rec()}
    for k, v in recs.items():
        records[k] = v
    r = {"name": name, "read_at": at, "name_status": status, "nx_streak": streak, "records": records}
    if owners:
        r["owners"] = owners
    return r


def kinds(changes):
    return [(c["name"], c["kind"]) for c in changes]


# ── addresses ─────────────────────────────────────────────────────────────────────────────────
def test_an_address_change_on_an_ordinary_server_is_a_move():
    o = {"t": reading("t", a=("24.38.70.8",))}
    n = {"t": reading("t", a=("52.119.65.6",), at=T1)}
    ch = sd.dns_changes(o, n)
    assert kinds(ch) == [("t", "address")]
    assert ch[0]["old"]["values"] == ["24.38.70.8"] and ch[0]["new"]["values"] == ["52.119.65.6"]


def test_same_addresses_in_another_order_or_case_is_no_change_and_ttl_alone_is_no_change():
    o = {"t": reading("t", a=("10.0.0.2", "10.0.0.1"))}
    n = {"t": reading("t", a=("10.0.0.1", "10.0.0.2"))}
    n["t"]["records"]["a"]["ttl"] = 3600
    assert sd.dns_changes(o, n) == []


def test_a_failed_or_carried_record_on_either_side_is_never_compared():
    o = {"t": reading("t", a=("24.38.70.8",))}
    for bad in (rec((), health="failed"), rec(("9.9.9.9",), carried=True), rec((), health="nxdomain")):
        n = {"t": reading("t", a=())}
        n["t"]["records"]["a"] = bad
        assert sd.dns_changes(o, n) == [], bad
        assert sd.dns_changes(n, o) == [], bad


def test_a_reading_carried_whole_is_not_observed_this_run():
    o = {"t": reading("t", a=("24.38.70.8",))}
    n = {"t": {**reading("t", a=("52.119.65.6",)), "carried": True}}
    assert sd.dns_changes(o, n) == []


def test_a_cname_to_the_same_target_never_moves_however_its_addresses_rotate():
    o = {"e": reading("e", a=("52.96.1.1",), cname=rec(("outlook.office365.com",)))}
    n = {"e": reading("e", a=("52.96.9.9", "52.96.8.8"), cname=rec(("outlook.office365.com",)))}
    assert sd.dns_changes(o, n) == []


def test_a_cloud_endpoint_moves_only_when_provider_or_owner_changes():
    own = lambda ip, org: {ip: {"asn": "AS1", "asn_org": org}}
    o = {"p": reading("p", a=("20.1.1.1",), owners=own("20.1.1.1", "Microsoft Corporation"))}
    rot = {"p": reading("p", a=("40.2.2.2",), owners=own("40.2.2.2", "Microsoft Corporation"))}
    azure = {"p": {"old": (True, "azure"), "new": (True, "azure")}}
    assert sd.dns_changes(o, rot, azure) == []
    other = {"p": reading("p", a=("40.2.2.2",), owners=own("40.2.2.2", "Some Other Host"))}
    assert kinds(sd.dns_changes(o, other, azure)) == [("p", "address")]
    left = {"p": {"old": (True, "azure"), "new": (False, None)}}
    assert kinds(sd.dns_changes(o, rot, left)) == [("p", "address")]
    # the provider is compared as text: Command's column is an enum, Prodex's is text
    enum_vs_text = {"p": {"old": (True, "AZURE "), "new": (True, "azure")}}
    assert sd.dns_changes(o, rot, enum_vs_text) == []


def test_unknown_owners_on_a_cloud_endpoint_never_claim_a_move():
    o = {"p": reading("p", a=("20.1.1.1",))}
    n = {"p": reading("p", a=("40.2.2.2",))}
    assert sd.dns_changes(o, n, {"p": {"old": (True, "aws"), "new": (True, "aws")}}) == []


# ── gone and back ─────────────────────────────────────────────────────────────────────────────
def nx(name, streak):
    r = reading(name, a=(), status="nxdomain", streak=streak)
    r["records"]["a"], r["records"]["aaaa"] = rec((), health="nxdomain"), rec((), health="nxdomain")
    return r


def test_gone_is_the_second_nxdomain_in_a_row_and_said_once():
    ok = {"g": reading("g")}
    assert sd.dns_changes(ok, {"g": nx("g", 1)}) == []
    assert kinds(sd.dns_changes({"g": nx("g", 1)}, {"g": nx("g", 2)})) == [("g", "gone")]
    assert sd.dns_changes({"g": nx("g", 2)}, {"g": nx("g", 3)}) == []
    # a baseline held back one run by a failed write (import_asm_to_surface): still said, once
    assert kinds(sd.dns_changes({"g": nx("g", 1)}, {"g": nx("g", 3)})) == [("g", "gone")]
    assert kinds(sd.dns_changes({"g": reading("g")}, {"g": nx("g", 2)})) == [("g", "gone")]
    a = sd.dns_changes({"g": nx("g", 1)}, {"g": nx("g", 2)})[0]
    b = sd.dns_changes({"g": nx("g", 1)}, {"g": nx("g", 3)})[0]
    assert sd.change_fingerprint(a) == sd.change_fingerprint(b)


def test_nxdomain_ok_nxdomain_is_never_gone_and_unknown_is_never_gone():
    seq = [reading("g"), nx("g", 1), reading("g"), nx("g", 1)]
    out = []
    for a, b in zip(seq, seq[1:]):
        out += sd.dns_changes({"g": a}, {"g": b})
    assert [k for _, k in kinds(out)] == []
    unk = reading("g", a=(), status="unknown", streak=1)
    unk["records"]["a"] = rec((), health="failed")
    assert sd.dns_changes({"g": nx("g", 1)}, {"g": unk}) == []


def test_nodata_and_a_dead_cname_target_are_not_gone():
    nodata = reading("m", a=())    # the name answers, with no address: an address change, never gone
    assert kinds(sd.dns_changes({"m": reading("m")}, {"m": nodata})) == [("m", "address")]
    dead = reading("d", a=(), cname=rec(("gone.azurewebsites.net",)))
    dead["records"]["a"]["dead_target"] = "gone.azurewebsites.net"
    for c in sd.dns_changes({"d": reading("d", cname=rec(("gone.azurewebsites.net",)))}, {"d": dead}):
        assert c["kind"] != "gone"


def test_back_after_gone_is_said_once_and_resets():
    assert kinds(sd.dns_changes({"g": nx("g", 2)}, {"g": reading("g")})) == [("g", "back")]
    assert kinds(sd.dns_changes({"g": nx("g", 5)}, {"g": reading("g")})) == [("g", "back")]
    assert sd.dns_changes({"g": nx("g", 1)}, {"g": reading("g")}) == []


# ── name servers, mail servers, mail policy, cname ────────────────────────────────────────────
def test_name_servers_compared_for_the_apex_only():
    o = {"a.com": reading("a.com", ns=rec(("ns35.domaincontrol.com", "ns36.domaincontrol.com"))),
         "www.a.com": reading("www.a.com", ns=rec(("ns35.domaincontrol.com",)))}
    n = {"a.com": reading("a.com", ns=rec(("ns-95.awsdns-11.com.", "NS-847.awsdns-41.net"))),
         "www.a.com": reading("www.a.com", ns=rec(("ns-95.awsdns-11.com",)))}
    assert kinds(sd.dns_changes(o, n, apex="a.com")) == [("a.com", "ns")]


def test_mail_servers_and_policy_and_cname():
    o = {"a.com": reading("a.com", mx=rec(("10 mail.a.com",)), txt=rec(("v=spf1 -all", "google-site=x")),
                          dmarc=rec(("v=DMARC1; p=none",)), cname=rec())}
    n = copy.deepcopy(o)
    n["a.com"]["records"]["mx"] = rec(("10 mx.evil.net",))
    n["a.com"]["records"]["dmarc"] = rec(("v=DMARC1; p=reject",))
    got = kinds(sd.dns_changes(o, n, apex="a.com"))
    assert ("a.com", "mx") in got and ("a.com", "mail_policy") in got
    same_policy = copy.deepcopy(o)
    same_policy["a.com"]["records"]["txt"] = rec(("google-site=y", "v=spf1 -all"))
    assert sd.dns_changes(o, same_policy, apex="a.com") == []
    c1 = {"w": reading("w", cname=rec(("old.pressable.com",)))}
    c2 = {"w": reading("w", cname=rec(("new.pressable.com",)))}
    assert ("w", "cname") in kinds(sd.dns_changes(c1, c2))


def test_names_missing_on_either_side_or_first_readings_give_nothing():
    assert sd.dns_changes({}, {"t": reading("t")}) == []
    assert sd.dns_changes({"t": reading("t")}, {}) == []
    assert sd.dns_changes(None, None) == []


# ── a move silences port events; the event rows ───────────────────────────────────────────────
def blob(name, ip, ports, naabu_ok=True):
    return {"subdomains": [{"name": name, "probe_status": {"naabu": {"ok": naabu_ok}},
                            "services": [{"ip": ip, "port": p, "protocol": "tcp"} for p in ports]}]}


def test_a_move_silences_both_port_directions_and_only_for_that_name():
    old = blob("t", "24.38.70.8", [80, 443])
    new = blob("t", "52.119.65.6", [])
    assert {e["event_type"] for e in sd.compute_events("t", old, new, "x")} == {"port_closed"}
    assert sd.compute_events("t", old, new, "x", skip_port_names=frozenset({"t"})) == []
    assert sd.compute_events("t", new, old, "x", skip_port_names=frozenset({"t"})) == []
    other = sd.compute_events("t", old, new, "x", skip_port_names=frozenset({"someone-else"}))
    assert len(other) == 2


def test_event_rows_carry_old_ports_when_last_seen_and_skip_names_without_an_asset():
    ch = sd.dns_changes({"t": reading("t", a=("24.38.70.8",))}, {"t": reading("t", a=("52.119.65.6",), at=T1)})
    ch += [{"name": "nobody", "kind": "gone", "old": {}, "new": {}}]
    rows = sd.dns_event_rows(
        ch, {"t": "t"}.get, "asm_cron",
        ports_old={"t": [{"ip": "24.38.70.8", "port": 80, "proto": "tcp"}]},
        ports_new={"t": []}, old_seen_at=T0,
        old_address_now={"24.38.70.8": {"owned_asset": True, "service_count": 2}})
    assert len(rows) == 1
    r = rows[0]
    assert r["event_type"] == "dns_address_changed" and r["host"] == "t" and r["port"] is None
    assert r["prev_value"]["ports"] == [{"ip": "24.38.70.8", "port": 80, "proto": "tcp"}]
    assert r["prev_value"]["last_seen"] == T0
    assert r["prev_value"]["owned_address_now"] == {"24.38.70.8": {"owned_asset": True, "service_count": 2}}
    assert r["new_value"]["ports"] == [] and len(r["new_value"]["fingerprint"]) == 16


def test_fingerprint_is_stable_ignores_times_and_ttl_and_differs_per_change():
    a = sd.dns_changes({"t": reading("t", a=("1.1.1.1",))}, {"t": reading("t", a=("2.2.2.2",), at=T1)})[0]
    b = copy.deepcopy(a)
    b["old"]["read_at"], b["new"]["ttl"] = "1999-01-01T00:00:00Z", 99999
    assert sd.change_fingerprint(a) == sd.change_fingerprint(b)
    c = sd.dns_changes({"t": reading("t", a=("2.2.2.2",))}, {"t": reading("t", a=("1.1.1.1",))})[0]
    assert sd.change_fingerprint(a) != sd.change_fingerprint(c)


def test_every_event_type_is_a_dns_type_and_none_is_a_kind_the_portal_already_shows():
    assert set(sd.DNS_EVENT_TYPES.values()) == {
        "dns_address_changed", "dns_cname_changed", "dns_ns_changed", "dns_mx_changed",
        "dns_mail_policy_changed", "dns_name_gone", "dns_name_back"}
    assert not set(sd.DNS_EVENT_TYPES.values()) & {"port_opened", "port_closed", "asset_first_seen", "asset_went_dark"}


# ── legacy copies (the history load and the replay) ───────────────────────────────────────────
def test_legacy_empty_sets_are_not_known_and_never_a_removal_or_gone():
    b1 = {"scan": {"completed_at": T0}, "subdomains": [{"name": "t", "dns": {"a": ["24.38.70.8"], "mx": [{"priority": 10, "host": "m"}]}}]}
    b2 = {"scan": {"completed_at": T1}, "subdomains": [{"name": "t", "dns": {"a": [], "mx": []}}]}
    r1, r2 = sd.legacy_readings(b1), sd.legacy_readings(b2)
    assert r2["t"]["name_status"] == "unknown"
    assert sd.dns_changes(r1, r2) == [] and sd.dns_changes(r2, r1) == []
    assert all(r.get("legacy") for r in r1.values())


# ── THE REPLAY GATE: months of this instance's own saved discovery copies ──────────────────────
# fixtures/dns_history_5a.json holds, per name, every DIFFERENT saved reading of that name from
# this instance's own git history (consecutive repeats dropped: they change nothing), and the
# changes EXPECTED, written by hand from the raw address timelines, not from this code. Each
# repo carries its own instance's fixture (Command's names never enter Prodex's repo, and the
# reverse); this test file is the same in both.
FIXTURE = HERE / "fixtures" / "dns_history_5a.json"


def replay(fx, name):
    entry = fx["names"][name]
    prev, prev_cloud, out = None, None, []
    for c in entry["copies"]:
        blob_ = {"scan": {"completed_at": c["at"]}, "subdomains": [{
            "name": name, "dns": {"a": c["a"], "aaaa": c["aaaa"], "cname": c["cname"], "ns": c["ns"]},
            "hosts": [{"ip": ip, "asn_org": org} for ip, org in c["owners"].items()]}]}
        cur = sd.legacy_readings(blob_)
        cloud = tuple(c["cloud"])
        if prev is not None:
            for ch in sd.dns_changes(prev, cur, {name: {"old": prev_cloud, "new": cloud}}, apex=entry["apex"]):
                out.append([c["at"], ch["kind"], ch["old"].get("values"), ch["new"].get("values")])
        prev, prev_cloud = cur, cloud
    return out


def test_replay_every_name_gives_exactly_its_real_changes_and_nothing_invented():
    fx = json.loads(FIXTURE.read_text())
    assert fx["names"] and set(fx["names"]) == set(fx["expect"])
    for name in sorted(fx["names"]):
        assert replay(fx, name) == fx["expect"][name], name


def test_replay_covers_a_rotating_cloud_name_and_a_real_move():
    fx = json.loads(FIXTURE.read_text())
    rotating = [n for n, e in fx["expect"].items() if not e and len(fx["names"][n]["copies"]) >= 20]
    moving = [n for n, e in fx["expect"].items() if any(k == "address" for _, k, *_ in e)]
    assert rotating, "the fixture must hold a name whose addresses rotate (the flood case)"
    assert moving, "the fixture must hold a name that really moved"
