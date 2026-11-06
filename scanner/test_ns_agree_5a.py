"""Job 5a, 2026-11-06: an apex's name-server change counts only when its name servers, asked
directly, all give the same new set.

WHY: two zones kept answering two ways through the everyday lookup ("ns01" and "ns01 + ns02"),
and every flip was written as a name-server change (four false rows on Nov 6). Howie, 14:42: "I
authorize discovery to query or ask each name server directly. I'm in favor of that."

These tests pin: the aa flag read from real dig output; nothing asked on a quiet run; every
server in either set asked (the false-change trap: asking only the everyday answer's servers);
a server an answer names asked too, within a cap; agree / disagree / incomplete; a server that
does not answer for its own zone (no aa) is no answer; the disagreement kept with its first
sighting; the first run under the rule; the wiring (the apex only, --previous from discovery,
the normalizer keeping the new fields).

Run:  pytest scanner/test_ns_agree_5a.py -q
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import dns_reading as dr  # noqa: E402
import normalize  # noqa: E402

APEX = "example.com"
NS1, NS2, NS3 = "ns01.example.com", "ns02.example.com", "ns03.example.com"


def ns_out(status="NOERROR", servers=(), aa=True, ttl=7200, qname=APEX):
    flags = "qr aa" if aa else "qr"
    lines = [f"; <<>> DiG 9.18.18 <<>> +noall +comments +answer +norecurse @x NS {qname}",
             ";; global options: +cmd", ";; Got answer:",
             f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 4242",
             f";; flags: {flags}; QUERY: 1, ANSWER: {len(servers)}, AUTHORITY: 0, ADDITIONAL: 1", "",
             ";; ANSWER SECTION:"]
    lines += [f"{qname}.\t{ttl}\tIN\tNS\t{s}." for s in servers]
    return "\n".join(lines) + "\n"


class Servers:
    """A fake set of name servers: {server: dig output or a callable}; records every question."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, server, name, qtype):
        self.asked.append((server, name, qtype))
        a = self.answers.get(server, "")
        return a() if callable(a) else a


def everyday(*servers, health="ok"):
    return {"health": health, "status": "NOERROR" if health == "ok" else None,
            "values": sorted(servers), "ttl": 1800}


def prev(counted=None, raw=None, dis=None, key=True):
    p = {"name": APEX, "name_status": "exists",
         "records": {"ns": everyday(*(raw if raw is not None else (counted or ())))}}
    if key:
        p["ns_counted"] = list(counted) if counted is not None else None
    if dis is not None:
        p["ns_disagreement"] = dis
    return p


SPLIT = {NS1: ns_out(servers=(NS1,), ttl=7200), NS2: ns_out(servers=(NS1, NS2), ttl=1800)}
BOTH = {NS1: ns_out(servers=(NS1, NS2)), NS2: ns_out(servers=(NS1, NS2))}


# ── parsing the direct answer ───────────────────────────────────────────────────────────────────
def test_the_aa_flag_is_read_from_the_flags_line():
    r = dr.parse_direct(ns_out(servers=(NS1, NS2)))
    assert r["authoritative"] is True and r["values"] == [NS1, NS2] and dr.server_answered(r)
    r = dr.parse_direct(ns_out(servers=(NS1, NS2), aa=False))
    assert r["authoritative"] is False and not dr.server_answered(r)


def test_refused_timeout_and_an_empty_answer_are_no_answer():
    for out in (ns_out("REFUSED"), ";; connection timed out; no servers could be reached\n", "",
                ns_out(servers=())):
        assert not dr.server_answered(dr.parse_direct(out)), out


def test_the_direct_question_is_plain_ns_without_recursion_at_the_server():
    import subprocess
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    orig = dr.subprocess.run
    dr.subprocess.run = fake_run
    try:
        dr.run_dig_at(NS2, APEX, "NS")
    finally:
        dr.subprocess.run = orig
    assert seen["cmd"][0] == "dig" and "+norecurse" in seen["cmd"] and "@" + NS2 in seen["cmd"]
    assert seen["cmd"][-2:] == ["NS", APEX] and "AXFR" not in " ".join(seen["cmd"]).upper()


# ── when Sentry asks, and whom ──────────────────────────────────────────────────────────────────
def test_a_quiet_run_asks_nothing():
    s = Servers(BOTH)
    got = dr.ns_fields(prev([NS1, NS2]), everyday(NS1, NS2), APEX, s, "T1")
    assert s.asked == [] and got["ns_counted"] == [NS1, NS2] and "ns_check" not in got


def test_a_flip_asks_every_server_in_either_set_and_counts_nothing_when_they_disagree():
    s = Servers(SPLIT)
    got = dr.ns_fields(prev([NS1, NS2]), everyday(NS1), APEX, s, "T2")
    assert sorted(a[0] for a in s.asked) == [NS1, NS2], "ns02 (only in the counted set) must be asked"
    assert all(a[1:] == (APEX, "NS") for a in s.asked)
    assert got["ns_counted"] == [NS1, NS2] and got["ns_check"]["verdict"] == "disagree"
    assert got["ns_disagreement"] == {"first_seen": "T2", "last_seen": "T2",
                                      "answers": {NS1: [NS1], NS2: [NS1, NS2]}}


def test_asking_only_the_everyday_answers_servers_would_have_counted_a_false_change():
    # The trap the rule closes: asked alone, ns01 says "ns01" and names nobody else, so asking
    # only the everyday answer's servers "agrees" on ns01; ns02, in the counted set, knows better.
    only_ns1 = dr.ask_name_servers(APEX, [NS1], Servers(SPLIT))
    assert only_ns1["verdict"] == "agree" and only_ns1["set"] == [NS1]
    full = dr.ns_fields(prev([NS1, NS2]), everyday(NS1), APEX, Servers(SPLIT), "T")
    assert full["ns_counted"] == [NS1, NS2] and full["ns_check"]["verdict"] == "disagree"


def test_a_server_an_answer_names_is_asked_too():
    # ns03 is in neither the counted set nor the everyday answer: only ns01's and ns02's own
    # answers name it, so it is asked only because an answer named it.
    s = Servers({NS1: ns_out(servers=(NS1, NS2, NS3)), NS2: ns_out(servers=(NS1, NS2, NS3)),
                 NS3: ns_out(servers=(NS1, NS2, NS3))})
    got = dr.ns_fields(prev([NS1]), everyday(NS1, NS2), APEX, s, "T")
    assert sorted({a[0] for a in s.asked}) == [NS1, NS2, NS3]
    assert got["ns_counted"] == [NS1, NS2, NS3] and got["ns_check"]["verdict"] == "agree"


def test_a_newly_named_server_that_disagrees_stops_the_count():
    s = Servers({NS1: ns_out(servers=(NS1, NS2, NS3)), NS2: ns_out(servers=(NS1, NS2, NS3)),
                 NS3: ns_out(servers=(NS3,))})
    got = dr.ns_fields(prev([NS1]), everyday(NS1, NS2), APEX, s, "T")
    assert got["ns_counted"] == [NS1] and got["ns_check"]["verdict"] == "disagree"
    assert got["ns_disagreement"]["answers"][NS3] == [NS3]


def test_the_number_of_servers_asked_is_capped_and_a_capped_run_counts_nothing():
    many = [f"ns{i:02d}.example.com" for i in range(1, 21)]
    s = Servers({m: ns_out(servers=many) for m in many})
    got = dr.ns_fields(prev([NS1]), everyday(*many), APEX, s, "T")
    assert len(s.asked) == dr.NS_ASK_MAX
    assert got["ns_check"]["verdict"] == "incomplete" and got["ns_counted"] == [NS1]


# ── what counts ─────────────────────────────────────────────────────────────────────────────────
def test_a_real_change_counts_when_every_server_agrees_and_clears_an_old_disagreement():
    s = Servers(BOTH)
    old = {"first_seen": "T0", "last_seen": "T1", "answers": {NS1: [NS1], NS2: [NS1, NS2]}}
    got = dr.ns_fields(prev([NS1], dis=old), everyday(NS1, NS2), APEX, s, "T2")
    assert got["ns_counted"] == [NS1, NS2] and got["ns_disagreement"] is None
    assert got["ns_check"]["verdict"] == "agree" and got["ns_check"]["set"] == [NS1, NS2]
    assert got["ns_check"]["counted_before"] == [NS1] and got["ns_check"]["everyday_answer"] == [NS1, NS2]


def test_a_server_with_no_answer_means_nothing_is_counted_from_this_run():
    s = Servers({NS1: ns_out(servers=(NS1, NS2)), NS2: ""})
    got = dr.ns_fields(prev([NS1]), everyday(NS1, NS2), APEX, s, "T")
    assert got["ns_check"]["verdict"] == "incomplete" and got["ns_counted"] == [NS1]
    assert [a[0] for a in s.asked].count(NS2) == 2, "a failed question is retried once"


def test_a_server_that_does_not_answer_for_its_own_zone_is_no_answer():
    s = Servers({NS1: ns_out(servers=(NS1, NS2)), NS2: ns_out(servers=(NS1, NS2), aa=False)})
    got = dr.ns_fields(prev([NS1]), everyday(NS1, NS2), APEX, s, "T")
    assert got["ns_check"]["verdict"] == "incomplete" and got["ns_counted"] == [NS1]


def test_the_disagreement_keeps_its_first_sighting_and_survives_a_quiet_or_incomplete_run():
    first = dr.ns_fields(prev([NS1, NS2]), everyday(NS1), APEX, Servers(SPLIT), "T1")
    again = dr.ns_fields({**prev([NS1, NS2]), **first}, everyday(NS1), APEX, Servers(SPLIT), "T2")
    assert again["ns_disagreement"]["first_seen"] == "T1" and again["ns_disagreement"]["last_seen"] == "T2"
    quiet = dr.ns_fields({**prev([NS1, NS2]), **again}, everyday(NS1, NS2), APEX, Servers(SPLIT), "T3")
    assert quiet["ns_disagreement"] == again["ns_disagreement"] and "ns_check" not in quiet
    down = dr.ns_fields({**prev([NS1, NS2]), **again}, everyday(NS1), APEX, Servers({NS1: "", NS2: ""}), "T4")
    assert down["ns_disagreement"] == again["ns_disagreement"] and down["ns_check"]["verdict"] == "incomplete"


def test_a_failed_everyday_lookup_asks_nothing_and_keeps_the_count():
    s = Servers(BOTH)
    got = dr.ns_fields(prev([NS1]), everyday(health="failed"), APEX, s, "T")
    assert s.asked == [] and got["ns_counted"] == [NS1]


# ── the first run under the rule ────────────────────────────────────────────────────────────────
def test_a_reading_from_before_the_rule_gives_its_everyday_answer_as_the_count():
    s = Servers(SPLIT)
    got = dr.ns_fields(prev(raw=[NS1], key=False), everyday(NS1), APEX, s, "T")
    assert s.asked == [] and got["ns_counted"] == [NS1]
    got = dr.ns_fields(prev(raw=[NS1], key=False), everyday(NS1, NS2), APEX, Servers(SPLIT), "T")
    assert got["ns_counted"] == [NS1] and got["ns_check"]["verdict"] == "disagree"


def test_no_previous_reading_leaves_the_count_unknown_and_asks_nothing():
    # Code review 2026-11-06, must-fix 1: with no previous copy, ns01 asked alone agrees with
    # itself; that one-sided count must never stand against an older count held elsewhere.
    for table in (BOTH, SPLIT):
        s = Servers(table)
        got = dr.ns_fields(None, everyday(NS1), APEX, s, "T")
        assert s.asked == [] and got == {"ns_counted": None, "ns_disagreement": None}


def test_an_unknown_count_asks_the_previous_everyday_answers_servers_too():
    s = Servers(SPLIT)
    got = dr.ns_fields(prev(None, raw=[NS1, NS2]), everyday(NS1), APEX, s, "T")
    assert sorted({a[0] for a in s.asked}) == [NS1, NS2]
    assert got["ns_check"]["verdict"] == "disagree" and got["ns_counted"] is None


def test_a_count_set_from_scratch_is_marked_fresh_and_only_then():
    got = dr.ns_fields(prev(None, raw=[NS1]), everyday(NS1, NS2), APEX, Servers(BOTH), "T1")
    assert got["ns_counted"] == [NS1, NS2] and got["ns_counted_fresh"] is True
    nxt = dr.ns_fields({**prev(None, raw=[NS1, NS2]), **got}, everyday(NS1), APEX, Servers(SPLIT), "T2")
    assert "ns_counted_fresh" not in nxt and nxt["ns_counted"] == [NS1, NS2]
    moved = dr.ns_fields(prev([NS1]), everyday(NS1, NS2), APEX, Servers(BOTH), "T3")
    assert moved["ns_counted"] == [NS1, NS2] and "ns_counted_fresh" not in moved


# ── wiring ──────────────────────────────────────────────────────────────────────────────────────
def _everyday_runner(ns_values):
    def run(name, qtype):
        if qtype == "NS" and name == APEX:
            lines = [";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1", ";; flags: qr rd ra;"]
            lines += [f"{APEX}.\t1800\tIN\tNS\t{v}." for v in ns_values]
            return "\n".join(lines) + "\n"
        return ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra;\n"
    return run


def test_read_names_adds_the_fields_to_the_apex_only():
    s = Servers(SPLIT)
    doc = dr.read_names([APEX, "www." + APEX], APEX, runner=_everyday_runner([NS1]),
                        prev_readings={APEX: prev([NS1, NS2])}, server_runner=s)
    ap, www = doc["readings"][APEX], doc["readings"]["www." + APEX]
    assert ap["ns_counted"] == [NS1, NS2] and ap["ns_check"]["verdict"] == "disagree"
    assert not any(k.startswith("ns_") for k in www)


def test_main_reads_the_previous_copy_and_survives_one_it_cannot_read():
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "names").write_text(APEX + "\n")
        (t / "prev.json").write_text(json.dumps({"dns_readings": {APEX: prev([NS1, NS2])}}))
        (t / "bad.json").write_text("{not json")
        assert dr.load_prev_readings(str(t / "prev.json"))[APEX]["ns_counted"] == [NS1, NS2]
        assert dr.load_prev_readings(str(t / "bad.json")) == {}
        assert dr.load_prev_readings(str(t / "missing.json")) == {}
        assert dr.load_prev_readings("") == {}


def test_main_compares_with_the_previous_copy_end_to_end(monkeypatch):
    # The everyday lookup says ns01 alone; the previous copy counted ns01 + ns02; the servers
    # disagree. With --previous the count holds; without it the count is unknown and nothing is
    # asked (asked alone, ns01 would agree with itself: code review 2026-11-06, must-fix 1).
    s = Servers(SPLIT)
    monkeypatch.setattr(dr, "run_dig", _everyday_runner([NS1]))
    monkeypatch.setattr(dr, "run_dig_at", s)
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "names").write_text(APEX + "\n")
        (t / "prev.json").write_text(json.dumps({"dns_readings": {APEX: prev([NS1, NS2])}}))
        assert dr.main(["--names", str(t / "names"), "--apex", APEX, "--out", str(t / "out.json"),
                        "--previous", str(t / "prev.json"), "--workers", "1"]) == 0
        got = json.loads((t / "out.json").read_text())["readings"][APEX]
        assert got["ns_counted"] == [NS1, NS2] and got["ns_check"]["verdict"] == "disagree"
        assert sorted({a[0] for a in s.asked}) == [NS1, NS2]
        asked_before = len(s.asked)
        for extra in ([], ["--previous", str(t / "unreadable.json")]):
            (t / "unreadable.json").write_text("{not json")
            assert dr.main(["--names", str(t / "names"), "--apex", APEX, "--out", str(t / "out2.json"),
                            "--workers", "1", *extra]) == 0
            got2 = json.loads((t / "out2.json").read_text())["readings"][APEX]
            assert got2["ns_counted"] is None and "ns_check" not in got2
        assert len(s.asked) == asked_before, "with no readable previous copy nothing is asked"


def test_discovery_hands_the_reader_the_previous_saved_copy():
    body = (HERE / "asm-discover.sh").read_text()
    start = body.index('python3 "$DNS_READER"')
    call = body[start:body.index("|| warn", start)]
    assert '--previous "$ASSETS_DIR/$(cat "$wd/_target_id" 2>/dev/null || echo none).json"' in call
    assert body.count('python3 "$DNS_READER"') == 1


def test_the_normalizer_keeps_the_new_fields_and_carries_them_when_the_reader_wrote_nothing():
    fields = {"ns_counted": [NS1, NS2],
              "ns_disagreement": {"first_seen": "T1", "last_seen": "T2", "answers": {NS1: [NS1]}}}
    fresh = {APEX: {**prev([NS1, NS2]), **fields, "read_at": "T2"}}
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        (work / "dns_readings.json").write_text(json.dumps({"readings": fresh}))
        got = normalize.build_dns_readings(work, [], {APEX: prev([NS1])})[APEX]
        assert got["ns_counted"] == [NS1, NS2] and got["ns_disagreement"] == fields["ns_disagreement"]
    with tempfile.TemporaryDirectory() as td:
        got = normalize.build_dns_readings(Path(td), [], fresh)[APEX]
        assert got["carried"] is True and got["ns_counted"] == [NS1, NS2]
