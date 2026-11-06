"""Job 5a, 2026-11-06: a name-server change is the COUNTED set moving, never the everyday
answer flipping.

Howie, 2026-11-06 14:42: "I authorize discovery to query or ask each name server directly."
The reader (scanner/dns_reading.py) keeps ns_counted, which moves only when every name server,
asked directly, gives the same new set. These tests pin the comparison: counted vs counted;
the first run under the rule sets the baseline quietly; an unknown count is never compared;
the old everyday comparison stays for readings without the field (the history load); the
servers' answers ride along as evidence but are not part of the change's identity.

The replay tests drive the reader and the comparison together through the two patterns seen on
Nov 6 (one zone flipping "ns01" / "ns01 + ns02" with ns01 and ns02 disagreeing, the other
steady for five runs and then flipping), with example names: no client's names in either repo.

Run:  pytest scripts/db/test_ns_agree_changes_5a.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "scanner"))
import surface_diff as sd  # noqa: E402
import dns_reading as dr  # noqa: E402

APEX = "example.com"
NS1, NS2 = "ns01.example.com", "ns02.example.com"


def ns_out(servers, aa=True):
    lines = [";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1",
             f";; flags: qr{' aa' if aa else ''}; QUERY: 1, ANSWER: {len(servers)}, AUTHORITY: 0, ADDITIONAL: 0"]
    lines += [f"{APEX}.\t1800\tIN\tNS\t{s}." for s in servers]
    return "\n".join(lines) + "\n"


SPLIT = {NS1: ns_out((NS1,)), NS2: ns_out((NS1, NS2))}
BOTH = {NS1: ns_out((NS1, NS2)), NS2: ns_out((NS1, NS2))}
ONE = {NS1: ns_out((NS1,)), NS2: ns_out((NS1,))}


def servers(table):
    return lambda server, name, qtype: table.get(server, "")


def raw(values, at):
    """A reading as the reader writes it before the counted rule is applied."""
    return {"name": APEX, "read_at": at, "name_status": "exists", "nx_streak": 0,
            "records": {"ns": {"health": "ok", "status": "NOERROR", "values": sorted(values), "ttl": 1800},
                        "a": {"health": "ok", "values": ["192.0.2.1"]}, "aaaa": {"health": "ok", "values": []}}}


def run(prev_reading, everyday_values, table, at):
    r = raw(everyday_values, at)
    r.update(dr.ns_fields(prev_reading, r["records"]["ns"], APEX, servers(table), at))
    return r


def ns_changes(old, new):
    return [c for c in sd.dns_changes({APEX: old}, {APEX: new}, apex=APEX) if c["kind"] == "ns"]


def replay(baseline, steps):
    """steps: [(everyday answer, servers)]. Returns every ns change, run by run."""
    found, prev = [], baseline
    for i, (everyday, table) in enumerate(steps):
        cur = run(prev, everyday, table, f"T{i + 1}")
        found += ns_changes(prev, cur)
        prev = cur
    return found, prev


# ── the comparison ──────────────────────────────────────────────────────────────────────────────
def test_counted_against_counted_one_change_with_the_servers_as_evidence():
    old = {**raw([NS1], "T1"), "ns_counted": [NS1]}
    new = {**raw([NS1, NS2], "T2"), "ns_counted": [NS1, NS2],
           "ns_check": {"servers": {NS1: {"values": [NS1, NS2]}, NS2: {"values": [NS1, NS2]}}}}
    got = ns_changes(old, new)
    assert len(got) == 1 and got[0]["old"]["values"] == [NS1] and got[0]["new"]["values"] == [NS1, NS2]
    assert got[0]["new"]["servers"] == {NS1: [NS1, NS2], NS2: [NS1, NS2]}


def test_the_everyday_answer_flipping_is_not_a_change_when_the_count_holds():
    old = {**raw([NS1, NS2], "T1"), "ns_counted": [NS1, NS2]}
    new = {**raw([NS1], "T2"), "ns_counted": [NS1, NS2]}
    assert ns_changes(old, new) == []


def test_the_first_run_under_the_rule_sets_the_baseline_quietly():
    before_the_rule = raw([NS1], "T1")                       # no ns_counted: a pre-rule blob
    after = {**raw([NS1, NS2], "T2"), "ns_counted": [NS1, NS2]}
    assert ns_changes(before_the_rule, after) == []


def test_an_unknown_count_is_never_compared():
    old = {**raw([NS1], "T1"), "ns_counted": None}
    new = {**raw([NS1, NS2], "T2"), "ns_counted": [NS1, NS2]}
    assert ns_changes(old, new) == [] and ns_changes(new, old) == []


def test_readings_without_the_field_keep_the_everyday_comparison():
    assert len(ns_changes(raw([NS1], "T1"), raw([NS1, NS2], "T2"))) == 1


def test_a_name_inside_the_zone_never_gives_a_name_server_change():
    old = {**raw([NS1], "T1"), "name": "www." + APEX, "ns_counted": [NS1]}
    new = {**raw([NS2], "T2"), "name": "www." + APEX, "ns_counted": [NS2]}
    assert sd.dns_changes({"www." + APEX: old}, {"www." + APEX: new}, apex=APEX) == []


def test_the_servers_answers_are_not_part_of_the_changes_identity():
    old = {**raw([NS1], "T1"), "ns_counted": [NS1]}
    a = {**raw([NS1, NS2], "T2"), "ns_counted": [NS1, NS2], "ns_check": {"servers": {NS1: {"values": [NS1, NS2]}}}}
    b = {**raw([NS1, NS2], "T3"), "ns_counted": [NS1, NS2], "ns_check": {"servers": {NS2: {"values": [NS1, NS2]}}}}
    ca, cb = ns_changes(old, a)[0], ns_changes(old, b)[0]
    assert ca["new"]["servers"] != cb["new"]["servers"], "the evidence differs between the two runs"
    assert sd.change_fingerprint(ca) == sd.change_fingerprint(cb)


def test_the_event_row_carries_the_counted_sets_and_the_servers():
    old = {**raw([NS1], "T1"), "ns_counted": [NS1]}
    new = {**raw([NS1, NS2], "T2"), "ns_counted": [NS1, NS2],
           "ns_check": {"servers": {NS1: {"values": [NS1, NS2]}, NS2: {"values": [NS1, NS2]}}}}
    rows = sd.dns_event_rows(ns_changes(old, new), lambda n: n, "asm_cron")
    assert len(rows) == 1 and rows[0]["event_type"] == "dns_ns_changed" and rows[0]["host"] == APEX
    assert rows[0]["prev_value"]["values"] == [NS1] and rows[0]["new_value"]["values"] == [NS1, NS2]
    assert rows[0]["new_value"]["servers"] == {NS1: [NS1, NS2], NS2: [NS1, NS2]}


# ── the Nov 6 patterns, reader and comparison together ──────────────────────────────────────────
def test_a_zone_flipping_between_two_answers_writes_no_change():
    # Pattern 1: the baseline is a pre-rule reading of "ns01"; then ns01+ns02, ns01, and
    # ns01+ns02 three times; ns01 says "ns01", ns02 says "ns01 + ns02".
    steps = [([NS1, NS2], SPLIT), ([NS1], SPLIT), ([NS1, NS2], SPLIT), ([NS1, NS2], SPLIT), ([NS1, NS2], SPLIT)]
    found, last = replay(raw([NS1], "T0"), steps)
    assert found == []
    assert last["ns_counted"] == [NS1] and last["ns_disagreement"]["answers"] == {NS1: [NS1], NS2: [NS1, NS2]}


def test_a_zone_steady_for_five_runs_then_flipping_writes_no_change():
    # Pattern 2: ns01+ns02 five times, then ns01.
    steps = [([NS1, NS2], SPLIT)] * 4 + [([NS1], SPLIT), ([NS1], SPLIT)]
    found, last = replay(raw([NS1, NS2], "T0"), steps)
    assert found == [] and last["ns_counted"] == [NS1, NS2]


def test_the_old_rule_would_have_written_the_false_rows():
    # The same pattern 1 compared the old way (everyday answer against everyday answer).
    seq = [raw(v, f"T{i}") for i, v in enumerate([[NS1], [NS1, NS2], [NS1], [NS1, NS2], [NS1, NS2]])]
    assert sum(len(ns_changes(a, b)) for a, b in zip(seq, seq[1:])) == 3


def test_a_real_change_in_the_middle_of_flips_is_counted_once():
    steps = [([NS1, NS2], SPLIT), ([NS1], SPLIT), ([NS1, NS2], BOTH), ([NS1, NS2], BOTH), ([NS1], SPLIT)]
    found, last = replay(raw([NS1], "T0"), steps)
    assert len(found) == 1 and found[0]["old"]["values"] == [NS1] and found[0]["new"]["values"] == [NS1, NS2]
    assert last["ns_counted"] == [NS1, NS2]


def test_a_real_change_back_is_counted_when_the_servers_agree_again():
    steps = [([NS1, NS2], BOTH), ([NS1], ONE)]
    found, _ = replay({**raw([NS1], "T0"), "ns_counted": [NS1]}, steps)
    assert [(c["old"]["values"], c["new"]["values"]) for c in found] == [([NS1], [NS1, NS2]), ([NS1, NS2], [NS1])]


def test_no_readable_previous_copy_never_writes_a_change_against_the_database_count():
    # Code review 2026-11-06, must-fix 1: the database holds ns01 + ns02; the saved copy cannot be
    # read; the everyday answer is ns01. Asked alone, ns01 would agree with itself.
    db_prior = {**raw([NS1, NS2], "T0"), "ns_counted": [NS1, NS2]}
    for table in (SPLIT, ONE):
        cur = run(None, [NS1], table, "T1")
        assert cur["ns_counted"] is None and "ns_check" not in cur
        assert ns_changes(db_prior, cur) == []


def test_a_count_set_from_scratch_is_not_compared_on_the_run_that_set_it():
    # The database is a run behind (its write failed) and still holds ns01 + ns02; the saved copy
    # holds an unknown count. The servers agree on ns01: the count is set, marked fresh, and not
    # compared. The next run compares counted with counted again.
    db_prior = {**raw([NS1, NS2], "T0"), "ns_counted": [NS1, NS2]}
    git_prev = {**raw([NS1, NS2], "T1"), "ns_counted": None, "ns_disagreement": None}
    cur = run(git_prev, [NS1], ONE, "T2")
    assert cur["ns_counted"] == [NS1] and cur["ns_counted_fresh"] is True
    assert ns_changes(db_prior, cur) == []
    nxt = run(cur, [NS1], ONE, "T3")
    assert ns_changes(cur, nxt) == [] and "ns_counted_fresh" not in nxt
    later = run(nxt, [NS1, NS2], BOTH, "T4")
    got = ns_changes(nxt, later)
    assert [(c["old"]["values"], c["new"]["values"]) for c in got] == [([NS1], [NS1, NS2])]


def test_servers_that_cannot_be_reached_never_produce_a_change():
    steps = [([NS1, NS2], {}), ([NS1], {}), ([NS1, NS2], {})]
    found, last = replay({**raw([NS1], "T0"), "ns_counted": [NS1]}, steps)
    assert found == [] and last["ns_counted"] == [NS1] and last["ns_check"]["verdict"] == "incomplete"
