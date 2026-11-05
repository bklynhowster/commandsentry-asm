"""Job 5a (plan v3 sections 0 and A): DNS readings with health, the sixth source, and the
normalizer's carried / streak / owners rules.

The load-bearing rule (plan review 2026-11-05 13:44, must-fix 2): a lookup that FAILED is
never read as "no records". These tests pin each health outcome from real dig output shapes,
the one retry, the name status (NXDOMAIN needs A and AAAA both), the dead-CNAME-target case
(the name exists: never "gone"), the scope filter, the sixth source's two inputs, and the
normalizer keeping the last good record when this run's lookup failed.

Run:  pytest scanner/test_dns_reading_5a.py -q
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import dns_reading as dr  # noqa: E402
import known_names as kn  # noqa: E402
import normalize  # noqa: E402


def dig_out(status, answers=(), qname="x.example.com"):
    lines = [f"; <<>> DiG 9.18.18 <<>> +noall +comments +answer {qname}",
             ";; global options: +cmd", ";; Got answer:",
             f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 4242",
             ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1", "",
             ";; ANSWER SECTION:"]
    lines += [f"{o}\t{t}\tIN\t{ty}\t{v}" for (o, t, ty, v) in answers]
    return "\n".join(lines) + "\n"


TIMEOUT = ";; connection timed out; no servers could be reached\n"


# ── parse_dig: every health outcome ───────────────────────────────────────────────────────────
def test_noerror_with_records_is_ok_and_normalized():
    r = dr.parse_dig(dig_out("NOERROR", [("x.example.com.", 300, "A", "24.38.70.8")]), "A")
    assert r["health"] == "ok" and r["values"] == ["24.38.70.8"] and r["ttl"] == 300


def test_noerror_without_records_is_nodata_ok_and_empty():
    r = dr.parse_dig(dig_out("NOERROR"), "MX")
    assert r["health"] == "ok" and r["values"] == []


def test_nxdomain_for_the_name_itself():
    r = dr.parse_dig(dig_out("NXDOMAIN"), "A")
    assert r["health"] == "nxdomain" and r["values"] == []


def test_nxdomain_with_a_cname_is_a_dead_target_not_a_missing_name():
    out = dig_out("NXDOMAIN", [("x.example.com.", 60, "CNAME", "gone.azurewebsites.net.")])
    r = dr.parse_dig(out, "A")
    assert r["health"] == "ok" and r["dead_target"] == "gone.azurewebsites.net"
    assert r["cname_chain"] == ["gone.azurewebsites.net"]


def test_servfail_refused_timeout_garbage_and_empty_all_fail():
    for out in (dig_out("SERVFAIL"), dig_out("REFUSED"), TIMEOUT, "garbage", ""):
        assert dr.parse_dig(out, "A")["health"] == "failed", out


def test_values_one_spelling():
    assert dr.normalize_values("NS", ["NS01.Example.COM.", "ns01.example.com"]) == ["ns01.example.com"]
    assert dr.normalize_values("MX", ["10 Mail.Example.com.", "010 mail.example.com"]) == ["10 mail.example.com"]
    assert dr.normalize_value("TXT", '"v=spf1 include:a" " -all"') == "v=spf1 include:a -all"
    assert dr.normalize_value("AAAA", "2001:0DB8:0000::1") == "2001:db8::1"
    assert dr.normalize_value("CNAME", "Outlook.Office365.com.") == "outlook.office365.com"


def test_a_cname_answer_lists_the_target_addresses_and_the_chain():
    out = dig_out("NOERROR", [("email.example.com.", 300, "CNAME", "outlook.office365.com."),
                              ("outlook.office365.com.", 20, "A", "52.96.1.1"),
                              ("outlook.office365.com.", 20, "A", "52.96.1.2")])
    r = dr.parse_dig(out, "A")
    assert r["values"] == ["52.96.1.1", "52.96.1.2"] and r["cname_chain"] == ["outlook.office365.com"]
    assert r["ttl"] == 20


# ── read_name: one retry, name status, DMARC on the apex only ─────────────────────────────────
class Runner:
    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, name, qtype):
        self.calls.append((name, qtype))
        v = self.table.get((name, qtype), dig_out("NOERROR"))
        return v.pop(0) if isinstance(v, list) else v


def test_a_failed_lookup_is_retried_once_then_kept_as_failed():
    run = Runner({("a.example.com", "A"): [TIMEOUT, TIMEOUT, dig_out("NOERROR", [("a.example.com.", 5, "A", "1.2.3.4")])]})
    r = dr.read_name("a.example.com", runner=run)
    assert r["records"]["a"]["health"] == "failed"
    assert run.calls.count(("a.example.com", "A")) == 2


def test_a_retry_that_answers_is_ok():
    run = Runner({("a.example.com", "A"): [TIMEOUT, dig_out("NOERROR", [("a.example.com.", 5, "A", "1.2.3.4")])]})
    r = dr.read_name("a.example.com", runner=run)
    assert r["records"]["a"] == {"health": "ok", "status": "NOERROR", "values": ["1.2.3.4"], "ttl": 5}


def test_name_status_needs_a_and_aaaa_both_nxdomain():
    nx = dig_out("NXDOMAIN")
    all_nx = Runner({("g.example.com", q): nx for q in dr.QTYPES})
    assert dr.read_name("g.example.com", runner=all_nx)["name_status"] == "nxdomain"
    one = Runner({("g.example.com", q): (nx if q == "A" else TIMEOUT) for q in dr.QTYPES})
    assert dr.read_name("g.example.com", runner=one)["name_status"] == "unknown"
    fails = Runner({("g.example.com", q): TIMEOUT for q in dr.QTYPES})
    assert dr.read_name("g.example.com", runner=fails)["name_status"] == "unknown"
    nodata = Runner({})
    assert dr.read_name("g.example.com", runner=nodata)["name_status"] == "exists"


def test_dmarc_is_read_for_the_apex_only_and_a_missing_policy_is_an_answer():
    run = Runner({("_dmarc.example.com", "TXT"): dig_out("NXDOMAIN")})
    apex = dr.read_name("example.com", apex="example.com", runner=run)
    assert apex["records"]["dmarc"]["health"] == "ok" and apex["records"]["dmarc"]["values"] == []
    sub = dr.read_name("www.example.com", apex="example.com", runner=run)
    assert "dmarc" not in sub["records"]


def test_scope_only_names_under_the_apex():
    run = Runner({})
    doc = dr.read_names(["a.example.com", "evil.com", "example.com.evil.com", "EXAMPLE.com."], "example.com", runner=run)
    assert sorted(doc["readings"]) == ["a.example.com", "example.com"]
    assert all(n.endswith("example.com") for n, _ in run.calls)


def test_cli_end_to_end_with_a_stand_in_dig_writes_all_or_nothing():
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / "dig"
        fake.write_text("#!/bin/sh\n"
                        "for a; do last=$a; done\n"
                        "printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\\n'\n"
                        "case \"$*\" in *' A '*) printf \"$last.\\t60\\tIN\\tA\\t192.0.2.7\\n\";; esac\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        names = Path(td) / "names.txt"
        names.write_text("www.example.com\nexample.com\nnot-ours.org\n")
        out = Path(td) / "r.json"
        env = dict(os.environ, PATH=f"{td}:{os.environ['PATH']}")
        p = subprocess.run([sys.executable, str(HERE / "dns_reading.py"), "--names", str(names),
                            "--apex", "example.com", "--out", str(out)], env=env, capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        doc = json.loads(out.read_text())
        assert doc["schema"] == "dns_readings_v1" and sorted(doc["readings"]) == ["example.com", "www.example.com"]
        assert doc["readings"]["www.example.com"]["records"]["a"]["values"] == ["192.0.2.7"]
        assert not (Path(td) / "r.json.tmp").exists()


def test_reader_sends_only_dns_questions():
    src = (HERE / "dns_reading.py").read_text()
    code = src.split('"""', 2)[2]
    assert "axfr" not in code.lower() and "ixfr" not in code.lower()
    assert '["dig", "+noall", "+comments", "+answer", "+time=3", "+tries=2", qtype, name]' in code
    for bad in ("socket.", "urllib", "requests", "http.client"):
        assert bad not in code, bad


# ── the sixth source ──────────────────────────────────────────────────────────────────────────
def test_known_names_from_the_previous_copy_drop_long_gone_and_foreign_names():
    prev = {"subdomains": [{"name": "ns02.example.com"}, {"name": "x.other.org"}],
            "dns_readings": {"test.example.com": {"nx_streak": 0},
                             "old.example.com": {"nx_streak": kn.NX_CARRY_LIMIT},
                             "fresh-gone.example.com": {"nx_streak": 2}}}
    assert kn.names_from_previous(prev, "example.com") == {"ns02.example.com", "test.example.com",
                                                           "fresh-gone.example.com"}
    assert kn.names_from_previous(None, "example.com") == set()


def test_known_names_cli_survives_a_bad_database_and_still_writes_the_previous_copys_names():
    with tempfile.TemporaryDirectory() as td:
        prev = Path(td) / "prev.json"
        prev.write_text(json.dumps({"subdomains": [{"name": "ns02.example.com"}]}))
        out = Path(td) / "known.txt"
        env = dict(os.environ, SUPABASE_DSN="postgresql://nobody@127.0.0.1:1/none")
        p = subprocess.run([sys.executable, str(HERE / "known_names.py"), "--apex", "example.com",
                            "--previous", str(prev), "--out", str(out)], env=env, capture_output=True, text=True)
        assert p.returncode == 0 and out.read_text() == "ns02.example.com\n"
        assert "database skipped" in p.stderr
        env.pop("SUPABASE_DSN")
        p = subprocess.run([sys.executable, str(HERE / "known_names.py"), "--apex", "example.com",
                            "--previous", str(Path(td) / "missing.json"), "--out", str(out)],
                           env=env, capture_output=True, text=True)
        assert p.returncode == 0 and out.read_text() == ""


def test_known_names_sql_reads_only_owned_names_that_once_answered():
    sql = " ".join(kn.KNOWN_NAMES_SQL.split())
    assert "ownership = 'owned'" in sql and "discovery_status IN ('confirmed_live', 'dns_only')" in sql
    assert sql.upper().startswith("SELECT")


# ── discovery wiring ──────────────────────────────────────────────────────────────────────────
def test_discovery_runs_source_six_merges_it_keeps_it_live_and_reads_every_name():
    sh = (HERE / "asm-discover.sh").read_text()
    body = sh[sh.index("discover_apex() {"):sh.index("# ─── Phase: Single IP discovery")]
    assert '"$KNOWN_NAMES" --apex "$apex"' in body
    merge = body[body.index("# ─── Merge + dedupe across all sources"):body.index("sort -u > \"$wd/_subdomains.txt\"")]
    assert 'cat "$wd/_src_known.txt"' in merge
    assert 'grep -E "(^|\\.)${apex}$" "$wd/_src_known.txt" >> "$wd/_live_subdomains.txt"' in body
    gate = body.index("Subdomain DNS resolution gate")
    read = body.index('"$DNS_READER" --names "$wd/_reading_names.txt" --apex "$apex"')
    loop = body.index("Per-sub deep scan")
    assert gate < read < loop
    assert 'rm -f "$wd/dns_readings.json"' in body[gate:read]
    names = body[body.index("DNS readings with health (job 5a): every resolved and every known name"):read]
    assert 'cat "$wd/_resolved_subdomains.txt" "$wd/_src_known.txt"' in names, "every known name is read, resolved or not"
    assert 'KNOWN_NAMES="$SCRIPT_DIR/known_names.py"' in sh and 'DNS_READER="$SCRIPT_DIR/dns_reading.py"' in sh


# ── the normalizer: carried, streak, owners ───────────────────────────────────────────────────
def _reading(name, status="exists", a=("1.1.1.1",), health="ok"):
    rec = {"health": health, "values": list(a) if health == "ok" else []}
    return {"name": name, "read_at": "2026-11-05T19:00:00Z", "name_status": status,
            "records": {"a": rec, "aaaa": {"health": health, "values": []}}}


def _work(readings: dict | None):
    td = tempfile.mkdtemp()
    if readings is not None:
        (Path(td) / "dns_readings.json").write_text(json.dumps({"readings": readings}))
    return Path(td)


def test_a_failed_record_keeps_the_last_good_one_marked_carried():
    prev = {"t.example.com": _reading("t.example.com", a=("24.38.70.8",))}
    work = _work({"t.example.com": _reading("t.example.com", status="unknown", health="failed")})
    got = normalize.build_dns_readings(work, [], prev)["t.example.com"]
    assert got["records"]["a"]["values"] == ["24.38.70.8"] and got["records"]["a"]["carried"] is True


def test_no_readings_file_carries_every_reading_and_none_without_history():
    prev = {"t.example.com": _reading("t.example.com")}
    got = normalize.build_dns_readings(_work(None), [], prev)
    assert got["t.example.com"]["carried"] is True
    assert normalize.build_dns_readings(_work(None), [], {}) is None


def test_nx_streak_counts_runs_in_a_row_and_unknown_neither_advances_nor_resets():
    nx = _reading("g.example.com", status="nxdomain", a=())
    prev = {"g.example.com": {**_reading("g.example.com"), "nx_streak": 0}}
    one = normalize.build_dns_readings(_work({"g.example.com": nx}), [], prev)["g.example.com"]
    assert one["nx_streak"] == 1
    unk = normalize.build_dns_readings(_work({"g.example.com": _reading("g.example.com", status="unknown", health="failed")}),
                                       [], {"g.example.com": one})["g.example.com"]
    assert unk["nx_streak"] == 1
    two = normalize.build_dns_readings(_work({"g.example.com": nx}), [], {"g.example.com": unk})["g.example.com"]
    assert two["nx_streak"] == 2
    back = normalize.build_dns_readings(_work({"g.example.com": _reading("g.example.com")}), [],
                                        {"g.example.com": two})["g.example.com"]
    assert back["nx_streak"] == 0


def test_owners_come_from_this_runs_hosts_only_for_the_names_addresses():
    subs = [{"name": "t.example.com", "hosts": [
        {"ip": "52.119.65.6", "asn": "AS18616", "asn_org": "Natural Wireless, LLC"},
        {"ip": "9.9.9.9", "asn": "AS1", "asn_org": "Elsewhere"}]}]
    got = normalize.build_dns_readings(_work({"t.example.com": _reading("t.example.com", a=("52.119.65.6",))}), subs, {})
    assert got["t.example.com"]["owners"] == {"52.119.65.6": {"asn": "AS18616", "asn_org": "Natural Wireless, LLC"}}


def test_the_normalizer_attaches_readings_after_the_previous_copy_is_loaded():
    src = (HERE / "normalize.py").read_text()
    main = src[src.index("def main():"):]
    assert main.index('asset_json["deltas"] = compute_deltas(prev, asset_json)') < \
        main.index('build_dns_readings(work, subdomains, (prev or {}).get("dns_readings"))')
