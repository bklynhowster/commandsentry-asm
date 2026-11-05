"""Job 5a: the importer's DNS wiring, driven through the REAL import_one with a stand-in
database (the pattern of test_importer_confirmed_live_branch.py: names resolve at runtime).

Pinned:
  * a move is found once per apex from the apex blob's OWN previous readings, and silences
    the port events that comparing two addresses would write (both directions);
  * the move row carries the old address's ports and, only for an owned address, its own record;
  * the DNS rows go into asset_surface_event and are NOT in the run's real-time fan-out list;
  * only the apex's stored blob carries dns_readings;
  * the whole DNS step runs under its own SAVEPOINT BEFORE any bucket is written; a failure
    rolls back to it, writes the port events exactly as before 5a and KEEPS the previous
    readings as the baseline, so the next run finds the change (code review 2026-11-05 14:33:
    a failed write may delay a DNS change, never erase it);
  * a first run with no previous readings writes no DNS rows and silences nothing.

Run:  pytest scripts/db/test_import_dns_5a.py -q
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import import_asm_to_surface as m  # noqa: E402

APEX = "example.com"
T0, T1 = "2026-11-04T00:48:08Z", "2026-11-04T06:41:24Z"


def _val(x):
    return getattr(x, "obj", x)     # psycopg Json → its object


def reading(name, addrs, at, streak=0):
    return {"name": name, "read_at": at, "name_status": "exists", "nx_streak": streak,
            "records": {"a": {"health": "ok", "values": list(addrs)}, "aaaa": {"health": "ok", "values": []},
                        "cname": {"health": "ok", "values": []}}}


def sub(name, ip, ports):
    return {"name": name, "alive": True, "is_root": name == APEX, "discovered_via": "dnsx",
            "first_discovered": T0, "last_seen": T1, "tags": [],
            "reachability": {"live": bool(ports)}, "probe_status": {"naabu": {"ok": True}},
            "hosts": [{"ip": ip, "asn": "AS1", "asn_org": "Org"}],
            "services": [{"ip": ip, "port": p, "protocol": "tcp", "service": "https"} for p in ports],
            "dns": {"a": [ip]}}


def doc(test_ip, test_ports, readings):
    d = {"schema_version": "3.0", "asset": {"value": APEX, "type": "apex"},
         "scan": {"started_at": T1, "completed_at": T1}, "registration": {},
         "summary": {}, "subdomains": [sub(APEX, "24.38.70.5", [443]), sub("test." + APEX, test_ip, test_ports)],
         "phantom_subdomains": [], "deltas": {}, "history": []}
    if readings is not None:
        d["dns_readings"] = readings
    return d


class Cur:
    def __init__(self, conn):
        self.conn, self.last, self.params = conn, "", None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.last, self.params = " ".join(str(sql).split()), params
        self.conn.calls.append((self.last, params))
        if self.last.startswith("SAVEPOINT") and self.conn.fail_savepoint:
            raise RuntimeError("savepoint refused")

    def executemany(self, sql, rows):
        rows = list(rows)
        if any(str(r.get("event_type", "")).startswith("dns_") for r in rows) and self.conn.fail_dns_insert:
            raise RuntimeError("insert refused")
        self.conn.inserted.extend(rows)

    def fetchone(self):
        u = self.last
        if u.startswith("SELECT aliases"):
            return ([],)
        if "SELECT surface_data" in u:
            return (self.conn.prior.get(self.params[0]),)
        if "cloud_source" in u:
            return ("derived", False, None)
        if "resurrection_count" in u:
            return None
        if "RETURNING" in u:
            return (self.params.get("asset_id") if isinstance(self.params, dict) else APEX, False, False)
        return None

    def fetchall(self):
        u = self.last
        if "is_cloud_endpoint, cloud_provider::text" in u:
            return [(a, False, None) for a in self.params[0]]
        if u.startswith("SELECT asset_id FROM public.assets WHERE asset_id = ANY"):   # the first build's read
            return [(a,) for a in self.params[0]]
        if u.startswith("SELECT asset_id, surface_data FROM public.asset_surface WHERE asset_id = ANY"):
            return [(a, self.conn.prior[a]) for a in self.params[0] if a in self.conn.prior]
        if "JOIN public.asset_surface s" in u:
            return [("24.38.70.8", 2, None)] if "24.38.70.8" in self.params[0] else []
        return []


class Conn:
    def __init__(self, prior, *, fail_dns_insert=False, fail_savepoint=False):
        self.prior, self.calls, self.inserted = prior, [], []
        self.fail_dns_insert, self.fail_savepoint = fail_dns_insert, fail_savepoint

    def cursor(self):
        return Cur(self)

    def commit(self):
        pass

    def rollback(self):
        pass


def prior_blobs(old_test_ip, old_ports, readings):
    apex_blob = {"scan": {"completed_at": T0}, "subdomains": [sub(APEX, "24.38.70.5", [443])]}
    if readings is not None:
        apex_blob["dns_readings"] = readings
    return {APEX: apex_blob,
            "test." + APEX: {"scan": {"completed_at": T0}, "subdomains": [sub("test." + APEX, old_test_ip, old_ports)]}}


OLD_R = {APEX: reading(APEX, ["24.38.70.5"], T0), "test." + APEX: reading("test." + APEX, ["24.38.70.8"], T0)}
NEW_R = {APEX: reading(APEX, ["24.38.70.5"], T1), "test." + APEX: reading("test." + APEX, ["52.119.65.6"], T1)}


def run(conn, d):
    return m.import_one(conn, d, "asm_cron", dry_run=False, skip_events=False)


def events(conn, kind_prefix=""):
    return [e for e in conn.inserted if str(e.get("event_type", "")).startswith(kind_prefix)]


def test_a_move_writes_one_dns_row_and_no_port_events_for_that_name():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    res = run(conn, doc("52.119.65.6", [], NEW_R))
    dns = events(conn, "dns_")
    assert [(e["event_type"], e["asset_id"], e["host"]) for e in dns] == [
        ("dns_address_changed", "test." + APEX, "test." + APEX)]
    assert not [e for e in events(conn, "port_") if e["host"] == "test." + APEX]
    prev = _val(dns[0]["prev_value"])
    assert prev["values"] == ["24.38.70.8"] and prev["last_seen"] == T0
    assert {p["port"] for p in prev["ports"]} == {80, 443}
    assert prev["owned_address_now"] == {"24.38.70.8": {"owned_asset": True, "service_count": 2, "last_seen": None}}
    assert res["dns_events_written"] == 1 and res["dns_changes_found"] == 1


def test_dns_rows_never_join_the_real_time_fan_out():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    res = run(conn, doc("52.119.65.6", [], NEW_R))
    assert not [e for e in res["events"] if str(e["event_type"]).startswith("dns_")]


def test_only_the_apex_blob_stores_the_readings():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    run(conn, doc("52.119.65.6", [], NEW_R))
    stored = {p["asset_id"]: _val(p["surface_data"]) for s, p in conn.calls
              if isinstance(p, dict) and "surface_data" in p}
    assert "dns_readings" in stored[APEX] and "dns_readings" not in stored["test." + APEX]


def stored_blobs(conn):
    return {p["asset_id"]: _val(p["surface_data"]) for s, p in conn.calls
            if isinstance(p, dict) and "surface_data" in p}


def test_the_dns_step_runs_in_its_own_savepoint_before_any_bucket_is_written():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    run(conn, doc("52.119.65.6", [], NEW_R))
    stmts = [s for s, _ in conn.calls]
    first_bucket_write = min(i for i, (s, p) in enumerate(conn.calls) if isinstance(p, dict) and "surface_data" in p)
    assert stmts.index("SAVEPOINT dns_5a") < stmts.index("RELEASE SAVEPOINT dns_5a") < first_bucket_write
    assert stored_blobs(conn)[APEX]["dns_readings"] == NEW_R


def test_a_failed_dns_write_delays_the_change_and_never_erases_it():
    """THE REVIEW'S MUST-FIX. On the first build a failed insert rolled back only the DNS rows:
    the moved name's port events had already been silenced and the new readings became the
    baseline, so the move was gone for good. Now: the port events are written as before 5a,
    the previous readings stay the baseline, and the next run writes the move."""
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R), fail_dns_insert=True)
    res = run(conn, doc("52.119.65.6", [], NEW_R))
    stmts = [s for s, _ in conn.calls]
    assert "ROLLBACK TO SAVEPOINT dns_5a" in stmts and "RELEASE SAVEPOINT dns_5a" not in stmts
    assert events(conn, "dns_") == []
    closed = {e["port"] for e in events(conn, "port_closed") if e["host"] == "test." + APEX}
    assert closed == {80, 443}, "the port evidence must not be silenced when the move was not written"
    blobs = stored_blobs(conn)
    assert blobs[APEX]["dns_readings"] == OLD_R, "the baseline must not advance past a change that was not written"
    assert res["status"] == "ok" and res["dns_events_written"] == 0 and res["dns_baseline_kept"] is True
    # the next run: same answers, the write works -> the move is written then
    retry = Conn({APEX: blobs[APEX], "test." + APEX: blobs["test." + APEX]})
    res2 = run(retry, doc("52.119.65.6", [], NEW_R))
    assert [e["event_type"] for e in events(retry, "dns_")] == ["dns_address_changed"]
    assert res2["dns_baseline_kept"] is False and stored_blobs(retry)[APEX]["dns_readings"] == NEW_R


def test_a_savepoint_that_cannot_be_made_is_a_failed_step_never_a_crash_or_a_rollback_to_nothing():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R), fail_savepoint=True)
    res = run(conn, doc("52.119.65.6", [], NEW_R))
    assert res["status"] == "ok" and res["dns_events_written"] == 0
    assert "ROLLBACK TO SAVEPOINT dns_5a" not in [s for s, _ in conn.calls]
    assert {e["port"] for e in events(conn, "port_closed") if e["host"] == "test." + APEX} == {80, 443}


def test_a_first_run_with_no_previous_readings_writes_nothing_and_silences_nothing():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], None))
    res = run(conn, doc("52.119.65.6", [], NEW_R))
    assert events(conn, "dns_") == [] and res["dns_changes_found"] == 0
    assert {e["event_type"] for e in events(conn, "port_") if e["host"] == "test." + APEX} == {"port_closed"}


def test_no_readings_this_run_means_no_dns_work_at_all():
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    res = run(conn, doc("24.38.70.8", [80, 443], None))
    assert res["dns_changes_found"] == 0 and "SAVEPOINT dns_5a" not in [s for s, _ in conn.calls]


def test_no_move_no_dns_rows_and_ordinary_port_events_still_flow():
    same = {APEX: reading(APEX, ["24.38.70.5"], T1), "test." + APEX: reading("test." + APEX, ["24.38.70.8"], T1)}
    conn = Conn(prior_blobs("24.38.70.8", [80, 443], OLD_R))
    run(conn, doc("24.38.70.8", [443], same))
    assert events(conn, "dns_") == []
    assert [(e["event_type"], e["port"]) for e in events(conn, "port_")] == [("port_closed", 80)]


def test_the_old_address_is_described_from_its_own_record_only_when_it_is_owned():
    sql = " ".join(m.OWNED_ADDRESS_NOW_SQL.split())
    assert "a.ownership = 'owned'" in sql and sql.upper().startswith("SELECT")
    assert "JOIN public.asset_surface s ON s.asset_id = a.asset_id" in sql


def test_dns_asset_id_routes_like_the_buckets():
    assert m.dns_asset_id("www.example.com", APEX, []) == APEX
    assert m.dns_asset_id("EXAMPLE.com", APEX, []) == APEX
    assert m.dns_asset_id("mail.example.com", APEX, ["mail.example.com"]) == APEX
    assert m.dns_asset_id("test.example.com", APEX, []) == "test.example.com"
