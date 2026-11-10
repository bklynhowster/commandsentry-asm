"""CISA's rescan schedule for the addresses on CISA's list (cisa_mirror_schedule.py).

Prodex plan 2026-11-10. The priority moves once per finished deep scan, the next scan is due
CISA's interval after the last one, and a light and a deep scan are queued only when due and
nothing is queued or running. Nothing happens without the table or without an owned address.

    python3 -m pytest scripts/scanner/test_cisa_mirror_schedule.py -q
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cisa_mirror_schedule as S  # noqa: E402

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
ROW = {"address": "136.81.173.196", "priority": 0, "last_counted_scan_run": None, "next_scan_at": None}


def _run(i, hours_ago, up=True, mirror=True):
    at = NOW - timedelta(hours=hours_ago)
    return {"scan_run_id": f"r{i}", "started_at": at - timedelta(minutes=20), "completed_at": at,
            "mirror": {"cisa_sees_up": up} if mirror else None}


def test_a_new_address_with_no_scan_is_due_now():
    p = S.plan(ROW, [], [], 0, NOW)
    assert p["due"] and p["enqueue"] and p["next_scan_at"] is None and p["priority"] == 0


def test_nothing_found_means_seven_days_after_the_scan():
    p = S.plan(ROW, [_run(1, 1)], [], 0, NOW)
    assert p["priority"] == -1 and p["hours"] == 168
    assert p["next_scan_at"] == NOW - timedelta(hours=1) + timedelta(hours=168)
    assert not p["due"] and not p["enqueue"] and p["last_counted_scan_run"] == "r1"


def test_a_high_open_brings_it_back_in_24_hours():
    p = S.plan(ROW, [_run(1, 25)], [{"severity": "HIGH"}], 0, NOW)
    assert p["priority"] == -8 and p["due"] and p["enqueue"]


def test_a_kev_means_12_hours_whatever_the_grade():
    p = S.plan(ROW, [_run(1, 13)], [{"severity": "LOW", "kev_listed": True}], 0, NOW)
    assert p["priority"] == -16 and p["hours"] == 12 and p["enqueue"]


def test_the_cvss_score_grades_it_the_way_cisa_would():
    p = S.plan(ROW, [_run(1, 1)], [{"severity": "MODERATE", "cvss_score": 9.1}], 0, NOW)
    assert p["priority"] == -16


def test_info_findings_are_not_cisa_tickets():
    assert S.plan(ROW, [_run(1, 1)], [{"severity": "INFO"}], 0, NOW)["priority"] == -1


def test_each_scan_moves_the_priority_once_oldest_first():
    row = dict(ROW, priority=-16)
    p = S.plan(row, [_run(1, 30), _run(2, 20), _run(3, 10)], [{"severity": "LOW"}], 0, NOW)
    assert p["priority"] == -13 and p["last_counted_scan_run"] == "r3"


def test_an_address_that_never_answers_backs_off_to_90_days():
    p = S.plan(ROW, [_run(1, 400, up=False), _run(2, 1, up=False)], [], 0, NOW)
    assert p["priority"] == 1 and p["hours"] == 2160 and not p["due"]


def test_a_scan_without_the_record_is_counted_but_moves_nothing():
    p = S.plan(dict(ROW, priority=-4), [_run(1, 97, mirror=False)], [{"severity": "MODERATE"}], 0, NOW)
    assert p["priority"] == -4 and p["last_counted_scan_run"] == "r1" and p["due"]


def test_a_stored_record_as_text_is_read_too():
    r = _run(1, 1)
    r["mirror"] = '{"cisa_sees_up": false}'
    assert S.plan(ROW, [r], [], 0, NOW)["priority"] == 1


def test_nothing_new_keeps_the_row_and_waits():
    row = dict(ROW, priority=-1, last_counted_scan_run="r9", next_scan_at=NOW + timedelta(days=2))
    p = S.plan(row, [], [], 0, NOW)
    assert p["priority"] == -1 and p["last_counted_scan_run"] == "r9" and not p["due"]


def test_due_but_already_queued_or_running_queues_nothing():
    p = S.plan(ROW, [], [], 1, NOW)
    assert p["due"] and not p["enqueue"]


# ── run(): the database part ─────────────────────────────────────────────────────────

class _Cur:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.sql.append((sql, params))
        self.last = sql

    def fetchone(self):
        if "to_regclass" in self.last:
            return {"present": self.conn.present}
        if "count(*) as n" in self.last:
            return {"n": self.conn.active}
        if "order by q.triggered_at desc" in self.last:
            return self.conn.last_queue
        raise AssertionError(self.last)

    def fetchall(self):
        if "from public.cisa_mirror_addresses m" in self.last:
            return [dict(r) for r in self.conn.rows]
        if "from public.scan_run s" in self.last:
            return []
        if "from public.findings" in self.last:
            return []
        raise AssertionError(self.last)


class _Conn:
    def __init__(self, present=True, rows=(), active=0):
        self.present, self.rows, self.active, self.sql = present, list(rows), active, []
        self.last_queue = None
        self.commits = self.rollbacks = 0

    def cursor(self):
        return _Cur(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def writes(self):
        return [s for s, _p in self.sql if s.lstrip().startswith(("insert", "update"))]


def test_no_table_means_nothing_at_all():
    c = _Conn(present=False)
    assert S.run(c, NOW, dry_run=False, log=lambda *a: None) == []
    assert len(c.sql) == 1 and c.writes() == []


def test_no_owned_address_means_nothing_written():
    c = _Conn(rows=[])
    assert S.run(c, NOW, dry_run=False, log=lambda *a: None) == []
    assert c.writes() == []


def test_due_addresses_get_a_light_and_a_deep_scan_capped_per_run():
    rows = [dict(ROW, address=f"10.0.0.{i}") for i in range(1, 8)]
    c = _Conn(rows=rows)
    out = S.run(c, NOW, dry_run=False, log=lambda *a: None)
    inserts = [p for s, p in c.sql if s.lstrip().startswith("insert")]
    assert len(inserts) == S.MAX_PER_TICK
    assert sum(1 for p in out if p.get("held")) == len(rows) - S.MAX_PER_TICK
    assert all("'light'" in s and "'heavy'" in s for s in c.writes() if s.lstrip().startswith("insert"))


def test_dry_run_writes_nothing():
    c = _Conn(rows=[dict(ROW)])
    out = S.run(c, NOW, dry_run=True, log=lambda *a: None)
    assert out[0]["enqueue"] and c.writes() == [] and c.rollbacks == 1


def test_the_queue_rows_say_why():
    c = _Conn(rows=[dict(ROW)])
    S.run(c, NOW, dry_run=False, log=lambda *a: None)
    notes = [p["notes"] for s, p in c.sql if s.lstrip().startswith("insert")]
    assert notes and "CISA's rescan schedule" in notes[0]


def test_the_rows_read_are_owned_and_not_retired():
    assert "a.ownership = 'owned'" in S.ROWS_SQL and "<> 'retired'" in S.ROWS_SQL


def test_only_finished_deep_scans_move_the_priority():
    # CISA steps once per scan of the address; here that is a deep scan (the one that sweeps
    # every port and writes the cisa_mirror record), finished complete or degraded.
    assert "and s.intensity::text = 'heavy'\n" in S.RUNS_SQL
    assert "and s.status::text in ('complete', 'degraded')\n" in S.RUNS_SQL
    assert "r.tool_name = 'cisa_mirror'" in S.RUNS_SQL
    assert "order by s.started_at asc" in S.RUNS_SQL


def test_an_address_the_rail_refused_is_held_a_day_then_tried_again():
    refused = NOW - timedelta(hours=3)
    p = S.plan(ROW, [], [], 0, NOW, refused_at=refused)
    assert p["due"] and not p["enqueue"] and "no name on its list" in p["held"]
    p = S.plan(ROW, [], [], 0, NOW, refused_at=NOW - timedelta(hours=S.REFUSED_HOLD_HOURS + 1))
    assert p["enqueue"] and "held" not in p


def test_run_reads_the_refusal_from_the_last_queue_row():
    c = _Conn(rows=[dict(ROW)])
    c.last_queue = {"completed_at": NOW - timedelta(hours=2), "triggered_at": NOW - timedelta(hours=2),
                    "error_message": S.REFUSED_PREFIX + " 136.81.173.196 now (prod.prodexlabs.com); not scanned"}
    out = S.run(c, NOW, dry_run=False, log=lambda *a: None)
    assert out[0].get("held") and not [s for s, _p in c.sql if s.lstrip().startswith("insert")]
    c2 = _Conn(rows=[dict(ROW)])
    c2.last_queue = {"completed_at": NOW - timedelta(hours=2), "triggered_at": NOW, "error_message": "some other failure"}
    assert S.run(c2, NOW, dry_run=False, log=lambda *a: None)[0]["enqueue"]


def test_the_held_prefix_is_the_scanners_own_refusal_words():
    import poll_queue as PQ
    _b, why = PQ.cisa_mirror_block({"address": "136.81.173.196", "names": ["x.example"]}, "136.81.173.196",
                                   resolve=lambda n: ["1.1.1.1"])
    assert why.startswith(S.REFUSED_PREFIX)



def test_an_unknown_up_or_down_is_counted_but_moves_nothing():
    r = _run(1, 1)
    r["mirror"] = {"cisa_sees_up": None, "exit_proven": False}
    p = S.plan(dict(ROW, priority=-1), [r], [], 0, NOW)
    assert p["priority"] == -1 and p["last_counted_scan_run"] == "r1"
