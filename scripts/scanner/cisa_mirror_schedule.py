#!/usr/bin/env python3
"""cisa_mirror_schedule.py — CISA's rescan schedule for the addresses on CISA's list.

Prodex plan 2026-11-10. Run by .github/workflows/cisa-mirror-schedule.yml every three
hours. For each row of public.cisa_mirror_addresses whose address is an owned asset:

  1. CISA's priority moves once per finished deep scan not counted yet, oldest first
     (cisa_mirror.next_priority): "up" is what that scan's cisa_mirror record says CISA's
     ping would call it; the grade is the worst open finding on the address now, graded
     the way CISA would (cisa_mirror.cisa_level: CVSS when scored, else Sentry's grade);
     a KEV is any open finding on CISA's Known Exploited Vulnerabilities list.
  2. The next scan is due interval_hours(priority) after the last counted scan finished:
     12 hours with a Critical or a KEV open, 24 with a High, 4 days with a Medium, 6 with
     a Low, 7 days with nothing, backing off to 90 days for an address that never answers.
  3. Due, and nothing queued or running for the address: a light and a deep scan are
     queued, at most MAX_PER_TICK addresses a run (the fleet enqueue's heavy cap is 10).

The table absent or empty (Command), or no row an owned asset yet (before the addresses
are added to Prodex's targets file): nothing happens. --dry-run reads and reports only.

    SUPABASE_DSN=... python3 scripts/scanner/cisa_mirror_schedule.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cisa_mirror as cm  # noqa: E402

MAX_PER_TICK = 5
REFUSED_HOLD_HOURS = 24
REFUSED_PREFIX = "cisa_mirror: no name on this address's list points at"


def step(priority: int, runs: list[dict], open_findings: list[dict]) -> tuple[int, str | None, datetime | None]:
    """(priority, last counted scan_run_id, when the last counted scan finished) after
    counting `runs` (oldest first). A run with no cisa_mirror record (the sweep never ran,
    or failed before it wrote one) is counted without moving the priority: it says
    nothing about up or down, and it must not be read again."""
    level = max((cm.cisa_level(f.get("severity"), f.get("cvss_score")) for f in open_findings), default=0)
    kev = sum(1 for f in open_findings if f.get("kev_listed"))
    last_id, last_at = None, None
    for r in runs:
        mirror = r.get("mirror")
        if isinstance(mirror, str):
            try:
                mirror = json.loads(mirror)
            except ValueError:
                mirror = None
        if isinstance(mirror, dict) and isinstance(mirror.get("cisa_sees_up"), bool):
            priority = cm.next_priority(priority, mirror["cisa_sees_up"], level, kev)
        last_id = r["scan_run_id"]
        last_at = r.get("completed_at") or r.get("started_at")
    return priority, last_id, last_at


def plan(row: dict, runs: list[dict], open_findings: list[dict], active: int, now: datetime,
         refused_at: datetime | None = None) -> dict:
    """What the scheduler does for one address. Pure. refused_at: when the Scanner last
    refused it because no name on its list pointed at it (poll_queue's safety rail). Within
    REFUSED_HOLD_HOURS of that it is held, not queued again every run; after that it is
    tried again, so a name put back in DNS brings it back by itself."""
    priority, counted, finished = step(int(row.get("priority") or 0), runs, open_findings)
    if counted is None:                       # nothing new: keep what the row says
        counted, next_at = row.get("last_counted_scan_run"), row.get("next_scan_at")
    else:
        next_at = finished + timedelta(hours=cm.interval_hours(priority)) if finished else None
    due = next_at is None or next_at <= now
    held = refused_at is not None and refused_at > now - timedelta(hours=REFUSED_HOLD_HOURS)
    out = {"address": row["address"], "priority": priority, "last_counted_scan_run": counted,
           "next_scan_at": next_at, "hours": cm.interval_hours(priority),
           "enqueue": bool(due and active == 0 and not held), "due": due, "active": active}
    if due and held:
        out["held"] = f"no name on its list pointed at it at {refused_at.isoformat()}; tried again after {REFUSED_HOLD_HOURS} h"
    return out


# ── database (thin) ───────────────────────────────────────────────────────────────────
PRESENT_SQL = "select to_regclass('public.cisa_mirror_addresses') is not null as present;"
ROWS_SQL = """
select m.address, m.priority, m.last_counted_scan_run, m.next_scan_at
  from public.cisa_mirror_addresses m
  join public.assets a on a.asset_id = m.address
 where a.ownership = 'owned'
   and coalesce(a.discovery_status, 'unverified') <> 'retired'
 order by m.next_scan_at asc nulls first, m.address;
"""
RUNS_SQL = """
select s.scan_run_id::text as scan_run_id, s.started_at, s.completed_at,
       (select r.content_jsonb from public.scan_run_artifacts r
         where r.scan_run_id = s.scan_run_id and r.tool_name = 'cisa_mirror'
         limit 1) as mirror
  from public.scan_run s
 where s.asset_id = %(address)s
   and s.intensity::text = 'heavy'
   and s.status::text in ('complete', 'degraded')
   and s.started_at > coalesce((select p.started_at from public.scan_run p
                                 where p.scan_run_id::text = %(counted)s), '-infinity'::timestamptz)
 order by s.started_at asc;
"""
OPEN_SQL = """
select severity::text as severity, cvss_score, kev_listed
  from public.findings
 where asset_id = %(address)s
   and current_status::text in ('detected', 'confirmed', 'open', 'regressed');
"""
ACTIVE_SQL = """
select count(*) as n
  from public.scan_queue q
 where q.asset_id = %(address)s
   and (q.status::text = 'queued'
        or (q.status::text = 'running' and q.started_at > now() - interval '8 hours'));
"""
REFUSED_SQL = """
select q.completed_at, q.triggered_at, q.error_message
  from public.scan_queue q
 where q.asset_id = %(address)s
 order by q.triggered_at desc
 limit 1;
"""
UPDATE_SQL = """
update public.cisa_mirror_addresses
   set priority = %(priority)s, last_counted_scan_run = %(last_counted_scan_run)s,
       next_scan_at = %(next_scan_at)s
 where address = %(address)s;
"""
ENQUEUE_SQL = """
insert into public.scan_queue (asset_id, intensity, authenticated, source, notes)
values (%(address)s, 'light', false, 'workflow_dispatch', %(notes)s),
       (%(address)s, 'heavy', false, 'workflow_dispatch', %(notes)s);
"""


def run(conn, now: datetime, dry_run: bool, log=print) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(PRESENT_SQL)
        if not cur.fetchone()["present"]:
            log("cisa_mirror_schedule: no address list here (table absent); nothing to do")
            return []
        cur.execute(ROWS_SQL)
        rows = [dict(r) for r in cur.fetchall()]
    if not rows:
        log("cisa_mirror_schedule: no address on the list is an owned asset yet; nothing to do")
        return []
    out, queued = [], 0
    for row in rows:
        args = {"address": row["address"], "counted": row.get("last_counted_scan_run") or ""}
        with conn.cursor() as cur:
            cur.execute(RUNS_SQL, args)
            runs = [dict(r) for r in cur.fetchall()]
            cur.execute(OPEN_SQL, args)
            found = [dict(r) for r in cur.fetchall()]
            cur.execute(ACTIVE_SQL, args)
            active = int(cur.fetchone()["n"])
            cur.execute(REFUSED_SQL, args)
            last = cur.fetchone()
        refused_at = None
        if last and str(last.get("error_message") or "").startswith(REFUSED_PREFIX):
            refused_at = last.get("completed_at") or last.get("triggered_at")
        p = plan(row, runs, found, active, now, refused_at)
        if p["enqueue"] and queued >= MAX_PER_TICK:
            p["enqueue"], p["held"] = False, f"over {MAX_PER_TICK} this run; next run"
        out.append(p)
        log(f"  {p['address']}: priority {p['priority']} ({p['hours']:g} h), next "
            f"{p['next_scan_at'].isoformat() if p['next_scan_at'] else 'now'}"
            f"{', QUEUE light + deep' if p['enqueue'] else ''}"
            f"{' (already queued or running)' if p['due'] and active else ''}"
            f"{' HELD: ' + p['held'] if p.get('held') else ''}")
        if dry_run:
            continue
        with conn.cursor() as cur:
            cur.execute(UPDATE_SQL, p)
            if p["enqueue"]:
                cur.execute(ENQUEUE_SQL, {"address": p["address"], "notes": (
                    f"cisa_mirror_schedule: due on CISA's rescan schedule (priority {p['priority']}, "
                    f"every {p['hours']:g} h)")})
                queued += 1
        conn.commit()
    if dry_run:
        conn.rollback()
        log("DRY-RUN: nothing written")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    dsn = os.environ.get("SUPABASE_DSN")
    if not dsn:
        print("SUPABASE_DSN not set", file=sys.stderr)
        return 2
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row, autocommit=False) as conn:
        run(conn, datetime.now(timezone.utc), a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
