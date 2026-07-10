#!/usr/bin/env python3
"""
vpn_slot.py — VPN concurrency-slot guard (the shared Mullvad 5-device cap).

Command + Prodex share ONE Mullvad account (5 device slots total). Each instance's
ACTIVE pool size is env VPN_SLOTS_N (Command=1, Prodex=2 → sum 3, 2 slots of slack).
This script is the single enforcement point every VPN'd scan converges on, so no
trigger path (portal, workflow_dispatch, cron drain, ASM-Discover backstop) can
bring up a tunnel without first claiming a slot. See PORTAL_HEAVY_PROMOTION_SPEC.md
§8, the 4.7 ruling (Q2), and scripts/db/migrations/20260710b_vpn_slots.sql.

Subcommands (both idempotent):

  claim  --scan-run-id UUID [--n N]
      1. Reap stale slots (see reap policy).
      2. Atomically claim one free slot with slot_id <= N (FOR UPDATE SKIP LOCKED).
      Emits `acquired=true|false` (+ `slot_id`) to $GITHUB_OUTPUT so downstream
      VPN + runner steps gate on it. On NO free slot the scan is DEFERRED, not
      failed: the scan_queue row is requeued with a backoff (poll_queue.py already
      honours scheduled_for) and the fresh, empty scan_run is dropped, so a later
      tick retries it once a slot frees. Gives up (marks failed) only after the
      queue row has waited past --max-wait-min. Always exits 0 on a clean decision.

  release --scan-run-id UUID
      Free the slot held by this scan_run. Idempotent — safe to call from an
      `if: always()` teardown step even if no slot was ever claimed.

Reap policy — NO background heartbeat. GH Actions steps are separate shells, so a
per-second heartbeat process spanning steps is fragile. Instead we reap-on-claim:
free any slot whose scan_run is terminal (complete/failed/degraded) OR whose
claimed_at is older than --stale-min (default 40 > the 30-min testssl wall). A
leaked slot (runner killed mid-scan) is thus reclaimed the moment the pool is next
under demand — exactly when it matters. (Deviation from the 4.7 heartbeat design;
documented for advisor sign-off.)

Env: SUPABASE_DSN (or --dsn), VPN_SLOTS_N, GITHUB_OUTPUT (optional).
Exit: 0 clean decision (claimed OR deferred OR released) | 1 DB/usage error | 2 deps.
"""
from __future__ import annotations
import argparse
import os
import sys


def _psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row
        return psycopg, dict_row
    except ImportError:
        print("error: psycopg (psycopg3) required: "
              "pip install --break-system-packages 'psycopg[binary]'", file=sys.stderr)
        sys.exit(2)


def log(m: str) -> None:
    print(f"[vpn_slot] {m}", file=sys.stderr)


def emit(k: str, v) -> None:
    go = os.environ.get("GITHUB_OUTPUT")
    if go:
        with open(go, "a") as f:
            f.write(f"{k}={v}\n")
    log(f"output {k}={v}")


# Reap: free slots whose scan_run finished/died, or that are older than the wall.
REAP_SQL = """
update public.vpn_slots s
   set scan_run_id = null, claimed_at = null, heartbeat_at = null
 where s.scan_run_id is not null
   and (s.claimed_at < now() - make_interval(mins => %(stale)s)
        or exists (select 1 from public.scan_run r
                    where r.scan_run_id = s.scan_run_id
                      and r.status in ('complete', 'failed', 'degraded')))
returning slot_id;
"""

# Atomic claim of one free slot within the active pool (slot_id <= N).
CLAIM_SQL = """
update public.vpn_slots
   set scan_run_id = %(sr)s, claimed_at = now(), heartbeat_at = now()
 where slot_id = (
       select slot_id from public.vpn_slots
        where scan_run_id is null and slot_id <= %(n)s
        order by slot_id
        for update skip locked
        limit 1)
returning slot_id;
"""

RELEASE_SQL = """
update public.vpn_slots
   set scan_run_id = null, claimed_at = null, heartbeat_at = null
 where scan_run_id = %(sr)s
returning slot_id;
"""

QUEUE_AGE_SQL = """
select now() - triggered_at as age
  from public.scan_queue
 where scan_run_id = %(sr)s;
"""

# Defer: requeue the queue row with a backoff (poll honours scheduled_for) and
# unlink the fresh scan_run so the next claim re-creates a clean one.
REQUEUE_SQL = """
update public.scan_queue
   set status = 'queued',
       scheduled_for = now() + make_interval(mins => %(backoff)s),
       started_at = null,
       scan_run_id = null,
       notes = coalesce(notes, '') || %(note)s
 where scan_run_id = %(sr)s and status = 'running'
returning queue_id;
"""
DROP_FRESH_RUN_SQL = """
delete from public.scan_run where scan_run_id = %(sr)s and status = 'running';
"""

# Give up after --max-wait-min: mark both rows failed with a clear reason.
GIVEUP_RUN_SQL = """
update public.scan_run
   set status = 'failed', completed_at = now(),
       duration_seconds = extract(epoch from (now() - started_at))::int,
       error_message = 'vpn_slot: no free VPN slot within max wait'
 where scan_run_id = %(sr)s;
"""
GIVEUP_QUEUE_SQL = """
update public.scan_queue
   set status = 'failed', completed_at = now(),
       error_message = 'vpn_slot: no free VPN slot within max wait; gave up'
 where scan_run_id = %(sr)s;
"""


def cmd_claim(conn, sr, n, stale, backoff, max_wait) -> int:
    with conn.cursor() as cur:
        cur.execute(REAP_SQL, {"stale": stale})
        reaped = [r["slot_id"] for r in cur.fetchall()]
        if reaped:
            log(f"reaped stale slots: {reaped}")

        cur.execute(CLAIM_SQL, {"sr": sr, "n": n})
        row = cur.fetchone()
        if row:
            conn.commit()
            emit("acquired", "true")
            emit("slot_id", row["slot_id"])
            log(f"claimed slot {row['slot_id']} for {sr} (active pool N={n})")
            return 0

        # Pool full — defer, unless we've been waiting too long.
        cur.execute(QUEUE_AGE_SQL, {"sr": sr})
        agerow = cur.fetchone()
        age_min = (agerow["age"].total_seconds() / 60.0) if agerow and agerow["age"] else 0.0

        if age_min >= max_wait:
            cur.execute(GIVEUP_RUN_SQL, {"sr": sr})
            cur.execute(GIVEUP_QUEUE_SQL, {"sr": sr})
            conn.commit()
            emit("acquired", "false")
            log(f"pool full and waited {age_min:.0f}m >= max {max_wait}m — gave up (failed)")
            return 0

        note = f" [vpn_slot: pool full (N={n}); deferred +{backoff}m after {age_min:.0f}m waited]"
        cur.execute(REQUEUE_SQL, {"sr": sr, "backoff": backoff, "note": note})
        cur.execute(DROP_FRESH_RUN_SQL, {"sr": sr})
        conn.commit()
        emit("acquired", "false")
        log(f"pool full (N={n}); requeued +{backoff}m (waited {age_min:.0f}m), dropped fresh scan_run")
        return 0


def cmd_release(conn, sr) -> int:
    with conn.cursor() as cur:
        cur.execute(RELEASE_SQL, {"sr": sr})
        freed = [r["slot_id"] for r in cur.fetchall()]
        conn.commit()
        log(f"released slot(s) {freed or '(none held — nothing to do)'} for {sr}")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description="VPN concurrency-slot guard (shared Mullvad device cap).",
        epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["claim", "release"])
    ap.add_argument("--scan-run-id", required=True)
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"))
    ap.add_argument("--n", type=int, default=int(os.environ.get("VPN_SLOTS_N", "1")))
    ap.add_argument("--stale-min", type=int, default=int(os.environ.get("VPN_SLOT_STALE_MIN", "40")))
    ap.add_argument("--backoff-min", type=int, default=int(os.environ.get("VPN_SLOT_BACKOFF_MIN", "5")))
    ap.add_argument("--max-wait-min", type=int, default=int(os.environ.get("VPN_SLOT_MAX_WAIT_MIN", "120")))
    args = ap.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)

    psycopg, dict_row = _psycopg()
    conn = psycopg.connect(args.dsn, row_factory=dict_row, autocommit=False)
    try:
        if args.command == "claim":
            rc = cmd_claim(conn, args.scan_run_id, args.n,
                           args.stale_min, args.backoff_min, args.max_wait_min)
        else:
            rc = cmd_release(conn, args.scan_run_id)
    except Exception as e:  # noqa: BLE001
        log(f"error: {e!r}")
        try:
            conn.rollback()
        except Exception:
            pass
        # Fail SAFE: on a claim error, do NOT let the scan run unguarded — emit
        # acquired=false so downstream VPN/runner steps skip; the failed step +
        # the always() cleanup mark the scan_run failed for a clean retry.
        if args.command == "claim":
            emit("acquired", "false")
        rc = 1
    finally:
        conn.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()
