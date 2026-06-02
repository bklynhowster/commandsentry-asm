#!/usr/bin/env python3
"""
poll_queue.py — Phase 4a M2 scan queue poller / claimer

Called once per GH Action cron tick (every 5 min). Atomically claims the
oldest queued scan, creates a scan_run row, and emits a JSON descriptor to
stdout for the downstream GH Action steps to consume and dispatch.

The dispatcher GH Action reads the descriptor and decides which tier-
specific runner to invoke (scripts/scanner/run_light.sh,
scripts/scanner/run_medium.sh, scripts/scanner/run_heavy.sh — those land
in M3+).

This script does NOT execute any scanners itself. Its job is purely:
  1. Atomically claim the next eligible queue entry (FOR UPDATE SKIP LOCKED)
  2. Create the matching scan_run row
  3. Fetch the asset row + optional asset_auth_config row
  4. Emit a JSON descriptor capturing everything the tier runner needs
  5. Exit 0

If no work is available, stdout is empty and exit code is still 0
(no-work-is-not-an-error). Real errors (DB unreachable, RLS misconfigured,
etc.) exit non-zero with a message to stderr.

DESCRIPTOR SHAPE (stdout):
  {
    "scan_run_id":    "<uuid>",
    "queue_id":       "<uuid>",
    "asset_id":       "<asset_id>",
    "intensity":      "light" | "medium" | "heavy",
    "authenticated":  true | false,
    "asset": {
      "asset_id":        "<id>",
      "name":            "<name>",
      "organization":    "<org>",
      "type":            "<type>",
      "kind":            "<kind>",
      "apex_domain":     "<apex>",
      "aliases":         ["..."],
      "current_risk":    "<risk>",
      "top_hosting_org": "<hosting org name | null>"
    },
    "auth_config": null | {
      "login_url":                "<url>",
      "username_field":           "<field>",
      "password_field":           "<field>",
      "username_credential_ref":  "<env var name>",
      "password_credential_ref":  "<env var name>",
      "post_login_check_url":     "<url> | null",
      "auth_cookie_name":         "<name> | null",
      "custom_login_script_path": "<path> | null"
    }
  }

ATOMICITY:
  Single transaction. FOR UPDATE SKIP LOCKED on the queue SELECT so
  concurrent workers (shouldn't exist, but if GH Actions concurrency
  control ever fails) cleanly skip claimed rows instead of blocking.

  If anything in the transaction fails — even after the queue UPDATE but
  before the scan_run INSERT — the entire transaction rolls back and the
  queue row goes back to 'queued'. No half-claimed state.

  The partial unique index `scan_queue_one_running_per_asset` adds a DB-
  level safety net: if a queued scan's asset already has a running scan,
  the UPDATE will violate the index and roll back. The worker treats that
  as "this row isn't claimable right now, try the next one" — typically
  it just exits 0 (no work claimable this tick).

ENVIRONMENT:
  SUPABASE_DSN — required (or pass --dsn)
                Format: postgresql://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres

USAGE (from GH Action):
  python scripts/scanner/poll_queue.py > /tmp/scan_descriptor.json
  if [ -s /tmp/scan_descriptor.json ]; then
    INTENSITY=$(jq -r '.intensity' /tmp/scan_descriptor.json)
    case "$INTENSITY" in
      light)  scripts/scanner/run_light.sh  /tmp/scan_descriptor.json ;;
      medium) scripts/scanner/run_medium.sh /tmp/scan_descriptor.json ;;
      heavy)  scripts/scanner/run_heavy.sh  /tmp/scan_descriptor.json ;;
    esac
  fi
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

# ─── Lazy import so --help works without psycopg installed ─────────────
def _import_deps() -> Any:
    try:
        import psycopg  # noqa: F401
        from psycopg.rows import dict_row  # noqa: F401
    except ImportError:
        print(
            "error: psycopg (psycopg3) is required.\n"
            "  install it with: pip install --user --break-system-packages 'psycopg[binary]'",
            file=sys.stderr,
        )
        sys.exit(2)
    return psycopg, dict_row


# ─── Default Supabase URL (matches other scripts in this repo) ─────────
DEFAULT_SUPABASE_PROJECT = "hdygktppfvuspnumpfuq"


# ─── The atomic claim ──────────────────────────────────────────────────
# Single SQL statement that:
#   1. Finds the oldest queued + due scan_queue row (FOR UPDATE SKIP LOCKED)
#   2. Updates it to 'running' with started_at = now()
#   3. Returns the full claimed row
#
# If no row matches, returns nothing — caller treats as "no work".
#
# Why CTE + UPDATE FROM: we need FOR UPDATE SKIP LOCKED behavior on the
# SELECT but UPDATE syntax for the state transition. The CTE pattern is
# the standard PostgreSQL idiom.
CLAIM_NEXT_SCAN_SQL = """
with next as (
  select queue_id
  from public.scan_queue
  where status = 'queued'
    and scheduled_for <= now()
  order by scheduled_for asc, triggered_at asc
  for update skip locked
  limit 1
)
update public.scan_queue q
set status = 'running',
    started_at = now()
from next
where q.queue_id = next.queue_id
returning q.*;
"""


# ─── Create the scan_run row + back-link it to the queue ───────────────
INSERT_SCAN_RUN_SQL = """
insert into public.scan_run (
  queue_id, asset_id, intensity, authenticated, status, started_at
)
values (%(queue_id)s, %(asset_id)s, %(intensity)s, %(authenticated)s,
        'running', now())
returning scan_run_id;
"""

BACKLINK_QUEUE_SQL = """
update public.scan_queue
set scan_run_id = %(scan_run_id)s
where queue_id = %(queue_id)s;
"""


# ─── Fetch asset metadata (joined with surface for hosting info) ──────
# LEFT JOIN to asset_surface so we surface top_hosting_org alongside the
# asset row. This drives the Pressable-aware VPN routing decision in
# scanner.yml's vpn_decision step (2026-06-02): Light tier normally
# skips VPN for speed, but Pressable/Atomic-hosted targets need VPN
# because Pressable rate-limits Azure ASN on wp-admin paths regardless
# of intensity. LEFT JOIN keeps the asset row even if no surface data
# has been imported yet.
FETCH_ASSET_SQL = """
select a.asset_id, a.name, a.organization, a.type, a.kind, a.apex_domain,
       a.aliases, a.current_risk,
       s.top_hosting_org
from public.assets a
left join public.asset_surface s on s.asset_id = a.asset_id
where a.asset_id = %s;
"""


# ─── Fetch auth config (only needed if authenticated=true) ─────────────
FETCH_AUTH_CONFIG_SQL = """
select login_url, username_field, password_field,
       username_credential_ref, password_credential_ref,
       post_login_check_url, auth_cookie_name, custom_login_script_path,
       enabled
from public.asset_auth_config
where asset_id = %s;
"""


# ─── Mark the claim failed (used when auth_config is required but missing) ─
# psycopg3 executes one statement per execute() call, so split into two SQL
# strings — caller runs both in sequence inside the open transaction.
ABORT_QUEUE_SQL = """
update public.scan_queue
set status = 'failed',
    completed_at = now(),
    duration_seconds = extract(epoch from (now() - started_at))::int,
    error_message = %(error)s
where queue_id = %(queue_id)s;
"""

ABORT_SCAN_RUN_SQL = """
update public.scan_run
set status = 'failed',
    completed_at = now(),
    duration_seconds = extract(epoch from (now() - started_at))::int,
    error_message = %(error)s
where queue_id = %(queue_id)s;
"""


def log(msg: str) -> None:
    """Log to stderr so stdout stays clean JSON-only."""
    print(f"[poll_queue] {msg}", file=sys.stderr)


def claim_next_scan(conn) -> dict | None:
    """Atomically claim the next eligible scan_queue row.

    Returns the claimed queue row as a dict, or None if nothing's eligible.
    Uses the explicit transaction the caller passes in; commit happens at
    the end of run() so all writes in the claim land atomically.
    """
    with conn.cursor() as cur:
        cur.execute(CLAIM_NEXT_SCAN_SQL)
        row = cur.fetchone()
        return dict(row) if row else None


def create_scan_run(conn, queue_row: dict) -> str:
    """Insert the matching scan_run row, return its UUID."""
    with conn.cursor() as cur:
        cur.execute(INSERT_SCAN_RUN_SQL, {
            "queue_id":      queue_row["queue_id"],
            "asset_id":      queue_row["asset_id"],
            "intensity":     queue_row["intensity"],
            "authenticated": queue_row["authenticated"],
        })
        scan_run_id = cur.fetchone()["scan_run_id"]
        cur.execute(BACKLINK_QUEUE_SQL, {
            "scan_run_id": scan_run_id,
            "queue_id":    queue_row["queue_id"],
        })
        return str(scan_run_id)


def fetch_asset(conn, asset_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(FETCH_ASSET_SQL, (asset_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def fetch_auth_config(conn, asset_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(FETCH_AUTH_CONFIG_SQL, (asset_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def abort_claim(conn, queue_id: str, error: str) -> None:
    """Mark a claimed scan as failed with an error message. Used when the
    claim succeeded structurally but the prerequisites for actually running
    the scan aren't met (e.g., authenticated=true but no auth_config exists).
    """
    with conn.cursor() as cur:
        params = {"queue_id": queue_id, "error": error}
        cur.execute(ABORT_QUEUE_SQL, params)
        cur.execute(ABORT_SCAN_RUN_SQL, params)


def build_descriptor(
    queue_row: dict, scan_run_id: str, asset: dict, auth_config: dict | None
) -> dict:
    """Construct the JSON descriptor the GH Action will consume."""
    descriptor: dict[str, Any] = {
        "scan_run_id":   scan_run_id,
        "queue_id":      str(queue_row["queue_id"]),
        "asset_id":      queue_row["asset_id"],
        "intensity":     queue_row["intensity"],
        "authenticated": queue_row["authenticated"],
        "asset": {
            "asset_id":     asset["asset_id"],
            "name":         asset["name"],
            "organization": asset["organization"],
            "type":         asset["type"],
            "kind":         asset.get("kind"),
            "apex_domain":  asset.get("apex_domain"),
            "aliases":      asset.get("aliases") or [],
            "current_risk": asset.get("current_risk"),
            # 2026-06-02: surface top_hosting_org so scanner.yml's
            # vpn_decision step can route Light scans through VPN for
            # IP-class-sensitive hosts (Pressable / Atomic). None when
            # no asset_surface row exists yet (e.g. brand-new asset
            # before first ASM Discover run).
            "top_hosting_org": asset.get("top_hosting_org"),
        },
        "auth_config": None,
    }
    if auth_config:
        # Strip the enabled flag from the descriptor — it's only relevant
        # at queue-time. The worker already decided to run authenticated
        # based on it.
        descriptor["auth_config"] = {
            "login_url":                auth_config["login_url"],
            "username_field":           auth_config["username_field"],
            "password_field":           auth_config["password_field"],
            "username_credential_ref":  auth_config["username_credential_ref"],
            "password_credential_ref":  auth_config["password_credential_ref"],
            "post_login_check_url":     auth_config["post_login_check_url"],
            "auth_cookie_name":         auth_config["auth_cookie_name"],
            "custom_login_script_path": auth_config["custom_login_script_path"],
        }
    return descriptor


def run(dsn: str) -> int:
    """Main entry. Returns the desired exit code (0 = success / no-work,
    non-0 = real error).
    """
    psycopg, dict_row = _import_deps()

    log("connecting...")
    try:
        conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
    except Exception as e:
        log(f"DB connect failed: {e}")
        return 1

    try:
        # ─── Step 1: atomic claim ─────────────────────────────────────
        queue_row = claim_next_scan(conn)
        if not queue_row:
            log("no eligible queued scans")
            conn.rollback()
            return 0

        log(f"claimed queue_id={queue_row['queue_id']} "
            f"asset_id={queue_row['asset_id']} "
            f"intensity={queue_row['intensity']} "
            f"authenticated={queue_row['authenticated']}")

        # ─── Step 2: create scan_run ──────────────────────────────────
        scan_run_id = create_scan_run(conn, queue_row)
        log(f"created scan_run_id={scan_run_id}")

        # ─── Step 3: fetch asset row ──────────────────────────────────
        asset = fetch_asset(conn, queue_row["asset_id"])
        if not asset:
            # This shouldn't happen — the queue row has an FK to assets.
            # But if it does, mark the scan failed and exit cleanly.
            err = f"asset {queue_row['asset_id']} not found in assets table"
            log(f"ERROR: {err}")
            abort_claim(conn, queue_row["queue_id"], err)
            conn.commit()
            return 0  # not a worker error; the claim+abort sequence is correct

        # ─── Step 4: optional auth_config fetch ───────────────────────
        auth_config = None
        if queue_row["authenticated"]:
            auth_config = fetch_auth_config(conn, queue_row["asset_id"])
            if not auth_config:
                err = (f"asset {queue_row['asset_id']} has no asset_auth_config "
                       f"row — cannot run authenticated scan")
                log(f"ERROR: {err}")
                abort_claim(conn, queue_row["queue_id"], err)
                conn.commit()
                return 0
            if not auth_config.get("enabled"):
                err = (f"asset_auth_config for {queue_row['asset_id']} exists "
                       f"but enabled=false")
                log(f"ERROR: {err}")
                abort_claim(conn, queue_row["queue_id"], err)
                conn.commit()
                return 0

        # ─── Step 5: emit descriptor ──────────────────────────────────
        descriptor = build_descriptor(queue_row, scan_run_id, asset, auth_config)

        # Commit ALL the writes (queue update, scan_run insert, queue backlink)
        # as one atomic transaction. If the GH Action subsequently dies, we
        # have a queue row in 'running' state with started_at set — the
        # liveness sweeper (separate cron, M11) detects scans stuck in
        # 'running' for > 4h and marks them failed.
        conn.commit()
        log(f"committed claim + scan_run; emitting descriptor")

        # JSON to stdout, nothing else
        json.dump(descriptor, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0

    except Exception as e:
        log(f"unexpected error: {e!r}")
        try:
            conn.rollback()
        except Exception:
            pass
        return 1
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Atomically claim the next queued scan and emit a "
                    "JSON descriptor for downstream tier-specific runners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN).",
    )
    args = parser.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)

    sys.exit(run(args.dsn))


if __name__ == "__main__":
    main()
