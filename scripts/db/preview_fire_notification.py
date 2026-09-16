#!/usr/bin/env python3
"""
test_fire_notification.py — preview the surface-event Resend email format.

Inserts a small batch of SYNTHETIC asset_surface_event rows for a real
asset in your inventory, then runs the same notification fan-out path
that the cron uses. You get a real email in your inbox so you can see
exactly what subscribers will see when a real port_opened / port_closed /
asset_went_dark event fires.

Safe to re-run. The synthetic events also persist in the timeline so the
asset detail page will show them — delete them via SQL after you're
done if you want a clean slate.

USAGE
-----
    export SUPABASE_DSN='postgresql://...'
    export RESEND_API_KEY='re_...'

    # Default: fires port_opened + port_closed + asset_went_dark
    # against the first IP-type asset, sends to anyone subscribed at
    # real_time cadence (including you if you've toggled your prefs).
    python3 scripts/db/test_fire_notification.py

    # Fire against a specific asset
    python3 scripts/db/test_fire_notification.py --asset 24.157.51.86

    # Only fire one event type
    python3 scripts/db/test_fire_notification.py --kinds port_opened
    python3 scripts/db/test_fire_notification.py --kinds asset_went_dark

    # Dry-run — show what WOULD be inserted/sent without doing it
    python3 scripts/db/test_fire_notification.py --dry-run

NOTES
-----
- Requires SUBSCRIBER notification prefs to be at cadence='real_time' for
  the corresponding pref key — otherwise nothing sends. Set yours at
  https://commandsentry-portal.netlify.app/account/notifications.
- The synthetic events DO get persisted to asset_surface_event with
  source_tag='manual_test_fire'. Delete them with:
      DELETE FROM public.asset_surface_event WHERE source_tag = 'manual_test_fire';
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "db"))

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install with: pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)

# Import the dispatch + insert primitives from the main importer
from import_asm_to_surface import (
    INSERT_EVENT,
    dispatch_event_notifications,
    DARK_THRESHOLD_HOURS,
)


SYNTHETIC_KINDS = ["port_opened", "port_closed", "asset_went_dark"]

# Realistic-looking synthetic detail per event type. The host fields
# match common COMMANDsentry assets so the email reads as a real change.
SYNTHETIC_TEMPLATES = {
    "port_opened": {
        "host": None,        # filled in from asset_id
        "port": 8080,
        "proto": "tcp",
        "service": "http-proxy",
        "tls": False,
        "prev_value": None,
        "new_value": Json({
            "host": "(filled)", "port": 8080, "proto": "tcp",
            "service": "http-proxy", "tls": False,
        }),
    },
    "port_closed": {
        "host": None,
        "port": 22,
        "proto": "tcp",
        "service": "ssh",
        "tls": False,
        "prev_value": Json({
            "host": "(filled)", "port": 22, "proto": "tcp",
            "service": "ssh", "tls": False,
        }),
        "new_value": None,
    },
    "asset_went_dark": {
        "host": None,
        "port": None,
        "proto": None,
        "service": None,
        "tls": None,
        "prev_value": Json({
            "last_seen": "2026-05-23T08:14:00+00:00",
            "primary_ptr": "(filled)",
            "top_hosting_org": "(filled)",
            "threshold_hours": DARK_THRESHOLD_HOURS,
        }),
        "new_value": None,
    },
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument(
        "--to",
        help="REQUIRED unless --dry-run. The single address that receives the "
             "preview. The send is routed here and NEVER to the subscriber list.",
    )
    ap.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN)",
    )
    ap.add_argument(
        "--asset",
        default=None,
        help=(
            "asset_id to fire events against. Defaults to the first IP-type "
            "asset found in public.assets."
        ),
    )
    ap.add_argument(
        "--kinds",
        nargs="+",
        choices=SYNTHETIC_KINDS,
        default=SYNTHETIC_KINDS,
        help="Which event types to fire. Default: all three.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without writing or sending anything.",
    )
    args = ap.parse_args()

    if not args.dry_run and not args.to:
        print(
            "error: --to is REQUIRED unless --dry-run.\n"
            "       This tool used to send to every real-time subscriber — the\n"
            "       whole admin list — which makes a synthetic 'new asset'\n"
            "       email indistinguishable from a real one for six other people.\n"
            "       Name the single address that should receive the preview.",
            file=sys.stderr,
        )
        return 2

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 1

    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key and not args.dry_run:
        print(
            "warning: RESEND_API_KEY not set — events will be inserted but "
            "no email will fire. Run with --dry-run to silence this.",
            file=sys.stderr,
        )

    conn = psycopg.connect(args.dsn, autocommit=False)

    try:
        # Pick a target asset
        with conn.cursor() as cur:
            if args.asset:
                cur.execute(
                    "SELECT asset_id FROM public.assets WHERE asset_id = %s",
                    (args.asset,),
                )
                row = cur.fetchone()
                if not row:
                    print(
                        f"error: asset_id={args.asset!r} not found in public.assets",
                        file=sys.stderr,
                    )
                    return 1
                asset_id = row[0]
            else:
                cur.execute(
                    "SELECT asset_id FROM public.assets WHERE type = 'ip' "
                    "ORDER BY first_observed DESC LIMIT 1"
                )
                row = cur.fetchone()
                if not row:
                    print("error: no IP-type assets found", file=sys.stderr)
                    return 1
                asset_id = row[0]

        print(f"target asset: {asset_id}")
        print(f"firing kinds: {', '.join(args.kinds)}")
        if args.dry_run:
            print("(DRY RUN — nothing will be written or sent)")

        # Build synthetic events
        events: list[dict] = []
        for kind in args.kinds:
            tpl = SYNTHETIC_TEMPLATES[kind].copy()
            tpl["host"] = asset_id  # fill host with asset_id for realism
            tpl["asset_id"] = asset_id
            tpl["event_type"] = kind
            tpl["source_tag"] = "manual_test_fire"
            events.append(tpl)

        for ev in events:
            print(f"  - {ev['event_type']:18s} host={ev.get('host')!s} port={ev.get('port')!s}")

        if args.dry_run:
            return 0

        # Insert events
        with conn.cursor() as cur:
            cur.executemany(INSERT_EVENT, events)
        conn.commit()
        print(f"inserted {len(events)} event(s) into asset_surface_event")

        # Dispatch notifications
        # ⛔ inserted_asset_ids={asset_id} ON PURPOSE (A6, relay 172/178).
        # The fan-out now suppresses asset_first_seen for any asset this run did
        # not INSERT — that gate is what stopped five false "new asset
        # discovered" emails about hosts the fleet had held for 9-50 days.
        # This tool's entire job is to show a human what a given email looks
        # like, so it declares its synthetic asset as newly-inserted rather than
        # being silently filtered into sending nothing. Passing an empty set
        # here would make --kinds asset_first_seen print "0 sent" and look like
        # a broken tool; passing nothing at all would rely on a default, which
        # is how a forgotten caller becomes a silent one.
        stats = dispatch_event_notifications(
            conn, events, "manual_test_fire",
            inserted_asset_ids={asset_id},
            to_override=args.to,
        )
        print(
            f"notifications: {stats['emails_sent']} sent, "
            f"{stats['emails_failed']} failed, "
            f"{stats['subscribers']} subscriber(s) checked"
        )
        if stats["subscribers"] == 0:
            print(
                "  (no subscribers found — toggle at least one ASM event to "
                "real_time on /account/notifications and re-run)",
                file=sys.stderr,
            )

    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
