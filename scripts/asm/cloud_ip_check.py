#!/usr/bin/env python3
"""
cloud_ip_check.py — scan-time port-scope decider (4.7 rulings P1-P6, REVISED M1, 2026-07-24).

Decides SHALLOW (cloud / load-balancer / CDN edge → probe only the curated port set)
vs DEEP (bare origin / unknown → full top-1000 sweep + N1 reconfirm) for an asset at
scan time. Consumed by asm-discover.sh's naabu gate.

REVISED M1 (supersedes the Cymru-ASN version, which empirically failed on the scanner
runner — Mullvad VPN egress alters the DNS path so `origin.asn.cymru.com` didn't resolve;
4.7 ruling P4 dropped it):

  1. PRIMARY — read the classifier's AUTHORITATIVE assets.device_class from the DB
     (SUPABASE_DSN). It was computed with all signals (ASN/CNAME/prefix/cert/headers).
       cloud_endpoint / cdn / waf → SHALLOW      origin_host → DEEP
  2. BACKSTOP (unclassified / device_class unknown / DB unavailable) — CIDR-match the
     resolved IP(s) against the LOCAL published-range table cloud_ip_ranges.json
     (refreshed weekly by refresh_cloud_ranges.py; zero runtime external calls).
       IP in a known cloud CIDR → SHALLOW
  3. FAIL-OPEN (4.7 P5) — anything else, or ANY error → DEEP. Missing a real origin's
     services (fail-closed) is worse than a few phantoms (fail-open); phantoms are
     detectable + autoclosable, missed services are invisible.

Usage:  cloud_ip_check.py <asset_id> [ip ...]
  exit 0 + "SHALLOW <reason>"  → cloud edge, curated probe
  exit 1 + "DEEP <reason>"     → full sweep
Never raises to the caller.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path

RANGES = Path(__file__).resolve().parent / "cloud_ip_ranges.json"
CLOUD_CLASSES = {"cloud_endpoint", "cdn", "waf"}


def _db_device_class(asset_id: str) -> str | None:
    """Authoritative device_class from the DB, or None if unavailable (fail-open)."""
    dsn = os.environ.get("SUPABASE_DSN")
    if not dsn:
        return None
    try:
        import psycopg
    except Exception:
        return None
    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select device_class from public.assets where asset_id=%s limit 1",
                    (asset_id,),
                )
                row = cur.fetchone()
                return row[0] if row and row[0] else None
    except Exception:
        return None


def _prefix_hit(ips: list[str]) -> str | None:
    """Provider id if any IP falls in a known cloud CIDR (local table), else None."""
    try:
        data = json.loads(RANGES.read_text())
    except Exception:
        return None
    nets: list[tuple[str, object]] = []
    for prov, cidrs in (data.get("prefixes") or {}).items():
        for c in cidrs:
            try:
                nets.append((prov, ipaddress.ip_network(c, strict=False)))
            except Exception:
                pass
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            continue
        for prov, net in nets:
            if addr in net:
                return prov
    return None


def decide(asset_id: str, ips: list[str]) -> tuple[bool, str]:
    """Return (shallow?, reason)."""
    dc = _db_device_class(asset_id)          # primary (authoritative)
    if dc in CLOUD_CLASSES:
        return True, f"db:device_class={dc}"
    if dc == "origin_host":
        return False, "db:device_class=origin_host"
    prov = _prefix_hit(ips)                   # backstop (bootstrap / db-unavailable)
    if prov:
        return True, f"ip_prefix:{prov}"
    return False, ("db:unknown_no_prefix" if dc is None else f"db:{dc}_no_prefix")


def main() -> int:
    if len(sys.argv) < 2:
        print("DEEP usage")
        return 1
    asset_id, ips = sys.argv[1], sys.argv[2:]
    try:
        shallow, reason = decide(asset_id, ips)
    except Exception as e:                    # fail-open (P5)
        print(f"DEEP error:{type(e).__name__}")
        return 1
    print(("SHALLOW " if shallow else "DEEP ") + reason)
    return 0 if shallow else 1


if __name__ == "__main__":
    sys.exit(main())
