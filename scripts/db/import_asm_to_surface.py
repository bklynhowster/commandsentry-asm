#!/usr/bin/env python3
"""
import_asm_to_surface.py — push legacy ASM JSON into the portal's asset_surface table.

The legacy `commandsentry-asm` cron writes one JSON file per asset to
`data/assets/*.json`. The Surface tab on the portal reads from the new
`asset_surface` table in Supabase. This script bridges the two until the
cron itself writes Supabase directly (Phase 4 cloud-scan migration).

Two-step ingest per asset:
  1. UPSERT public.assets  — make sure the asset row exists (FK target).
     New assets get organization='UNKNOWN' so Howie can tag them later.
  2. UPSERT public.asset_surface — write the full ASM blob + derived
     convenience columns (top_hosting_org, primary_asn, primary_ptr,
     alive, counts).

Idempotent. Safe to re-run. Used initially for backfill (locally) and
later from GH Actions after every cron scan.

USAGE
-----
    export SUPABASE_DSN='postgresql://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres'
    python3 scripts/db/import_asm_to_surface.py [--dry-run] [--data-dir PATH]

ENV VARS
--------
    SUPABASE_DSN   Postgres DSN (or pass --dsn)

EXIT CODES
----------
    0  success
    1  failure (DSN missing, schema error, etc.)
    2  partial success (some files failed, others succeeded)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install it with: pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "assets"


# ---------------------------------------------------------------------------
# Asset-id mapping
# ---------------------------------------------------------------------------
# Legacy ASM uses dash-form IDs internally (`24-157-51-68`, `commandcommcentral`)
# but stores the canonical value in `asset.value`. The portal's `assets.asset_id`
# uses the canonical form (`24.157.51.68`, `commandcommcentral.com`). Always
# derive from `value`, never from `id`.


def derive_portal_asset_id(asm_doc: dict) -> str | None:
    asset = asm_doc.get("asset") or {}
    val = (asset.get("value") or "").strip()
    if not val:
        return None
    return val


def derive_asset_type(asm_doc: dict) -> str:
    """Map legacy ASM type values to portal asset_type_t enum.

    Legacy ASM uses:  ip | apex | fqdn | cidr | asn
    Portal enum:      ip | apex_domain | single_host | ip_range | ...

    Anything we don't recognize defaults to 'single_host' (the catch-all
    for a named host that isn't an apex).
    """
    asset = asm_doc.get("asset") or {}
    raw = (asset.get("type") or "").strip().lower()
    mapping = {
        "ip":   "ip",
        "apex": "apex_domain",
        "fqdn": "single_host",
        "cidr": "ip_range",
        "asn":  "ip_range",
    }
    return mapping.get(raw, "single_host")


def derive_organization(asm_doc: dict) -> str:
    """Map legacy ASM 'owner' (free-form) to portal organization_t enum.

    Portal enum values are LOWERCASE:
      command_companies | command_digital | command_financial |
      command_missouri  | command_marketing | unimac | sci | unknown

    Unknown/missing → 'unknown' (the enum's catch-all).
    """
    asset = asm_doc.get("asset") or {}
    owner = (asset.get("owner") or "").strip().lower()
    if not owner or owner in ("unknown", ""):
        return "unknown"
    mapping = {
        "command digital":   "command_digital",
        "command_digital":   "command_digital",
        "command companies": "command_companies",
        "command_companies": "command_companies",
        "command marketing": "command_marketing",
        "command_marketing": "command_marketing",
        "command financial": "command_financial",
        "command_financial": "command_financial",
        "command missouri":  "command_missouri",
        "command_missouri":  "command_missouri",
        "unimac":            "unimac",
        "sci":               "sci",
    }
    # Default to 'unknown' if the owner string doesn't match a known org —
    # safer than inventing a new enum value that would fail the insert.
    return mapping.get(owner, "unknown")


# ---------------------------------------------------------------------------
# Derive convenience columns from the ASM blob
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# #24 — auth-gated target detection (2026-06-15)
# ---------------------------------------------------------------------------
# Asset is auth_gated if the primary subdomain's root reachability shows
# BOTH (a) a login-like title AND (b) a TLS cert SAN that matches a known
# identity provider domain. The AND-gate is the safety: a real app with
# a "Sign In" link in its title doesn't false-flag because its cert is
# its own domain, not an IdP's.
#
# Verified discriminator on real data (Howie 2026-06-15):
#   myordersauth-test.unimacgraphics.com  → title "Sign in to your account"
#                                           + cert SAN login.microsoftonline.com
#                                           → auth_gated=true ✓
#   test.commandcommcentral.com           → title "CommandCommCentral"
#                                           + cert SAN *.commandcommcentral.com
#                                           → auth_gated=false ✓ (FortiWeb-fronted
#                                              real app, NOT a login page)
#
# KNOWN LIMITATION (accepted Phase 2): custom-domain IdP — Entra/Okta/
# Auth0 behind a vanity login domain like `login.company.com` — presents
# the customer's OWN cert, not an *.idp SAN, so the cert match fails
# and the asset is NOT flagged as auth_gated. Medium scans waste time on
# it. Future enhancement: detect IdP redirect chain or login-form
# structure, not cert-suffix alone.

IDP_CERT_SAN_SUFFIXES: tuple[str, ...] = (
    # Microsoft Entra / Azure AD
    "login.microsoftonline.com",
    "login.windows.net",
    "sts.windows.net",
    "login.microsoftonline.us",  # Azure Government
    ".b2clogin.com",             # Azure AD B2C
    # Google identity
    "accounts.google.com",
    # Common third-party identity providers
    ".okta.com",          # Okta (matches *.okta.com)
    ".auth0.com",         # Auth0 (matches *.auth0.com including *.<region>.auth0.com)
    ".onelogin.com",      # OneLogin
    ".pingidentity.com",  # Ping Identity
    ".pingone.com",       # Ping Identity (cloud)
    ".amazoncognito.com", # AWS Cognito hosted UI
)

# Case-insensitive substring match. AND-gated with cert match — loose
# title substrings (e.g. "sign in") can't false-positive without an IdP
# cert also present, so the conservative title list is safe.
LOGIN_TITLE_PATTERNS: tuple[str, ...] = (
    "sign in to your account",
    "sign in",
    "log in",
    "login",
)


def _title_matches_login(title: str | None) -> bool:
    """Case-insensitive substring match of `title` against the login
    patterns. None or empty → False."""
    if not title:
        return False
    title_lc = title.lower()
    return any(pat in title_lc for pat in LOGIN_TITLE_PATTERNS)


def _cert_san_matches_idp(san_entries: list[str] | None) -> bool:
    """True if any SAN entry endswith one of the IdP suffixes. Handles
    None / empty defensively (False, not raise)."""
    if not san_entries:
        return False
    for san in san_entries:
        if not isinstance(san, str):
            continue
        san_lc = san.lower().strip().lstrip("*.")  # normalize wildcard SANs
        for suffix in IDP_CERT_SAN_SUFFIXES:
            # Both exact match (login.microsoftonline.com) and suffix
            # match (.okta.com) handled by endswith. The suffix entries
            # already include the leading "." so .okta.com matches
            # foo.okta.com but NOT myokta.com.
            if san_lc.endswith(suffix) or san_lc == suffix.lstrip("."):
                return True
    return False


def compute_auth_gated(asm_doc: dict) -> bool:
    """AND-gate: primary subdomain has a login-like title AND a TLS cert
    SAN matching a known identity provider domain.

    "Primary subdomain" = subdomains[0] (consistent with the existing
    `primary_host = hosts[0]` pattern in derive_convenience). For
    single-host assets there's one subdomain entry; for apex assets the
    apex root usually isn't reachable, so reachability.title is None and
    the AND-gate fails harmlessly to False.

    Returns False for any unparseable / missing-data case — fail SAFE
    (don't skip tools when we're not sure if the asset is auth-gated).
    """
    subs = asm_doc.get("subdomains") or []
    if not subs:
        return False

    primary = subs[0]
    if not isinstance(primary, dict):
        return False

    # (a) Title check
    reach = primary.get("reachability") or {}
    title = reach.get("title")
    if not _title_matches_login(title):
        return False

    # (b) Cert SAN check — walk services[] for the 443 service's cert.
    # Pattern matches normalize.py: services[N].cert.san is the canonical
    # location. Some legacy paths put cert under .tls.* — defensive walk.
    services = primary.get("services") or []
    if not isinstance(services, list):
        return False

    for svc in services:
        if not isinstance(svc, dict):
            continue
        # Only check HTTPS-facing services (port 443 typically; some
        # alternate ports use TLS too)
        port = svc.get("port")
        if port not in (443, 8443):
            continue
        cert = svc.get("cert") or {}
        san = cert.get("san")
        if _cert_san_matches_idp(san):
            return True  # AND-gate satisfied — both signals present

    return False


def derive_convenience(asm_doc: dict) -> dict[str, Any]:
    summary = asm_doc.get("summary") or {}
    subs = asm_doc.get("subdomains") or []

    # Pull host context from the first subdomain's first host. Most assets
    # only have one host; for multi-host assets this is the "primary" view.
    primary_host: dict[str, Any] = {}
    for sub in subs:
        hosts = sub.get("hosts") or []
        if hosts:
            primary_host = hosts[0]
            break

    # Alive if any subdomain reports reachability.live=true
    alive = False
    for sub in subs:
        reach = sub.get("reachability") or {}
        if reach.get("live"):
            alive = True
            break

    asn = primary_host.get("asn")
    asn_str = str(asn) if asn else None

    return {
        "top_hosting_org": summary.get("top_hosting_org"),
        "platforms": summary.get("platforms") or [],
        "primary_asn": asn_str,
        "primary_ptr": primary_host.get("reverse_dns"),
        "subdomain_count": int(summary.get("subdomain_count") or 0),
        "live_subdomain_count": int(summary.get("live_subdomain_count") or 0),
        "host_count": int(summary.get("host_count") or 0),
        "service_count": int(summary.get("service_count") or 0),
        "newest_cert_expiry_days": summary.get("newest_cert_expiry_days"),
        "alive": alive,
        # #24 Phase 2 — derived every asm-discover refresh (never latched
        # per Q2 advisor 2026-06-15). Drives run_medium's skip wiring on
        # auth-gated targets where unauth attack tools can't produce signal.
        "auth_gated": compute_auth_gated(asm_doc),
    }


def derive_lifecycle(asm_doc: dict) -> dict[str, Any]:
    """first_discovered / last_seen from the asset's subdomain history."""
    subs = asm_doc.get("subdomains") or []
    asset = asm_doc.get("asset") or {}
    first_seen = None
    last_seen = None
    for sub in subs:
        fd = sub.get("first_discovered")
        ls = sub.get("last_seen")
        if fd and (not first_seen or fd < first_seen):
            first_seen = fd
        if ls and (not last_seen or ls > last_seen):
            last_seen = ls
    return {
        "discovered_via": asset.get("discovered_via"),
        "first_discovered": first_seen,
        "last_seen": last_seen,
    }


# ---------------------------------------------------------------------------
# Event-diff helpers — produce asset_surface_event rows from old vs new blob.
# ---------------------------------------------------------------------------
# Service identity is the tuple (host, port, proto). Same triple in both
# blobs = no event. Triple only in new = port_opened. Triple only in old =
# port_closed. We keep extra detail (service, tls) on the event row but
# don't use it for identity — banner-name / TLS-detection flips should
# not look like a close-and-reopen.


def flatten_services(blob: dict) -> dict[tuple[str, int, str], dict]:
    """Walk surface_data.subdomains[].hosts[].services[] (or the legacy
    surface_data.subdomains[].services[] shape) and return a map keyed by
    (host, port, proto) → service detail dict.

    Returns an empty dict for any unparseable blob — the importer never
    fails an upsert because of event-diff problems.
    """
    out: dict[tuple[str, int, str], dict] = {}
    if not isinstance(blob, dict):
        return out
    subs = blob.get("subdomains") or []
    if not isinstance(subs, list):
        return out

    for sub in subs:
        if not isinstance(sub, dict):
            continue
        sub_name = sub.get("name") or sub.get("subdomain")

        # Two possible shapes — the ASM JSON has services attached either
        # to each host or directly to the subdomain. Handle both.
        host_entries = sub.get("hosts") or []
        if host_entries:
            for h in host_entries:
                if not isinstance(h, dict):
                    continue
                host_addr = h.get("ip") or h.get("address") or sub_name or "?"
                for svc in (h.get("services") or []):
                    _record_service(out, host_addr, sub_name, svc)
        else:
            host_addr = sub_name or "?"
            for svc in (sub.get("services") or []):
                _record_service(out, host_addr, sub_name, svc)

    return out


def _record_service(
    out: dict[tuple[str, int, str], dict],
    host: str,
    subdomain: str | None,
    svc: dict,
) -> None:
    if not isinstance(svc, dict):
        return
    try:
        port = int(svc.get("port"))
    except (TypeError, ValueError):
        return
    proto = (svc.get("protocol") or svc.get("proto") or "tcp").lower()
    key = (host, port, proto)
    # First-wins: if a service appears twice across hosts for the same
    # (host, port, proto), keep the first detail.
    if key in out:
        return
    out[key] = {
        "host": host,
        "subdomain": subdomain,
        "port": port,
        "proto": proto,
        "service": svc.get("service") or svc.get("name"),
        "tls": bool(svc.get("tls")),
    }


def compute_events(
    asset_id: str,
    existing_blob: dict | None,
    new_blob: dict,
    source_tag: str,
) -> list[dict]:
    """Return a list of asset_surface_event row dicts (ready for executemany).

    Rules:
      - existing_blob is None (asset never seen) → one asset_first_seen row
        and NOTHING ELSE (don't flood on new-asset discovery)
      - both blobs present → port_opened for keys in new not in old,
        port_closed for keys in old not in new
    """
    if existing_blob is None:
        return [
            {
                "asset_id": asset_id,
                "event_type": "asset_first_seen",
                "host": None,
                "port": None,
                "proto": None,
                "service": None,
                "tls": None,
                "prev_value": None,
                "new_value": None,
                "source_tag": source_tag,
            }
        ]

    old_map = flatten_services(existing_blob)
    new_map = flatten_services(new_blob)

    events: list[dict] = []

    for key in new_map.keys() - old_map.keys():
        det = new_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_opened",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": None,
                "new_value": Json(det),
                "source_tag": source_tag,
            }
        )

    for key in old_map.keys() - new_map.keys():
        det = old_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_closed",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": Json(det),
                "new_value": None,
                "source_tag": source_tag,
            }
        )

    return events


INSERT_EVENT = """
INSERT INTO public.asset_surface_event (
  asset_id, event_type, host, port, proto, service, tls,
  prev_value, new_value, source_tag
) VALUES (
  %(asset_id)s, %(event_type)s, %(host)s, %(port)s, %(proto)s, %(service)s, %(tls)s,
  %(prev_value)s, %(new_value)s, %(source_tag)s
);
"""


# ---------------------------------------------------------------------------
# Dark-asset detection — emit one asset_went_dark event per asset whose
# last_seen has aged past the threshold, suppressed for SUPPRESS_DAYS after
# the most recent dark event so we don't re-alert every cron tick.
# ---------------------------------------------------------------------------
# Threshold: 72h ≈ 12 cron ticks at 6h cadence. Long enough to weather a
# normal Friday-night outage without a false alarm; short enough that a real
# long-weekend dark asset gets noticed Monday morning.
# Suppress window: 7d. If an asset stays dark for a month you get one email,
# not 30. When it comes back and goes dark again later, that's a new event.
DARK_THRESHOLD_HOURS = 72
DARK_SUPPRESS_DAYS = 7

FIND_DARK_ASSETS = """
SELECT
  s.asset_id,
  s.last_seen,
  s.primary_ptr,
  s.top_hosting_org
FROM public.asset_surface s
-- Tier 2 phantom defense — join assets and skip ct_ghost rows.
-- A ghost going "dark" is restating yesterday's classification, not real
-- news; the alerter shouldn't email about it. Also skip namesakes and
-- unknown-ownership rows for the same reasons that gate the scan cron.
JOIN public.assets a ON a.asset_id = s.asset_id
WHERE a.discovery_status = 'confirmed_live'
  AND a.ownership = 'owned'
  -- #34 Gate #2 (note 93, "respond don't just resolve"): an asset that never
  -- had a responding service can't "go dark" — it was never lit. Gate on
  -- service_count, NOT the `alive` flag: `alive` is HTTP-reachability-based,
  -- so DNS-only infra (ns01/ns02, service_count=1, alive=False) would be
  -- wrongly dropped. service_count keeps real infra, drops the svc=0 phantoms
  -- (sciimage.com apex + the bare IPs). Verified 2026-06-17.
  AND s.service_count > 0
  AND s.last_seen IS NOT NULL
  AND s.last_seen < (now() - (%s::int * interval '1 hour'))
  AND NOT EXISTS (
    SELECT 1 FROM public.asset_surface_event e
    WHERE e.asset_id = s.asset_id
      AND e.event_type = 'asset_went_dark'
      AND e.observed_at > (now() - (%s::int * interval '1 day'))
  );
"""


def detect_dark_assets(conn, source_tag: str) -> list[dict]:
    """Find assets whose last_seen has crossed the dark threshold AND
    don't already have a recent asset_went_dark alert. Returns one event
    dict per dark asset, ready for INSERT.

    Run AFTER the per-asset upserts complete so last_seen reflects the
    current cron tick before we check freshness.
    """
    with conn.cursor() as cur:
        cur.execute(FIND_DARK_ASSETS, (DARK_THRESHOLD_HOURS, DARK_SUPPRESS_DAYS))
        rows = cur.fetchall()

    return [
        {
            "asset_id": r[0],
            "event_type": "asset_went_dark",
            "host": None,
            "port": None,
            "proto": None,
            "service": None,
            "tls": None,
            "prev_value": Json({
                "last_seen": r[1].isoformat() if r[1] else None,
                "primary_ptr": r[2],
                "top_hosting_org": r[3],
                "threshold_hours": DARK_THRESHOLD_HOURS,
            }),
            "new_value": None,
            "source_tag": source_tag,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Notification fan-out — fire Resend emails to users subscribed to ASM
# events at real_time cadence. Daily/weekly digests are out-of-scope here.
# ---------------------------------------------------------------------------
# Event-type → preference-key mapping. The portal's notification-prefs
# vocabulary uses slightly different names than our event log:
#   port_opened       → checks asm_prefs.new_port_opened
#   port_closed       → checks asm_prefs.port_closed
#   asset_first_seen  → checks asm_prefs.new_asset_discovered
EVENT_TYPE_TO_PREF_KEY = {
    "port_opened":      "new_port_opened",
    "port_closed":      "port_closed",
    "asset_first_seen": "new_asset_discovered",
    "asset_went_dark":  "asset_went_dark",
}

# Migrated 2026-07-01 — Resend/Golden Lane → SendGrid/commandcompanies.com,
# completing D-031. The old sender (commandsentry@alerts.goldenlaneinc.com) was
# Howie's personal domain over Resend; commandcompanies.com is Command-owned,
# SendGrid-verified, and IronPort-trusted. Uses the SAME SENDGRID_API_KEY the
# daily digest already runs on (asm repo Actions secret).
SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"
SENDGRID_FROM_EMAIL = "CommandSentry@commandcompanies.com"
SENDGRID_FROM_NAME = "COMMANDsentry"

FETCH_SUBSCRIBERS = """
SELECT
  p.user_id,
  u.email,
  p.asm_prefs
FROM public.user_notification_prefs p
JOIN auth.users u ON u.id = p.user_id
WHERE
  (p.asm_prefs -> 'new_port_opened'      ->> 'cadence' = 'real_time')
  OR (p.asm_prefs -> 'port_closed'           ->> 'cadence' = 'real_time')
  OR (p.asm_prefs -> 'new_asset_discovered'  ->> 'cadence' = 'real_time');
"""


def dispatch_event_notifications(
    conn,
    all_events: list[dict],
    source_tag: str,
) -> dict[str, int]:
    """After all per-asset events have been inserted, fan out Resend emails.

    Groups by (user_id, asset_id) so a single scan that flips many ports on
    one host produces ONE summary email per subscriber, not N noisy ones.

    Returns a small stats dict for the run summary line.
    """
    stats = {"subscribers": 0, "emails_sent": 0, "emails_failed": 0, "skipped_no_key": 0}

    if not all_events:
        return stats

    api_key = os.environ.get("SENDGRID_API_KEY")
    if not api_key:
        # Not a failure — just nothing to send. Importer still committed
        # the events to the table; the UI timeline will still render them.
        # Email is a best-effort augmentation.
        stats["skipped_no_key"] = 1
        print("  ! SENDGRID_API_KEY not set — skipping notification fan-out", file=sys.stderr)
        return stats

    # Fetch subscribers once. Small table; cheap.
    with conn.cursor() as cur:
        cur.execute(FETCH_SUBSCRIBERS)
        subscribers = cur.fetchall()

    stats["subscribers"] = len(subscribers)
    if not subscribers:
        return stats

    # Group events by asset_id for the per-(user, asset) email batching.
    by_asset: dict[str, list[dict]] = {}
    for ev in all_events:
        by_asset.setdefault(ev["asset_id"], []).append(ev)

    # ─── Tier 2 phantom defense — suppress emails for non-confirmed_live ──
    # The events themselves stay in asset_surface_event (audit trail),
    # but we don't email subscribers about phantoms / namesakes / unverified
    # rows. Real-time email is reserved for genuinely confirmed-live new
    # exposure. Yesterday's noise problem (10+ emails per night about ghosts
    # restating yesterday's classification) is fixed by this single gate.
    # Per Security Advisor 4.7 + Tier 2 design 2026-06-06.
    if by_asset:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT asset_id, discovery_status, ownership "
                "FROM public.assets WHERE asset_id = ANY(%s)",
                (list(by_asset.keys()),),
            )
            classification = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        suppressed_count = 0
        for aid in list(by_asset.keys()):
            disc, own = classification.get(aid, ("unverified", "unknown"))
            # Only confirmed_live + owned assets get real-time emails.
            # Any other classification = suppressed for this run.
            if disc != "confirmed_live" or own != "owned":
                suppressed_count += len(by_asset.pop(aid))
        if suppressed_count > 0:
            print(
                f"  ! suppressed {suppressed_count} event email(s) for "
                f"non-confirmed_live or non-owned assets (Tier 2 gate)",
                file=sys.stderr,
            )

    # For each subscriber, decide which events they care about.
    import urllib.request
    import urllib.error

    for sub in subscribers:
        user_id, email, asm_prefs = sub
        if not email:
            continue
        if not isinstance(asm_prefs, dict):
            asm_prefs = {}

        # For each asset, filter to events the user is subscribed to at real_time
        for asset_id, asset_events in by_asset.items():
            matching = [
                ev for ev in asset_events
                if _user_wants_event(asm_prefs, ev["event_type"])
            ]
            if not matching:
                continue

            ok = _send_notification_email(
                api_key=api_key,
                to_email=email,
                asset_id=asset_id,
                events=matching,
            )
            if ok:
                stats["emails_sent"] += 1
            else:
                stats["emails_failed"] += 1

    return stats


def _user_wants_event(asm_prefs: dict, event_type: str) -> bool:
    key = EVENT_TYPE_TO_PREF_KEY.get(event_type)
    if not key:
        return False
    entry = asm_prefs.get(key)
    if not isinstance(entry, dict):
        return False
    return entry.get("cadence") == "real_time"


def _send_notification_email(
    api_key: str,
    to_email: str,
    asset_id: str,
    events: list[dict],
) -> bool:
    """Send one branded SendGrid email summarizing all event matches for this
    asset for this user. Returns True on SendGrid 2xx (202), False on any
    failure. Failures print to stderr but never raise (best-effort).
    """
    import urllib.request
    import urllib.error

    # Compose subject + body
    # IRONPORT-AWARE PATTERN: Cisco IronPort quarantines emails with bracketed
    # prefixes, IP-like strings in subject, and uppercase scare-words ("WENT
    # DARK") as spam. We compose subjects in natural English with a single
    # descriptive verb and the asset name in normal position. Daily digest
    # uses this same shape and passes through M365/IronPort cleanly.
    n_open = sum(1 for e in events if e["event_type"] == "port_opened")
    n_close = sum(1 for e in events if e["event_type"] == "port_closed")
    n_first = sum(1 for e in events if e["event_type"] == "asset_first_seen")
    n_dark = sum(1 for e in events if e["event_type"] == "asset_went_dark")

    # Pick the most operationally important event as the subject anchor.
    # Priority: went dark > new asset > port changes.
    if n_dark:
        subject = f"COMMANDsentry alert: {asset_id} stopped responding"
    elif n_first:
        subject = f"COMMANDsentry: new asset discovered ({asset_id})"
    elif n_open and not n_close:
        word = "port" if n_open == 1 else "ports"
        subject = f"COMMANDsentry: {n_open} new {word} on {asset_id}"
    elif n_close and not n_open:
        word = "port" if n_close == 1 else "ports"
        subject = f"COMMANDsentry: {n_close} {word} no longer responding on {asset_id}"
    else:
        # Mixed opens and closes
        subject = f"COMMANDsentry: surface change on {asset_id}"

    # Internal-readable summary for the email body header (no spam triggers,
    # but keeps the structured detail visible inline).
    bits: list[str] = []
    if n_dark:
        bits.append("asset stopped responding")
    if n_first:
        bits.append("first observation")
    if n_open:
        bits.append(f"{n_open} port{'s' if n_open != 1 else ''} opened")
    if n_close:
        bits.append(f"{n_close} port{'s' if n_close != 1 else ''} closed")
    summary = ", ".join(bits) if bits else "surface change"

    rows_html = "\n".join(_event_to_html_row(ev) for ev in events)

    portal_url = "https://commandsentry-portal.netlify.app"
    asset_url = f"{portal_url}/assets/{asset_id}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#EAE7DF;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#0B1B2B;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#EAE7DF;">
    <tr><td align="center" style="padding:40px 16px;">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="background-color:#FBFAF6;border:1px solid #CAD0D8;max-width:600px;width:100%;">
        <tr><td style="background-color:#C8632A;height:3px;line-height:3px;font-size:0;">&nbsp;</td></tr>
        <tr><td align="center" style="padding:24px 32px 8px 32px;background-color:#FFFFFF;">
          <div style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#4F5F70;font-weight:600;">Command Companies</div>
          <div style="margin-top:8px;font-size:28px;font-weight:700;letter-spacing:-0.01em;line-height:1.1;">
            <span style="color:#0B1B2B;">COMMAND</span><span style="color:#C8632A;">sentry</span>
          </div>
        </td></tr>
        <tr><td style="padding:20px 32px 4px 32px;background-color:#FFFFFF;">
          <h1 style="margin:0;font-size:18px;font-weight:700;line-height:1.3;color:#0B1B2B;">
            Surface change on <span style="font-family:'SF Mono',Menlo,Consolas,monospace;">{_html_escape(asset_id)}</span>
          </h1>
          <p style="margin:8px 0 0 0;font-size:13px;color:#4F5F70;">{_html_escape(summary)}</p>
        </td></tr>
        <tr><td style="padding:16px 32px 8px 32px;background-color:#FFFFFF;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-size:14px;line-height:1.5;border-collapse:collapse;">
            {rows_html}
          </table>
        </td></tr>
        <tr><td align="center" style="padding:16px 32px 24px 32px;background-color:#FFFFFF;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0">
            <tr><td align="center" style="background-color:#C8632A;">
              <a href="{asset_url}" target="_blank" style="display:inline-block;padding:12px 28px;font-size:14px;font-weight:600;color:#FFFFFF;text-decoration:none;letter-spacing:0.02em;">
                View asset in COMMANDsentry &rarr;
              </a>
            </td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:16px 32px;background-color:#F4F2EE;border-top:1px solid #E4E8EE;font-size:11px;line-height:1.5;color:#4F5F70;text-align:center;">
          <div><strong style="color:#0B1B2B;">Command Companies</strong> · Information Security &amp; Compliance</div>
          <div style="margin-top:4px;">You are receiving this because you enabled real-time notifications for this event type. Change settings at <a href="{portal_url}/account/notifications" style="color:#4F5F70;text-decoration:underline;">commandsentry-portal/account/notifications</a>.</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""

    # List-Unsubscribe / Precedence headers identify this as legitimate
    # opt-in transactional mail, reducing the spam-classifier suspicion.
    # The unsubscribe URL points at the user's notification-prefs page so
    # they can actually opt out (good citizenship + RFC 8058 compliance).
    portal_url = "https://commandsentry-portal.netlify.app"
    # SendGrid v3 shape: recipients under personalizations[].to[], sender as
    # {email,name}, MIME parts under content[]. Custom deliverability headers
    # (List-Unsubscribe / RFC 8058 one-click, X-Entity-Ref-ID) go top-level.
    body = json.dumps({
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": SENDGRID_FROM_EMAIL, "name": SENDGRID_FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/html", "value": html}],
        "headers": {
            "List-Unsubscribe": f"<{portal_url}/account/notifications>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            "X-Entity-Ref-ID": f"commandsentry-{asset_id}",
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        SENDGRID_API_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "COMMANDsentry-importer/1.0 (+https://commandsentry-portal.netlify.app)",
            "Accept": "application/json",
        },
    )

    try:
        # SendGrid returns 202 Accepted (empty body) on success.
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        print(
            f"  ! SendGrid {e.code} for {to_email} ({asset_id}): {err_body[:200]}",
            file=sys.stderr,
        )
        return False
    except Exception as e:
        print(f"  ! Notification send failed for {to_email} ({asset_id}): {e}", file=sys.stderr)
        return False


def _event_to_html_row(ev: dict) -> str:
    et = ev["event_type"]
    if et == "asset_first_seen":
        return (
            '<tr><td style="padding:6px 0;border-bottom:1px solid #F0EEE8;">'
            '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#C8632A;margin-right:8px;vertical-align:middle;"></span>'
            'Asset first observed in inventory</td></tr>'
        )
    if et == "asset_went_dark":
        prev = ev.get("prev_value") or {}
        # prev_value may be a Json wrapper if we're rendering events fresh
        # from compute; unwrap to a plain dict for safe .get().
        if hasattr(prev, "obj"):
            prev = prev.obj
        last_seen = prev.get("last_seen") if isinstance(prev, dict) else None
        threshold = prev.get("threshold_hours") if isinstance(prev, dict) else DARK_THRESHOLD_HOURS
        last_seen_str = f" (last successful response: {_html_escape(last_seen)})" if last_seen else ""
        return (
            f'<tr><td style="padding:6px 0;border-bottom:1px solid #F0EEE8;">'
            f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#475569;margin-right:8px;vertical-align:middle;"></span>'
            f'<strong>Asset went dark</strong> — no response for {threshold}+ hours{last_seen_str}'
            f'</td></tr>'
        )
    verb = "opened" if et == "port_opened" else "closed"
    color = "#16A34A" if et == "port_opened" else "#D97706"
    port = ev.get("port") or "?"
    proto = (ev.get("proto") or "tcp").upper()
    svc = ev.get("service")
    svc_str = f" ({_html_escape(svc)})" if svc else ""
    host = ev.get("host")
    host_str = f" on <span style=\"font-family:'SF Mono',Menlo,monospace;\">{_html_escape(host)}</span>" if host else ""
    return (
        f'<tr><td style="padding:6px 0;border-bottom:1px solid #F0EEE8;">'
        f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{color};margin-right:8px;vertical-align:middle;"></span>'
        f'Port <span style="font-family:\'SF Mono\',Menlo,monospace;">{port}/{proto}</span> {verb}{svc_str}{host_str}'
        f'</td></tr>'
    )


def _html_escape(s: Any) -> str:
    if s is None:
        return ""
    s = str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# DB upserts
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-subdomain routing — session 2 of asset decomposition (task #29).
# ---------------------------------------------------------------------------
# Each subdomain in the ASM JSON belongs to ONE asset in the portal. Most
# are their own asset (kind=web/portal/mail/etc.). www.X is an alias of X.
# The apex itself is its own asset. This routing decides which asset gets
# which subdomain's surface data.

import re as _re

_STAGING_PAT = _re.compile(
    r'(-test|-staging|-dev|-uat|-qa|test\.|staging\.|dev\.|uat\.|qa\.)',
    _re.IGNORECASE,
)
_MAIL_PAT = _re.compile(
    r'^(mail|smtp|imap|mx[0-9]*|pop3?|webmail|exchange)\.', _re.IGNORECASE
)
_API_PAT = _re.compile(r'^(api|rest|graphql)\.', _re.IGNORECASE)
_FTP_PAT = _re.compile(r'^(ftp|sftp|ftps)[0-9]*\.', _re.IGNORECASE)
_INFRA_PAT = _re.compile(
    r'^(ns[0-9]+|dns[0-9]*|vpn[0-9]*|jump[0-9]*|bastion|hyperv|xen|admin|backup|vcenter|esxi)\.',
    _re.IGNORECASE,
)


def classify_subdomain_kind(name: str) -> str:
    """Return asset_kind_t value. Mirror of classify_kind in split_assets_by_system.py
    — duplicated inline so the importer doesn't need the sibling script in the
    GH Actions environment.
    """
    if _MAIL_PAT.search(name):
        return "mail"
    if _STAGING_PAT.search(name):
        return "staging"
    if _API_PAT.search(name):
        return "api"
    if _FTP_PAT.search(name):
        return "ftp"
    if _INFRA_PAT.search(name):
        return "infra"
    return "unknown"


def lookup_existing_aliases(conn, apex_asset_id: str) -> list[str]:
    """Read the apex asset's aliases[] column. Used so we can route the
    apex's www variant (and any other aliases) into the apex bucket rather
    than treating them as separate assets.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT aliases FROM public.assets WHERE asset_id = %s",
            (apex_asset_id,),
        )
        row = cur.fetchone()
        if row and row[0]:
            return [a.lower() for a in row[0]]
    return []


def route_subdomains_to_assets(
    asm_doc: dict, apex_asset_id: str, aliases: list[str]
) -> dict[str, list[dict]]:
    """Bucket the ASM JSON's subdomains[] by destination asset_id.

    Returns a dict {asset_id: [subdomain_entry, ...]}. The apex's bucket
    always exists, even if empty, so its asset_surface row gets refreshed
    every cron tick.

    IMPLICIT www ALIAS: `www.<apex>` is ALWAYS treated as an alias of the
    apex, even if it isn't in the apex's aliases[] column yet. This
    catches the case where ASM first-scans a newly-added apex whose
    aliases[] hasn't been populated. Without this, www.<apex> ends up as
    its own asset row, which is never what we want.
    """
    buckets: dict[str, list[dict]] = {apex_asset_id: []}
    subs = asm_doc.get("subdomains") or []
    apex_lower = apex_asset_id.lower()
    alias_set = set(aliases)
    # Hardcoded implicit alias — www.<apex>
    implicit_www = f"www.{apex_lower}"

    for sub in subs:
        if not isinstance(sub, dict):
            continue
        name = (sub.get("name") or sub.get("subdomain") or "").lower().strip()
        if not name:
            continue

        # Apex itself, any stored alias, OR the implicit www variant → apex bucket
        if name == apex_lower or name in alias_set or name == implicit_www:
            buckets[apex_asset_id].append(sub)
            continue

        # Everything else gets its own bucket. Auto-creates a new asset
        # row downstream if one doesn't already exist.
        buckets.setdefault(name, []).append(sub)

    return buckets


def ensure_www_alias_recorded(conn, apex_asset_id: str) -> None:
    """If www.<apex> was discovered in this scan, make sure it's recorded
    in the apex's aliases[] column so future runs are explicit, not
    relying on the implicit www-alias rule.
    """
    www_name = f"www.{apex_asset_id.lower()}"
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE public.assets
            SET aliases = (
                SELECT array_agg(DISTINCT a) FROM (
                    SELECT unnest(coalesce(aliases, '{}'::text[])) AS a
                    UNION SELECT %s
                ) t
            )
            WHERE asset_id = %s
              AND NOT (aliases @> ARRAY[%s]::text[])
            """,
            (www_name, apex_asset_id, www_name),
        )


def build_sliced_doc(orig_doc: dict, sub_list: list[dict]) -> dict:
    """Create a per-asset copy of the ASM JSON containing only the given
    subdomain entries. The summary is recomputed for that subset so the
    convenience columns (service_count, etc.) reflect just this asset.

    Preserves top-level keys (asset, scan, registration, history) so
    derive_lifecycle, derive_convenience etc. continue to work unchanged.
    """
    sliced = dict(orig_doc)
    sliced["subdomains"] = sub_list

    # Recompute the summary block for this slice
    summary = dict(orig_doc.get("summary") or {})
    summary["subdomain_count"] = len(sub_list)
    summary["live_subdomain_count"] = sum(
        1 for s in sub_list
        if isinstance(s, dict) and (s.get("reachability") or {}).get("live")
    )
    summary["host_count"] = len({
        h.get("ip")
        for s in sub_list if isinstance(s, dict)
        for h in (s.get("hosts") or []) if isinstance(h, dict) and h.get("ip")
    })
    # Count services from BOTH nesting shapes — subdomain.services[] (the
    # actual ASM JSON layout) AND hosts[].services[] (legacy/alt). Some
    # asset blobs use one, some the other; this counts whichever's present.
    def _count_svcs(sub: dict) -> int:
        n = len(sub.get("services") or [])
        for h in (sub.get("hosts") or []):
            if isinstance(h, dict):
                n += len(h.get("services") or [])
        return n
    summary["service_count"] = sum(
        _count_svcs(s) for s in sub_list if isinstance(s, dict)
    )
    # Top hosting org for the slice — first non-null asn_org we find
    top_org = None
    for s in sub_list:
        if not isinstance(s, dict):
            continue
        for h in (s.get("hosts") or []):
            if isinstance(h, dict) and h.get("asn_org"):
                top_org = h["asn_org"]
                break
        if top_org:
            break
    if top_org:
        summary["top_hosting_org"] = top_org
    sliced["summary"] = summary
    return sliced


UPSERT_ASSET = """
INSERT INTO public.assets
  (asset_id, name, type, organization, ownership, discovery_status,
   first_observed, last_observed)
VALUES (%(asset_id)s, %(name)s, %(type)s, %(organization)s,
        %(ownership)s, %(discovery_status)s,
        %(first_observed)s, %(last_observed)s)
ON CONFLICT (asset_id) DO UPDATE SET
  last_observed = GREATEST(public.assets.last_observed, EXCLUDED.last_observed),
  -- Tier 2 phantom defense: promote ct_ghost → confirmed_live if a later
  -- scan resolves the host. Don't downgrade in the other direction — that
  -- happens via the nightly DNS heartbeat (Tier 3, separate workflow) so
  -- we don't oscillate on transient DNS hiccups.
  discovery_status = CASE
    WHEN EXCLUDED.discovery_status = 'confirmed_live'
      AND public.assets.discovery_status IN ('ct_ghost', 'unverified', 'dns_only')
      THEN 'confirmed_live'
    ELSE public.assets.discovery_status
  END,
  -- Same idea for ownership — if asm-discover is processing a target from
  -- data/targets.yml (which is the scope_verified allowlist), promote
  -- 'unknown' or NULL to 'owned'. Never downgrade.
  ownership = CASE
    WHEN EXCLUDED.ownership = 'owned'
      AND public.assets.ownership IN ('unknown', 'unverified')
      THEN 'owned'
    ELSE public.assets.ownership
  END
RETURNING asset_id, (xmax = 0) AS inserted;
"""

# Auto-create row for a newly-discovered subdomain. Sets kind + apex_domain
# so the new asset appears properly in the dashboard from the moment it's
# discovered. ON CONFLICT updates last_observed (+ promotion rules same as
# UPSERT_ASSET) — preserves any kind the admin has manually flipped.
UPSERT_NEW_SUBDOMAIN_ASSET = """
INSERT INTO public.assets
  (asset_id, name, type, organization, kind, apex_domain,
   ownership, discovery_status,
   first_observed, last_observed)
VALUES
  (%(asset_id)s, %(asset_id)s, 'single_host', %(organization)s,
   %(kind)s, %(apex_domain)s,
   %(ownership)s, %(discovery_status)s,
   %(first_observed)s, %(last_observed)s)
ON CONFLICT (asset_id) DO UPDATE SET
  last_observed = GREATEST(public.assets.last_observed, EXCLUDED.last_observed),
  discovery_status = CASE
    WHEN EXCLUDED.discovery_status = 'confirmed_live'
      AND public.assets.discovery_status IN ('ct_ghost', 'unverified', 'dns_only')
      THEN 'confirmed_live'
    ELSE public.assets.discovery_status
  END,
  ownership = CASE
    WHEN EXCLUDED.ownership = 'owned'
      AND public.assets.ownership IN ('unknown', 'unverified')
      THEN 'owned'
    ELSE public.assets.ownership
  END
RETURNING asset_id, (xmax = 0) AS inserted;
"""

# Tier 2 phantom defense — separate UPSERT path for phantom subdomains.
# Same shape as UPSERT_NEW_SUBDOMAIN_ASSET but stamped with discovery_status
# ='ct_ghost' from the start. No surface row written (we have no data
# to populate it — by definition we couldn't reach the host). The row
# exists purely so /admin/phantoms surfaces it for review.
UPSERT_PHANTOM_SUBDOMAIN = """
INSERT INTO public.assets
  (asset_id, name, type, organization, kind, apex_domain,
   ownership, discovery_status,
   first_observed, last_observed)
VALUES
  (%(asset_id)s, %(asset_id)s, 'single_host', %(organization)s,
   'unknown', %(apex_domain)s,
   'owned', 'ct_ghost',
   %(first_observed)s, %(last_observed)s)
ON CONFLICT (asset_id) DO UPDATE SET
  -- Always bump last_observed — proves the phantom is still in CT logs.
  last_observed = GREATEST(public.assets.last_observed, EXCLUDED.last_observed)
  -- Note: do NOT update discovery_status here. If a phantom was previously
  -- promoted to confirmed_live by a successful scan, keep that classification.
  -- Only the nightly DNS heartbeat (Tier 3) can demote live → ghost.
RETURNING asset_id, (xmax = 0) AS inserted;
"""

UPSERT_SURFACE = """
INSERT INTO public.asset_surface (
  asset_id, asset_type, alive, top_hosting_org, platforms,
  primary_asn, primary_ptr,
  subdomain_count, live_subdomain_count, host_count, service_count,
  newest_cert_expiry_days,
  discovered_via, first_discovered, last_seen,
  auth_gated,
  surface_data, updated_at, updated_by
)
VALUES (
  %(asset_id)s, %(asset_type)s, %(alive)s, %(top_hosting_org)s, %(platforms)s,
  %(primary_asn)s, %(primary_ptr)s,
  %(subdomain_count)s, %(live_subdomain_count)s, %(host_count)s, %(service_count)s,
  %(newest_cert_expiry_days)s,
  %(discovered_via)s, %(first_discovered)s, %(last_seen)s,
  %(auth_gated)s,
  %(surface_data)s, NOW(), %(updated_by)s
)
ON CONFLICT (asset_id) DO UPDATE SET
  asset_type              = EXCLUDED.asset_type,
  alive                   = EXCLUDED.alive,
  top_hosting_org         = EXCLUDED.top_hosting_org,
  platforms               = EXCLUDED.platforms,
  primary_asn             = EXCLUDED.primary_asn,
  primary_ptr             = EXCLUDED.primary_ptr,
  subdomain_count         = EXCLUDED.subdomain_count,
  live_subdomain_count    = EXCLUDED.live_subdomain_count,
  host_count              = EXCLUDED.host_count,
  service_count           = EXCLUDED.service_count,
  newest_cert_expiry_days = EXCLUDED.newest_cert_expiry_days,
  discovered_via          = EXCLUDED.discovered_via,
  first_discovered        = COALESCE(public.asset_surface.first_discovered, EXCLUDED.first_discovered),
  last_seen               = GREATEST(public.asset_surface.last_seen, EXCLUDED.last_seen),
  -- #24 Phase 2 — derived every asm-discover refresh, never latched
  -- (per Q2 advisor 2026-06-15). Plain EXCLUDED SET so an asset that
  -- goes public flips auth_gated false on the next 6h cron.
  auth_gated              = EXCLUDED.auth_gated,
  surface_data            = EXCLUDED.surface_data,
  updated_at              = NOW(),
  updated_by              = EXCLUDED.updated_by;
"""


def import_one(
    conn,
    asm_doc: dict,
    source_tag: str,
    dry_run: bool,
    skip_events: bool = False,
) -> dict[str, Any]:
    """Push one asset JSON to the DB, routing subdomains to per-system
    asset rows (asset decomposition session 2, task #29 follow-up).

    For each subdomain in the JSON, decide which asset_id it belongs to:
      - subdomain name == apex OR in apex.aliases → goes to apex bucket
      - otherwise → goes to its own bucket (auto-creates the asset row
        with classify_subdomain_kind for kind)

    For each bucket, write a per-asset asset_surface row containing ONLY
    that bucket's subdomains. The apex's surface row no longer carries
    the whole apex blob — it carries only the apex + its aliases. New
    sibling assets (portal.*, myorders.*, mail.*, etc.) get their own
    surface data populated.

    Returns a status dict aggregating across all buckets processed.
    """
    apex_asset_id = derive_portal_asset_id(asm_doc)
    if not apex_asset_id:
        return {"status": "skipped", "reason": "no asset.value"}

    asset_type = derive_asset_type(asm_doc)
    organization = derive_organization(asm_doc)

    # Discover aliases via the existing asset row (set by today's split).
    # Empty list if the apex doesn't have an assets row yet — fine, just
    # means www variants will also go into their own buckets and we'll
    # backfill the aliases column on a later run.
    aliases = lookup_existing_aliases(conn, apex_asset_id) if not dry_run else []

    buckets = route_subdomains_to_assets(asm_doc, apex_asset_id, aliases)

    # If www.<apex> appeared in this scan and was routed via the implicit
    # alias rule, persist that fact in the apex's aliases[] column so
    # future scans don't depend on the runtime rule. Cheap upsert; no-op
    # if it's already there.
    if not dry_run:
        apex_subs = buckets.get(apex_asset_id, [])
        www_name = f"www.{apex_asset_id.lower()}"
        if any(
            (s.get("name") or "").lower() == www_name
            for s in apex_subs if isinstance(s, dict)
        ):
            try:
                ensure_www_alias_recorded(conn, apex_asset_id)
            except Exception as e:
                print(
                    f"  ! ensure_www_alias_recorded for {apex_asset_id} failed (non-fatal): {e}",
                    file=sys.stderr,
                )

    if dry_run:
        return {
            "status": "dry_run",
            "asset_id": apex_asset_id,
            "buckets": {bid: len(subs) for bid, subs in buckets.items()},
        }

    all_events: list[dict] = []
    assets_inserted = 0
    surfaces_written = 0

    for bucket_id, sub_list in buckets.items():
        is_apex = bucket_id == apex_asset_id
        sliced = build_sliced_doc(asm_doc, sub_list)
        bucket_convenience = derive_convenience(sliced)
        bucket_lifecycle = derive_lifecycle(sliced)

        with conn.cursor() as cur:
            # 1. Fetch existing surface for event diff
            existing_blob: dict | None = None
            if not skip_events:
                cur.execute(
                    "SELECT surface_data FROM public.asset_surface WHERE asset_id = %s",
                    (bucket_id,),
                )
                row = cur.fetchone()
                if row and row[0] is not None:
                    existing_blob = row[0]

            # 2. Upsert the asset row. The apex uses the standard
            #    UPSERT_ASSET (preserves its existing kind/aliases).
            #    Non-apex subdomains use UPSERT_NEW_SUBDOMAIN_ASSET which
            #    auto-classifies kind on insert and sets apex_domain.
            # #34 Gate #1 (note 93, "respond don't just resolve"): stamp
            # discovery_status from whether the asset actually answered with a
            # SERVICE, not merely whether it resolves. asm-discover rows are in
            # scope (targets.yml) + resolved DNS (Tier 2 dnsx gate) — but a
            # resolve-with-no-service name (sciimage.com apex, bare IPs) is
            # `dns_only`, NOT a confirmed_live asset.
            # SIGNAL = service_count, NOT `alive`: alive is HTTP-reachability,
            # so DNS-only infra (ns01/ns02: svc=1, alive=False) must stay
            # confirmed_live — service_count keeps them, drops only svc=0.
            # The upsert CASE re-promotes dns_only → confirmed_live
            # if a later discovery finds svc>0. No downgrade here (confirmed_live
            # that loses service is demoted by Tier 3 heartbeat / backfill, not
            # this path — mirrors the existing no-downgrade-in-upsert rule).
            svc_count = int(bucket_convenience.get("service_count") or 0)
            host_count = int(bucket_convenience.get("host_count") or 0)
            # Phantom-classification fix (2026-06-24): a 0-service name is
            # `dns_only` ONLY if it actually resolved to a host. A non-apex
            # subdomain with host_count=0 never resolved — it's a passively-
            # discovered (subfinder/CT) phantom and must be `ct_ghost`, not
            # surfaced as a live-IP asset. Apexes stay dns_only even at
            # host_count=0 (scoped real domains, e.g. sciimage.com). svc>0
            # always wins (keeps DNS infra like ns01/ns02 confirmed_live).
            if svc_count > 0:
                disc = "confirmed_live"
            elif is_apex or host_count > 0:
                disc = "dns_only"
            else:
                disc = "ct_ghost"
            if is_apex:
                cur.execute(UPSERT_ASSET, {
                    "asset_id": bucket_id,
                    "name": bucket_id,
                    "type": asset_type,
                    "organization": organization,
                    "ownership": "owned",
                    "discovery_status": disc,
                    "first_observed": bucket_lifecycle["first_discovered"],
                    "last_observed": bucket_lifecycle["last_seen"],
                })
            else:
                cur.execute(UPSERT_NEW_SUBDOMAIN_ASSET, {
                    "asset_id": bucket_id,
                    "organization": organization,
                    "kind": classify_subdomain_kind(bucket_id),
                    "apex_domain": apex_asset_id,
                    "ownership": "owned",
                    "discovery_status": disc,
                    "first_observed": bucket_lifecycle["first_discovered"],
                    "last_observed": bucket_lifecycle["last_seen"],
                })
            a_row = cur.fetchone()
            if a_row and a_row[1]:
                assets_inserted += 1

            # 3. Upsert the per-asset surface row
            cur.execute(UPSERT_SURFACE, {
                "asset_id": bucket_id,
                "asset_type": asset_type if is_apex else "single_host",
                **bucket_convenience,
                "discovered_via": bucket_lifecycle["discovered_via"],
                "first_discovered": bucket_lifecycle["first_discovered"],
                "last_seen": bucket_lifecycle["last_seen"],
                "surface_data": Json(sliced),
                "updated_by": source_tag,
            })
            surfaces_written += 1

            # 4. Per-bucket event diff
            if not skip_events:
                try:
                    bucket_events = compute_events(
                        bucket_id, existing_blob, sliced, source_tag,
                    )
                    if bucket_events:
                        cur.executemany(INSERT_EVENT, bucket_events)
                        all_events.extend(bucket_events)
                except Exception as e:
                    print(
                        f"  ! event-diff for {bucket_id} failed (non-fatal): {e}",
                        file=sys.stderr,
                    )

    # ─── Tier 2 phantom defense — record phantom subdomains as ct_ghost rows ─
    # The normalizer surfaces non-resolving subdomain candidates from
    # asm-discover.sh's DNS gate as asm_doc["phantom_subdomains"]: a plain
    # list of hostname strings. UPSERT each as a ct_ghost asset so the
    # /admin/phantoms page surfaces it for review without emitting a
    # real-time "new asset" notification (the alerter gate filters by
    # discovery_status). No asset_surface row — we have no data to write
    # there because we couldn't reach the host. The audit story is in the
    # asset row itself (ownership=owned, discovery_status=ct_ghost) plus
    # the data/phantoms/{target}_{ts}.json file kept by asm-discover.sh.
    phantom_inserted = 0
    phantom_names = asm_doc.get("phantom_subdomains") or []
    if phantom_names:
        first_seen = (asm_doc.get("scan") or {}).get("completed_at") or utc_now()
        with conn.cursor() as cur:
            for phantom_name in phantom_names:
                if not phantom_name:
                    continue
                # Skip if it would collide with the apex/aliases bucket
                # processed above — those are real assets that happen to
                # not be in this scan's phantom list (defensive).
                if phantom_name.lower() == apex_asset_id.lower():
                    continue
                cur.execute(UPSERT_PHANTOM_SUBDOMAIN, {
                    "asset_id": phantom_name,
                    "organization": organization,
                    "apex_domain": apex_asset_id,
                    "first_observed": first_seen,
                    "last_observed": first_seen,
                })
                p_row = cur.fetchone()
                if p_row and p_row[1]:
                    phantom_inserted += 1

    return {
        "status": "ok",
        "asset_id": apex_asset_id,
        "asset_inserted": assets_inserted > 0,
        "buckets_processed": len(buckets),
        "assets_inserted": assets_inserted,
        "surfaces_written": surfaces_written,
        "phantoms_seen": len(phantom_names),
        "phantoms_inserted": phantom_inserted,
        "events": all_events,
        "events_emitted": len(all_events),
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory of legacy ASM asset JSON files (default: {DEFAULT_DATA_DIR})",
    )
    ap.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN)",
    )
    ap.add_argument(
        "--source-tag",
        default="legacy_asm_import",
        help="Stamp written to asset_surface.updated_by",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse + derive but don't write to DB",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process first N files (debug aid). 0 = all.",
    )
    ap.add_argument(
        "--skip-events",
        action="store_true",
        help=(
            "Suppress asset_surface_event writes. Use for silent backfills "
            "where you don't want to flood the event log with asset_first_seen "
            "rows for assets that have actually been around for ages."
        ),
    )
    ap.add_argument(
        "--skip-notifications",
        action="store_true",
        help=(
            "Insert events to the DB but DON'T fan out Resend emails. Use "
            "for testing the importer without spamming subscribers, or "
            "during ops work where the event log should update silently."
        ),
    )
    args = ap.parse_args()

    if not args.dry_run and not args.dsn:
        print("error: --dsn or SUPABASE_DSN required (or use --dry-run)", file=sys.stderr)
        return 1

    if not args.data_dir.is_dir():
        print(f"error: data dir not found: {args.data_dir}", file=sys.stderr)
        return 1

    files = sorted(args.data_dir.glob("*.json"))
    if args.limit > 0:
        files = files[: args.limit]
    if not files:
        print(f"no JSON files in {args.data_dir}", file=sys.stderr)
        return 1

    print(f"importing {len(files)} asset(s) from {args.data_dir}")
    if args.dry_run:
        print("  (dry-run — no DB writes)")

    okay = 0
    new_assets = 0
    skipped = 0
    failed = 0
    all_events: list[dict] = []

    conn = None
    if not args.dry_run:
        conn = psycopg.connect(args.dsn, autocommit=False)

    try:
        for path in files:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"  ! {path.name}: parse error: {e}", file=sys.stderr)
                failed += 1
                continue

            try:
                result = import_one(
                    conn, doc, args.source_tag, args.dry_run, args.skip_events
                )
            except Exception as e:
                print(f"  ! {path.name}: import error: {e}", file=sys.stderr)
                if conn:
                    conn.rollback()
                failed += 1
                continue

            if result["status"] == "skipped":
                print(f"  - {path.name}: skipped ({result['reason']})")
                skipped += 1
            elif result["status"] == "dry_run":
                print(f"  · {path.name}: would upsert asset_id={result['asset_id']}")
                okay += 1
            else:
                tag = "NEW" if result.get("asset_inserted") else "upd"
                ev = result.get("events_emitted") or 0
                ev_str = f" [+{ev} event{'s' if ev != 1 else ''}]" if ev else ""
                print(f"  ✓ {path.name}: {tag} {result['asset_id']}{ev_str}")
                okay += 1
                if result.get("asset_inserted"):
                    new_assets += 1
                # Collect this asset's events for end-of-run notification dispatch
                all_events.extend(result.get("events") or [])

        if conn and not args.dry_run:
            # Dark-asset sweep BEFORE the first commit so the dark events
            # land in the same transaction as the surface updates. Skipped
            # under --skip-events because dark events ARE events. Failures
            # here are non-fatal — current-state still commits.
            if not args.skip_events:
                try:
                    dark_events = detect_dark_assets(conn, args.source_tag)
                    if dark_events:
                        with conn.cursor() as cur:
                            cur.executemany(INSERT_EVENT, dark_events)
                        all_events.extend(dark_events)
                        print(
                            f"dark-asset sweep: {len(dark_events)} asset(s) "
                            f"crossed {DARK_THRESHOLD_HOURS}h threshold"
                        )
                except Exception as e:
                    print(
                        f"  ! dark-asset sweep failed (non-fatal): {e}",
                        file=sys.stderr,
                    )

            conn.commit()

            # Fan-out notifications AFTER the surface/event writes have
            # committed. We never let a Resend hiccup roll back the
            # surface inventory updates — current-state correctness wins
            # over notification delivery.
            if all_events and not args.skip_notifications and not args.skip_events:
                ns = dispatch_event_notifications(conn, all_events, args.source_tag)
                if ns["subscribers"]:
                    print(
                        f"notifications: {ns['emails_sent']} sent, "
                        f"{ns['emails_failed']} failed, "
                        f"{ns['subscribers']} subscriber(s) checked"
                    )
                elif ns["skipped_no_key"]:
                    pass  # already printed warning
    finally:
        if conn:
            conn.close()

    print()
    print(f"summary: {okay} ok ({new_assets} new), {skipped} skipped, {failed} failed")

    if failed and okay == 0:
        return 1
    if failed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
