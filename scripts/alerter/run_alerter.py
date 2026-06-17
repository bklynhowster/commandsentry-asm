#!/usr/bin/env python3
"""
run_alerter.py — Daily COMMANDsentry posture digest.

Queries the canonical Postgres data layer for status transitions since the
last successful run, renders an HTML + plaintext digest, and emails it via
Resend. Designed to run as a GitHub Actions cron job.

What triggers an item in the digest:
  - Finding history row with status 'confirmed' / 'open' (passed 2-scan
    confirmation) in the window since last run
  - Finding history row with status 'regressed' in the window
  - Asset whose current_risk is CRITICAL / HIGH / MODERATE-HIGH and that
    we haven't already reported in a previous run (deduped via the runs
    table)

Even if nothing fires, the alerter sends a brief "all clear" so you know
it's alive.

Required env vars:
  SUPABASE_DSN       postgres URL (use direct connection or session pooler)
  SENDGRID_API_KEY   from Walter @ Command's SendGrid account
                       (legacy RESEND_API_KEY still honored as fallback
                       during the 2026-05-28 cutover transition)
  ALERTER_FROM       verified Command sender; default
                       CommandSentry@commandcompanies.com
  ALERTER_FROM_NAME  display name; default "COMMANDsentry"
  ALERTER_TO         comma-separated recipient list, e.g.
                       hschneider@commandcompanies.com,howiehow@mac.com

Optional env vars:
  ALERTER_NAME             default 'daily_digest' — keys the runs table
  ALERTER_FIRST_RUN_HOURS  default 24 — how far back to look on the first
                           ever run (when there's no prior success row)
  ALERTER_DASHBOARD_URL    default Supabase dashboard link in the footer

Usage:
  python3 run_alerter.py             # send email + record run
  python3 run_alerter.py --dry-run   # print body + skip Resend + skip DB write
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from html import escape, unescape

try:
    import psycopg
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install with: pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _env(name: str, default: str | None = None, required: bool = False) -> str | None:
    v = os.environ.get(name, default)
    if required and not v:
        print(f"error: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------

SQL_LAST_WINDOW_END = """
SELECT alerter_last_window_end(%s)
"""

SQL_NEW_CONFIRMED = """
SELECT finding_id, asset_id, title, severity, current_status, source,
       scan_id, event_at, alert_kind
FROM v_alerter_changes
WHERE event_at > %s
  AND event_at <= %s
  AND alert_kind IN ('CONFIRMED', 'CONFIRMED_HIGH')
ORDER BY
  CASE severity
    WHEN 'CRITICAL'      THEN 1
    WHEN 'HIGH'          THEN 2
    WHEN 'MODERATE-HIGH' THEN 3
    WHEN 'MODERATE'      THEN 4
    WHEN 'LOW'           THEN 5
    WHEN 'INFO'          THEN 6
  END,
  asset_id, finding_id;
"""

SQL_REGRESSED = """
SELECT finding_id, asset_id, title, severity, current_status, source,
       scan_id, event_at, alert_kind
FROM v_alerter_changes
WHERE event_at > %s
  AND event_at <= %s
  AND alert_kind = 'REGRESSED'
ORDER BY asset_id, finding_id;
"""

SQL_HIGH_RISK_ASSETS_NOW = """
-- Full live set of high-risk assets. The Python alerter diffs this against
-- the previous run's snapshot to surface only newly-elevated ones.
SELECT asset_id, name, organization, current_risk, current_risk_reason,
       updated_at
FROM v_alerter_high_risk_assets
ORDER BY
  CASE current_risk
    WHEN 'CRITICAL'      THEN 1
    WHEN 'HIGH'          THEN 2
    WHEN 'MODERATE-HIGH' THEN 3
  END,
  asset_id;
"""

SQL_PRIOR_HIGH_RISK_SET = """
SELECT alerter_prior_high_risk_set(%s)
"""

SQL_OPEN_BASELINE = """
-- Always include a baseline snapshot of currently-open work so the
-- digest reflects today's posture, even on a "no changes" day.
--
-- Tier 2 phantom defense (2026-06-07): join to assets and restrict to
-- confirmed_live + owned rows. Without this, the baseline counts inflate
-- with findings on ct_ghost / namesake / unverified assets — the same
-- exclusion the alerter notification gate applies, now applied here too.
SELECT
  COUNT(*) FILTER (WHERE f.severity = 'CRITICAL')      AS critical_open,
  COUNT(*) FILTER (WHERE f.severity = 'HIGH')          AS high_open,
  COUNT(*) FILTER (WHERE f.severity = 'MODERATE-HIGH') AS mod_high_open,
  COUNT(*) FILTER (WHERE f.severity = 'MODERATE')      AS moderate_open,
  COUNT(*) FILTER (WHERE f.severity = 'LOW')           AS low_open
FROM findings f
JOIN assets a ON a.asset_id = f.asset_id
WHERE f.current_status IN ('detected', 'confirmed', 'open', 'regressed')
  AND a.ownership = 'owned'
  AND a.discovery_status = 'confirmed_live';
"""

# ---------------------------------------------------------------------------
# Asset-surface events in the window — added 2026-06-07
#
# The original digest only surfaced finding state transitions and asset risk
# shifts. It was structurally blind to asset_first_seen + asset_went_dark
# events, which is why the 2026-06-07 morning digest reported "0 chng" while
# 4-6 real-time emails about phantom assets had fired the night before.
#
# Both queries apply the same Tier 2 gate as dispatch_event_notifications:
# only confirmed_live + owned assets count. Events for ct_ghost / unverified
# / namesake assets stay in asset_surface_event (audit trail intact) but
# don't surface in the digest, matching the real-time email behavior.
# ---------------------------------------------------------------------------

SQL_NEW_ASSETS_IN_WINDOW = """
SELECT
  e.asset_id,
  a.name,
  a.organization,
  e.observed_at,
  a.current_risk
FROM public.asset_surface_event e
JOIN public.assets a ON a.asset_id = e.asset_id
WHERE e.event_type = 'asset_first_seen'
  AND e.observed_at >  %s
  AND e.observed_at <= %s
  AND a.ownership = 'owned'
  AND a.discovery_status = 'confirmed_live'
ORDER BY e.observed_at DESC, e.asset_id;
"""

SQL_DARK_ASSETS_IN_WINDOW = """
SELECT
  e.asset_id,
  a.name,
  a.organization,
  e.observed_at,
  e.prev_value
FROM public.asset_surface_event e
JOIN public.assets a ON a.asset_id = e.asset_id
WHERE e.event_type = 'asset_went_dark'
  AND e.observed_at >  %s
  AND e.observed_at <= %s
  AND a.ownership = 'owned'
  AND a.discovery_status = 'confirmed_live'
ORDER BY e.observed_at DESC, e.asset_id;
"""

# ---------------------------------------------------------------------------
# Watchdog v1 — internal pipeline health checks (added 2026-06-07)
#
# Two checks because they catch DIFFERENT failure classes:
#
#   1. STALENESS (per-asset on the DISCOVERY clock = assets.last_observed):
#      finds confirmed_live + owned assets whose last_observed has aged
#      past the discovery cadence threshold (default 9h = 6h cron + 3h
#      grace). LEFT JOIN to asset_surface so we can show last_seen
#      alongside, but the WHERE filter is on assets.last_observed —
#      asset_surface might legitimately lag if there's a deep-scan
#      rotation policy.
#
#      Catches: scheduled discovery runs that silently stopped firing
#      (the bug that bit us 2026-06-06 → 2026-06-07: 3 missed crons).
#
#      Does NOT catch: assets WRONGLY DEMOTED to ct_ghost. Once an asset
#      is no longer confirmed_live, it falls out of this WHERE clause,
#      so the bug is invisible to this check. Hence check #2.
#
#   2. CANARY (direct sensor on a known-good allowlist):
#      for every scope_verified apex in data/targets.yml, assert that
#      both the apex AND www.<apex> exist in assets with
#      discovery_status='confirmed_live' AND ownership='owned'. Any
#      that don't are flagged BY NAME.
#
#      Catches: real hosts wrongly demoted to ct_ghost (the 2026-06-06
#      19:55 UTC broken-dnsx-gate misclassification of 4 www aliases).
#      Cheap, reuses the scope_verified allowlist we already maintain.
#
# Per Howie 2026-06-07: a global MAX(last_observed) would have missed
# both the partial-cron-stop and the demotion bug. Two narrow checks
# beat one wide check.
# ---------------------------------------------------------------------------

SQL_STALE_LIVE_ASSETS = """
-- Per-asset staleness check on BOTH clocks. An asset alarms if EITHER
-- the discovery clock OR the deep-scan clock is stale (or never set).
--
-- Why both: a one-clock check would let "discovery happened but no deep
-- scan ever ran" slip through silently — exactly the insite.sciimage.com
-- pattern (HIGH-risk finding, asset present in DB, NEVER deep-scanned by
-- this pipeline). Per Howie 2026-06-07: "the thing that surfaced the gap
-- stops surfacing it without the gap being closed."
--
-- Clocks:
--   discovery   = assets.last_observed       (asm-discover.yml, 6h cron)
--   deep_scan   = asset_surface.last_seen    (scanner.yml + per-sub loop)
--
-- Thresholds passed in by caller; defaults are 9h discovery (= cron + 3h
-- grace) and 168h deep-scan (= 7d, generous because scanner.yml rotation
-- is slower than discovery).
--
-- IMPORTANT: scoped to assets whose apex_domain is in the scope_verified
-- allowlist. Without that scope, manually-added or non-scope_verified
-- assets (commandmi.com, edelivery-bessemer.com, netlify.app) would
-- false-positive forever.
--
-- The output includes per-row reason flags so the renderer can show
-- WHICH clock(s) tripped, not just that something tripped.
SELECT
  a.asset_id,
  a.last_observed,
  s.last_seen                                            AS deep_scan_last_seen,
  EXTRACT(EPOCH FROM (now() - a.last_observed))/3600.0   AS hours_since_discovery,
  CASE
    WHEN s.asset_id  IS NULL                             THEN NULL
    ELSE EXTRACT(EPOCH FROM (now() - s.last_seen))/3600.0
  END                                                    AS hours_since_deep_scan,
  -- Per-row reason flags
  (a.last_observed IS NULL OR a.last_observed < (now() - (%(disc_h)s::int  * interval '1 hour'))) AS discovery_stale,
  (s.asset_id      IS NULL)                                                                       AS never_deep_scanned,
  (s.asset_id      IS NOT NULL AND s.last_seen < (now() - (%(deep_h)s::int * interval '1 hour'))) AS deep_scan_stale
FROM public.assets a
LEFT JOIN public.asset_surface s ON s.asset_id = a.asset_id
WHERE a.ownership = 'owned'
  AND a.discovery_status = 'confirmed_live'
  AND a.apex_domain = ANY(%(apexes)s)
  AND (
       a.last_observed IS NULL
    OR a.last_observed < (now() - (%(disc_h)s::int * interval '1 hour'))
    OR s.asset_id      IS NULL
    OR s.last_seen     < (now() - (%(deep_h)s::int * interval '1 hour'))
  )
ORDER BY
  -- Worst cases first: never deep-scanned, then oldest discovery clock
  (s.asset_id IS NULL) DESC,
  a.last_observed NULLS FIRST,
  a.asset_id;
"""

SQL_CANARY_VIOLATIONS = """
-- Canary tripwire on the scope_verified allowlist. For every host the
-- caller passes in, assert it exists in assets as confirmed_live + owned.
-- Returns one row per FAILED assertion (missing, wrong status, or wrong
-- ownership). The expected list is built in Python from data/targets.yml
-- so the SQL stays generic.
WITH expected(asset_id) AS (
  SELECT unnest(%s::text[])
)
SELECT
  e.asset_id,
  COALESCE(a.discovery_status, 'MISSING') AS actual_status,
  COALESCE(a.ownership,        'MISSING') AS actual_ownership,
  a.last_observed
FROM expected e
LEFT JOIN public.assets a ON a.asset_id = e.asset_id
-- #34 Gate #1: `dns_only` is an ACCEPTABLE state for a scope_verified host,
-- not a violation. The canary exists to catch hosts WRONGLY demoted to
-- ct_ghost (the 2026-06-06 broken-dnsx misclassification). A resolve-but-
-- no-service host correctly classified `dns_only` (e.g. sciimage.com apex —
-- NS/MX only, web lives on ftp/vpn subdomains) is NOT a regression; flagging
-- it would just re-create the false-positive we're removing. Both
-- confirmed_live and dns_only are "known + correctly classified."
-- FORWARD NOTE (revisit when the Tier-3 DNS heartbeat lands): today nothing
-- demotes confirmed_live → dns_only except the one-time #34 backfill (no
-- downgrade in the asm-discover upsert). If Tier-3 ever demotes a host that
-- USED to serve, a canary host transitioning confirmed_live → dns_only would
-- mean "lost a service it used to have" — at that point decide whether that
-- transition deserves its own notice, distinct from a host that was always
-- dns_only (sciimage). Until Tier-3 exists, accepting dns_only masks nothing.
WHERE COALESCE(a.discovery_status, 'MISSING') NOT IN ('confirmed_live', 'dns_only')
   OR COALESCE(a.ownership,        'MISSING') <> 'owned'
ORDER BY e.asset_id;
"""


def _load_targets_yml(targets_yml_path: str) -> dict | None:
    """Shared loader for load_canary_hosts + load_scope_verified_apexes.
    Returns None on any parse/read failure (callers degrade gracefully)."""
    try:
        import yaml  # PyYAML — already a dep of the importer
    except ImportError:
        print(
            "warn: PyYAML not installed — canary + staleness scope disabled. "
            "Install with: pip install --user --break-system-packages pyyaml",
            file=sys.stderr,
        )
        return None
    try:
        with open(targets_yml_path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"warn: {targets_yml_path} not found — watchdog scope disabled",
              file=sys.stderr)
        return None


def load_canary_hosts(targets_yml_path: str = "data/targets.yml") -> list[str]:
    """Build the canary host list from data/targets.yml. Auto-derives
    apex + www.<apex> for every scope_verified apex, with two per-target
    overrides:

      canary_no_www: true       — skip the www auto-derivation
                                  (e.g. sciimage.com has no www in DNS)
      canary_extras: [api, vpn] — additional subdomains to assert
                                  (e.g. add vpn.<apex>)

    Returns sorted unique list. Empty list disables the canary check.
    """
    doc = _load_targets_yml(targets_yml_path)
    if doc is None:
        return []
    hosts: set[str] = set()
    for t in (doc.get("targets") or []):
        if t.get("type") != "apex" or not t.get("scope_verified"):
            continue
        apex = t.get("value")
        if not apex:
            continue
        hosts.add(apex)
        if not t.get("canary_no_www"):
            hosts.add(f"www.{apex}")
        for sub in (t.get("canary_extras") or []):
            hosts.add(f"{sub}.{apex}")
    return sorted(hosts)


def load_scope_verified_apexes(targets_yml_path: str = "data/targets.yml") -> list[str]:
    """Just the apex strings (no www, no extras) — used to scope the
    staleness check to assets whose apex_domain is something discovery
    actually runs against. Without this scope, manually-added or
    non-scope_verified assets (like commandsentry-portal.netlify.app)
    false-positive every run."""
    doc = _load_targets_yml(targets_yml_path)
    if doc is None:
        return []
    apexes: set[str] = set()
    for t in (doc.get("targets") or []):
        if t.get("type") != "apex" or not t.get("scope_verified"):
            continue
        apex = t.get("value")
        if apex:
            apexes.add(apex)
    return sorted(apexes)

SQL_INSERT_RUN_START = """
INSERT INTO meta_alerter_runs (alerter_name, window_start, window_end, status)
VALUES (%s, %s, %s, 'started')
RETURNING id
"""

SQL_FINALIZE_RUN = """
UPDATE meta_alerter_runs
   SET finished_at   = now(),
       new_confirmed = %s,
       new_regressed = %s,
       new_high_risk = %s,
       email_sent    = %s,
       status        = %s,
       error_message = %s,
       reported_high_risk_assets = %s
 WHERE id = %s
"""


# ---------------------------------------------------------------------------
# Email rendering
# ---------------------------------------------------------------------------

SEV_COLOR = {
    "CRITICAL":      "#a51c30",
    "HIGH":          "#dc3545",
    "MODERATE-HIGH": "#fd7e14",
    "MODERATE":      "#ffc107",
    "LOW":           "#6c757d",
    "INFO":          "#9ca3af",
}


def _sev_pill(sev: str) -> str:
    color = SEV_COLOR.get(sev, "#6c757d")
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:'
        f'10px;background:{color};color:white;font-size:11px;font-weight:600;'
        f'letter-spacing:0.4px;">{escape(sev)}</span>'
    )


def render_html(
    *,
    window_start: datetime,
    window_end: datetime,
    confirmed: list[tuple],
    regressed: list[tuple],
    high_risk: list[tuple],
    new_assets: list[tuple],
    dark_assets: list[tuple],
    stale_assets: list[tuple],
    canary_violations: list[tuple],
    discovery_stale_hours: int,
    deepscan_stale_hours: int,
    baseline: dict,
    dashboard_url: str,
) -> str:
    today = window_end.strftime("%Y-%m-%d")
    win = (
        f"{window_start.strftime('%Y-%m-%d %H:%M UTC')} → "
        f"{window_end.strftime('%Y-%m-%d %H:%M UTC')}"
    )

    def section(title: str, count: int, body: str) -> str:
        if count == 0:
            return ""
        return (
            f'<h2 style="margin:24px 0 8px;font-size:15px;color:#1a1a1a;">'
            f"{escape(title)} <span style=\"color:#888;font-weight:400;\">"
            f"({count})</span></h2>{body}"
        )

    def find_table(rows: list[tuple]) -> str:
        if not rows:
            return ""
        cells = "".join(
            f"<tr>"
            f'<td style="padding:6px 12px 6px 0;font-family:monospace;font-size:12px;">{escape(r[1])}</td>'
            f'<td style="padding:6px 12px 6px 0;">{_sev_pill(r[3])}</td>'
            f'<td style="padding:6px 12px 6px 0;font-size:13px;">{escape(r[2])}</td>'
            f'<td style="padding:6px 0;font-family:monospace;font-size:11px;color:#888;">{escape(r[0])}</td>'
            f"</tr>"
            for r in rows
        )
        return (
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead><tr style="text-align:left;color:#666;font-size:11px;'
            f'text-transform:uppercase;letter-spacing:0.6px;">'
            f'<th style="padding:0 12px 8px 0;">Asset</th>'
            f'<th style="padding:0 12px 8px 0;">Severity</th>'
            f'<th style="padding:0 12px 8px 0;">Title</th>'
            f'<th style="padding:0 0 8px 0;">Finding ID</th>'
            f"</tr></thead><tbody>{cells}</tbody></table>"
        )

    def asset_table(rows: list[tuple]) -> str:
        if not rows:
            return ""
        cells = "".join(
            f"<tr>"
            f'<td style="padding:6px 12px 6px 0;font-family:monospace;font-size:12px;">{escape(r[0])}</td>'
            f'<td style="padding:6px 12px 6px 0;">{_sev_pill(r[3])}</td>'
            f'<td style="padding:6px 0;font-size:13px;color:#555;">{escape(unescape(r[4] or ""))}</td>'
            f"</tr>"
            for r in rows
        )
        return (
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead><tr style="text-align:left;color:#666;font-size:11px;'
            f'text-transform:uppercase;letter-spacing:0.6px;">'
            f'<th style="padding:0 12px 8px 0;">Asset</th>'
            f'<th style="padding:0 12px 8px 0;">Risk</th>'
            f'<th style="padding:0 0 8px 0;">Reason</th>'
            f"</tr></thead><tbody>{cells}</tbody></table>"
        )

    def surface_event_table(rows: list[tuple], dark: bool) -> str:
        """Render the new_assets / dark_assets rows. For new assets we show
        the current_risk pill; for dark assets we show when the asset last
        responded (from prev_value.last_seen) so the recipient can tell
        whether this is a fresh outage or a long-standing one."""
        if not rows:
            return ""
        cells_parts = []
        for r in rows:
            aid = r[0]
            display_name = r[1] or aid
            org = r[2] or ""
            observed = r[3]
            extra = r[4]
            if dark:
                # extra is prev_value JSONB with last_seen / primary_ptr
                last_seen_iso = (extra or {}).get("last_seen") if isinstance(extra, dict) else None
                detail = f"last responded {last_seen_iso}" if last_seen_iso else "last_seen unknown"
            else:
                # extra is current_risk severity string
                detail = _sev_pill(extra) if extra and extra != "NONE" else '<span style="color:#888;font-size:12px;">no risk yet</span>'
            # Build org suffix outside the f-string — Python 3.10 f-strings
            # can't contain backslashes in the expression part, and the
            # inline conditional version needed escaped quotes.
            if org and org != display_name:
                org_suffix = f' <span style="color:#888;">({escape(org)})</span>'
            else:
                org_suffix = ""
            observed_fmt = observed.strftime("%Y-%m-%d %H:%M UTC")
            cells_parts.append(
                f"<tr>"
                f'<td style="padding:6px 12px 6px 0;font-family:monospace;font-size:12px;">{escape(aid)}</td>'
                f'<td style="padding:6px 12px 6px 0;font-size:13px;">{escape(display_name)}{org_suffix}</td>'
                f'<td style="padding:6px 12px 6px 0;font-size:12px;color:#555;">{detail}</td>'
                f'<td style="padding:6px 0;font-family:monospace;font-size:11px;color:#888;">{observed_fmt}</td>'
                f"</tr>"
            )
        cells = "".join(cells_parts)
        header_label = "Last seen" if dark else "Risk"
        return (
            f'<table style="border-collapse:collapse;width:100%;">'
            f'<thead><tr style="text-align:left;color:#666;font-size:11px;'
            f'text-transform:uppercase;letter-spacing:0.6px;">'
            f'<th style="padding:0 12px 8px 0;">Asset ID</th>'
            f'<th style="padding:0 12px 8px 0;">Name</th>'
            f'<th style="padding:0 12px 8px 0;">{escape(header_label)}</th>'
            f'<th style="padding:0 0 8px 0;">Observed</th>'
            f"</tr></thead><tbody>{cells}</tbody></table>"
        )

    confirmed_section = section(
        "Newly confirmed findings", len(confirmed), find_table(confirmed)
    )
    regressed_section = section(
        "Regressed findings (was fixed, came back)", len(regressed), find_table(regressed)
    )
    high_risk_section = section(
        "Assets elevated to HIGH / CRITICAL", len(high_risk), asset_table(high_risk)
    )
    new_assets_section = section(
        "New assets discovered", len(new_assets), surface_event_table(new_assets, dark=False)
    )
    dark_assets_section = section(
        "Assets that went dark", len(dark_assets), surface_event_table(dark_assets, dark=True)
    )

    pipeline_degraded = bool(stale_assets or canary_violations)
    has_changes = bool(confirmed or regressed or high_risk or new_assets or dark_assets)

    # Headline reflects pipeline health FIRST, then activity. Don't say
    # "healthy" if the watchdog has anything to report — that was exactly
    # the lie that hid the 2026-06-06 over-suppression.
    if pipeline_degraded:
        headline = (
            f'<strong style="color:#a51c30;">&#x26A0; SCAN PIPELINE DEGRADED</strong> '
            f"&mdash; <strong>{len(canary_violations)}</strong> canary violation(s), "
            f"<strong>{len(stale_assets)}</strong> stale live asset(s). See below."
        )
    elif has_changes:
        headline = (
            f"<strong>{len(confirmed) + len(regressed)}</strong> finding change(s), "
            f"<strong>{len(high_risk)}</strong> asset risk shift(s), "
            f"<strong>{len(new_assets)}</strong> new asset(s), "
            f"<strong>{len(dark_assets)}</strong> dark asset(s) in this window."
        )
    else:
        headline = "<strong>No changes</strong> since last run &mdash; pipeline healthy."

    # Watchdog banner — only renders when something is wrong. Appears
    # ABOVE the "currently open" baseline so it can't be missed.
    watchdog_banner = ""
    if pipeline_degraded:
        canary_block = ""
        if canary_violations:
            canary_rows = "".join(
                f"<tr>"
                f'<td style="padding:4px 12px 4px 0;font-family:monospace;font-size:12px;">{escape(r[0])}</td>'
                f'<td style="padding:4px 12px 4px 0;font-size:12px;color:#a51c30;">disc={escape(r[1])} own={escape(r[2])}</td>'
                f"</tr>"
                for r in canary_violations
            )
            canary_block = (
                '<div style="margin-top:8px;font-size:12px;color:#1a1a1a;">'
                '<div style="font-weight:600;margin-bottom:4px;">Canary violations '
                f'(scope_verified apex/www that aren&rsquo;t confirmed_live + owned):</div>'
                f'<table style="border-collapse:collapse;">{canary_rows}</table>'
                '</div>'
            )
        stale_block = ""
        if stale_assets:
            stale_rows_parts = []
            for r in stale_assets:
                # 8-tuple shape from SQL_STALE_LIVE_ASSETS
                aid, lo, ls, hrs_disc, hrs_deep, disc_stale, never_ds, deep_ds = r
                lo_fmt = lo.strftime("%Y-%m-%d %H:%M UTC") if lo else "NEVER"
                ls_fmt = ls.strftime("%Y-%m-%d %H:%M UTC") if ls else "no surface row"
                hrs_disc_fmt = f"{hrs_disc:.1f}h" if hrs_disc is not None else "?"
                hrs_deep_fmt = f"{hrs_deep:.1f}h" if hrs_deep is not None else "n/a"
                # Highlight the clock(s) actually tripped, mute the OK one
                disc_style  = "color:#a51c30;font-weight:600;" if disc_stale else "color:#666;"
                if never_ds:
                    deep_style, deep_label = "color:#a51c30;font-weight:600;", "NEVER deep-scanned"
                elif deep_ds:
                    deep_style, deep_label = "color:#a51c30;font-weight:600;", f"{ls_fmt} ({hrs_deep_fmt})"
                else:
                    deep_style, deep_label = "color:#666;",                   f"{ls_fmt} ({hrs_deep_fmt})"
                stale_rows_parts.append(
                    f"<tr>"
                    f'<td style="padding:4px 12px 4px 0;font-family:monospace;font-size:12px;vertical-align:top;">{escape(aid)}</td>'
                    f'<td style="padding:4px 12px 4px 0;font-size:12px;{disc_style}vertical-align:top;">discovery: {escape(lo_fmt)} ({escape(hrs_disc_fmt)})</td>'
                    f'<td style="padding:4px 0;font-size:12px;{deep_style}vertical-align:top;">deep-scan: {escape(deep_label)}</td>'
                    f"</tr>"
                )
            stale_block = (
                '<div style="margin-top:8px;font-size:12px;color:#1a1a1a;">'
                f'<div style="font-weight:600;margin-bottom:4px;">Stale live assets '
                f'(discovery &gt; {discovery_stale_hours}h OR deep-scan &gt; {deepscan_stale_hours}h OR never deep-scanned):</div>'
                f'<table style="border-collapse:collapse;">{"".join(stale_rows_parts)}</table>'
                '<div style="margin-top:6px;color:#666;">Clock note: '
                '<em>discovery</em> = assets.last_observed (asm-discover.yml every 6h). '
                '<em>deep-scan</em> = asset_surface.last_seen (scanner.yml + per-sub loop). '
                'Red = tripped, grey = OK.</div>'
                '</div>'
            )
        watchdog_banner = (
            '<div style="background:#fde8eb;border:1px solid #a51c30;'
            'border-radius:6px;padding:12px 16px;margin:0 0 16px;">'
            '<div style="font-size:13px;font-weight:700;color:#a51c30;'
            'text-transform:uppercase;letter-spacing:0.8px;">'
            'Watchdog &mdash; pipeline integrity check</div>'
            f'{canary_block}{stale_block}'
            '</div>'
        )

    baseline_pill = (
        f'<span style="margin-right:12px;">CRITICAL: <strong>{baseline["critical_open"]}</strong></span>'
        f'<span style="margin-right:12px;">HIGH: <strong>{baseline["high_open"]}</strong></span>'
        f'<span style="margin-right:12px;">MOD-HIGH: <strong>{baseline["mod_high_open"]}</strong></span>'
        f'<span style="margin-right:12px;">MODERATE: <strong>{baseline["moderate_open"]}</strong></span>'
        f'<span>LOW: <strong>{baseline["low_open"]}</strong></span>'
    )

    return f"""<!DOCTYPE html>
<html><body style="font-family:-apple-system,Segoe UI,sans-serif;background:#f6f6f6;margin:0;padding:24px;color:#1a1a1a;">
<div style="max-width:780px;margin:0 auto;background:#fff;padding:32px;border-radius:8px;border:1px solid #e2e2e2;">
  <div style="border-bottom:1px solid #e2e2e2;padding-bottom:16px;margin-bottom:24px;">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:#888;">COMMANDsentry</div>
    <h1 style="margin:4px 0 0;font-size:22px;color:#1a1a1a;">Daily posture digest — {today}</h1>
    <div style="margin-top:6px;font-size:12px;color:#888;">Window: {win}</div>
  </div>

  <p style="font-size:14px;color:#333;margin:0 0 16px;">{headline}</p>

  {watchdog_banner}

  <div style="background:#fafafa;padding:12px 16px;border-radius:6px;font-size:12px;color:#555;margin-bottom:8px;">
    <div style="text-transform:uppercase;font-size:10px;letter-spacing:0.8px;color:#888;margin-bottom:4px;">Currently open across the fleet</div>
    {baseline_pill}
  </div>

  {confirmed_section}
  {regressed_section}
  {high_risk_section}
  {new_assets_section}
  {dark_assets_section}

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #e2e2e2;font-size:11px;color:#888;">
    <a href="{escape(dashboard_url)}" style="color:#888;">Open Supabase dashboard</a> ·
    Generated {window_end.strftime("%Y-%m-%d %H:%M UTC")} ·
    See <code>scripts/alerter/run_alerter.py</code> for source
  </div>
</div>
</body></html>"""


def render_text(
    *,
    window_start: datetime,
    window_end: datetime,
    confirmed: list[tuple],
    regressed: list[tuple],
    high_risk: list[tuple],
    new_assets: list[tuple],
    dark_assets: list[tuple],
    stale_assets: list[tuple],
    canary_violations: list[tuple],
    discovery_stale_hours: int,
    deepscan_stale_hours: int,
    baseline: dict,
) -> str:
    lines: list[str] = []
    lines.append(f"COMMANDsentry — Daily posture digest — {window_end:%Y-%m-%d}")
    lines.append(f"Window: {window_start:%Y-%m-%d %H:%M UTC} -> {window_end:%Y-%m-%d %H:%M UTC}")
    lines.append("")

    pipeline_degraded = bool(stale_assets or canary_violations)
    if pipeline_degraded:
        lines.append("!!! WATCHDOG — SCAN PIPELINE DEGRADED !!!")
        if canary_violations:
            lines.append(f"  CANARY VIOLATIONS ({len(canary_violations)}) — scope_verified apex/www not confirmed_live+owned:")
            for r in canary_violations:
                aid, st, own, lo = r
                lines.append(f"    {aid:<45} disc={st:<14} own={own}")
        if stale_assets:
            lines.append(
                f"  STALE LIVE ASSETS ({len(stale_assets)}) — discovery > {discovery_stale_hours}h "
                f"OR deep-scan > {deepscan_stale_hours}h OR never deep-scanned:"
            )
            for r in stale_assets:
                aid, lo, ls, hrs_disc, hrs_deep, disc_stale, never_ds, deep_ds = r
                lo_fmt = lo.strftime("%Y-%m-%d %H:%M UTC") if lo else "NEVER"
                hrs_disc_fmt = f"{hrs_disc:.1f}h" if hrs_disc is not None else "?"
                disc_marker = "!" if disc_stale else " "
                if never_ds:
                    deep_str = "!!NEVER deep-scanned"
                elif deep_ds:
                    ls_fmt = ls.strftime("%Y-%m-%d %H:%M UTC") if ls else "?"
                    hrs_deep_fmt = f"{hrs_deep:.1f}h" if hrs_deep is not None else "?"
                    deep_str = f"!{ls_fmt} ({hrs_deep_fmt})"
                else:
                    ls_fmt = ls.strftime("%Y-%m-%d %H:%M UTC") if ls else "n/a"
                    hrs_deep_fmt = f"{hrs_deep:.1f}h" if hrs_deep is not None else "n/a"
                    deep_str = f" {ls_fmt} ({hrs_deep_fmt})"
                lines.append(f"    {aid:<45} {disc_marker}disc={lo_fmt} ({hrs_disc_fmt})  deep={deep_str}")
        lines.append(
            "  Clock note: discovery=assets.last_observed (asm-discover every 6h). "
            "deep-scan=asset_surface.last_seen (scanner.yml + per-sub loop). "
            "'!' prefix = clock tripped."
        )
        lines.append("")

    lines.append(
        f"Currently open: CRITICAL={baseline['critical_open']}  HIGH={baseline['high_open']}  "
        f"MOD-HIGH={baseline['mod_high_open']}  MODERATE={baseline['moderate_open']}  "
        f"LOW={baseline['low_open']}"
    )
    lines.append("")

    if not (confirmed or regressed or high_risk or new_assets or dark_assets):
        if not pipeline_degraded:
            lines.append("No changes since last run — pipeline healthy.")
        return "\n".join(lines)

    if confirmed:
        lines.append(f"NEWLY CONFIRMED ({len(confirmed)}):")
        for r in confirmed:
            lines.append(f"  [{r[3]:<13}] {r[1]:<32} {r[2][:60]}  ({r[0]})")
        lines.append("")
    if regressed:
        lines.append(f"REGRESSED ({len(regressed)}):")
        for r in regressed:
            lines.append(f"  [{r[3]:<13}] {r[1]:<32} {r[2][:60]}  ({r[0]})")
        lines.append("")
    if high_risk:
        lines.append(f"ASSETS ELEVATED TO HIGH / CRITICAL ({len(high_risk)}):")
        for r in high_risk:
            reason = unescape(r[4] or "")
            lines.append(f"  [{r[3]:<13}] {r[0]:<40}  {reason}")
        lines.append("")
    if new_assets:
        lines.append(f"NEW ASSETS DISCOVERED ({len(new_assets)}):")
        for r in new_assets:
            risk = r[4] if r[4] and r[4] != "NONE" else "no-risk-yet"
            lines.append(f"  [{risk:<13}] {r[0]:<40}  ({r[3]:%Y-%m-%d %H:%M UTC})")
        lines.append("")
    if dark_assets:
        lines.append(f"ASSETS WENT DARK ({len(dark_assets)}):")
        for r in dark_assets:
            prev = r[4] if isinstance(r[4], dict) else {}
            last_seen = prev.get("last_seen", "unknown")
            lines.append(f"  {r[0]:<40}  last responded {last_seen}  (event {r[3]:%Y-%m-%d %H:%M UTC})")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SendGrid
# ---------------------------------------------------------------------------
#
# MIGRATED 2026-05-28 from Resend (Decision D-031). See Obsidian
# COMMANDsentry note 47 for the verification record + rationale. Same
# shape as the prior Resend function so the call site needs minimal edits.

def send_via_sendgrid(
    *,
    api_key: str,
    from_addr: str,
    from_name: str,
    to_addrs: list[str],
    subject: str,
    html: str,
    text: str,
) -> dict:
    """
    POST to SendGrid v3 /mail/send. Returns a dict shaped to look like the
    Resend response ({'id': ...}) so the call site doesn't have to special-
    case providers. SendGrid puts the message ID in the X-Message-Id
    response header rather than a JSON body; success is HTTP 202 Accepted
    with an empty body.
    """
    payload = {
        "personalizations": [
            {"to": [{"email": a} for a in to_addrs]},
        ],
        "from":    {"email": from_addr, "name": from_name},
        "subject": subject,
        "content": [
            # text/plain first so HTML clients pick the html alternative.
            {"type": "text/plain", "value": text},
            {"type": "text/html",  "value": html},
        ],
    }
    req = urllib.request.Request(
        url="https://api.sendgrid.com/v3/mail/send",
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            "User-Agent":    "COMMANDsentry-alerter/1.0 (+https://github.com/bklynhowster/commandsentry-asm)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # SendGrid returns 202 with empty body. Message ID is in
            # the X-Message-Id header.
            message_id = resp.headers.get("X-Message-Id") or ""
            return {"id": message_id, "status_code": resp.status}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"SendGrid HTTP {e.code}: {body[:500]}") from None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="render email but skip Resend + DB writes")
    args = ap.parse_args()

    dsn          = _env("SUPABASE_DSN", required=True)
    # Migrated 2026-05-28: RESEND_API_KEY → SENDGRID_API_KEY. Fall back to
    # the legacy var name during the transition so an unset SENDGRID_API_KEY
    # in CI doesn't break the digest before secrets are updated.
    api_key      = (
        _env("SENDGRID_API_KEY", required=False)
        or _env("RESEND_API_KEY", required=not args.dry_run)
        or ""
    )
    from_addr    = _env("ALERTER_FROM", default="CommandSentry@commandcompanies.com")
    from_name    = _env("ALERTER_FROM_NAME", default="COMMANDsentry")
    to_raw       = _env("ALERTER_TO",
                        default="hschneider@commandcompanies.com,howiehow@mac.com")
    to_addrs     = [a.strip() for a in (to_raw or "").split(",") if a.strip()]
    name         = _env("ALERTER_NAME", default="daily_digest") or "daily_digest"
    first_hours  = int(_env("ALERTER_FIRST_RUN_HOURS", default="24") or "24")
    dashboard_url= _env("ALERTER_DASHBOARD_URL",
                        default="https://supabase.com/dashboard/project/hdygktppfvuspnumpfuq")

    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            # Resolve the window
            cur.execute(SQL_LAST_WINDOW_END, (name,))
            row = cur.fetchone()
            last_end: datetime | None = row[0] if row else None
            window_end = datetime.now(tz=timezone.utc)
            window_start = last_end or (window_end - timedelta(hours=first_hours))

            # Open the run row early so we can finalize it in any branch
            run_id: int | None = None
            if not args.dry_run:
                cur.execute(SQL_INSERT_RUN_START, (name, window_start, window_end))
                run_id = cur.fetchone()[0]
                conn.commit()

            # Pull the changes
            cur.execute(SQL_NEW_CONFIRMED, (window_start, window_end))
            confirmed = cur.fetchall()
            cur.execute(SQL_REGRESSED, (window_start, window_end))
            regressed = cur.fetchall()

            # Live high-risk asset set + prior reported set for dedup
            cur.execute(SQL_HIGH_RISK_ASSETS_NOW)
            live_high_risk = cur.fetchall()
            cur.execute(SQL_PRIOR_HIGH_RISK_SET, (name,))
            prior_row = cur.fetchone()
            prior_set: set[str] = set(prior_row[0]) if prior_row and prior_row[0] else set()

            # Surface only newly-elevated assets in the digest
            high_risk = [r for r in live_high_risk if r[0] not in prior_set]
            # The snapshot we persist for next run's dedup = full current set
            current_high_risk_ids = sorted({r[0] for r in live_high_risk})

            cur.execute(SQL_OPEN_BASELINE)
            b = cur.fetchone()
            baseline = {
                "critical_open": b[0],
                "high_open":     b[1],
                "mod_high_open": b[2],
                "moderate_open": b[3],
                "low_open":      b[4],
            }

            # Asset-surface events in window (added 2026-06-07 — closes the
            # "0 chng while real-time emails fire" gap). Same Tier 2 gate as
            # dispatch_event_notifications: only confirmed_live + owned.
            cur.execute(SQL_NEW_ASSETS_IN_WINDOW, (window_start, window_end))
            new_assets = cur.fetchall()
            cur.execute(SQL_DARK_ASSETS_IN_WINDOW, (window_start, window_end))
            dark_assets = cur.fetchall()

            # Watchdog v1 — pipeline health checks (added 2026-06-07).
            # Two clocks, two thresholds, single alarm if EITHER is stale:
            #   ALERTER_DISCOVERY_STALE_HOURS (default 9h  = 6h cron + 3h)
            #   ALERTER_DEEPSCAN_STALE_HOURS  (default 168h = 7d, generous)
            # Per Howie 2026-06-07: a discovery-only check lets the
            # "discovery touched it but no deep scan ever ran" pattern
            # slip through silently (insite.sciimage.com — HIGH risk,
            # 73d since last deep-scan, would have gone invisible after
            # the next discovery run touched it).
            discovery_stale_hours = int(_env("ALERTER_DISCOVERY_STALE_HOURS", default="9") or "9")
            deepscan_stale_hours  = int(_env("ALERTER_DEEPSCAN_STALE_HOURS",  default="168") or "168")
            targets_yml = _env("ALERTER_TARGETS_YML", default="data/targets.yml") or "data/targets.yml"
            scope_apexes = load_scope_verified_apexes(targets_yml)

            stale_assets = []
            if scope_apexes:
                cur.execute(SQL_STALE_LIVE_ASSETS, {
                    "apexes": scope_apexes,
                    "disc_h": discovery_stale_hours,
                    "deep_h": deepscan_stale_hours,
                })
                stale_assets = cur.fetchall()

            canary_hosts = load_canary_hosts(targets_yml)
            canary_violations = []
            if canary_hosts:
                cur.execute(SQL_CANARY_VIOLATIONS, (canary_hosts,))
                canary_violations = cur.fetchall()

        # Render — subject line builds non-zero counters only so a quiet
        # night reads "(0 changes)" and a busy night reads
        # "(3 chng, 1 asset, 2 new, 1 dark)" without padding. Watchdog
        # hits (stale / canary) prepend "(!)" so the subject visibly
        # alerts even in inbox preview, AND show their counts first so
        # they're not buried.
        subject_parts: list[str] = []
        if (n := len(canary_violations)) > 0:
            subject_parts.append(f"{n} canary")
        if (n := len(stale_assets)) > 0:
            subject_parts.append(f"{n} stale")
        if (n := len(confirmed) + len(regressed)) > 0:
            subject_parts.append(f"{n} chng")
        if (n := len(high_risk)) > 0:
            subject_parts.append(f"{n} asset")
        if (n := len(new_assets)) > 0:
            subject_parts.append(f"{n} new")
        if (n := len(dark_assets)) > 0:
            subject_parts.append(f"{n} dark")
        subject_tail = ", ".join(subject_parts) if subject_parts else "0 changes"
        watchdog_prefix = "(!) " if (canary_violations or stale_assets) else ""
        subject = (
            f"[COMMANDsentry] {watchdog_prefix}Daily posture digest — "
            f"{window_end:%Y-%m-%d} ({subject_tail})"
        )
        html = render_html(
            window_start=window_start, window_end=window_end,
            confirmed=confirmed, regressed=regressed, high_risk=high_risk,
            new_assets=new_assets, dark_assets=dark_assets,
            stale_assets=stale_assets, canary_violations=canary_violations,
            discovery_stale_hours=discovery_stale_hours,
            deepscan_stale_hours=deepscan_stale_hours,
            baseline=baseline, dashboard_url=dashboard_url,
        )
        text = render_text(
            window_start=window_start, window_end=window_end,
            confirmed=confirmed, regressed=regressed, high_risk=high_risk,
            new_assets=new_assets, dark_assets=dark_assets,
            stale_assets=stale_assets, canary_violations=canary_violations,
            discovery_stale_hours=discovery_stale_hours,
            deepscan_stale_hours=deepscan_stale_hours,
            baseline=baseline,
        )

        if args.dry_run:
            print(">> DRY RUN — would send to:", ", ".join(to_addrs))
            print(">> Subject:", subject)
            print(">> From:", from_addr)
            print()
            print("===== PLAINTEXT =====")
            print(text)
            print()
            print("===== HTML (first 800 chars) =====")
            print(html[:800])
            print("... (truncated)")
            return 0

        # Send + finalize
        status = "success"
        err: str | None = None
        sent = False
        try:
            resp = send_via_sendgrid(
                api_key=api_key, from_addr=from_addr, from_name=from_name,
                to_addrs=to_addrs,
                subject=subject, html=html, text=text,
            )
            # SendGrid returns 202 with X-Message-Id header. Treat HTTP 202
            # as the success signal — message-id can be empty in rare cases
            # but the API accepted the request for delivery either way.
            sent = resp.get("status_code") == 202 or bool(resp.get("id"))
        except Exception as e:
            status = "error"
            err = str(e)[:1900]

        with conn.cursor() as cur:
            cur.execute(SQL_FINALIZE_RUN, (
                len(confirmed), len(regressed), len(high_risk),
                sent, status, err, current_high_risk_ids, run_id,
            ))
        conn.commit()

        if status == "error":
            print(f"alerter failed: {err}", file=sys.stderr)
            return 1
        print(f"alerter ok: confirmed={len(confirmed)} regressed={len(regressed)} high_risk={len(high_risk)} sent={sent}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
