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
  ALERTER_FROM       verified sender for THIS instance. NO DEFAULT.
  ALERTER_FROM_NAME  product display name, e.g. COMMANDsentry / PRODEXsentry.
                       NO DEFAULT — also used for the subject prefix, the
                       HTML footer and the plaintext header.
  ALERTER_TO         comma-separated recipient list. NO DEFAULT.

  These three had Command values as defaults, identically in BOTH scanner
  repos, so an unset env silently sent as/to the wrong tenant. Now unset =>
  the digest refuses to send and warns. Sending nothing beats sending another
  instance's posture from a Command address to a Command inbox.

Optional env vars:
  ALERTER_NAME             default 'daily_digest' — keys the runs table
  ALERTER_FIRST_RUN_HOURS  default 24 — how far back to look on the first
                           ever run (when there's no prior success row)
  ALERTER_PORTAL_URL       per-instance portal link (finding links + footer),
                           e.g. https://commandsentry-portal.netlify.app.
  ALERTER_DASHBOARD_URL    legacy Supabase dashboard link; used only when
                           ALERTER_PORTAL_URL is unset.

Usage:
  python3 run_alerter.py             # send email + record run
  python3 run_alerter.py --dry-run   # print body + skip Resend + skip DB write
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import mailer as _mailer  # noqa: E402 — shared provider-branching send path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "normalize"))
import block_page_signatures as _bps  # noqa: E402 — Obsidian 312: the block-page library
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import digest_daily as _dd  # noqa: E402 — KB 12 job 3l: the daily list (buckets, bar, email-safe HTML)
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

# DISTINCT ON (finding_id) — one row per finding per window (same observation-log
# fan-out as SQL_REGRESSED: a re-scanned asset would otherwise emit N identical
# CONFIRMED rows). Inner picks most-recent event; outer applies severity order.
SQL_NEW_CONFIRMED = """
SELECT finding_id, asset_id, title, severity, current_status, source,
       scan_id, event_at, alert_kind
FROM (
  SELECT DISTINCT ON (finding_id)
         finding_id, asset_id, title, severity, current_status, source,
         scan_id, event_at, alert_kind
  FROM v_alerter_changes
  WHERE event_at > %s
    AND event_at <= %s
    AND alert_kind IN ('CONFIRMED', 'CONFIRMED_HIGH')
  ORDER BY finding_id, event_at DESC
) d
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

# DISTINCT ON (finding_id) — collapse to ONE row per finding per window.
# v_alerter_changes derives from finding_history, which is an OBSERVATION log
# (one row per scan per finding), so an asset scanned N times in a window emits
# N identical REGRESSED rows. The 2026-07-11 digest showed the same
# unimacgraphics.com OCSP_stapling finding 4x (4 heavy re-scans overnight).
# Dedup keeps the most-recent event per finding; outer query preserves display
# order. NOTE: does NOT fix the upstream "regressed re-stamped every scan"
# mislabel (see spec/backlog) — that's an alerter-semantics change for 4.7.
SQL_REGRESSED = """
SELECT finding_id, asset_id, title, severity, current_status, source,
       scan_id, event_at, alert_kind
FROM (
  SELECT DISTINCT ON (finding_id)
         finding_id, asset_id, title, severity, current_status, source,
         scan_id, event_at, alert_kind
  FROM v_alerter_changes
  WHERE event_at > %s
    AND event_at <= %s
    AND alert_kind = 'REGRESSED'
  ORDER BY finding_id, event_at DESC
) d
ORDER BY asset_id, finding_id;
"""

# ---------------------------------------------------------------------------
# NEW findings in the window — added 2026-09-14 (relay 133, rule 9).
#
# ⛔ THE DEFECT THIS CLOSES. The digest's "finding change(s)" number was
# len(confirmed) + len(regressed), both of which read v_alerter_changes. That
# view's outer WHERE (20260711b_...sql:89) admits ONLY rows whose status is
# 'regressed', 'confirmed' or 'open'. A brand-new finding is inserted with
# current_status = 'detected' (run_medium.py:4578, run_light.py:2769) and the
# ON CONFLICT ... ELSE 'detected' branch re-writes 'detected' on every
# re-observation, so it never leaves that state on its own. finding_history
# stamps the FINAL current_status, so the row enters the view NEVER.
#
# The digest was therefore counting TRANSITIONS BETWEEN EXISTING STATES and was
# structurally blind to creation. Measured on the 2026-09-13 15:24 → 2026-09-14
# 17:20 window: 65 findings created, all 65 'detected', 0 rows in
# v_alerter_changes for the entire window. The email said "0 finding change(s)".
#
# This query is the definition 4.7 named in relay 133: creation, read from the
# findings table itself, not inferred from a transition log. It is ADDITIVE —
# the confirmed/regressed queries are untouched, so no existing number moves.
# The headline now names both quantities separately instead of letting one
# stand in for the other.
#
# Same Tier 2 gate as every other digest query: owned + confirmed_live only.
SQL_NEW_FINDINGS_IN_WINDOW = """
SELECT f.finding_id, f.asset_id, f.title, f.severity, f.current_status,
       f.source, f.first_detected_at
FROM findings f
JOIN assets a ON a.asset_id = f.asset_id
WHERE f.first_detected_at >  %s
  AND f.first_detected_at <= %s
  AND a.ownership = 'owned'
  AND a.discovery_status = 'confirmed_live'
ORDER BY
  CASE f.severity
    WHEN 'CRITICAL'      THEN 1
    WHEN 'HIGH'          THEN 2
    WHEN 'MODERATE-HIGH' THEN 3
    WHEN 'MODERATE'      THEN 4
    WHEN 'LOW'           THEN 5
    WHEN 'INFO'          THEN 6
  END,
  f.asset_id, f.finding_id;
"""

# D-031 — the asset block's device class. ⚠ READ FROM device_class_dryrun, the
# LATEST row per asset, because `--write` is still off on both instances: the label
# is a dry-run classification and the digest says so rather than implying it is live.
# A retired asset is excluded from classify entirely (relay 285), so it simply has no
# row here and gets no class line — which is the honest answer, not "unknown".
SQL_ASSET_DEVICE_CLASS = """
SELECT DISTINCT ON (d.asset_id)
       d.asset_id, d.device_class, d.confidence, d.vendor_product
FROM public.device_class_dryrun d
JOIN assets a ON a.asset_id = d.asset_id
WHERE a.ownership = 'owned'
ORDER BY d.asset_id, d.evaluated_at DESC;
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

SQL_OPEN_POSTURE = """
-- Note 307 (2026-10-13): "currently open" counts PROBLEMS the way the portal's
-- dashboard does, not finding rows. Until push-307c this was COUNT(*) over
-- findings on owned+confirmed_live assets, which printed HIGH 23 on a day the
-- dashboard said 6: Slider Revolution on 3 sites was 13 rows (apex + www, one
-- row per advisory), and findings nobody had seen in weeks counted the same
-- as fresh ones.
--
-- v_fleet_open_reps (migration 20261013a) is the dashboard's rule in SQL: the
-- portal's scope (owned, not ghost/dark/retired, unverified only for IP and
-- range markers), apex + www merged into one site, the portal's dedup key
-- inside a site, v_open_findings_dedup rows elsewhere. One row per problem.
--
-- "stale" = no scan has seen the problem for 30+ days. The dashboard softens
-- those; the digest says how many there are so the headline number is read
-- for what it is.
SELECT severity::text,
       count(*)                                                                 AS open_now,
       count(*) FILTER (WHERE last_observed_at < now() - interval '30 days')     AS stale_30d
FROM public.v_fleet_open_reps
GROUP BY severity;
"""

# Note 307 — "fixed this period" replaces the "status change(s)" counter. That
# counter read v_alerter_changes, which only ever yields confirmed / regressed
# / open transitions; the scanners write 'detected' and people mark things
# 'remediated', so it printed 0 on the day the Next.js CRITICAL was fixed.
# remediated_at is stamped by the portal's "mark remediated" and by the
# scanner's own closure path, so it is the honest "fixed" clock.
SQL_FIXED_IN_WINDOW = """
SELECT f.finding_id, f.asset_id, f.title, f.severity, f.current_status, f.source,
       f.remediated_at
FROM findings f
JOIN assets a ON a.asset_id = f.asset_id
WHERE f.remediated_at >  %s
  AND f.remediated_at <= %s
  AND f.current_status IN ('remediated', 'validated_remediated')
  AND a.ownership = 'owned'
ORDER BY
  CASE f.severity
    WHEN 'CRITICAL'      THEN 1
    WHEN 'HIGH'          THEN 2
    WHEN 'MODERATE-HIGH' THEN 3
    WHEN 'MODERATE'      THEN 4
    WHEN 'LOW'           THEN 5
    WHEN 'INFO'          THEN 6
  END,
  f.asset_id, f.finding_id;
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
  -- ⛔ THE ASSET MUST ACTUALLY BE NEW. Added 2026-09-14, CORRECTED same night
  -- (relay 133 ask 2 / relay 137). This is the load-bearing predicate; the
  -- NOT EXISTS below is only a de-duplicator.
  --
  -- 4.7 wrote the rule in 133: "Either it reads first_observed (and the label
  -- is true) or the label changes to what it measures. No third option."
  -- I shipped a third option first — a NOT EXISTS over earlier
  -- asset_first_seen rows — and executing it against live data showed it
  -- suppressing only 5 of the 14 false announcements. The other 9 survived,
  -- because asset_surface_event only has history back to when its writer went
  -- live (~2026-05-26); an asset first observed BEFORE that has no
  -- asset_first_seen row at all, so "no earlier event" is trivially true while
  -- the asset is four months old.
  --
  -- ⇒ The event-log test asks what the LOG remembers. The label claims
  -- something about the ASSET. Measured on 2026-09-13 15:24 -> 09-14 17:20:
  --     old digest                                   14
  --     NOT EXISTS over earlier events (wrong)         9   still false
  --     assets.first_observed inside the window        0   correct — none were new
  -- Same failure shape as defect ① in this file: reading a derived log
  -- instead of the fact. NULL first_observed is excluded by the comparison,
  -- which is right — an asset with no known first sighting is not evidence of
  -- a new one.
  AND a.first_observed >  %s
  AND a.first_observed <= %s
  -- De-duplication only, NOT the newness test. Two producers can both emit
  -- asset_first_seen for a genuinely new asset inside one window; without this
  -- the panel lists it twice. Keep both predicates: the one above decides
  -- WHETHER the asset is new, this one decides HOW MANY ROWS it gets.
  --
  -- ⛔ FIRST-EVER, NOT FIRST-PER-PRODUCER. Added 2026-09-14 (relay 133).
  --
  -- surface_diff.py:120-138 emits asset_first_seen when "existing_blob is None
  -- (this producer never saw the asset)". That is deliberately PER-PRODUCER —
  -- it is the right semantic for the surface diff, which reasons about one
  -- producer's view. It is the WRONG semantic for a human-facing panel titled
  -- "New assets discovered", which claims first-ever discovery.
  --
  -- The two only agreed while asm_cron was the sole producer. The light-tier
  -- surface write-back (mine, live 2026-09-09T11:53) added a second producer,
  -- and every asset it touches for the first time emits asset_first_seen on an
  -- asset the fleet has known for months. Measured on the 2026-09-13 →
  -- 09-14 window: 14 events, ALL source_tag='scanner_light', assets.first_observed
  -- ranging 2026-03-27 .. 2026-07-19. Not one was new. Corpus check: 45
  -- scanner_light asset_first_seen rows all time, earliest 2026-09-09T11:53 —
  -- zero before the write-back shipped. The producer is the cause.
  --
  -- This predicate does not touch the writer: the per-producer events stay in
  -- asset_surface_event as the audit trail, exactly as the namesake/ct_ghost
  -- rows above do. It only stops the DIGEST from restating a producer's first
  -- look as the fleet's first sighting.
  AND NOT EXISTS (
    SELECT 1 FROM public.asset_surface_event e0
    WHERE e0.asset_id   = e.asset_id
      AND e0.event_type = 'asset_first_seen'
      AND e0.observed_at < e.observed_at
  )
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
# Assets back online — added 2026-10-10 (note 307).
#
# The digest announced "went dark" and then never said another word about
# the asset. pm.unimacgraphics.com was reported dark on 10-05 and showed up
# with new findings on 10-10 — the email never said it had come back, so the
# reader was left holding two statements that cannot both be true.
#
# DEFINITION: the asset's most recent asset_went_dark event (last 30 days),
# and the FIRST liveness verdict after it in which the host answered, from
# any route (the direct sweep or the VPN re-check). It is reported in the
# window that contains that first answer — once, never again.
#
# Same Tier 2 gate as the dark query (owned + confirmed_live), so a host the
# digest could call dark is a host it can call back.
#
# ⚠ THE WINDOW IS SHIFTED BACK 30 MINUTES (independent review, 2026-10-10).
# A verdict's probed_at is the time its transaction STARTED; it is committed
# minutes later. The discovery sweep and this digest both fire at 12:00 UTC,
# so an answer stamped 12:05 and committed 12:09 is invisible to a digest
# reading at 12:08, and would fall outside the next digest's window: lost.
# Shifted windows still tile with no gap and no overlap, so each comeback is
# reported exactly once, at most 30 minutes late.
#
# Placeholders, in order: window_end, window_end, window_start, window_end.
# (No percent signs in these comments: psycopg would read them as params.)
# ---------------------------------------------------------------------------
SQL_CAME_BACK_IN_WINDOW = """
WITH last_dark AS (
  SELECT DISTINCT ON (e.asset_id) e.asset_id, e.observed_at AS dark_at
    FROM public.asset_surface_event e
   WHERE e.event_type = 'asset_went_dark'
     AND e.observed_at <= %s
     AND e.observed_at >  %s - interval '30 days'
   ORDER BY e.asset_id, e.observed_at DESC
), back AS (
  SELECT d.asset_id, d.dark_at,
         (SELECT min(v.probed_at)
            FROM public.asset_liveness_verdict v
           WHERE v.asset_id = d.asset_id
             AND v.any_port_responded
             AND v.probed_at > d.dark_at) AS back_at
    FROM last_dark d
)
SELECT b.asset_id, a.name, a.organization, b.back_at, b.dark_at
  FROM back b
  JOIN public.assets a ON a.asset_id = b.asset_id
 WHERE b.back_at >  %s - interval '30 minutes'
   AND b.back_at <= %s - interval '30 minutes'
   AND a.ownership = 'owned'
   AND a.discovery_status = 'confirmed_live'
 ORDER BY b.back_at DESC, b.asset_id;
"""

# ---------------------------------------------------------------------------
# Security device enforcement flips — added 2026-10-13 (Obsidian 310).
#
# uat.prodexlabs.com: on 10-12 the heavy tier's differential probe measured
# every attack-payload class passing straight through; on 10-13 it measured
# all of them blocked behind a Google 403 page. The scanner saw the device
# come on within a day and the email said nothing. The only trace was a chip
# on the asset page.
#
# DEFINITION: for each asset, every MEASUREMENT of the differential probe
# (stack_id_waf_differential with a non-null verdict; null = the probe did
# not fire, which is not a measurement), ordered by scan completion. A row is
# reported when its verdict differs from the previous measurement, or when it
# is the asset's first measurement and it is a block. A first-ever
# pass-through is NOT reported here: that is the "No enforcing WAF" (MODERATE since 3b)
# finding's job, and it is already in the new-problems section. Each flip is
# reported once, in the window holding the measurement.
#
# Presence-only, like the probe: it says BLOCKED or PASSED THROUGH and names
# no product. The classifier and the asset page carry the vendor name.
#
# Same gate as dark/back (owned + confirmed_live). Same 30-minute shift as
# the comeback query: the artifact commits at the scan's close-out.
# Placeholders, in order: window_start, window_end.
# (No percent signs in these comments: psycopg would read them as params.)
# ---------------------------------------------------------------------------
SQL_ENFORCEMENT_FLIPS_IN_WINDOW = """
WITH m AS (
  SELECT r.asset_id,
         r.completed_at AS measured_at,
         (a.content_jsonb->>'waf_present_differential')::boolean AS blocked,
         a.content_jsonb->'blocked' AS classes
    FROM public.scan_run_artifacts a
    JOIN public.scan_run r ON r.scan_run_id = a.scan_run_id
   WHERE a.tool_name = 'stack_id_waf_differential'
     AND r.status::text = 'complete'
     AND r.completed_at IS NOT NULL
     AND a.content_jsonb->>'waf_present_differential' IS NOT NULL
), ordered AS (
  SELECT m.*,
         lag(m.blocked)     OVER (PARTITION BY m.asset_id ORDER BY m.measured_at) AS prev_blocked,
         lag(m.measured_at) OVER (PARTITION BY m.asset_id ORDER BY m.measured_at) AS prev_at
    FROM m
)
SELECT o.asset_id, a.name, a.organization, o.measured_at, o.blocked,
       o.prev_blocked, o.prev_at, o.classes
  FROM ordered o
  JOIN public.assets a ON a.asset_id = o.asset_id
 WHERE o.measured_at >  %s - interval '30 minutes'
   AND o.measured_at <= %s - interval '30 minutes'
   AND o.prev_blocked IS DISTINCT FROM o.blocked
   AND (o.blocked OR o.prev_blocked IS NOT NULL)
   AND a.ownership = 'owned'
   AND a.discovery_status = 'confirmed_live'
 ORDER BY o.measured_at DESC, o.asset_id;
"""

# ---------------------------------------------------------------------------
# Unrecognized block pages — added 2026-10-14 (Obsidian 312).
#
# Howie, 2026-10-13: "What if there's a Palo Alto in front of us or a Cisco …"
# The heavy differential probe captures every deny page it receives. The
# block-page library (scripts/normalize/block_page_signatures.py, cited entries
# in artifact_signatures.yaml) names the vendor when the page names itself. When
# a measured block's deny pages match NOTHING in the library, the device is real
# and unnamed — and the right thing is to say so, once, and keep the page: this
# query returns every MEASURED BLOCK in the window with its captured deny
# responses; the Python side runs the library over them and reports the ones
# nobody recognized. Same window shift and ownership gate as the flips above.
# Placeholders, in order: window_start, window_end.
# ---------------------------------------------------------------------------
SQL_MEASURED_BLOCKS_IN_WINDOW = """
SELECT r.asset_id, a.name, a.organization, r.completed_at AS measured_at,
       art.content_jsonb->'details'->'fired' AS fired
  FROM public.scan_run_artifacts art
  JOIN public.scan_run r ON r.scan_run_id = art.scan_run_id
  JOIN public.assets a ON a.asset_id = r.asset_id
 WHERE art.tool_name = 'stack_id_waf_differential'
   AND r.status::text = 'complete'
   AND r.completed_at IS NOT NULL
   AND (art.content_jsonb->>'waf_present_differential')::boolean IS TRUE
   AND r.completed_at >  %s - interval '30 minutes'
   AND r.completed_at <= %s - interval '30 minutes'
   AND a.ownership = 'owned'
   AND a.discovery_status = 'confirmed_live'
 ORDER BY r.completed_at DESC, r.asset_id;
"""


def unrecognized_block_pages(rows: list[tuple]) -> list[tuple]:
    """Rows from SQL_MEASURED_BLOCKS_IN_WINDOW -> the measured blocks whose captured deny
    pages matched NO library entry: (asset_id, name, organization, measured_at,
    [{cls, status, size}, ...]). A block where at least one page named its vendor is
    not reported here — that name went to the classifier. A block whose denies carried
    no readable body (nothing captured) is not reported either: there is no page to add.

    ⛔ 316 (2026-10-14). The Command digest of 10-14 12:08Z CRASHED here, in 6 seconds:
    the first morning with a measured block inside the window (the apex, 09:13Z) was
    the first time this ran for real, and the digest job installs psycopg only — the
    library reads artifact_signatures.yaml with PyYAML, which was not there. No email
    went out. The job now installs PyYAML (alerter.yml); AND this section can never
    take the digest down again: the library is loaded ONCE, up front, and if it cannot
    be, the section is skipped with one log line and the rest of the email is sent.
    A side section's failure is not a reason to send nothing."""
    out = []
    if not rows:
        return out
    try:
        entries = _bps.load_block_page_entries()
    except Exception as e:  # PyYAML missing, the YAML unreadable, an entry malformed
        print(f"[alerter] block-page library unavailable ({type(e).__name__}: {e}); "
              f"'Block pages not recognized' skipped this run", file=sys.stderr)
        return out
    seen: set = set()
    for r in rows:                      # ordered newest first: one line per asset, its newest block
        if r[0] in seen:
            continue
        seen.add(r[0])
        fired = r[4]
        if isinstance(fired, str):
            try:
                fired = json.loads(fired)
            except ValueError:
                fired = None
        res = _bps.scan_fired(fired if isinstance(fired, list) else [], entries)
        if res["matched"] or not res["unrecognized"]:
            continue
        out.append((r[0], r[1], r[2], r[3], res["unrecognized"]))
    return out


def unrecognized_words(denies: list[dict]) -> str:
    """'HTTP 403 x3, about 134 B' — the shape of the pages nobody recognized."""
    by: dict = {}
    for d in denies:
        by.setdefault(d.get("status"), []).append(d.get("size") or 0)
    parts = []
    for status, sizes in sorted(by.items(), key=lambda kv: str(kv[0])):
        n = len(sizes)
        avg = int(sum(sizes) / n) if n else 0
        parts.append(f"HTTP {status}" + (f" x{n}" if n > 1 else "") + (f", about {avg:,} B" if avg else ""))
    return "; ".join(parts)

# ---------------------------------------------------------------------------
# Watchdog v1 — internal pipeline health checks (added 2026-06-07)
#
# Two checks because they catch DIFFERENT failure classes:
#
#   1. STALENESS (per-asset on the DISCOVERY clock = assets.last_observed):
#      finds confirmed_live + owned assets whose last_observed has aged
#      past the discovery cadence threshold (default 24h since 321; was
#      9h = 6h cron + 3h grace). LEFT JOIN to asset_surface so we can show last_seen
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
# 321 (2026-10-16) — the FULL-SCAN leg reads public.scan_run (newest complete or degraded
# run), NOT asset_surface.last_seen. The discovery importer upserts asset_surface.last_seen
# on every 6-hourly pass, so that column moved with discovery and "no full scan in 7 days"
# could never fire for a host discovery kept seeing. Howie, 2026-10-16, on ns02.sciimage.com
# printed as "last full scan Oct 16" (its last real scan: 2026-08-27): "To me, it looks like
# an impossibility." Hosts marked assets.not_web_scannable (the nameservers, skipped by the
# weekly sweep on purpose since 4.7 ruling 74) are not counted as behind on full scans, and
# a host known for less than the full-scan window is not overdue for its first one yet.
#
# Per Howie 2026-06-07: a global MAX(last_observed) would have missed
# both the partial-cron-stop and the demotion bug. Two narrow checks
# beat one wide check.
# ---------------------------------------------------------------------------

SQL_STALE_LIVE_ASSETS = """
-- Per-asset check on BOTH clocks. An asset is listed if EITHER clock is overdue.
--
-- Why both: a one-clock check would let "discovery happened but no full scan ever ran"
-- slip through silently — exactly the insite.sciimage.com pattern (HIGH-risk finding,
-- asset present in DB, NEVER deep-scanned by this pipeline). Per Howie 2026-06-07:
-- "the thing that surfaced the gap stops surfacing it without the gap being closed."
--
-- Clocks:
--   seen       = GREATEST(assets.last_observed, assets.last_probe_alive_at)
--                last_observed is asm-discover (6h cron); last_probe_alive_at is the
--                liveness probe (Obsidian 161 / 4.7 Q6). Migration 20260724a: "freshness
--                consumers compose (last_observed OR last_probe_alive_at)". 320: a host the
--                probe proved alive is not a host we lost sight of. seen_via names the winner.
--   full scan  = newest public.scan_run with status complete or degraded (321).
--                NOT asset_surface.last_seen: import_asm_to_surface.py upserts that column
--                on every discovery pass, so it moved with discovery (ns02.sciimage.com read
--                "last full scan Oct 16" on 2026-10-16; its last real scan was 2026-08-27).
--                Degraded counts, as in enqueue-fleet.yml: a degraded run still collected
--                and persisted findings. Failed and running do not.
--
-- Not counted as behind on full scans:
--   * assets.not_web_scannable: skipped by the weekly sweep on purpose (4.7 ruling 74,
--     the nameservers). Still listed if we stop SEEING them; the row says why there is
--     no recent full scan (skipped = true).
--   * a host known for less than the full-scan window (first_observed, else created_at)
--     that has not had its first full scan yet: it is not overdue yet.
--
-- Thresholds passed in by caller; defaults are 24h seen (321: a nameserver an outside
-- source lists about 2 passes in 3 was flagged at 9h) and 192h full scan (321: 8 days.
-- The weekly sweep rescans a host once its last scan is older than 7 days, so on-schedule
-- rescans land just past 168h: measured over 45 days, median 168.2h, 97 in 100 within 170h,
-- Command and Prodex alike. At 168h every host on schedule would read "behind" for an
-- hour or two each week. One day of grace.)
--
-- IMPORTANT: scoped to assets whose apex_domain is in the scope_verified allowlist.
-- Without that scope, manually-added or non-scope_verified assets (commandmi.com,
-- edelivery-bessemer.com, netlify.app) would false-positive forever.
--
-- Columns 0-8 keep their 320 positions (the renderers index 5, 6 and 7); 9 is new.
-- deep_scan_last_seen / hours_since_deep_scan now carry the scan_run clock.
WITH c AS (
  SELECT a.asset_id,
         a.last_observed,
         a.last_probe_alive_at,
         GREATEST(a.last_observed, a.last_probe_alive_at)        AS seen_at,
         CASE WHEN a.last_probe_alive_at IS NOT NULL
               AND (a.last_observed IS NULL OR a.last_probe_alive_at > a.last_observed)
              THEN 'probe' ELSE 'discovery' END                  AS seen_via,
         COALESCE(a.not_web_scannable, false)                    AS skipped,
         COALESCE(a.first_observed, a.created_at)                AS known_since,
         (SELECT max(r.completed_at)
            FROM public.scan_run r
           WHERE r.asset_id = a.asset_id
             AND r.status IN ('complete', 'degraded'))           AS scanned_at
  FROM public.assets a
  WHERE a.ownership = 'owned'
    AND a.discovery_status = 'confirmed_live'
    AND a.apex_domain = ANY(%(apexes)s)
), f AS (
  SELECT c.*,
         (c.seen_at IS NULL OR c.seen_at < (now() - (%(disc_h)s::int * interval '1 hour')))   AS discovery_stale,
         (NOT c.skipped AND c.scanned_at IS NULL
          AND (c.known_since IS NULL
               OR c.known_since < (now() - (%(deep_h)s::int * interval '1 hour'))))            AS never_scanned,
         (NOT c.skipped AND c.scanned_at IS NOT NULL
          AND c.scanned_at < (now() - (%(deep_h)s::int * interval '1 hour')))                  AS scan_stale
  FROM c
)
SELECT
  f.asset_id,
  f.seen_at                                                AS last_observed,
  f.scanned_at                                             AS deep_scan_last_seen,
  EXTRACT(EPOCH FROM (now() - f.seen_at))/3600.0           AS hours_since_discovery,
  EXTRACT(EPOCH FROM (now() - f.scanned_at))/3600.0        AS hours_since_deep_scan,
  f.discovery_stale,
  f.never_scanned                                          AS never_deep_scanned,
  f.scan_stale                                             AS deep_scan_stale,
  f.seen_via,
  f.skipped
FROM f
WHERE f.discovery_stale OR f.never_scanned OR f.scan_stale
ORDER BY
  -- Worst cases first: never fully scanned, then the oldest sighting
  f.never_scanned DESC,
  f.seen_at NULLS FIRST,
  f.asset_id;
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

# ---------------------------------------------------------------------------
# KB 12 job 3l (2026-10-22) — four small reads for the daily list. Each is read in
# its own savepoint and FAILS SOFT: without it the email loses one decoration, never
# the send. Same gate as every digest query: owned + confirmed_live.
# ---------------------------------------------------------------------------

# Every live site's rating now (assets.current_risk) and at the window's start, rebuilt
# from findings: since job 3m a rating IS the worst open finding, so the past one is the
# worst finding open at that moment, INFO ignored. Closed for good (no clock of its own,
# so never counted): false_positive, wont_fix, accepted_risk, closed_reclassified,
# detector_retired — the same closed set v_open_findings_dedup uses. Remediated ones count
# until their remediated_at. Builder, 2026-10-22 16:15 ET, the rebuild at now() against
# assets.current_risk: Command 51 of 51 equal, Prodex 29 of 29 (with false_positive alone
# the four nameservers read MODERATE against UNKNOWN — the retired-detector rows).
# ever_found splits "not rated": never scanned vs everything resolved.
SQL_SITE_RATINGS = """
SELECT a.asset_id,
       a.current_risk::text,
       EXISTS (SELECT 1 FROM public.findings f0 WHERE f0.asset_id = a.asset_id) AS ever_found,
       (SELECT f.severity::text
          FROM public.findings f
         WHERE f.asset_id = a.asset_id
           AND f.current_status::text NOT IN ('false_positive', 'wont_fix', 'accepted_risk',
                                              'closed_reclassified', 'detector_retired')
           AND NOT (f.current_status::text IN ('remediated', 'validated_remediated')
                    AND f.remediated_at IS NULL)
           AND f.severity::text <> 'INFO'
           AND f.first_detected_at <= %(t)s
           AND (f.remediated_at IS NULL OR f.remediated_at > %(t)s)
         ORDER BY CASE f.severity::text WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                  WHEN 'MODERATE-HIGH' THEN 3 WHEN 'MODERATE' THEN 4 ELSE 5 END
         LIMIT 1) AS rating_then
  FROM public.assets a
 WHERE a.ownership = 'owned'
   AND a.discovery_status = 'confirmed_live'
 ORDER BY a.asset_id
"""

# Certificates about to expire: the newest open "TLS certificate expiring soon — expires
# < N days (k)" per host. The digest works out today's days-left from k and when the
# check last looked. ⛔ ONLY WHILE THE LATEST DEEP SCAN STILL SEES IT: the certificate
# check runs in the deep scan (testssl), and a renewed certificate leaves its old warning
# open — commandcompanies.com's "< 30 days (28)" was last seen 2026-09-22 and four deep
# scans since (Oct 3, 10, 14, 22) never repeated it; the first render of this digest
# called it "expired". A deep scan finished after the warning's last sighting retires it
# here (10 minutes of slack: the observing scan finishes when it writes the finding).
SQL_CERTS_EXPIRING = """
SELECT DISTINCT ON (f.asset_id) f.asset_id, f.title, f.last_observed_at
  FROM public.findings f
  JOIN public.assets a ON a.asset_id = f.asset_id
 WHERE a.ownership = 'owned'
   AND a.discovery_status = 'confirmed_live'
   AND f.current_status::text IN ('detected', 'confirmed', 'open', 'regressed')
   AND position('TLS certificate expiring soon' in f.title) = 1
   AND f.last_observed_at IS NOT NULL
   AND NOT EXISTS (
         SELECT 1 FROM public.scan_run r
          WHERE r.asset_id = f.asset_id
            AND r.intensity::text = 'heavy'
            AND r.status::text IN ('complete', 'degraded')
            AND r.completed_at > f.last_observed_at + interval '10 minutes')
 ORDER BY f.asset_id, f.last_observed_at DESC
"""

# Each listed host's previous finished deep scan before the window — for "its first deep
# scan since Jul 23" (the 10-22 question: why do long-scanned boxes have "new" findings).
SQL_PREV_DEEP_SCANS = """
SELECT ids.asset_id,
       (SELECT max(r.completed_at)
          FROM public.scan_run r
         WHERE r.asset_id = ids.asset_id
           AND r.intensity::text = 'heavy'
           AND r.status::text IN ('complete', 'degraded')
           AND r.completed_at < %s) AS prev_deep
  FROM unnest(%s::text[]) AS ids(asset_id)
"""

# The first remediation step of each listed finding, for the item's "Do:" line.
SQL_FINDING_HINTS = """
SELECT finding_id, remediation FROM public.findings WHERE finding_id = ANY(%s::text[])
"""

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


# Note 307 — INFO is inventory (headers seen, technologies seen, paths that
# exist), not a problem. The headline counts problems; inventory gets its own
# number so it is neither hidden nor mistaken for risk. Element 3 of every
# finding row is severity (SQL_NEW_FINDINGS_IN_WINDOW, SQL_NEW_CONFIRMED,
# SQL_REGRESSED, SQL_FIXED_IN_WINDOW all select it fourth).
def split_problems_inventory(rows: list[tuple]) -> tuple[list[tuple], list[tuple]]:
    problems = [r for r in rows if (r[3] if len(r) > 3 else None) != "INFO"]
    inventory = [r for r in rows if (r[3] if len(r) > 3 else None) == "INFO"]
    return problems, inventory


def posture_from_rows(rows: list[tuple]) -> dict:
    """SQL_OPEN_POSTURE rows (severity, open_now, stale_30d) -> the digest's baseline dict.

    Every key is present even when a severity has no row, so the renderers never KeyError
    on a quiet fleet. problems_* exclude INFO; info_* is inventory on its own."""
    by = {str(sev): (int(n or 0), int(st or 0)) for sev, n, st in rows}
    get = lambda k: by.get(k, (0, 0))  # noqa: E731
    out = {
        "critical_open": get("CRITICAL")[0],
        "high_open":     get("HIGH")[0],
        "mod_high_open": get("MODERATE-HIGH")[0],
        "moderate_open": get("MODERATE")[0],
        "low_open":      get("LOW")[0],
        "info_open":     get("INFO")[0],
    }
    out["problems_open"] = (out["critical_open"] + out["high_open"] + out["mod_high_open"]
                            + out["moderate_open"] + out["low_open"])
    out["problems_stale_30d"] = sum(get(k)[1] for k in ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW"))
    out["info_stale_30d"] = get("INFO")[1]
    return out


def _count_overlap(new_findings, confirmed, regressed) -> int:
    """How many findings appear in BOTH the creation count and the transition count.

    ⛔ THE TWO NUMBERS ARE NOT ADDABLE, and the overlap is large — not a corner
    case. A finding is created 'detected'; if it is re-observed and settles to
    'confirmed' before the window closes, it is BOTH new AND a status change,
    and it is counted once in each. Measured over the most recent 1000
    v_alerter_changes rows (2026-09-14): 254 of 570 transition events — 44.6% —
    fired within 24h of their finding's creation, i.e. inside one typical
    digest window.

    A reader who adds "N new + M status changes" therefore over-counts by
    roughly the size of this intersection. Rather than disclaim that vaguely,
    the digest states the intersection, so the arithmetic is reconcilable:
    distinct findings touched = N + M - overlap.

    Element 0 of every row is finding_id (SQL_NEW_FINDINGS_IN_WINDOW,
    SQL_NEW_CONFIRMED and SQL_REGRESSED all select it first). Guarded so a
    future column reorder degrades to 0 rather than to a wrong number.
    """
    try:
        created = {r[0] for r in new_findings}
        changed = {r[0] for r in confirmed} | {r[0] for r in regressed}
    except (IndexError, TypeError):
        return 0
    return len(created & changed)


# ══ 152 PUSH 2 — THE RENDER HALF (P1-P5 + D-031). Relay 304 ══════════════════
# Howie's words on digest #130: "formatting is kind of crappy". Every finding was
# real and every count was true — and bcbsma appeared SIXTEEN TIMES because the
# table repeated the asset on every row. These helpers are PURE so the layout is
# testable without matching HTML strings: the bug in a digest is almost never a
# broken tag, it is a decision about what to group, merge, collapse or say.

_SEV_ORDER = {"CRITICAL": 1, "HIGH": 2, "MODERATE-HIGH": 3,
              "MODERATE": 4, "LOW": 5, "INFO": 6}

# D-031: what produced this finding, in words a reader can act on. `source` is the
# finding's own enum — never guessed from the title.
_TIER_LABEL = {
    "light": "light scan", "medium": "medium scan", "heavy": "deep scan",
    "asm": "discovery", "importer": "discovery",
}


def scan_tier_label(source: str | None) -> str:
    """D-031: the tier that produced a finding, in English.

    ⚠ READ FROM `source`, NEVER INFERRED FROM THE TITLE. A title is prose; the
    source column is the fact. Unknown sources render as the raw value rather than
    a guess — "unknown" in a digest is information, an invented tier is not."""
    if not source:
        return "unknown tier"
    key = str(source).strip().lower()
    for prefix, label in _TIER_LABEL.items():
        if key == prefix or key.startswith(prefix + "_") or key.startswith(prefix + "-"):
            return label
        # The scanners' own finding_source_t values: commandsentry_light /
        # commandsentry_medium / commandsentry_heavy. Until note 307 these
        # rendered raw ("commandsentry_medium") because only the prefix form
        # was known.
        if key.endswith("_" + prefix):
            return label
    return key


# P3: two tools, one fact. naabu says the port is open; fingerprintx names the
# service on it. They are one sentence about the host, rendered as two rows since
# the digest existed.
# ⛔ RENDER-SIDE ONLY. `finding_id` embeds the tool and is load-bearing for
# identity, dedupe and close-out — a parser-level merge would change what a
# finding IS. 4.7's instruction, and the reason this lives here and not there.
_PORT_FINDING_RE = re.compile(r"^(?:open-port|service)-(\d{1,5})(?:-(tcp|udp))?$",
                              re.IGNORECASE)


def _port_of(check_name: str | None) -> str | None:
    m = _PORT_FINDING_RE.match((check_name or "").strip())
    return m.group(1) if m else None


def merge_service_inventory(rows: list[tuple], check_names: dict | None = None) -> list[tuple]:
    """P3 — collapse per-port rows into ONE service-inventory row per asset.

    Input rows are (finding_id, asset_id, title, severity, status, source, first_seen).
    `check_names` maps finding_id -> check_name when the caller has it; without it
    the port is read from the title, which is the shape the digest already renders.

    ⚠ The merged row keeps the WORST severity of its inputs and the FIRST finding_id,
    so the link still lands somewhere true. Nothing is dropped silently: the count in
    the title says how many rows became one."""
    out, ports = [], {}
    for r in rows:
        fid, asset = r[0], r[1]
        name = (check_names or {}).get(fid) or ""
        port = _port_of(name) or _port_of(_check_name_from_title(r[2]))
        if port is None:
            out.append(r)
            continue
        slot = ports.setdefault(asset, {"ports": set(), "rows": [], "first": r})
        slot["ports"].add(port)
        slot["rows"].append(r)
    for asset, slot in ports.items():
        rs = slot["rows"]
        worst = min((r[3] for r in rs), key=lambda s: _SEV_ORDER.get(s, 9))
        listed = ", ".join(f"{p}/tcp" for p in sorted(slot["ports"], key=int))
        first = slot["first"]
        out.append((first[0], asset,
                    f"Service inventory: {listed}  ({len(rs)} rows merged)",
                    worst, first[4], first[5], first[6]))
    return out


def _check_name_from_title(title: str | None) -> str:
    """The digest renders titles, not check names. `open-port-53` appears in the
    title for these rows; this pulls it back out without guessing at anything else."""
    m = re.search(r"\b((?:open-port|service)-\d{1,5}(?:-(?:tcp|udp))?)\b", title or "")
    return m.group(1) if m else ""


def split_info(rows: list[tuple]) -> tuple[list[tuple], list[tuple]]:
    """P4 — (shown in full, collapsed to one line). INFO is inventory: worth keeping,
    not worth a row each. ⚠ The SUBJECT COUNT STILL COUNTS THEM (152) — collapsing a
    row in the body must never change the number in the header, or the digest starts
    disagreeing with itself."""
    full = [r for r in rows if (r[3] or "").upper() != "INFO"]
    info = [r for r in rows if (r[3] or "").upper() == "INFO"]
    return full, info


def group_by_asset(rows: list[tuple]) -> list[tuple]:
    """P1 — [(asset_id, worst_severity, [rows])], worst asset first, findings inside
    each asset worst first. One asset header instead of sixteen repetitions."""
    by: dict = {}
    for r in rows:
        by.setdefault(r[1], []).append(r)
    blocks = []
    for asset, rs in by.items():
        rs = sorted(rs, key=lambda r: (_SEV_ORDER.get((r[3] or "").upper(), 9), r[2] or ""))
        blocks.append((asset, (rs[0][3] or "").upper(), rs))
    blocks.sort(key=lambda b: (_SEV_ORDER.get(b[1], 9), b[0]))
    return blocks


def vendor_product_label(vendor: str | None, product: str | None) -> str:
    """Vendor + product, without saying the vendor twice.

    ⛔ THE DIGEST HAS PRINTED "Google Cloud Google Cloud Armor" SINCE D-031
    (relay 346). The join was `f"{vendor + ' ' if vendor else ''}{product}"`,
    which is right whenever the product name does not already begin with the
    vendor name — and wrong whenever it does:

        Google Cloud  + Google Cloud Armor  -> "Google Cloud Google Cloud Armor"
        Cloudflare    + Cloudflare          -> "Cloudflare Cloudflare"
        Fortinet      + FortiWeb            -> "Fortinet FortiWeb"          fine

    ⚠ IT WAS PRODEX-ONLY, AND THAT IS WHY THREE WEEKS OF DIGESTS DID NOT SHOW
    IT. Command's estate is Fortinet/FortiWeb, which reads correctly; Prodex is
    Google Cloud Armor. The digest reads were Command-heavy, so the string was
    wrong on an instance nobody was reading closely. Rule 9 step 3 on the
    PORTAL — the same construction, inherited faithfully — is what surfaced it.

    The rule: if the product already names the vendor, the vendor is noise.

    ⛔ The portal carries the identical rule in JS (vendorProductLabel), and
    both are pinned to the SAME fixtures — the real Prodex row among them — so
    the digest string and the chip cannot drift apart silently.
    """
    v = (vendor or "").strip()
    p = (product or "").strip()
    if not p:
        return v
    if not v:
        return p
    # Case-insensitive: the registry is not consistent about capitalisation and
    # a case difference is not a second vendor.
    return p if p.lower().startswith(v.lower()) else f"{v} {p}"


def asset_class_line(asset_id: str, classes: dict | None) -> str:
    """D-031 — the asset's device class, confidence and vendor PRODUCT.

    ⚠ SOURCE STATED, because it is the dry-run table until `--write` flips it onto
    `assets`: the line says "(dry-run classification)" rather than implying the label
    is live. ⚠ An asset with no classification gets NO CLASS — not "unknown", which
    would read as a verdict we never made."""
    row = (classes or {}).get(asset_id)
    if not row:
        return ""
    cls = row.get("device_class")
    if not cls:
        return ""
    conf = row.get("confidence") or "unknown confidence"
    product = (row.get("vendor_product") or {}).get("product")
    vendor = (row.get("vendor_product") or {}).get("vendor")
    bits = [f"{cls}/{conf}"]
    if product:
        bits.append(vendor_product_label(vendor, product))
    return "  ·  ".join(bits) + "  (dry-run classification)"


# P5 / D-031: "new" means DISCOVERED IN THIS WINDOW, not "new to you". Howie ran
# assets for weeks that the digest still called new.
NEW_ASSETS_HEADING = "Assets discovered in this window"


def enforcement_words(blocked: bool, prev_blocked) -> tuple[str, str]:
    """PURE. The verdict words for one enforcement flip and their colour.
    blocked=True  -> "BLOCKED" (green): a device in front is denying attack payloads.
    blocked=False -> "PASSED THROUGH" (red): they reached the application; the
                     'No enforcing WAF' finding (MODERATE since 3b) carries the detail.
    prev_blocked is None on a first measurement (only a first BLOCK is reported)."""
    if blocked:
        return ("BLOCKED" if prev_blocked is None else "NOW BLOCKED"), "#1a7f37"
    return "NOW PASSING THROUGH", "#b42318"



def _ago(hours) -> str:
    """'3 hours ago' / '2 days ago' / '20 days ago' for a float of hours."""
    if hours is None:
        return "?"
    h = float(hours)
    if h < 1.5:
        return "about an hour ago"
    if h < 48:
        return f"{int(round(h))} hours ago"
    return f"{int(round(h / 24))} days ago"


def _day(dt) -> str:
    """'Oct 9' — a reader's date, not a log timestamp."""
    return f"{dt:%b} {dt.day}"


def stale_row_words(r) -> tuple[str, str, str]:
    """320 (2026-10-15) — one row of "we may have lost sight of these", in words a reader
    does not have to decode.

    Howie, on the shipped 'disc=2026-09-25 12:23 UTC (479.7h) deep=…' line: "I, as the
    main creator of this with you, am completely confused" — and he wants the people who
    read these mails not to be. So no clock names (discovery / probe / deep scan), no
    column names, no hours-with-decimals: when we last saw it, when we last fully scanned
    it. Returns (asset_id, seen_sentence, scan_sentence). The red/`!` marking is the
    renderer's. Accepts the 10-tuple from SQL_STALE_LIVE_ASSETS (321) and the older 9- and
    8-tuples. seen_via (which of our two checks saw it last) stays in the row for us; the
    reader does not need it.

    321 (2026-10-16): the scan date is a real full scan (scan_run), and a host we skip on
    purpose (not a website: the nameservers) says so instead of showing a date or being
    called behind.
    """
    aid, lo, ls, hrs_disc, hrs_deep, disc_stale, never_ds, deep_ds = r[:8]
    skipped = bool(r[9]) if len(r) > 9 else False
    seen = "never seen by our checks" if lo is None else f"last seen {_day(lo)} ({_ago(hrs_disc)})"
    if skipped:
        scan = "not full-scanned on purpose (not a website)"
    elif never_ds:
        scan = "never had a full scan"
    elif ls is None:
        scan = "first full scan not due yet"
    else:
        scan = f"last full scan {_day(ls)} ({_ago(hrs_deep)})"
    return aid, seen, scan


STALE_INTRO = ("Sentry looks for every host it knows about every 6 hours, and gives each website "
               "a full scan about once a week. The hosts below have fallen behind on that. "
               "This is a gap in our own checking, not a problem found on the hosts.")


def _span(hours) -> str:
    """24 -> 'a day', 168 -> '7 days', 9 -> '9 hours'."""
    h = int(hours)
    if h == 24:
        return "a day"
    return f"{h // 24} days" if h % 24 == 0 else f"{h} hours"


def stale_overdue_note(discovery_stale_hours, deepscan_stale_hours) -> str:
    """What the red / '!' marks, in words."""
    return (f"not seen in {_span(discovery_stale_hours)}, no full scan in "
            f"{_span(deepscan_stale_hours)}, or never")


def _digest_model(*, window_start, window_end, new_findings, confirmed, regressed,
                  high_risk, new_assets, dark_assets, stale_assets, canary_violations,
                  baseline, came_back=None, fixed=None, enforcement_flips=None,
                  unrecognized_pages=None, sites=None, certs=None, prev_deep=None,
                  hints=None, brand=None, discovery_stale_hours=24,
                  deepscan_stale_hours=192) -> dict:
    """KB 12 job 3l — every part of the old email, sorted into Do today / Worth a ticket /
    Off your plate by digest_daily.build_model. The stale-host wording stays this file's
    (stale_row_words, note 320)."""
    return _dd.build_model(
        window_start=window_start, window_end=window_end, new_findings=new_findings,
        confirmed=confirmed, regressed=regressed, high_risk=high_risk,
        new_assets=new_assets, dark_assets=dark_assets, stale_assets=stale_assets,
        canary_violations=canary_violations, baseline=baseline, came_back=came_back,
        fixed=fixed, enforcement_flips=enforcement_flips,
        unrecognized_pages=unrecognized_pages, sites=sites, certs=certs,
        prev_deep=prev_deep, hints=hints, brand=brand if brand is not None else _dd.load_brand(),
        stale_words=stale_row_words, stale_intro=STALE_INTRO,
        stale_note=stale_overdue_note(discovery_stale_hours, deepscan_stale_hours),
    )


def render_html(
    *,
    window_start: datetime,
    window_end: datetime,
    new_findings: list[tuple],
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
    product_name: str,
    device_classes: dict | None = None,
    came_back: list[tuple] | None = None,
    fixed: list[tuple] | None = None,
    enforcement_flips: list[tuple] | None = None,
    unrecognized_pages: list[tuple] | None = None,
    sites: list[tuple] | None = None,
    certs: list[tuple] | None = None,
    prev_deep: dict | None = None,
    hints: dict | None = None,
    brand: dict | None = None,
) -> str:
    """The daily digest as a to-do list (KB 12 job 3l, design D). Howie, 2026-10-22:
    "This entire email needs to be simplified and redesigned" … "Let's have it be
    colorful." Every part of the old email has a home (plan 2026-10-22 1530, D1); the
    layout lives in digest_daily.py. `dashboard_url` is the portal link (main passes
    ALERTER_PORTAL_URL, note 307)."""
    model = _digest_model(
        window_start=window_start, window_end=window_end, new_findings=new_findings,
        confirmed=confirmed, regressed=regressed, high_risk=high_risk,
        new_assets=new_assets, dark_assets=dark_assets, stale_assets=stale_assets,
        canary_violations=canary_violations, baseline=baseline, came_back=came_back,
        fixed=fixed, enforcement_flips=enforcement_flips,
        unrecognized_pages=unrecognized_pages, sites=sites, certs=certs,
        prev_deep=prev_deep, hints=hints, brand=brand,
        discovery_stale_hours=discovery_stale_hours, deepscan_stale_hours=deepscan_stale_hours)
    return _dd.render_html(model, portal_url=dashboard_url, product_name=product_name)


def render_text(
    *,
    window_start: datetime,
    window_end: datetime,
    new_findings: list[tuple],
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
    product_name: str,
    device_classes: dict | None = None,
    came_back: list[tuple] | None = None,
    fixed: list[tuple] | None = None,
    enforcement_flips: list[tuple] | None = None,
    unrecognized_pages: list[tuple] | None = None,
    sites: list[tuple] | None = None,
    certs: list[tuple] | None = None,
    prev_deep: dict | None = None,
    hints: dict | None = None,
    brand: dict | None = None,
    portal_url: str = "",
) -> str:
    """Plain-text twin of render_html: the same buckets, finding ids kept (plain text is
    what gets grepped and pasted into a ticket, note 152 P2)."""
    model = _digest_model(
        window_start=window_start, window_end=window_end, new_findings=new_findings,
        confirmed=confirmed, regressed=regressed, high_risk=high_risk,
        new_assets=new_assets, dark_assets=dark_assets, stale_assets=stale_assets,
        canary_violations=canary_violations, baseline=baseline, came_back=came_back,
        fixed=fixed, enforcement_flips=enforcement_flips,
        unrecognized_pages=unrecognized_pages, sites=sites, certs=certs,
        prev_deep=prev_deep, hints=hints, brand=brand,
        discovery_stale_hours=discovery_stale_hours, deepscan_stale_hours=deepscan_stale_hours)
    return _dd.render_text(model, portal_url=portal_url, product_name=product_name)


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
    inline_images: list | None = None,
) -> dict:
    """Delegates to scripts/common/mailer.py — provider chosen by MAIL_PROVIDER
    (4.7 M1, Obsidian 164).

    Name kept for the call site's sake; this is no longer SendGrid-specific.
    It was, hardcoded, in BOTH repos — which is why Prodex (iCloud SMTP, never
    SendGrid) had no working scanner mail transport at all. `api_key` is now
    ignored; the mailer reads SENDGRID_API_KEY itself when that provider is
    selected. Raises on failure to preserve this function's existing contract.
    """
    ok, detail = _mailer.send_email(
        to_addrs=to_addrs, subject=subject, html=html, text=text,
        from_addr=from_addr, from_name=from_name, inline_images=inline_images,
    )
    if not ok:
        raise RuntimeError(f"mail send failed [{_mailer.describe_config()}]: {detail}")
    return {"id": detail, "status_code": 202}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="render email but skip Resend + DB writes")
    ap.add_argument("--html-out", default="",
                    help="with --dry-run: also write the full HTML here (to look at it)")
    args = ap.parse_args()

    dsn          = _env("SUPABASE_DSN", required=True)
    # Migrated 2026-05-28: RESEND_API_KEY → SENDGRID_API_KEY. Fall back to
    # the legacy var name during the transition so an unset SENDGRID_API_KEY
    # in CI doesn't break the digest before secrets are updated.
    #
    # 319 (2026-10-14): NOT required any more. The first Prodex digest died
    # here with "error: RESEND_API_KEY not set" — Prodex sends over SMTP and
    # has no SendGrid/Resend key at all, and `api_key` is ignored by the send
    # path (the mailer reads its own provider's settings; see send_via_
    # sendgrid's docstring). Whether THIS instance can send is the mailer's
    # startup check (check_config / warn_if_unconfigured, 4.7 M5), which knows
    # the provider; a SendGrid-only demand up here is the cross-instance bug
    # 4.7 M1 removed from the send path, surviving in the preamble.
    api_key      = (
        _env("SENDGRID_API_KEY", required=False)
        or _env("RESEND_API_KEY", required=False)
        or ""
    )
    # PER-INSTANCE IDENTITY — NO CROSS-TENANT DEFAULTS (2026-07-29).
    #
    # These defaulted to Command's sender AND, worse, to a
    # hschneider@commandcompanies.com RECIPIENT — identically in both scanner
    # repos. Dormant only because no Prodex workflow invokes this digest yet;
    # the day one does, Prodex fleet posture would be mailed from a Command
    # address to a Command inbox. A default is exactly what makes that silent.
    #
    # Unset => empty, and the send path below treats "no recipients" as a
    # no-op. Sending nothing beats sending another tenant's posture to the
    # wrong people.
    from_addr    = _env("ALERTER_FROM", default="")
    from_name    = _env("ALERTER_FROM_NAME", default="")
    to_raw       = _env("ALERTER_TO", default="")
    to_addrs     = [a.strip() for a in (to_raw or "").split(",") if a.strip()]
    _mailer.warn_if_unconfigured(os.environ.get("INSTANCE_NAME", ""))  # 4.7 M5
    name         = _env("ALERTER_NAME", default="daily_digest") or "daily_digest"
    first_hours  = int(_env("ALERTER_FIRST_RUN_HOURS", default="24") or "24")
    dashboard_url= _env("ALERTER_DASHBOARD_URL", default="")
    # Note 307 — links go to the PORTAL (finding pages, the footer), not to the
    # raw database. ALERTER_PORTAL_URL is set per repo in alerter.yml; the old
    # Supabase link is the fallback only so an unset var cannot break a send.
    portal_url   = (_env("ALERTER_PORTAL_URL", default="") or "").rstrip("/") or dashboard_url

    if not args.dry_run and not (from_addr and from_name and to_addrs):
        _missing = [n for n, v in (("ALERTER_FROM", from_addr),
                                   ("ALERTER_FROM_NAME", from_name),
                                   ("ALERTER_TO", to_addrs)) if not v]
        print(f"::warning::{', '.join(_missing)} not set — refusing to send the digest "
              f"rather than send as/to another instance. Set them per repo.",
              file=sys.stderr)
        return 0

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
            cur.execute(SQL_NEW_FINDINGS_IN_WINDOW, (window_start, window_end))
            new_findings = cur.fetchall()
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

            # Note 307 — counted as the portal counts them (v_fleet_open_reps).
            cur.execute(SQL_OPEN_POSTURE)
            baseline = posture_from_rows(cur.fetchall())
            cur.execute(SQL_FIXED_IN_WINDOW, (window_start, window_end))
            fixed = cur.fetchall()

            # Asset-surface events in window (added 2026-06-07 — closes the
            # "0 chng while real-time emails fire" gap). Same Tier 2 gate as
            # dispatch_event_notifications: only confirmed_live + owned.
            # FOUR params: the event window, then the asset's own first_observed
            # window. Same two values twice — they are deliberately separate
            # placeholders so the two questions stay visibly distinct in the SQL
            # ("did an event fire in the window" vs "is the asset itself new").
            cur.execute(
                SQL_NEW_ASSETS_IN_WINDOW,
                (window_start, window_end, window_start, window_end),
            )
            new_assets = cur.fetchall()
            cur.execute(SQL_DARK_ASSETS_IN_WINDOW, (window_start, window_end))
            dark_assets = cur.fetchall()
            # Note 307 — the other half of "went dark": say when it came back.
            cur.execute(SQL_CAME_BACK_IN_WINDOW,
                        (window_end, window_end, window_start, window_end))
            came_back = cur.fetchall()
            # Obsidian 310 — a security device starting (or stopping) to block.
            cur.execute(SQL_ENFORCEMENT_FLIPS_IN_WINDOW, (window_start, window_end))
            enforcement_flips = cur.fetchall()
            # Obsidian 312 — a measured block whose deny page the library does not know.
            cur.execute(SQL_MEASURED_BLOCKS_IN_WINDOW, (window_start, window_end))
            unrecognized_pages = unrecognized_block_pages(cur.fetchall())

            # Watchdog v1 — pipeline health checks (added 2026-06-07).
            # Two clocks, two thresholds, single alarm if EITHER is stale:
            #   ALERTER_DISCOVERY_STALE_HOURS (default 24h since 321; was 9h = 6h cron + 3h.
            #     ns02.sciimage.com, listed by an outside source about 2 passes in 3 and
            #     sometimes missed twice running, read as "lost sight" at 9h)
            #   ALERTER_DEEPSCAN_STALE_HOURS  (default 192h = 8 days since 321; the weekly
            #     sweep rescans just past 7 days, so 168h flagged hosts on schedule)
            # Per Howie 2026-06-07: a discovery-only check lets the
            # "discovery touched it but no deep scan ever ran" pattern
            # slip through silently (insite.sciimage.com — HIGH risk,
            # 73d since last deep-scan, would have gone invisible after
            # the next discovery run touched it).
            discovery_stale_hours = int(_env("ALERTER_DISCOVERY_STALE_HOURS", default="24") or "24")
            deepscan_stale_hours  = int(_env("ALERTER_DEEPSCAN_STALE_HOURS",  default="192") or "192")
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

            # D-031 — the per-asset device class, latest row per asset.
            # ⚠ FAILS SOFT, DELIBERATELY: a digest that does not send because a
            # decoration query failed is worse than a digest without the decoration.
            # An empty map renders no class lines at all, which is the same as an
            # unclassified fleet and reads honestly either way.
            device_classes: dict = {}
            try:
                cur.execute(SQL_ASSET_DEVICE_CLASS)
                for _aid, _cls, _conf, _vp in cur.fetchall():
                    device_classes[_aid] = {"device_class": _cls, "confidence": _conf,
                                            "vendor_product": _vp or {}}
            except Exception as exc:                       # pragma: no cover - live only
                print(f"  device-class read failed ({exc!r}) — digest renders without class lines")
                device_classes = {}

        # KB 12 job 3l — the daily list's four extra reads, each in its own savepoint so a
        # failure costs that decoration only (the bar, the certificates, "first deep scan
        # since", the "Do:" line), never the send.
        def _soft(label, sql, params=None):
            try:
                with conn.transaction():
                    with conn.cursor() as c2:
                        c2.execute(sql, params)
                        return c2.fetchall()
            except Exception as exc:                       # pragma: no cover - live only
                print(f"  {label} read failed ({exc!r}) — digest renders without it")
                return []
        sites = _soft("site ratings", SQL_SITE_RATINGS, {"t": window_start})
        certs = _soft("expiring certificates", SQL_CERTS_EXPIRING)
        listed = sorted({r[1] for r in list(new_findings) + list(regressed) + list(confirmed)})
        prev_deep = dict(_soft("previous deep scans", SQL_PREV_DEEP_SCANS, (window_start, listed))) if listed else {}
        hint_ids = sorted({r[0] for r in list(new_findings) + list(regressed) + list(confirmed)})
        hints = dict(_soft("remediation hints", SQL_FINDING_HINTS, (hint_ids,))) if hint_ids else {}
        brand = _dd.load_brand()

        # Render — KB 12 job 3l: one model, two renderings, one subject. The subject says
        # what you will do ("2 checks and 1 ticket"); "(!) Coverage gap." leads when Sentry
        # has lost sight of hosts; the [name] prefix stays for mail filters.
        new_problems, new_inventory = split_problems_inventory(new_findings)
        model = _digest_model(
            window_start=window_start, window_end=window_end,
            new_findings=new_findings, confirmed=confirmed, regressed=regressed,
            high_risk=high_risk, new_assets=new_assets, dark_assets=dark_assets,
            stale_assets=stale_assets, canary_violations=canary_violations,
            baseline=baseline, came_back=came_back, fixed=fixed,
            enforcement_flips=enforcement_flips, unrecognized_pages=unrecognized_pages,
            sites=sites, certs=certs, prev_deep=prev_deep, hints=hints, brand=brand,
            discovery_stale_hours=discovery_stale_hours, deepscan_stale_hours=deepscan_stale_hours,
        )
        subject = _dd.subject(model, from_name)
        html = _dd.render_html(model, portal_url=portal_url, product_name=from_name)
        text = _dd.render_text(model, portal_url=portal_url, product_name=from_name)

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
            if args.html_out:
                with open(args.html_out, "w", encoding="utf-8") as f:
                    f.write(html.replace(f"cid:{_dd.LOGO_CID}", "logo.png"))
                print(f">> full HTML written to {args.html_out} (logo as logo.png beside it)")
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
                inline_images=_dd.inline_images(brand),
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
        print(f"alerter ok: new_problems={len(new_problems)} new_inventory={len(new_inventory)} fixed={len(fixed)} "
              f"confirmed={len(confirmed)} regressed={len(regressed)} high_risk={len(high_risk)} sent={sent}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
