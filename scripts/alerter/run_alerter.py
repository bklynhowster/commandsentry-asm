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
  SUPABASE_DSN     postgres URL (use direct connection or session pooler)
  RESEND_API_KEY   from https://resend.com/api-keys
  ALERTER_FROM     verified sender, e.g. commandsentry@goldenlaneinc.com
  ALERTER_TO       comma-separated recipient list, e.g.
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
SELECT
  COUNT(*) FILTER (WHERE severity = 'CRITICAL')      AS critical_open,
  COUNT(*) FILTER (WHERE severity = 'HIGH')          AS high_open,
  COUNT(*) FILTER (WHERE severity = 'MODERATE-HIGH') AS mod_high_open,
  COUNT(*) FILTER (WHERE severity = 'MODERATE')      AS moderate_open,
  COUNT(*) FILTER (WHERE severity = 'LOW')           AS low_open
FROM findings
WHERE current_status IN ('detected', 'confirmed', 'open', 'regressed');
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


def render_html(
    *,
    window_start: datetime,
    window_end: datetime,
    confirmed: list[tuple],
    regressed: list[tuple],
    high_risk: list[tuple],
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

    confirmed_section = section(
        "Newly confirmed findings", len(confirmed), find_table(confirmed)
    )
    regressed_section = section(
        "Regressed findings (was fixed, came back)", len(regressed), find_table(regressed)
    )
    high_risk_section = section(
        "Assets elevated to HIGH / CRITICAL", len(high_risk), asset_table(high_risk)
    )

    has_changes = bool(confirmed or regressed or high_risk)
    headline = (
        f"<strong>{len(confirmed) + len(regressed)}</strong> finding change(s) and "
        f"<strong>{len(high_risk)}</strong> asset risk shift(s) in this window."
        if has_changes
        else "<strong>No changes</strong> since last run — alerter is healthy."
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

  <div style="background:#fafafa;padding:12px 16px;border-radius:6px;font-size:12px;color:#555;margin-bottom:8px;">
    <div style="text-transform:uppercase;font-size:10px;letter-spacing:0.8px;color:#888;margin-bottom:4px;">Currently open across the fleet</div>
    {baseline_pill}
  </div>

  {confirmed_section}
  {regressed_section}
  {high_risk_section}

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
    baseline: dict,
) -> str:
    lines: list[str] = []
    lines.append(f"COMMANDsentry — Daily posture digest — {window_end:%Y-%m-%d}")
    lines.append(f"Window: {window_start:%Y-%m-%d %H:%M UTC} -> {window_end:%Y-%m-%d %H:%M UTC}")
    lines.append("")
    lines.append(
        f"Currently open: CRITICAL={baseline['critical_open']}  HIGH={baseline['high_open']}  "
        f"MOD-HIGH={baseline['mod_high_open']}  MODERATE={baseline['moderate_open']}  "
        f"LOW={baseline['low_open']}"
    )
    lines.append("")

    if not (confirmed or regressed or high_risk):
        lines.append("No changes since last run — alerter is healthy.")
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

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Resend
# ---------------------------------------------------------------------------

def send_via_resend(
    *,
    api_key: str,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    html: str,
    text: str,
) -> dict:
    payload = {
        "from": from_addr,
        "to":   to_addrs,
        "subject": subject,
        "html": html,
        "text": text,
    }
    req = urllib.request.Request(
        url="https://api.resend.com/emails",
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend HTTP {e.code}: {body}") from None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="render email but skip Resend + DB writes")
    args = ap.parse_args()

    dsn          = _env("SUPABASE_DSN", required=True)
    api_key      = _env("RESEND_API_KEY", required=not args.dry_run) or ""
    from_addr    = _env("ALERTER_FROM", default="commandsentry@goldenlaneinc.com")
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

        # Render
        subject = (
            f"[COMMANDsentry] Daily posture digest — "
            f"{window_end:%Y-%m-%d} "
            f"({len(confirmed)+len(regressed)} chng, {len(high_risk)} asset)"
        )
        html = render_html(
            window_start=window_start, window_end=window_end,
            confirmed=confirmed, regressed=regressed, high_risk=high_risk,
            baseline=baseline, dashboard_url=dashboard_url,
        )
        text = render_text(
            window_start=window_start, window_end=window_end,
            confirmed=confirmed, regressed=regressed, high_risk=high_risk,
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
            resp = send_via_resend(
                api_key=api_key, from_addr=from_addr, to_addrs=to_addrs,
                subject=subject, html=html, text=text,
            )
            sent = bool(resp.get("id"))
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
