#!/usr/bin/env python3
"""
COMMANDsentry — email alert dispatcher (Resend).

Reads asset records under data/assets/, identifies signal-worthy changes
from the `deltas` field of each asset (recently scanned ones), and sends
a single consolidated alert email via the Resend API.

Triggers (worth alerting):
  - New 'watch'-severity exposure (e.g. exposed admin panel, .git, weak TLS)
  - New open port discovered
  - Cert expires in < 7 days
  - WAF disappeared (was protected, now isn't)
  - Asset offline (was up, now isn't)
  - New subdomain (apex scans only)
  - Tech version changed (notice)
  - Asset newly added (first scan)

Environment:
  RESEND_API_KEY    — your Resend API key (required to send)
  ALERT_FROM_EMAIL  — sender, e.g. "alerts@yourdomain.com" (required)
  ALERT_TO_EMAIL    — recipient (required)
  DASHBOARD_URL     — link back to the dashboard (default: commandsentry-asm.netlify.app)
  ALERT_FROM_NAME   — display name for sender (default: "COMMANDsentry ASM")
  ALERT_SCAN_WINDOW — only consider scans from the last N hours (default: 12)

Behavior:
  - No env vars set → graceful no-op with log message (workflow doesn't fail)
  - No alerts to send → graceful no-op (no email)
  - Resend API error → exit non-zero so the workflow surfaces the problem
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# ─── Config from env ─────────────────────────────────────────────────────────

API_KEY        = os.environ.get("RESEND_API_KEY", "").strip()
FROM_EMAIL     = os.environ.get("ALERT_FROM_EMAIL", "").strip()
FROM_NAME      = os.environ.get("ALERT_FROM_NAME", "COMMANDsentry ASM").strip()
TO_EMAIL       = os.environ.get("ALERT_TO_EMAIL", "").strip()
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://commandsentry-asm.netlify.app").strip()
SCAN_WINDOW_HR = int(os.environ.get("ALERT_SCAN_WINDOW", "12"))

REPO_ROOT  = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "data" / "assets"

# ─── Severity helpers ────────────────────────────────────────────────────────

WATCH_TYPES_FROM_NEW_EXPOSURE = {
    "exposed_admin_panel", "exposed_git_dir", "exposed_env_file",
    "exposed_debug_endpoint", "cert_expired", "cert_self_signed",
    "weak_tls_protocol", "waf_disappeared",
}

def is_watch(exposure: dict) -> bool:
    return (exposure or {}).get("severity") == "watch"

# ─── Alert collector ─────────────────────────────────────────────────────────

class Alert:
    __slots__ = ("severity", "asset", "kind", "title", "detail")
    def __init__(self, severity: str, asset: str, kind: str, title: str, detail: str = ""):
        self.severity = severity
        self.asset    = asset
        self.kind     = kind
        self.title    = title
        self.detail   = detail

def collect_alerts() -> list[Alert]:
    """Walk data/assets/*.json, build alert list from each asset's deltas."""
    out: list[Alert] = []
    if not ASSETS_DIR.exists():
        return out

    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=SCAN_WINDOW_HR)

    for path in sorted(ASSETS_DIR.glob("*.json")):
        if path.name.endswith(".example.json"):
            continue
        try:
            asset = json.loads(path.read_text())
        except Exception:
            continue

        # Was this asset scanned recently? Skip stale assets that didn't
        # update on this run (they have nothing new to report).
        completed_at = asset.get("scan", {}).get("completed_at")
        if completed_at:
            try:
                ts = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue
            except Exception:
                pass

        asset_name = asset.get("asset", {}).get("value") or asset.get("asset", {}).get("id") or path.stem
        deltas     = asset.get("deltas") or {}
        added      = deltas.get("added") or {}
        removed    = deltas.get("removed") or {}
        changed    = deltas.get("changed") or {}
        first_scan = (deltas.get("since_scan") in (None, ""))

        # First-time scan flagged as a notice (operator just added this target)
        if first_scan:
            n_exp = len(asset.get("exposures") or [])
            n_watch = sum(1 for e in (asset.get("exposures") or []) if is_watch(e))
            out.append(Alert(
                "notice", asset_name, "first_scan",
                f"First scan completed for {asset_name}",
                f"{n_exp} exposure(s) recorded ({n_watch} watch-severity)."
            ))

        # New watch-severity exposures (the highest-priority signal)
        added_exp_ids = added.get("exposures") or []
        if added_exp_ids:
            exposures_by_id = {e.get("id"): e for e in (asset.get("exposures") or []) if e.get("id")}
            for eid in added_exp_ids:
                e = exposures_by_id.get(eid)
                if not e:
                    continue
                if is_watch(e) or e.get("type") in WATCH_TYPES_FROM_NEW_EXPOSURE:
                    out.append(Alert(
                        "watch", asset_name, "new_watch_exposure",
                        e.get("title") or e.get("type") or eid,
                        e.get("detail") or ""
                    ))
                else:
                    out.append(Alert(
                        "notice", asset_name, "new_notice_exposure",
                        e.get("title") or e.get("type") or eid,
                        e.get("detail") or ""
                    ))

        # New open ports
        for port in (added.get("ports") or []):
            p = port.get("port") if isinstance(port, dict) else port
            proto = port.get("protocol", "tcp") if isinstance(port, dict) else "tcp"
            out.append(Alert(
                "watch", asset_name, "new_port",
                f"New open port: {p}/{proto}",
                "Port wasn't open in the previous scan."
            ))

        # Closed ports
        for port in (removed.get("ports") or []):
            p = port.get("port") if isinstance(port, dict) else port
            proto = port.get("protocol", "tcp") if isinstance(port, dict) else "tcp"
            out.append(Alert(
                "notice", asset_name, "port_closed",
                f"Port closed: {p}/{proto}",
                "Port was open in the previous scan."
            ))

        # New subdomains
        for sub in (added.get("subdomains") or []):
            out.append(Alert(
                "notice", asset_name, "new_subdomain",
                f"New subdomain: {sub}", ""
            ))

        # Removed subdomains
        for sub in (removed.get("subdomains") or []):
            out.append(Alert(
                "notice", asset_name, "subdomain_gone",
                f"Subdomain gone: {sub}", ""
            ))

        # Tech version changes
        for t in (changed.get("tech") or []):
            out.append(Alert(
                "notice", asset_name, "tech_changed",
                f"{t.get('name')} changed: {t.get('from') or '?'} → {t.get('to') or '?'}",
                ""
            ))

        # Cert expiring soon
        tls = (asset.get("inventory") or {}).get("tls") or {}
        days = tls.get("days_until_expiry")
        if isinstance(days, (int, float)) and days < 7:
            out.append(Alert(
                "watch", asset_name, "cert_expiring",
                f"Certificate expires in {int(days)} day(s)",
                f"not_after: {tls.get('not_after')}"
            ))

        # WAF disappeared
        waf = (asset.get("inventory") or {}).get("waf") or {}
        if waf.get("detected") is False:
            history = asset.get("history") or []
            # if the previous scan in history had WAF detected (heuristic flag), alert
            # We don't store waf in history right now; this is a placeholder hook.
            # TODO: bake WAF state into history[] so we can detect transitions.
            pass

        # Asset offline
        http = (asset.get("inventory") or {}).get("http") or {}
        if http.get("live") is False:
            history = asset.get("history") or []
            # If previous scan was live and this one isn't, alert
            prev_live = next((h.get("live") for h in reversed(history[:-1])), None)
            if prev_live:
                out.append(Alert(
                    "watch", asset_name, "asset_offline",
                    f"Asset {asset_name} is offline",
                    "Was responding in the previous scan."
                ))

    return out

# ─── Email rendering ─────────────────────────────────────────────────────────

def severity_color(sev: str) -> str:
    return {"watch": "#C8632A", "notice": "#556574"}.get(sev, "#556574")

def severity_label(sev: str) -> str:
    return {"watch": "WATCH", "notice": "notice"}.get(sev, sev)

def render_html(alerts: list[Alert]) -> str:
    by_asset: dict[str, list[Alert]] = {}
    for a in alerts:
        by_asset.setdefault(a.asset, []).append(a)

    n_watch  = sum(1 for a in alerts if a.severity == "watch")
    n_notice = sum(1 for a in alerts if a.severity == "notice")

    lines = []
    lines.append('<!doctype html><html><body style="font-family: -apple-system, system-ui, Segoe UI, Inter, Arial, sans-serif; background:#EAE7DF; margin:0; padding:24px; color:#0B1B2B;">')
    lines.append('<div style="max-width:640px; margin:0 auto; background:#FBFAF6; border:1px solid #D7D2C2; border-top:4px solid #C8632A; border-radius:4px;">')

    # Header
    lines.append('<div style="padding:20px 24px; border-bottom:1px solid #E4E8EE;">')
    lines.append('<div style="font-family: Archivo, Helvetica Neue, sans-serif; font-size:22px; font-weight:800; color:#0B1B2B; letter-spacing:-0.005em;">COMMAND<span style="color:#C8632A; font-weight:600;">sentry</span> ASM</div>')
    lines.append(f'<div style="font-family: JetBrains Mono, ui-monospace, monospace; font-size:11px; letter-spacing:0.14em; text-transform:uppercase; color:#556574; margin-top:4px;">{n_watch} WATCH · {n_notice} NOTICE · {len(by_asset)} ASSET(S)</div>')
    lines.append('</div>')

    # Per-asset blocks
    for asset, asset_alerts in by_asset.items():
        lines.append('<div style="padding:18px 24px; border-bottom:1px solid #E4E8EE;">')
        lines.append(f'<div style="font-family: JetBrains Mono, ui-monospace, monospace; font-size:14px; color:#0B1B2B; word-break:break-all; margin-bottom:8px;">{asset}</div>')
        for a in asset_alerts:
            color = severity_color(a.severity)
            lines.append(f'<div style="margin:8px 0; padding:10px 14px; background:{("#F1E1D3" if a.severity=="watch" else "#F2F4F7")}; border-left:3px solid {color}; border-radius:3px;">')
            lines.append(f'<div style="font-size:11px; font-family: JetBrains Mono, ui-monospace, monospace; letter-spacing:0.1em; text-transform:uppercase; color:{color}; font-weight:600;">{severity_label(a.severity)}</div>')
            lines.append(f'<div style="font-size:14px; color:#0B1B2B; font-weight:500; margin-top:4px;">{a.title}</div>')
            if a.detail:
                lines.append(f'<div style="font-size:13px; color:#2A3A4B; margin-top:4px;">{a.detail}</div>')
            lines.append('</div>')
        lines.append('</div>')

    # Footer
    lines.append('<div style="padding:16px 24px; text-align:center;">')
    lines.append(f'<a href="{DASHBOARD_URL}" style="display:inline-block; padding:9px 18px; background:#C8632A; color:#fff; text-decoration:none; border-radius:4px; font-family: Inter, sans-serif; font-size:14px; font-weight:600;">Open dashboard</a>')
    lines.append('</div>')
    lines.append('<div style="padding:0 24px 18px; text-align:center; font-family: JetBrains Mono, ui-monospace, monospace; font-size:10px; letter-spacing:0.14em; text-transform:uppercase; color:#8A97A4;">automated alert · do not reply</div>')

    lines.append('</div></body></html>')
    return "".join(lines)

def render_subject(alerts: list[Alert]) -> str:
    n_watch = sum(1 for a in alerts if a.severity == "watch")
    if n_watch:
        return f"[COMMANDsentry] {n_watch} watch · {len(alerts)} total alert(s)"
    return f"[COMMANDsentry] {len(alerts)} notice(s)"

# ─── Resend API ──────────────────────────────────────────────────────────────

def send_email(subject: str, html: str) -> None:
    """
    POST to Resend API. Uses curl rather than Python urllib because Resend
    sits behind Cloudflare, and Cloudflare blocks Python's default TLS
    fingerprint with error 1010. Curl's fingerprint is well-trusted.
    """
    body = json.dumps({
        "from":    f"{FROM_NAME} <{FROM_EMAIL}>",
        "to":      [TO_EMAIL],
        "subject": subject,
        "html":    html,
    })

    if not shutil.which("curl"):
        print("ERROR: curl not found in PATH. Required to bypass Cloudflare TLS fingerprint check.", file=sys.stderr)
        sys.exit(2)

    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--max-time", "30",
        "--user-agent", "commandsentry-asm/1.0",
        "-X", "POST",
        "https://api.resend.com/emails",
        "-H", f"Authorization: Bearer {API_KEY}",
        "-H", "Content-Type: application/json",
        "-w", "\n[HTTP %{http_code}]",
        "--data-binary", body,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    except subprocess.TimeoutExpired:
        print("Resend network error: curl timed out", file=sys.stderr)
        sys.exit(2)

    out  = (result.stdout or "")[:1000]
    err  = (result.stderr or "")[:500]

    if result.returncode != 0:
        print(f"Resend curl failed (exit {result.returncode}): stdout={out}  stderr={err}", file=sys.stderr)
        sys.exit(2)

    if "[HTTP 2" not in out:  # any 2xx is fine
        print(f"Resend non-2xx response: {out}", file=sys.stderr)
        sys.exit(2)

    print(f"Resend OK: {out}", file=sys.stderr)

# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    if not API_KEY or not FROM_EMAIL or not TO_EMAIL:
        print("Email alerts disabled — RESEND_API_KEY / ALERT_FROM_EMAIL / ALERT_TO_EMAIL not all set. Skipping.")
        return

    alerts = collect_alerts()
    if not alerts:
        print("No alerts to send.")
        return

    print(f"Sending {len(alerts)} alert(s) to {TO_EMAIL}")
    subject = render_subject(alerts)
    html    = render_html(alerts)
    send_email(subject, html)
    print("Email sent.")

if __name__ == "__main__":
    main()
