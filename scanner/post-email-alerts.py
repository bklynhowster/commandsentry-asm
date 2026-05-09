#!/usr/bin/env python3
"""
COMMANDsentry — email alert dispatcher (Resend, v2 ASM schema).

Reads asset records under data/assets/, identifies SURFACE CHANGES from the
deltas field of each recently-scanned asset, and sends a single consolidated
alert email via Resend.

Pure ASM signals only — no exposure analysis, no posture grading.

Triggers:
  watch  — new host IP, new service, asset offline, cert < 7d, cert chain change
  notice — new subdomain, subdomain gone, port closed, cert 7-30d, tech version change

Environment:
  RESEND_API_KEY    — Resend API key (required)
  ALERT_FROM_EMAIL  — sender (required)
  ALERT_TO_EMAIL    — recipient (required)
  DASHBOARD_URL     — link in email (default: commandsentry-asm.netlify.app)
  ALERT_FROM_NAME   — sender display name
  ALERT_SCAN_WINDOW — only consider scans from last N hours (default: 12)

Behavior:
  No env vars set → graceful no-op.
  No alerts to send → graceful no-op.
  Resend API error → exit non-zero so workflow surfaces the failure.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

API_KEY        = os.environ.get("RESEND_API_KEY", "").strip()
FROM_EMAIL     = os.environ.get("ALERT_FROM_EMAIL", "").strip()
FROM_NAME      = os.environ.get("ALERT_FROM_NAME", "COMMANDsentry ASM").strip()
TO_EMAIL       = os.environ.get("ALERT_TO_EMAIL", "").strip()
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://commandsentry-asm.netlify.app").strip()
SCAN_WINDOW_HR = int(os.environ.get("ALERT_SCAN_WINDOW", "12"))

REPO_ROOT  = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "data" / "assets"

class Alert:
    __slots__ = ("severity", "asset", "kind", "title", "detail")
    def __init__(self, severity, asset, kind, title, detail=""):
        self.severity, self.asset, self.kind, self.title, self.detail = severity, asset, kind, title, detail

def collect_alerts() -> list[Alert]:
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
        # Only v3 records
        if asset.get("schema_version") != "3.0":
            continue

        completed_at = asset.get("scan", {}).get("completed_at")
        if completed_at:
            try:
                ts = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue
            except Exception:
                pass

        aname  = asset.get("asset", {}).get("value") or asset.get("asset", {}).get("id") or path.stem
        deltas = asset.get("deltas") or {}
        added   = deltas.get("added")   or {}
        removed = deltas.get("removed") or {}
        changed = deltas.get("changed") or {}
        first_scan = (deltas.get("since_scan") in (None, ""))

        summary = asset.get("summary") or {}
        if first_scan:
            sc = summary.get("live_subdomain_count", 0)
            hc = summary.get("host_count", 0)
            vc = summary.get("service_count", 0)
            out.append(Alert(
                "notice", aname, "first_scan",
                f"First scan completed for {aname}",
                f"{sc} live subdomain(s), {hc} host(s), {vc} service(s)."
            ))

        # WATCH: new IPs (per subdomain)
        for h in (added.get("hosts") or []):
            sub = h.get("subdomain") or "?"
            out.append(Alert(
                "watch", aname, "new_host",
                f"New host IP {h.get('ip')} on {sub}",
                "Hosting expanded or moved."
            ))
        for h in (removed.get("hosts") or []):
            sub = h.get("subdomain") or "?"
            out.append(Alert("notice", aname, "host_removed",
                             f"Host IP {h.get('ip')} removed from {sub}", ""))

        # WATCH: new services (per subdomain)
        for s in (added.get("services") or []):
            sub = s.get("subdomain") or "?"
            out.append(Alert(
                "watch", aname, "new_service",
                f"New service open on {sub}: {s.get('port')}/{s.get('protocol')}",
                f"On host {s.get('ip')}. Port wasn't open in the previous scan."
            ))
        for s in (removed.get("services") or []):
            sub = s.get("subdomain") or "?"
            out.append(Alert("notice", aname, "service_closed",
                             f"Service closed on {sub}: {s.get('port')}/{s.get('protocol')}", ""))

        # NOTICE: subdomain churn
        for sub in (added.get("subdomains") or []):
            out.append(Alert("notice", aname, "new_subdomain",
                             f"New subdomain discovered: {sub}",
                             "Surfaced via subfinder passive enumeration."))
        for sub in (removed.get("subdomains") or []):
            out.append(Alert("notice", aname, "subdomain_gone",
                             f"Subdomain went away: {sub}", ""))

        # NOTICE: tech version changes (per subdomain)
        for t in (changed.get("fingerprint") or []):
            sub = t.get("subdomain") or "?"
            out.append(Alert(
                "notice", aname, "tech_changed",
                f"{sub}: {t.get('name')} {t.get('from') or '?'} → {t.get('to') or '?'}",
                "Detected version change in tech fingerprint."
            ))

        # WATCH: cert chain changed (per subdomain)
        for c in (changed.get("cert") or []):
            sub = c.get("subdomain") or "?"
            out.append(Alert(
                "watch", aname, "cert_changed",
                f"Certificate chain changed on {sub}",
                f"Issuer set: {(c.get('from') or [])} → {(c.get('to') or [])}"
            ))

        # WATCH/notice: cert expiry windows (across all subs' services)
        for sub in (asset.get("subdomains") or []):
            sub_name = sub.get("name", "?")
            for svc in (sub.get("services") or []):
                cert = svc.get("cert") or {}
                days = cert.get("days_to_expiry")
                if not isinstance(days, (int, float)):
                    continue
                label = f"{sub_name} ({svc.get('ip')}:{svc.get('port')})"
                if days < 7:
                    out.append(Alert("watch", aname, "cert_expiring",
                                     f"Cert on {label} expires in {int(days)} day(s)",
                                     f"Issuer: {cert.get('issuer') or '?'}"))
                elif days < 30:
                    out.append(Alert("notice", aname, "cert_expiring_soon",
                                     f"Cert on {label} expires in {int(days)} day(s)", ""))

        # WATCH: any subdomain went offline that was previously live
        # (best-effort — we don't store per-sub history yet, just flag dead-when-expected)
        for sub in (asset.get("subdomains") or []):
            if sub.get("reachability", {}).get("live") is False and sub.get("is_root"):
                out.append(Alert("watch", aname, "asset_offline",
                                 f"Apex {aname} is offline",
                                 "Root subdomain not responding."))

    return out

def severity_color(s): return {"watch": "#C8632A", "notice": "#556574"}.get(s, "#556574")
def severity_label(s): return {"watch": "WATCH", "notice": "notice"}.get(s, s)

def render_html(alerts):
    by_asset = {}
    for a in alerts:
        by_asset.setdefault(a.asset, []).append(a)
    n_watch  = sum(1 for a in alerts if a.severity == "watch")
    n_notice = sum(1 for a in alerts if a.severity == "notice")

    out = []
    out.append('<!doctype html><html><body style="font-family: -apple-system, system-ui, Segoe UI, Inter, Arial, sans-serif; background:#EAE7DF; margin:0; padding:24px; color:#0B1B2B;">')
    out.append('<div style="max-width:640px; margin:0 auto; background:#FBFAF6; border:1px solid #D7D2C2; border-top:4px solid #C8632A; border-radius:4px;">')
    out.append('<div style="padding:20px 24px; border-bottom:1px solid #E4E8EE;">')
    out.append('<div style="font-family: Archivo, Helvetica Neue, sans-serif; font-size:22px; font-weight:800; color:#0B1B2B; letter-spacing:-0.005em;">COMMAND<span style="color:#C8632A; font-weight:600;">sentry</span> ASM</div>')
    out.append(f'<div style="font-family: JetBrains Mono, ui-monospace, monospace; font-size:11px; letter-spacing:0.14em; text-transform:uppercase; color:#556574; margin-top:4px;">SURFACE CHANGES · {n_watch} WATCH · {n_notice} NOTICE · {len(by_asset)} ASSET(S)</div>')
    out.append('</div>')

    for asset, asset_alerts in by_asset.items():
        out.append('<div style="padding:18px 24px; border-bottom:1px solid #E4E8EE;">')
        out.append(f'<div style="font-family: JetBrains Mono, ui-monospace, monospace; font-size:14px; color:#0B1B2B; word-break:break-all; margin-bottom:8px;">{asset}</div>')
        for a in asset_alerts:
            color = severity_color(a.severity)
            bg    = "#F1E1D3" if a.severity == "watch" else "#F2F4F7"
            out.append(f'<div style="margin:8px 0; padding:10px 14px; background:{bg}; border-left:3px solid {color}; border-radius:3px;">')
            out.append(f'<div style="font-size:11px; font-family: JetBrains Mono, ui-monospace, monospace; letter-spacing:0.1em; text-transform:uppercase; color:{color}; font-weight:600;">{severity_label(a.severity)}</div>')
            out.append(f'<div style="font-size:14px; color:#0B1B2B; font-weight:500; margin-top:4px;">{a.title}</div>')
            if a.detail:
                out.append(f'<div style="font-size:13px; color:#2A3A4B; margin-top:4px;">{a.detail}</div>')
            out.append('</div>')
        out.append('</div>')

    out.append('<div style="padding:16px 24px; text-align:center;">')
    out.append(f'<a href="{DASHBOARD_URL}" style="display:inline-block; padding:9px 18px; background:#C8632A; color:#fff; text-decoration:none; border-radius:4px; font-family: Inter, sans-serif; font-size:14px; font-weight:600;">Open dashboard</a>')
    out.append('</div>')
    out.append('<div style="padding:0 24px 18px; text-align:center; font-family: JetBrains Mono, ui-monospace, monospace; font-size:10px; letter-spacing:0.14em; text-transform:uppercase; color:#8A97A4;">automated alert · do not reply</div>')
    out.append('</div></body></html>')
    return "".join(out)

def render_subject(alerts):
    n_watch = sum(1 for a in alerts if a.severity == "watch")
    if n_watch:
        return f"[COMMANDsentry] {n_watch} watch · {len(alerts)} surface change(s)"
    return f"[COMMANDsentry] {len(alerts)} surface change(s)"

def send_email(subject, html):
    body = json.dumps({
        "from":    f"{FROM_NAME} <{FROM_EMAIL}>",
        "to":      [TO_EMAIL],
        "subject": subject,
        "html":    html,
    })
    if not shutil.which("curl"):
        print("ERROR: curl not found.", file=sys.stderr)
        sys.exit(2)
    cmd = [
        "curl", "--silent", "--show-error", "--fail-with-body",
        "--max-time", "30",
        "--user-agent", "commandsentry-asm/2.0",
        "-X", "POST", "https://api.resend.com/emails",
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
    out = (result.stdout or "")[:1000]
    if result.returncode != 0 or "[HTTP 2" not in out:
        print(f"Resend failed (exit {result.returncode}): {out}  stderr={(result.stderr or '')[:300]}", file=sys.stderr)
        sys.exit(2)
    print(f"Resend OK: {out}", file=sys.stderr)

def main():
    if not API_KEY or not FROM_EMAIL or not TO_EMAIL:
        print("Email alerts disabled — RESEND_API_KEY / ALERT_FROM_EMAIL / ALERT_TO_EMAIL not all set. Skipping.")
        return
    alerts = collect_alerts()
    if not alerts:
        print("No surface-change alerts to send.")
        return
    print(f"Sending {len(alerts)} alert(s) to {TO_EMAIL}")
    send_email(render_subject(alerts), render_html(alerts))
    print("Email sent.")

if __name__ == "__main__":
    main()
