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
  SENDGRID_API_KEY  — SendGrid API key (required; same secret as the digest)
  ALERT_FROM_EMAIL  — sender (optional; defaults to CommandSentry@commandcompanies.com)
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

API_KEY        = os.environ.get("SENDGRID_API_KEY", "").strip()
FROM_EMAIL     = os.environ.get("ALERT_FROM_EMAIL", "CommandSentry@commandcompanies.com").strip()
FROM_NAME      = os.environ.get("ALERT_FROM_NAME", "COMMANDsentry ASM").strip()
TO_EMAIL       = os.environ.get("ALERT_TO_EMAIL", "").strip()
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "https://commandsentry-asm.netlify.app").strip()
SCAN_WINDOW_HR = int(os.environ.get("ALERT_SCAN_WINDOW", "12"))

REPO_ROOT  = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "data" / "assets"
STATE_DIR  = REPO_ROOT / "data" / "state"
CERT_STATE_FILE = STATE_DIR / "cert_alert_tiers.json"

# IP prefixes for managed-hosting providers that auto-renew certs. Cert
# expiry alerts for these are suppressed at NOTICE tier (only fire WATCH
# under 7 days, in case the provider's auto-renewal genuinely fails).
PRESSABLE_IP_PREFIXES = ("199.16.172.", "199.16.173.")
WPENGINE_IP_PREFIXES  = ("141.193.213.", "141.193.32.", "141.193.221.")  # Flywheel/WPE; partial
CLOUDFLARE_IP_PREFIXES = (
    "104.16.",  "104.17.",  "104.18.",  "104.19.",  "104.20.",  "104.21.",
    "104.22.",  "104.23.",  "104.24.",  "104.25.",  "104.26.",  "104.27.",
    "104.28.",  "104.29.",  "104.30.",  "104.31.",
    "172.64.",  "172.65.",  "172.66.",  "172.67.",  "172.68.",  "172.69.",
    "172.70.",  "172.71.",
)
AUTORENEW_IP_PREFIXES = PRESSABLE_IP_PREFIXES + WPENGINE_IP_PREFIXES + CLOUDFLARE_IP_PREFIXES


# ---------------------------------------------------------------------------
# Cert-expiry tier-cross helpers
#
# Old behavior was THRESHOLD-based: any cert with days_to_expiry < 30 fired a
# NOTICE on every scan → 23 daily emails per cert as it counted down.
#
# New behavior is TIER-CROSS-based: tiers at 30 / 14 / 7 / 3 / 1 days. Fire
# only when a cert crosses into a more-urgent tier. State persists between
# scans in data/state/cert_alert_tiers.json (committed by the asm-discover
# workflow alongside data/assets/).
#
# First-run behavior: if no state file exists, record current tiers WITHOUT
# firing alerts. Avoids dumping a flood of "currently in tier X" notices on
# the day the new logic deploys. Renewals (cert moves back to a safer tier)
# are silent — state updates so the next downward cross re-fires correctly.
# ---------------------------------------------------------------------------

def cert_tier(days: int) -> int:
    """Lower number = safer. 0 means no alert at all."""
    if days < 1:    return 5
    if days < 3:    return 4
    if days < 7:    return 3
    if days < 14:   return 2
    if days < 30:   return 1
    return 0

def is_autorenew_ip(ip: str) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in AUTORENEW_IP_PREFIXES)

def load_cert_state() -> dict:
    if not CERT_STATE_FILE.exists():
        return {}
    try:
        return json.loads(CERT_STATE_FILE.read_text())
    except Exception:
        return {}

def save_cert_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CERT_STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

class Alert:
    __slots__ = ("severity", "asset", "kind", "title", "detail")
    def __init__(self, severity, asset, kind, title, detail=""):
        self.severity, self.asset, self.kind, self.title, self.detail = severity, asset, kind, title, detail

def collect_alerts() -> list[Alert]:
    out: list[Alert] = []
    if not ASSETS_DIR.exists():
        return out
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=SCAN_WINDOW_HR)

    # Cert tier-cross state. Empty dict on first run → seed-without-firing.
    cert_state          = load_cert_state()
    cert_state_dirty    = False
    cert_state_seeding  = (len(cert_state) == 0 and not CERT_STATE_FILE.exists())

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

        # Two-scan-confirmation logic for 'new' alerts. The previous version
        # of this code suppressed alerts when X appeared in the prior 3 scans
        # (handles 'X went away then came back'). But it still fired on the
        # FIRST sighting — which catches single-scan wordlist flickers as
        # false positives (e.g. accounts.sciimage.com surfaced once via dig
        # then never resolved again).
        #
        # New approach: a sub / (sub,ip) / (sub,ip,port) only fires its 'new'
        # alert when present in BOTH the current scan AND the immediately
        # previous scan, AND absent from all retained earlier scans. This:
        #   1. Silences single-scan flickers (false positives) — they never
        #      get the 2-scan confirmation
        #   2. Delays legit alerts by one scan (~6h at default cadence) —
        #      acceptable trade for filtered noise
        #   3. Subsumes the prior 'recent absence' check — a sub seen earlier
        #      then re-found is in earlier_set, so it's filtered out
        history = asset.get("history") or []
        if len(history) < 2:
            # Not enough history yet to do 2-scan confirmation — skip the
            # 'new' alerts entirely. (The first-scan alert is handled
            # separately as 'first_scan' above.)
            confirmed_new_subs = set()
            confirmed_new_hosts = set()        # set of (sub, ip)
            confirmed_new_services = set()     # set of (sub, ip, port)
        else:
            current = history[-1]
            prev = history[-2]
            earlier = history[:-2]

            # Build subdomain sets
            current_subs  = set(current.get("subdomain_names") or [])
            prev_subs     = set(prev.get("subdomain_names") or [])
            earlier_subs  = set()
            for entry in earlier:
                earlier_subs.update(entry.get("subdomain_names") or [])
            confirmed_new_subs = (current_subs & prev_subs) - earlier_subs

            # Build (sub, ip) sets from ports_by_sub
            def host_set(entry: dict) -> set:
                bag = set()
                for sub_name, ip_map in (entry.get("ports_by_sub") or {}).items():
                    for ip in (ip_map or {}).keys():
                        bag.add((sub_name, ip))
                return bag
            current_hosts = host_set(current)
            prev_hosts    = host_set(prev)
            earlier_hosts = set()
            for entry in earlier:
                earlier_hosts.update(host_set(entry))
            confirmed_new_hosts = (current_hosts & prev_hosts) - earlier_hosts

            # Build (sub, ip, port) sets from ports_by_sub
            def service_set(entry: dict) -> set:
                bag = set()
                for sub_name, ip_map in (entry.get("ports_by_sub") or {}).items():
                    for ip, ports in (ip_map or {}).items():
                        for port in ports:
                            bag.add((sub_name, ip, port))
                return bag
            current_svcs = service_set(current)
            prev_svcs    = service_set(prev)
            earlier_svcs = set()
            for entry in earlier:
                earlier_svcs.update(service_set(entry))
            confirmed_new_services = (current_svcs & prev_svcs) - earlier_svcs

        # WATCH: new hosts — confirmed by 2 consecutive scans, never seen before
        for (sub, ip) in sorted(confirmed_new_hosts):
            out.append(Alert(
                "watch", aname, "new_host",
                f"New host IP {ip} on {sub}",
                "Confirmed by 2 consecutive scans. Hosting expanded or moved."
            ))
        # Removals still come from deltas — single-scan removal is fine,
        # the symmetric 'gone' suppression handled below uses its own threshold.
        for h in (removed.get("hosts") or []):
            sub = h.get("subdomain") or "?"
            out.append(Alert("notice", aname, "host_removed",
                             f"Host IP {h.get('ip')} removed from {sub}", ""))

        # WATCH: new services — confirmed by 2 consecutive scans, never seen before
        for (sub, ip, port) in sorted(confirmed_new_services):
            out.append(Alert(
                "watch", aname, "new_service",
                f"New service open on {sub}: {port}/tcp",
                f"On host {ip}. Confirmed by 2 consecutive scans."
            ))
        for s in (removed.get("services") or []):
            sub = s.get("subdomain") or "?"
            out.append(Alert("notice", aname, "service_closed",
                             f"Service closed on {sub}: {s.get('port')}/{s.get('protocol')}", ""))

        # NOTICE: new subdomain — confirmed by 2 consecutive scans, never seen before
        for sub in sorted(confirmed_new_subs):
            out.append(Alert("notice", aname, "new_subdomain",
                             f"New subdomain discovered: {sub}",
                             "Confirmed by 2 consecutive scans. Surfaced via multi-source enumeration (passive CT logs, DNS records, wordlist brute-force, or TLS cert SANs)."))

        # NOTICE: subdomain went away — but ONLY fire if it's been absent for
        # 3+ consecutive scans. The wordlist enum is probabilistic (parallel
        # dig with 2-sec timeout); a single network blip can make a sub appear
        # 'missing' from one scan even though it still resolves fine. Requires
        # the new 'subdomain_names' field in each history entry (populated by
        # normalize.py and the backfill script).
        ABSENCE_THRESHOLD = 3
        history = asset.get("history") or []
        recent = history[-ABSENCE_THRESHOLD:] if len(history) >= ABSENCE_THRESHOLD else history
        for sub in (removed.get("subdomains") or []):
            # Skip the alert if any of the last N scans (including the current
            # one which is at history[-1]) had this sub present.
            absent_streak = 0
            for entry in reversed(history):
                names = entry.get("subdomain_names") or []
                if sub in names:
                    break
                absent_streak += 1
                if absent_streak >= ABSENCE_THRESHOLD:
                    break
            if absent_streak >= ABSENCE_THRESHOLD:
                out.append(Alert("notice", aname, "subdomain_gone",
                                 f"Subdomain went away: {sub}",
                                 f"Not seen in the last {ABSENCE_THRESHOLD} consecutive scans."))

        # NOTICE: tech version changes — 2-scan-confirmation required.
        #
        # Single-scan flickers (e.g. Pressable cache nodes briefly disagreeing
        # on a plugin readme version, or a probabilistic fingerprint resolver
        # pulling from a different source) used to fire false-positive alert
        # emails. Classic case: Yoast SEO 27.6 → 27.5 → 27.6 flip-flop across
        # consecutive scans. The old code path read `changed.fingerprint`
        # directly from this scan's deltas with no stability gate.
        #
        # New gate: a version change only fires if the new value persists
        # across 2 consecutive scans AND a different known prior value
        # existed in the scan before that. State machine:
        #   N-2: A    N-1: B    N: B   → fire "A → B" (B confirmed stable)
        #   N-2: A    N-1: B    N: A   → flicker, suppress
        #   N-2: A    N-1: A    N: A   → no change
        # Real upgrades fire on the scan immediately after they stabilize
        # (~6h max delay at our cadence). Cold start: assets with fewer than
        # 3 history entries with tech_versions populated get no tech_change
        # alerts (only affects first ~18h after this code ships, since
        # existing history entries lack the tech_versions field).
        history = asset.get("history") or []
        if len(history) >= 3:
            current_tv = (history[-1].get("tech_versions") or {})
            prev_tv = (history[-2].get("tech_versions") or {})
            prev_prev_tv = (history[-3].get("tech_versions") or {})
            for name, cur_v in current_tv.items():
                prv_v = prev_tv.get(name)
                old_v = prev_prev_tv.get(name)
                if not (cur_v and prv_v and old_v):
                    continue  # missing data — can't confirm
                if cur_v != prv_v:
                    continue  # new value hasn't stabilized across 2 scans
                if old_v == cur_v:
                    continue  # no actual change
                # Confirmed version transition: old_v → cur_v.
                # Attribute to current subs running this name+version.
                subs_with: list[str] = []
                for sub in (asset.get("subdomains") or []):
                    fp = sub.get("fingerprint") or {}
                    for t in (fp.get("tech") or []):
                        if t.get("name") == name and str(t.get("version") or "") == cur_v:
                            sn = sub.get("name")
                            if sn:
                                subs_with.append(sn)
                            break
                subs_with = sorted(set(subs_with))
                count = len(subs_with)
                title = f"{name} {old_v} → {cur_v}"
                if count == 1:
                    title = f"{subs_with[0]}: {title}"
                    detail = "Detected version change in tech fingerprint. Confirmed by 2 consecutive scans."
                elif count > 1:
                    title = f"{title} (on {count} subs)"
                    detail = (
                        "Detected version change in tech fingerprint. "
                        f"Confirmed by 2 consecutive scans. Affected: {', '.join(subs_with)}"
                    )
                else:
                    detail = "Detected version change in tech fingerprint. Confirmed by 2 consecutive scans."
                out.append(Alert("notice", aname, "tech_changed", title, detail))

        # WATCH: cert chain changed (per subdomain)
        for c in (changed.get("cert") or []):
            sub = c.get("subdomain") or "?"
            out.append(Alert(
                "watch", aname, "cert_changed",
                f"Certificate chain changed on {sub}",
                f"Issuer set: {(c.get('from') or [])} → {(c.get('to') or [])}"
            ))

        # Cert expiry — TIER-CROSS-based, not threshold. Tiers at
        # 30 / 14 / 7 / 3 / 1 days; alert fires only when a cert crosses
        # into a more-urgent tier. Auto-renew managed-hosting IPs
        # (Pressable, WP Engine, Cloudflare) suppress NOTICE-tier alerts
        # since they auto-rotate; only fire WATCH (<7d) for those, in case
        # the provider's renewal genuinely fails.
        #
        # See cert_tier(), is_autorenew_ip(), load_cert_state() above.
        for sub in (asset.get("subdomains") or []):
            sub_name = sub.get("name", "?")
            for svc in (sub.get("services") or []):
                cert = svc.get("cert") or {}
                days = cert.get("days_to_expiry")
                if not isinstance(days, (int, float)):
                    continue
                ip   = svc.get("ip") or ""
                port = svc.get("port") or ""
                label = f"{sub_name} ({ip}:{port})"
                key   = f"{aname}::{sub_name}::{ip}::{port}"

                current = cert_tier(int(days))
                previous = cert_state.get(key, 0)

                # No-op tiers
                if current == previous:
                    continue
                # Renewal — cert moved BACK to a safer tier. Silent; state
                # resets so next downward cross re-fires correctly.
                if current < previous:
                    cert_state[key]  = current
                    cert_state_dirty = True
                    continue
                # First-run seeding: record tiers but don't fire anything.
                if cert_state_seeding:
                    cert_state[key]  = current
                    cert_state_dirty = True
                    continue
                # Auto-renew host: suppress NOTICE tiers (1, 2). Update state
                # so we still escalate properly when it drops to WATCH (3+).
                if is_autorenew_ip(ip) and current < 3:
                    cert_state[key]  = current
                    cert_state_dirty = True
                    continue

                # Real alert.
                severity = "watch" if current >= 3 else "notice"
                out.append(Alert(severity, aname, "cert_expiring",
                                 f"Cert on {label} expires in {int(days)} day(s)",
                                 f"Issuer: {cert.get('issuer') or '?'}"))
                cert_state[key]  = current
                cert_state_dirty = True

        # WATCH/notice: root liveness TRANSITIONS — only for domain-type assets
        # where HTTP liveness is a meaningful signal. Two important fixes vs
        # the prior implementation:
        #   1. Asset-type gate (apex/fqdn only) — IP assets don't speak HTTP
        #      at the bare IP, so 'not live' is normal, not an outage.
        #   2. CHANGE-based, not STATE-based — we fire on the transition
        #      (live → offline or offline → live), not on persistent state.
        #      The reachability change feed is computed in normalize.py.
        asset_type = (asset.get("asset") or {}).get("type") or ""
        if asset_type in ("apex", "fqdn"):
            for r in (changed.get("reachability") or []):
                if not r.get("is_root"):
                    continue
                if r.get("from") is True and r.get("to") is False:
                    out.append(Alert("watch", aname, "asset_offline",
                                     f"Domain {aname} root went offline",
                                     "Root was responding to HTTP in the previous scan, now it isn't."))
                elif r.get("from") is False and r.get("to") is True:
                    out.append(Alert("notice", aname, "asset_back_online",
                                     f"Domain {aname} root came back online",
                                     "Root was not responding to HTTP in the previous scan, now it is."))

    # Persist cert-tier state for next run.
    if cert_state_dirty or cert_state_seeding:
        save_cert_state(cert_state)

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
    # SendGrid v3 shape (migrated from Resend/Golden Lane 2026-07-01, D-031):
    # recipients under personalizations[].to[], sender as {email,name}, MIME
    # under content[]. Success = HTTP 202 (empty body).
    body = json.dumps({
        "personalizations": [{"to": [{"email": TO_EMAIL}]}],
        "from":    {"email": FROM_EMAIL, "name": FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/html", "value": html}],
    })
    if not shutil.which("curl"):
        print("ERROR: curl not found.", file=sys.stderr)
        sys.exit(2)
    cmd = [
        "curl", "--silent", "--show-error", "--fail-with-body",
        "--max-time", "30",
        "--user-agent", "commandsentry-asm/2.0",
        "-X", "POST", "https://api.sendgrid.com/v3/mail/send",
        "-H", f"Authorization: Bearer {API_KEY}",
        "-H", "Content-Type: application/json",
        "-w", "\n[HTTP %{http_code}]",
        "--data-binary", body,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    except subprocess.TimeoutExpired:
        print("SendGrid network error: curl timed out", file=sys.stderr)
        sys.exit(2)
    out = (result.stdout or "")[:1000]
    if result.returncode != 0 or "[HTTP 2" not in out:
        print(f"SendGrid failed (exit {result.returncode}): {out}  stderr={(result.stderr or '')[:300]}", file=sys.stderr)
        sys.exit(2)
    print(f"SendGrid OK: {out}", file=sys.stderr)

def main():
    if not API_KEY or not FROM_EMAIL or not TO_EMAIL:
        print("Email alerts disabled — SENDGRID_API_KEY / ALERT_TO_EMAIL not set. Skipping.")
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
