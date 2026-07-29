#!/usr/bin/env python3
"""
mailer.py — one send path, provider chosen by env. 2026-07-29.

    MAIL_PROVIDER = "sendgrid" (default) | "smtp"

WHY THIS EXISTS. The two scanner-side senders — scripts/db/import_asm_to_surface.py
and scripts/alerter/run_alerter.py — were **SendGrid-only**, hardcoded, in BOTH
repos. Prodex does not use SendGrid: per Obsidian 135 its mail is iCloud SMTP
(MAIL_PROVIDER=smtp, smtp.mail.me.com), which is what the PORTAL already speaks
via src/lib/email.ts. So Prodex scanner-side email had no working transport at
all — real-time asset-surface notifications and the daily posture digest could
never send from that instance. Not a leak; a silent functional gap.

THIS IS NOT A PARITY DEVIATION. Both repos ship this identical file. Command
sets MAIL_PROVIDER=sendgrid (or omits it — that's the default, so Command is
unchanged with no env set); Prodex sets MAIL_PROVIDER=smtp. Same code, different
env — the standing parity rule working as intended, not an exception to it. The
alternative (forking Prodex's senders) would have created the drift the rule
exists to prevent.

DELIBERATELY MIRRORS THE PORTAL (src/lib/email.ts) rather than inventing a
second pattern: same env names (MAIL_PROVIDER, SMTP_HOST/PORT/USER/PASS), same
default provider, same `secure = port == 465` rule (465 implicit TLS, 587
STARTTLS), same warn-and-return-False when config is missing. One mental model
across portal and scanner.

NO NEW DEPENDENCY. The portal uses nodemailer; here it's stdlib `smtplib` +
`email.message`, so nothing to install on the runner.

BEST-EFFORT BY CONTRACT. Never raises. Returns (ok, detail). Both callers treat
email as an augmentation — the DB rows are the durable signal — so a mail
failure must never take down a scan or an import.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Sequence

# ── PROVIDER DECISION — do not remove this branch (4.7 M1/M4, Obsidian 164) ──
# MAIL_PROVIDER chooses transport at runtime.
#   Command : sendgrid  — SENDGRID_API_KEY in that repo's Actions secrets.
#   Prodex  : smtp/iCloud — SMTP_HOST/PORT/USER/PASS in that repo's secrets.
# The portal mirrors this exact branch in TypeScript (src/lib/email.ts) and uses
# the SAME six env names — verified identical, do not rename on one side only.
#
# DUAL-PROVIDER IS DELIBERATE AND RATIFIED (M4). Do NOT "unify" these. Command's
# SendGrid is IronPort-trusted and domain-verified (D-031) and has real
# recipients; iCloud SMTP from a GitHub runner would lose that trust and break
# domain alignment, so unifying makes deliverability WORSE for the instance that
# actually needs it. Prodex has no comparable deliverability requirement.
# Revisit only if Prodex grows an external recipient list.
__all__ = ["send_email", "provider_name", "describe_config", "check_config",
           "warn_if_unconfigured"]

_SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


def provider_name() -> str:
    """Lowercased provider. Default 'sendgrid' keeps Command unchanged."""
    return (os.environ.get("MAIL_PROVIDER") or "sendgrid").strip().lower()


def describe_config() -> str:
    """One-line, credential-free summary for logs — makes a misconfigured
    instance obvious in CI output instead of silently not sending."""
    p = provider_name()
    if p == "smtp":
        return (f"provider=smtp host={os.environ.get('SMTP_HOST') or '(unset)'} "
                f"port={os.environ.get('SMTP_PORT') or '587'} "
                f"user={'set' if os.environ.get('SMTP_USER') else '(unset)'} "
                f"pass={'set' if os.environ.get('SMTP_PASS') else '(unset)'}")
    return f"provider=sendgrid key={'set' if os.environ.get('SENDGRID_API_KEY') else '(unset)'}"


def check_config() -> tuple[bool, str]:
    """Startup assertion (4.7 M5). Returns (configured, message).

    Called at process start, NOT on first send — an operator who mistypes an env
    var should see it immediately, not hours later when the digest tries to go
    out. Messages are DIFFERENTIATED per failure state so the operator can fix
    the specific thing rather than investigate a generic "unconfigured".
    """
    p = provider_name()
    if p == "smtp":
        missing = [n for n in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS")
                   if not os.environ.get(n)]
        if missing:
            return False, (f"SMTP provider selected but {', '.join(missing)} missing "
                           f"— this instance cannot send mail.")
        return True, f"smtp -> {os.environ.get('SMTP_HOST')}:{os.environ.get('SMTP_PORT') or '587'}"
    if p == "sendgrid":
        if not os.environ.get("SENDGRID_API_KEY"):
            explicit = "MAIL_PROVIDER" in os.environ
            how = "selected" if explicit else "selected by default"
            return False, (f"SendGrid provider {how} but SENDGRID_API_KEY missing "
                           f"— this instance cannot send mail. Set SENDGRID_API_KEY, "
                           f"or set MAIL_PROVIDER=smtp if this instance uses SMTP.")
        return True, "sendgrid -> api key set"
    return False, (f"MAIL_PROVIDER={p!r} is not a known provider "
                   f"(expected 'sendgrid' or 'smtp') — this instance cannot send mail.")


def warn_if_unconfigured(instance_hint: str = "") -> bool:
    """Emit ONE ::warning:: per process if mail can't send. Returns configured?

    ::warning::, deliberately NOT ::error:: (4.7 M5) — escalating would fail the
    workflow and break the standing "mail must never fail a scan" contract. This
    is visible on the Actions summary page without blocking anything. Per-run,
    not per-send; no persistent state, so it clears itself once configured.
    """
    ok, msg = check_config()
    if not ok:
        tag = f"[{instance_hint}] " if instance_hint else ""
        print(f"::warning::[MAIL_UNCONFIGURED] {tag}{msg}", file=sys.stderr)
    return ok


def send_email(
    *,
    to_addrs: Sequence[str],
    subject: str,
    html: str,
    text: str = "",
    from_addr: str = "",
    from_name: str = "",
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> tuple[bool, str]:
    """Send one message via the configured provider.

    Returns (ok, detail). Never raises — see module docstring.
    `headers` (List-Unsubscribe etc.) is honoured by both providers.
    """
    to_addrs = [a for a in (to_addrs or []) if a]
    if not to_addrs:
        return False, "no recipients"
    if not from_addr:
        return False, "no from_addr (set ALERTER_FROM)"

    p = provider_name()
    if p == "smtp":
        return _send_smtp(to_addrs, subject, html, text, from_addr, from_name,
                          headers or {}, timeout)
    if p == "sendgrid":
        return _send_sendgrid(to_addrs, subject, html, text, from_addr, from_name,
                              headers or {}, timeout)
    return False, f"unknown MAIL_PROVIDER={p!r} (expected 'sendgrid' or 'smtp')"


# ── SendGrid ──────────────────────────────────────────────────────────────
def _send_sendgrid(to_addrs, subject, html, text, from_addr, from_name,
                   headers, timeout) -> tuple[bool, str]:
    api_key = os.environ.get("SENDGRID_API_KEY")
    if not api_key:
        return False, "SENDGRID_API_KEY not set"

    content = []
    if text:
        # text/plain first so HTML-capable clients pick the html alternative.
        content.append({"type": "text/plain", "value": text})
    content.append({"type": "text/html", "value": html})

    payload = {
        "personalizations": [{"to": [{"email": a} for a in to_addrs]}],
        "from": {"email": from_addr, "name": from_name or from_addr},
        "subject": subject,
        "content": content,
    }
    if headers:
        payload["headers"] = headers

    req = urllib.request.Request(
        url=_SENDGRID_URL,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "asm-mailer/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"sendgrid {resp.status} id={resp.headers.get('X-Message-Id') or ''}"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        return False, f"sendgrid HTTP {e.code}: {body}"
    except Exception as e:  # noqa — best-effort by contract
        return False, f"sendgrid error: {e!r}"


# ── SMTP (iCloud et al.) ──────────────────────────────────────────────────
def _send_smtp(to_addrs, subject, html, text, from_addr, from_name,
               headers, timeout) -> tuple[bool, str]:
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT") or "587")
    user = os.environ.get("SMTP_USER")
    pw = os.environ.get("SMTP_PASS")
    if not (host and user and pw):
        # Same shape as the portal's warn-and-skip.
        return False, "SMTP_HOST/USER/PASS not all set"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = ", ".join(to_addrs)
    for k, v in (headers or {}).items():
        msg[k] = v
    # set_content = text/plain root; add_alternative promotes to multipart/alternative
    msg.set_content(text or "This message requires an HTML-capable client.")
    msg.add_alternative(html, subtype="html")

    try:
        ctx = ssl.create_default_context()
        if port == 465:
            # Implicit TLS — same rule as the portal's `secure: port === 465`.
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as s:
                s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
                s.login(user, pw)
                s.send_message(msg)
        return True, f"smtp {host}:{port} -> {len(to_addrs)} recipient(s)"
    except Exception as e:  # noqa — best-effort by contract
        return False, f"smtp error: {e!r}"
