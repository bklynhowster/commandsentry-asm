"""approval.py — the digest comes to Howie first; he sends it on (KB 12 job 3l, 2026-10-26).

Howie, 2026-10-26 14:00: "I want the mail to come only to me, and then I have the ability to
approve it for further distribution." 14:05: "Why can't it be just in the email itself?"
14:17: "This should be a simple process. I don't want to have to go into a GitHub web page
every morning to simply approve it." 14:19: "Go."

So, every scheduled daily and Monday weekly:
  1. Sentry builds the email exactly as before, and sends it ONLY to the approver
     (repo variable ALERTER_APPROVER), with a strip on top: "Only you have this so far",
     who it would go to, and a "Send to the others" button.
  2. The button opens the portal's /digest/approve page; its "Send it" button marks the
     email approved (public.digest_approve, migration 20261026c).
  3. digest-send.yml (every 10 minutes, and fired by the portal at once) sends the stored
     email, byte for byte the one Howie read without the strip, to the others, then
     records the run and what was told.
  Not approved = nobody else gets it. The next daily is built from the last email that
  actually went out, so a skipped day rolls into it; building it retires the older one.

PURE. No database, no network. run_alerter.py does the reading, writing and sending.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from html import escape

APPROVAL_PREFIX = "For approval: "
APPROVE_PATH = "/digest/approve"
DAILY_EXPIRES_HOURS = 36          # the next daily retires it first; this is the backstop
WEEKLY_EXPIRES_HOURS = 7 * 24
MAX_SEND_ATTEMPTS = 3

STRIP_BG, STRIP_TEXT, STRIP_BUTTON = "#FFF1C2", "#3B2C00", "#14213D"
_FONT = "-apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif"
_BODY_OPEN = re.compile(r"<body\b[^>]*>")
TEXT_RULE = "-" * 64


def split_recipients(to_addrs: list[str], approver: str) -> tuple[list[str], list[str]]:
    """([approver], everyone else on ALERTER_TO). The approver is never also an 'other'
    (compared case-insensitively), so Howie gets one copy, the approval copy."""
    a = (approver or "").strip()
    if not a:
        return [], []
    others, seen = [], {a.lower()}
    for addr in to_addrs:
        k = addr.strip().lower()
        if k and k not in seen:
            seen.add(k)
            others.append(addr.strip())
    return [a], others


def new_token() -> str:
    """A one-time, unguessable token for the Send button (256 bits)."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """What the database keeps: sha256 hex of the token (the same as the migration's
    encode(sha256(convert_to(p_token, 'UTF8')), 'hex')). The token itself is never stored
    and never printed; it lives only in the approver's copy."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def fingerprint(subject: str, html: str, text: str) -> str:
    """sha256 over exactly what the others receive, checked again just before it is sent."""
    h = hashlib.sha256()
    for part in (subject, html, text):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def approve_url(portal_url: str, token: str) -> str:
    """The token rides in the #fragment: browsers never send a fragment to the server, so it
    stays out of every request log. The page reads it and posts it."""
    return f"{(portal_url or '').rstrip('/')}{APPROVE_PATH}#{token}"


def approval_subject(subject: str) -> str:
    return APPROVAL_PREFIX + subject


def _if_not(kind: str) -> str:
    if kind == "weekly":
        return "If you don't send it, nobody else gets this week's review."
    return "If you don't send it, nobody else gets it, and tomorrow's email will cover today too."


def strip_html(url: str, others: list[str], kind: str) -> str:
    who = ", ".join(escape(a) for a in others)
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'data-approval-strip="1"><tr><td align="center" style="padding:20px 8px 0;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'bgcolor="{STRIP_BG}" style="width:100%;max-width:640px;background:{STRIP_BG};border-radius:14px;">'
        f'<tr><td style="padding:18px 24px 6px;font-family:{_FONT};font-size:17px;line-height:1.35;'
        f'font-weight:700;color:{STRIP_TEXT};">Only you have this so far.</td></tr>'
        f'<tr><td style="padding:0 24px 14px;font-family:{_FONT};font-size:14px;line-height:1.5;'
        f'color:{STRIP_TEXT};">Send it to: {who}</td></tr>'
        '<tr><td style="padding:0 24px 12px;"><table role="presentation" cellpadding="0" cellspacing="0" '
        f'border="0"><tr><td bgcolor="{STRIP_BUTTON}" style="background:{STRIP_BUTTON};border-radius:8px;">'
        f'<a href="{escape(url)}" style="display:inline-block;padding:12px 20px;font-family:{_FONT};'
        'font-size:15px;font-weight:700;color:#FFFFFF;text-decoration:none;">Send to the others</a>'
        '</td></tr></table></td></tr>'
        f'<tr><td style="padding:0 24px 18px;font-family:{_FONT};font-size:13px;line-height:1.5;'
        f'color:{STRIP_TEXT};">{escape(_if_not(kind))}</td></tr>'
        '</table></td></tr></table>'
    )


def strip_text(url: str, others: list[str], kind: str) -> str:
    return "\n".join([
        "ONLY YOU HAVE THIS SO FAR.",
        f"Send it to: {', '.join(others)}",
        f"Send to the others: {url}",
        _if_not(kind),
        TEXT_RULE,
        "",
    ])


def with_strip_html(html: str, strip: str) -> str:
    """The approver's copy: the others' HTML with the strip right after <body>. Nothing else
    differs, so what Howie reads is what they get."""
    m = _BODY_OPEN.search(html)
    if not m:
        raise ValueError("no <body> in the digest HTML")
    return html[:m.end()] + "\n" + strip + html[m.end():]


def with_strip_text(text: str, strip: str) -> str:
    return strip + text


def approver_copy(subject: str, html: str, text: str, *, url: str, others: list[str], kind: str):
    """(subject, html, text) for the approver, from exactly what the others will get."""
    return (approval_subject(subject),
            with_strip_html(html, strip_html(url, others, kind)),
            with_strip_text(text, strip_text(url, others, kind)))
