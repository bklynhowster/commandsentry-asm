"""approval.py — the digest comes to Howie first; he sends it on (KB 12 job 3l, 2026-10-26).

Howie, 2026-10-26 14:00: "I want the mail to come only to me, and then I have the ability to
approve it for further distribution." 14:05: "Why can't it be just in the email itself?"
14:17: "This should be a simple process. I don't want to have to go into a GitHub web page
every morning to simply approve it." 14:19: "Go."

So, every scheduled daily and Monday weekly:
  1. Sentry builds the email exactly as before, and sends it ONLY to the approver
     (repo variable ALERTER_APPROVER), with a strip on top: "Only you have this so far" and
     who it would go to; and, under the email, a "Send to the others" button (2026-10-29).
  2. The button opens the portal's /digest/approve page; its "Send it" button marks the
     email approved (public.digest_approve, migration 20261026c).
  3. digest-send.yml (every 10 minutes, and fired by the portal at once) sends the stored
     email, byte for byte the one Howie read without the strip, to the others, then
     records the run and what was told.
  Not approved = nobody else gets it. The next daily is built from the last email that
  actually went out, so a skipped day rolls into it; building it retires the older one.

Round 5 (2026-10-27, Howie 08:46–08:47): his copy carries TWO one-time buttons, "Approve for
email" (the email, exactly as the others get it) and "Post to Slack" (a different, shorter
piece of writing for the developers in #on-call), each its own decision; the Slack draft is
shown above its button; the Slack button is absent on a day with nothing for a developer.
With no Slack half given, the strip is the 3l one (Command's daily).

2026-10-29 (Howie 08:37: "maybe we put the 'Approve for email' right under the email message";
15:51: "Seems pretty perfect to me. Push it"): every button sits under what it sends. The top
strip keeps the note and the #on-call draft with its button; the email's own button moves to a
second strip right under the email (bottom_html), on both instances.

PURE. No database, no network. run_alerter.py does the reading, writing and sending.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from html import escape

APPROVAL_PREFIX = "For approval: "
APPROVE_PATH = "/digest/approve"
DAILY_EXPIRES_HOURS = 36          # the next daily retires it first; this is the backstop
WEEKLY_EXPIRES_HOURS = 7 * 24
MAX_SEND_ATTEMPTS = 3
DAILY_EXPIRES_VAR = "DIGEST_DAILY_EXPIRES_HOURS"   # round 5, ruling 3: Prodex sets 24; unset = 36


def daily_expires_hours(env=None) -> int:
    """Per instance: a daily expires when the next one is built (Howie, 2026-10-27 09:53,
    ruling 3) — Prodex sets DIGEST_DAILY_EXPIRES_HOURS=24; an unset or bad value keeps 36, so
    Command is unchanged (the review's M5: this file is byte-identical in both repos)."""
    raw = (env if env is not None else os.environ).get(DAILY_EXPIRES_VAR, "")
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return DAILY_EXPIRES_HOURS
    return n if 1 <= n <= 24 * 14 else DAILY_EXPIRES_HOURS

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


def _box_html(attr: str, rows: str, pad: str) -> str:
    """One yellow box, centred, 640 wide: the strip's frame, shared by the top and the bottom."""
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'data-approval-strip="{attr}"><tr><td align="center" style="padding:{pad};">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'bgcolor="{STRIP_BG}" style="width:100%;max-width:640px;background:{STRIP_BG};border-radius:14px;">'
        + rows + '</table></td></tr></table>'
    )


def _button_html(url: str, label: str, color: str) -> str:
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
            f'<td bgcolor="{color}" style="background:{color};border-radius:8px;">'
            f'<a href="{escape(url)}" style="display:inline-block;padding:12px 20px;font-family:{_FONT};'
            f'font-size:15px;font-weight:700;color:#FFFFFF;text-decoration:none;">{label}</a>'
            '</td></tr></table>')


# Gmail cuts an email off at about 102 KB ("[Message clipped] View entire message"), and the
# email's button now sits at the very end. Past this size the top strip carries the button too,
# so it is never hidden behind that link. A daily is about 10 KB; this is for a long weekly.
# Gmail counts bytes of the whole HTML Howie gets, strips included, and an em dash or a bullet
# is 3 bytes (code review of push-373, minor 2), so the guard measures the same: UTF-8 bytes of
# the finished copy.
CLIP_SAFE_BYTES = 90_000


def _too_long(html: str) -> bool:
    return len(html.encode("utf-8")) > CLIP_SAFE_BYTES


def _top_button_row(url: str, label: str) -> str:
    return f'<tr><td style="padding:0 24px 14px;">{_button_html(url, label, STRIP_BUTTON)}</td></tr>'


def bottom_html(url: str, label: str, kind: str) -> str:
    """Under the email (Howie 2026-10-29 08:37: "maybe we put the 'Approve for email' right
    under the email message"; 15:51: "Push it"): the email's own button, then what happens if
    he does nothing. Every button now sits under what it sends. `label` is HTML-safe."""
    return _box_html(
        "bottom",
        f'<tr><td style="padding:18px 24px 12px;">{_button_html(url, label, STRIP_BUTTON)}</td></tr>'
        f'<tr><td style="padding:0 24px 18px;font-family:{_FONT};font-size:13px;line-height:1.5;'
        f'color:{STRIP_TEXT};">{escape(_if_not(kind))}</td></tr>',
        "0 8px 32px")


def bottom_text(url: str, label: str, kind: str) -> str:
    return "\n".join([TEXT_RULE, f"{label}: {url}", _if_not(kind)])


def strip_html(url: str, others: list[str], kind: str, *, top_button: bool = False) -> str:
    who = ", ".join(escape(a) for a in others)
    return _box_html(
        "1",
        f'<tr><td style="padding:18px 24px 6px;font-family:{_FONT};font-size:17px;line-height:1.35;'
        f'font-weight:700;color:{STRIP_TEXT};">Only you have this so far.</td></tr>'
        f'<tr><td style="padding:0 24px 6px;font-family:{_FONT};font-size:14px;line-height:1.5;'
        f'color:{STRIP_TEXT};">Send it to: {who}</td></tr>'
        + (_top_button_row(url, "Send to the others") if top_button else "") +
        f'<tr><td style="padding:0 24px 18px;font-family:{_FONT};font-size:13px;line-height:1.5;'
        f'color:{STRIP_TEXT};">Below: the email exactly as the others would get it, with its button under it.</td></tr>',
        "20px 8px 0")


def strip_text(url: str, others: list[str], kind: str) -> str:
    return "\n".join([
        "ONLY YOU HAVE THIS SO FAR.",
        f"Send it to: {', '.join(others)}",
        "The email follows; the link to send it is at the end.",
        TEXT_RULE,
        "",
    ])


def with_strip_html(html: str, strip: str) -> str:
    """The approver's copy: the others' HTML with the strip right after <body> (and, since
    10-29, the email's button just before </body>). Nothing else differs, so what Howie reads
    between the two is what they get."""
    m = _BODY_OPEN.search(html)
    if not m:
        raise ValueError("no <body> in the digest HTML")
    return html[:m.end()] + "\n" + strip + html[m.end():]


def with_strip_text(text: str, strip: str) -> str:
    return strip + text


_BODY_CLOSE = "</body>"


def with_bottom_html(html: str, bottom: str) -> str:
    """The email's button, right under the email: just before the last </body>."""
    i = html.rfind(_BODY_CLOSE)
    if i < 0:
        raise ValueError("no </body> in the digest HTML")
    return html[:i] + bottom + "\n" + html[i:]


def with_bottom_text(text: str, bottom: str) -> str:
    return text.rstrip("\n") + "\n\n" + bottom + "\n"


def approver_copy(subject: str, html: str, text: str, *, url: str, others: list[str], kind: str,
                  slack: dict | None = None, notes: list[str] | None = None):
    """(subject, html, text) for the approver, from exactly what the others will get, with a
    strip on top and the email's button under the email (10-29). With `slack` (round 5) the top
    strip carries the Slack draft and its button; `notes` are lines for the approver only
    (Sentry's own problems, a fallback reason). Neither given = the 3l strip."""
    if slack is None and not notes:
        label = "Send to the others"

        def build(top: bool) -> str:
            return with_bottom_html(with_strip_html(html, strip_html(url, others, kind, top_button=top)),
                                    bottom_html(url, label, kind))
        out = build(False)
        return (approval_subject(subject), build(True) if _too_long(out) else out,
                with_bottom_text(with_strip_text(text, strip_text(url, others, kind)), bottom_text(url, label, kind)))
    who = ", ".join(escape(a) for a in others)

    def build_v2(top: bool) -> str:
        return with_bottom_html(with_strip_html(html, strip_html_v2(url, others, kind, slack=slack, notes=notes or [],
                                                                    top_button=top)),
                                bottom_html(url, f"Approve for email&nbsp;&nbsp;&rarr; {who}", kind))
    out = build_v2(False)
    return (approval_subject(subject), build_v2(True) if _too_long(out) else out,
            with_bottom_text(with_strip_text(text, strip_text_v2(url, others, kind, slack=slack, notes=notes or [])),
                             bottom_text(url, f"Approve for email ({', '.join(others)})", kind)))


# ── round 5: two buttons ───────────────────────────────────────────────────────
SLACK_BUTTON = "#4A154B"
SLACK_PATH = APPROVE_PATH          # same page; the token says which action it is for


def slack_url(portal_url: str, token: str) -> str:
    return approve_url(portal_url, token)


_BOLD_LINE = re.compile(r"^\*(.+)\*$")
_BOLD_RUN = re.compile(r"\*([^*\n]+)\*")


def _mrkdwn_html(escaped: str) -> str:
    """Slack's *bold* runs (the post's host names) as bold in the email's copy of it."""
    return _BOLD_RUN.sub(lambda m: f'<span style="font-weight:600;">{m.group(1)}</span>', escaped)


def slack_box_html(payload_text: str, ch: str) -> str:
    """The #on-call draft as the email shows it (round 5, Howie 17:43): a white box with
    Slack's purple edge, the post's lines inside it, each graded line with the grade as a
    pill (digest_voice.grade_pill) instead of a word in brackets. With nothing to post, the
    same box says so, so the Slack half is never missing from Howie's copy."""
    from digest_voice import grade_row, split_grade  # noqa: E402 — the one pill, drawn in one place
    body = (payload_text or "").strip()
    if not body:
        inner = (f'<div style="font-family:{_FONT};font-size:14px;line-height:1.5;color:{STRIP_TEXT};">'
                 f'Nothing for {escape(ch)} today: nothing new that a developer acts on, and no nudge due.</div>')
    else:
        rows, first = [], True
        for ln in body.split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            m = _BOLD_LINE.match(ln)
            if m:
                rows.append(f'<tr><td colspan="2" style="padding:{0 if first else 12}px 0 2px;font-family:{_FONT};'
                            f'font-size:13px;line-height:1.5;font-weight:700;color:{STRIP_TEXT};">{escape(m.group(1))}</td></tr>')
            elif ln.startswith("• "):
                word, line = split_grade(ln[2:])
                rows.append(grade_row(word, _mrkdwn_html(escape(line)), first=True, size=14, color=STRIP_TEXT, pad=4))
            else:
                rows.append(f'<tr><td colspan="2" style="padding:8px 0 0;font-family:{_FONT};font-size:13px;'
                            f'line-height:1.5;color:{STRIP_TEXT};">{escape(ln)}</td></tr>')
            first = False
        inner = ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                 + "".join(rows) + '</table>')
    return (f'<div style="background:#FFFFFF;border-left:4px solid {SLACK_BUTTON};border-radius:0 8px 8px 0;'
            f'padding:10px 14px;">{inner}</div>')


def _slack_block_html(slack: dict | None) -> str:
    if slack is None:
        return ""
    ch = escape(slack.get("channel") or "#on-call")
    if not slack.get("payload_text"):
        return (f'<tr><td style="padding:0 24px 6px;font-family:{_FONT};font-size:13px;line-height:1.5;font-weight:700;'
                f'text-transform:uppercase;letter-spacing:.06em;color:{STRIP_TEXT};">What {ch} would get</td></tr>'
                f'<tr><td style="padding:0 24px 12px;">{slack_box_html("", slack.get("channel") or "#on-call")}</td></tr>')
    wired = slack.get("wired", True)
    btn = (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td bgcolor="{SLACK_BUTTON}" '
           f'style="background:{SLACK_BUTTON};border-radius:8px;"><a href="{escape(slack["url"])}" style="display:inline-block;'
           f'padding:12px 20px;font-family:{_FONT};font-size:15px;font-weight:700;color:#FFFFFF;text-decoration:none;">'
           f'Post to Slack&nbsp;&nbsp;&rarr; {ch}</a></td></tr></table>') if wired else (
           f'<div style="font-family:{_FONT};font-size:14px;color:{STRIP_TEXT};">Post to Slack: not wired yet '
           f'(the {ch} webhook is not set on GitHub), so nothing can post.</div>')
    return (f'<tr><td style="padding:0 24px 6px;font-family:{_FONT};font-size:13px;line-height:1.5;font-weight:700;'
            f'text-transform:uppercase;letter-spacing:.06em;color:{STRIP_TEXT};">What {ch} would get</td></tr>'
            f'<tr><td style="padding:0 24px 12px;">{slack_box_html(slack["payload_text"], slack.get("channel") or "#on-call")}</td></tr>'
            f'<tr><td style="padding:0 24px 14px;">{btn}</td></tr>')


def preview_copy(subject: str, html: str, text: str, *, slack: dict | None, notes: list[str] | None = None):
    """A TEST SEND's copy (round 5, Howie 15:33: "You've yet to show me what we're going to
    throw into Slack"): the email as the others would get it, with a strip on top showing the
    #on-call draft and the notes, and NO buttons: a test send approves nothing and posts
    nothing. `subject` already carries the test prefix."""
    notes = list(notes or [])
    if slack is None and not notes:
        return subject, html, text
    ch = (slack or {}).get("channel") or "#on-call"
    body = (slack or {}).get("payload_text") or ""
    slack_rows = ((f'<tr><td style="padding:0 24px 6px;font-family:{_FONT};font-size:13px;line-height:1.5;font-weight:700;'
                   f'text-transform:uppercase;letter-spacing:.06em;color:{STRIP_TEXT};">What {escape(ch)} would get</td></tr>'
                   f'<tr><td style="padding:0 24px 12px;">{slack_box_html(body, ch)}</td></tr>') if slack is not None else "")
    note_rows = "".join(
        f'<tr><td style="padding:0 24px 10px;font-family:{_FONT};font-size:13px;line-height:1.5;color:{STRIP_TEXT};">'
        f'{escape(n)}</td></tr>' for n in notes)
    strip = (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'data-approval-strip="test"><tr><td align="center" style="padding:20px 8px 0;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'bgcolor="{STRIP_BG}" style="width:100%;max-width:640px;background:{STRIP_BG};border-radius:14px;">'
        f'<tr><td style="padding:18px 24px 6px;font-family:{_FONT};font-size:17px;line-height:1.35;'
        f'font-weight:700;color:{STRIP_TEXT};">Test send. Nothing was sent to anyone else and nothing was posted.</td></tr>'
        + slack_rows + note_rows +
        f'<tr><td style="padding:0 24px 18px;font-family:{_FONT};font-size:13px;line-height:1.5;'
        f'color:{STRIP_TEXT};">Below this note: the email exactly as the others would get it.</td></tr>'
        '</table></td></tr></table>'
    )
    tlines = ["TEST SEND. Nothing was sent to anyone else and nothing was posted."]
    if slack is not None:
        tlines += [f"What {ch} would get:", body] if body else [f"Nothing for {ch} today."]
    tlines += notes + [TEXT_RULE, ""]
    return subject, with_strip_html(html, strip), with_strip_text(text, "\n".join(tlines))


def _two_decisions(slack: dict | None) -> bool:
    """Two decisions are on the table only when there is a Slack post AND its button can post.
    A quiet day (nothing for #on-call), a webhook not wired yet, or no Slack half at all leaves
    one: the email (code review of push-373, minor 3: "Two separate decisions" showed anyway)."""
    return bool(slack) and bool(slack.get("payload_text")) and bool(slack.get("wired", True))


ONE_DECISION_HTML = "One decision today: the email. Its button is under it; nothing goes anywhere until you press it."
TWO_DECISIONS_HTML = ("Two separate decisions. Each button sits under what it sends. Press one, both, or neither; "
                      "nothing goes anywhere until you do.")


def strip_html_v2(url: str, others: list[str], kind: str, *, slack: dict | None, notes: list[str],
                  top_button: bool = False) -> str:
    """The top of Howie's copy: the two decisions, then the #on-call draft with its button under
    it. The email's button is no longer here: bottom_html puts it under the email (10-29).
    `url` and `others` stay in the signature so every caller is unchanged."""
    note_rows = "".join(
        f'<tr><td style="padding:0 24px 10px;font-family:{_FONT};font-size:13px;line-height:1.5;color:{STRIP_TEXT};">'
        f'{escape(n)}</td></tr>' for n in notes)
    return _box_html(
        "2",
        f'<tr><td style="padding:18px 24px 6px;font-family:{_FONT};font-size:17px;line-height:1.35;'
        f'font-weight:700;color:{STRIP_TEXT};">Only you have this so far.</td></tr>'
        f'<tr><td style="padding:0 24px 14px;font-family:{_FONT};font-size:14px;line-height:1.5;'
        f'color:{STRIP_TEXT};">{TWO_DECISIONS_HTML if _two_decisions(slack) else ONE_DECISION_HTML}</td></tr>'
        + (_top_button_row(url, "Approve for email&nbsp;&nbsp;&rarr; " + ", ".join(escape(a) for a in others))
           if top_button else "")
        + _slack_block_html(slack) + note_rows +
        f'<tr><td style="padding:0 24px 18px;font-family:{_FONT};font-size:13px;line-height:1.5;'
        f'color:{STRIP_TEXT};">Below: the email exactly as the others would get it, with its own button under it.</td></tr>',
        "20px 8px 0")


def strip_text_v2(url: str, others: list[str], kind: str, *, slack: dict | None, notes: list[str]) -> str:
    lines = ["ONLY YOU HAVE THIS SO FAR. " + ("Two separate decisions; press one, both, or neither."
                                              if _two_decisions(slack) else
                                              "One decision today: the email; nothing goes anywhere until you approve it.")]
    if slack is not None:
        ch = slack.get("channel") or "#on-call"
        if not slack.get("payload_text"):
            lines.append(f"Nothing for {ch} today.")
        elif slack.get("wired", True):
            lines += [f"What {ch} would get:", slack["payload_text"], f"Post to Slack ({ch}): {slack['url']}"]
        else:
            lines += [f"What {ch} would get:", slack["payload_text"], f"Post to Slack ({ch}): not wired yet, nothing can post."]
    lines += list(notes)
    lines += ["The email follows; the link to approve it is at the end.", TEXT_RULE, ""]
    return "\n".join(lines)
