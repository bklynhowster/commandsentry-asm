#!/usr/bin/env python3
"""
mail_canary.py — prove mail actually delivers. 4.7 ruling M6 (Obsidian 164).

WHY THIS IS MANDATORY, NOT FOLLOW-UP. I proposed deferring it. 4.7 overruled,
correctly: a startup config assertion verifies "SMTP_PASS is set to something."
It does NOT verify "SMTP_PASS is still valid at Apple's authentication."

The failure mode it exists for:
    day 1   SMTP_PASS valid, digest sends fine.
    day 30  Howie rotates his Apple ID password. The app-specific password
            silently becomes invalid.
    day 31+ Every send fails auth. Best-effort discipline swallows it. The
            digest is informational, so nobody notices its ABSENCE.
Startup config check passes throughout — the env var is still set. Only a
canary catches this, and iCloud app-specific passwords are specifically prone
to it (revoked on password change, revocable from Apple ID settings, and
invisible when broken).

That is the same shape as the bug this whole thread started from: mail that
cannot send produces the identical observable to mail with nothing to say.

TWO PARTS, both required:
  send    — actually send a canary. Failure here is an ::error:: because this
            IS the check; it is not "mail must never fail a scan" territory.
  watch   — verify one was RECEIVED recently. Send-succeeded is not
            delivered-successfully; only the watchdog closes that gap.

CADENCE (M6): daily, and scheduled BEFORE the digest so a failure leaves time
to fix things before the mail that matters goes out. More often is noise; less
often lets a breakage hide for a week.

MONITORED TARGET (M6): MAIL_CANARY_ADDRESS must be an address someone or
something actually watches. A canary to an unwatched mailbox is not a signal.

BOTH INSTANCES send their own canary (M6) — Command over SendGrid, Prodex over
SMTP — so a provider-specific outage or a per-instance credential expiry is
attributable rather than ambiguous.

USAGE
    mail_canary.py send   [--instance prodex]
    mail_canary.py watch  --max-age-hours 26
Exit: 0 ok | 1 canary failed / overdue | 2 usage.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mailer import check_config, describe_config, send_email  # noqa: E402

CANARY_HEADER = "X-Mail-Canary"
DEFAULT_MAX_AGE_HOURS = 26  # 24h cadence + 2h grace


def _instance() -> str:
    return (os.environ.get("INSTANCE_NAME")
            or os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1]
            or "unknown")


def cmd_send(args) -> int:
    to = os.environ.get("MAIL_CANARY_ADDRESS")
    if not to:
        print("::warning::MAIL_CANARY_ADDRESS not set — canary disabled for this "
              "instance. Mail delivery is therefore UNVERIFIED.", file=sys.stderr)
        return 0  # not configured != broken; M5 handles config loudness

    ok_cfg, cfg_msg = check_config()
    if not ok_cfg:
        print(f"::error::canary cannot send — {cfg_msg}", file=sys.stderr)
        return 1

    inst = args.instance or _instance()
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    subject = f"[canary] {inst} scanner mail health — {now:%Y-%m-%d}"
    body_txt = (f"Canary from {inst} at {stamp}.\n\n"
                f"Transport: {describe_config()}\n\n"
                f"If these stop arriving, scanner mail for this instance is "
                f"broken — most likely an expired credential. See Obsidian 164.")
    body_html = (f"<p>Canary from <b>{inst}</b> at {stamp}.</p>"
                 f"<p>Transport: <code>{describe_config()}</code></p>"
                 f"<p>If these stop arriving, scanner mail for this instance is "
                 f"broken — most likely an expired credential. See Obsidian 164.</p>")

    ok, detail = send_email(
        to_addrs=[to], subject=subject, html=body_html, text=body_txt,
        from_addr=os.environ.get("ALERTER_FROM", ""),
        from_name=os.environ.get("ALERTER_FROM_NAME", ""),
        headers={CANARY_HEADER: "1"},
    )
    if not ok:
        # ::error:: is correct here and does NOT violate "mail must never fail a
        # scan" — the canary is a standalone health check, not a scan step.
        print(f"::error::canary send FAILED for {inst}: {detail}", file=sys.stderr)
        return 1
    print(f"canary sent [{inst}] {detail}")
    return 0


def cmd_watch(args) -> int:
    """Verify a canary was RECEIVED recently.

    Receipt confirmation needs an inbox this process can read, which is
    deliberately NOT wired here — see the note below. Until it is, this
    reports honestly that delivery is unverified rather than printing a
    green check it cannot justify. A watchdog that always says OK is worse
    than no watchdog, and that is precisely the trap this file exists to
    avoid (see Q6 in Obsidian 163).
    """
    last = os.environ.get("MAIL_CANARY_LAST_RECEIVED")  # ISO8601, set by the reader
    if not last:
        print("::warning::canary watchdog has no receipt source wired "
              "(MAIL_CANARY_LAST_RECEIVED unset) — SEND is verified, DELIVERY is "
              "NOT. Wire an inbox reader before trusting this as green.",
              file=sys.stderr)
        return 0
    try:
        seen = datetime.fromisoformat(last)
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
    except Exception as e:
        print(f"::error::MAIL_CANARY_LAST_RECEIVED unparseable ({last!r}): {e!r}",
              file=sys.stderr)
        return 1

    age = (datetime.now(timezone.utc) - seen).total_seconds() / 3600.0
    if age > args.max_age_hours:
        print(f"::error::no canary received in {age:.1f}h "
              f"(threshold {args.max_age_hours}h) — scanner mail is likely broken. "
              f"Most common cause: expired iCloud app-specific password.",
              file=sys.stderr)
        return 1
    print(f"canary receipt OK — last seen {age:.1f}h ago")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("send"); s.add_argument("--instance", default="")
    w = sub.add_parser("watch")
    w.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS)
    args = ap.parse_args()
    return cmd_send(args) if args.cmd == "send" else cmd_watch(args)


if __name__ == "__main__":
    sys.exit(main())
