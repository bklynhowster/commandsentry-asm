"""319 (2026-10-14) — an SMTP instance's digest must not die for want of a SendGrid key.

The first Prodex digest (run 38642858302) exited in half a second:
"error: RESEND_API_KEY not set". Prodex sends over SMTP/iCloud and has never had
a SendGrid or Resend key; the send path ignores `api_key` (4.7 M1) but main()'s
preamble still demanded one. The mailer's own startup check is the one place that
decides whether this instance can send.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
import run_alerter as ra  # noqa: E402


class _StopHere(Exception):
    """Raised from the first call AFTER the key preamble, so main() never reaches the DB."""


def _run_main(monkeypatch, env: dict[str, str], argv: list[str]):
    for k in ("SENDGRID_API_KEY", "RESEND_API_KEY", "MAIL_PROVIDER", "SMTP_HOST", "SMTP_USER", "SMTP_PASS",
              "ALERTER_FROM", "ALERTER_FROM_NAME", "ALERTER_TO", "SUPABASE_DSN"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(ra._mailer, "warn_if_unconfigured", lambda *a, **k: (_ for _ in ()).throw(_StopHere()))
    monkeypatch.setattr(sys, "argv", ["run_alerter.py", *argv])
    return ra.main()


SMTP = {"SUPABASE_DSN": "postgresql://x", "MAIL_PROVIDER": "smtp", "SMTP_HOST": "smtp.mail.me.com",
        "SMTP_USER": "u", "SMTP_PASS": "p", "ALERTER_FROM": "a@b", "ALERTER_FROM_NAME": "X", "ALERTER_TO": "c@d"}


def test_319_an_smtp_instance_with_no_sendgrid_or_resend_key_gets_past_the_preamble(monkeypatch):
    # Before 319 this was SystemExit(2) with "error: RESEND_API_KEY not set".
    with pytest.raises(_StopHere):
        _run_main(monkeypatch, SMTP, [])


def test_319_dry_run_too(monkeypatch):
    with pytest.raises(_StopHere):
        _run_main(monkeypatch, SMTP, ["--dry-run"])


def test_319_a_sendgrid_instance_with_its_key_is_unchanged(monkeypatch):
    with pytest.raises(_StopHere):
        _run_main(monkeypatch, {"SUPABASE_DSN": "postgresql://x", "SENDGRID_API_KEY": "SG.x", "ALERTER_FROM": "a@b",
                                "ALERTER_FROM_NAME": "X", "ALERTER_TO": "c@d"}, [])


def test_319_the_database_dsn_is_still_required(monkeypatch):
    # The one preamble requirement that is real for every instance stays.
    with pytest.raises(SystemExit) as e:
        _run_main(monkeypatch, {k: v for k, v in SMTP.items() if k != "SUPABASE_DSN"}, [])
    assert e.value.code == 2


def test_319_the_mailer_not_the_preamble_decides_whether_this_instance_can_send(monkeypatch):
    # An SMTP instance missing its password: the mailer's check says so, in words naming SMTP.
    for k in ("SENDGRID_API_KEY", "RESEND_API_KEY", "SMTP_PASS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MAIL_PROVIDER", "smtp"); monkeypatch.setenv("SMTP_HOST", "h"); monkeypatch.setenv("SMTP_USER", "u")
    ok, msg = ra._mailer.check_config()
    assert not ok and "SMTP_PASS" in msg and "SendGrid" not in msg
