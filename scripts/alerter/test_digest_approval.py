"""(KB 12 job 3l, 2026-10-26) The digest comes to Howie first; he sends it on from the email.

Howie, 14:00: "I want the mail to come only to me, and then I have the ability to approve it
for further distribution." 14:17: "This should be a simple process. I don't want to have to go
into a GitHub web page every morning to simply approve it."

Pinned here: who gets the approval copy and who gets it after (the approver never twice); the
approver's copy is the others' email plus one strip and a subject prefix, nothing else; the
token rides in the URL fragment, is stored only as its sha256 (the migration's own formula) and
is never printed; no approver = a real digest sends nothing; a dry run and a test send are not
gated; the sender workflow and the digest workflow carry what they need. The database half is
proven on PostgreSQL 16 in the build note (pgproof-dg.txt).
"""
from __future__ import annotations

import hashlib
import inspect
import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import approval as ap  # noqa: E402
import digest_daily as dd  # noqa: E402
import run_alerter as ra  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
WF = os.path.join(REPO, ".github", "workflows")
MIG = os.path.join(REPO, "scripts", "db", "migrations", "20261026c_digest_approval.sql")
OTHERS = ["dklaiss@example.com", "wmerfert@example.com"]


def _daily_html():
    from test_digest_daily_3l import model  # the daily's own fixture
    m = model()
    return dd.render_html(m, portal_url="https://p.example", product_name="X"), \
        dd.render_text(m, portal_url="https://p.example", product_name="X")


# ── who gets what ───────────────────────────────────────────────────────────────────
def test_the_approver_gets_one_copy_and_is_never_also_an_other():
    a, o = ap.split_recipients(["HowieHow@mac.com", "dklaiss@x.com", "howiehow@mac.com", "wmerfert@x.com",
                                "dklaiss@x.com"], "howiehow@mac.com")
    assert a == ["howiehow@mac.com"]
    assert o == ["dklaiss@x.com", "wmerfert@x.com"]


def test_no_approver_means_nobody():
    assert ap.split_recipients(["a@x.com"], "") == ([], [])
    assert ap.split_recipients(["a@x.com"], "   ") == ([], [])


# ── the approver's copy is the others' email plus the strip ─────────────────────────
def test_the_approver_copy_is_the_others_email_plus_one_strip_and_a_prefix():
    html, text = _daily_html()
    url = ap.approve_url("https://p.example", "TOKEN123")
    s, h, t = ap.approver_copy("[X] Command, Tuesday: 2 checks", html, text, url=url, others=OTHERS, kind="daily")
    assert s == "For approval: [X] Command, Tuesday: 2 checks"
    strip = ap.strip_html(url, OTHERS, "daily")
    assert h.count('data-approval-strip="1"') == 1
    assert h.replace("\n" + strip, "", 1) == html, "nothing but the strip differs"
    assert h.index(strip) > h.index("<body") and h.index(strip) < h.index("</body>")
    assert t == ap.strip_text(url, OTHERS, "daily") + text
    for addr in OTHERS:
        assert addr in h and addr in t, "the strip says who it will go to"
    assert "Send to the others" in h and url in t


def test_both_renderers_have_the_one_body_tag_the_strip_goes_after():
    for mod in ("digest_daily.py", "digest_weekly.py"):
        src = open(os.path.join(HERE, mod), encoding="utf-8").read()
        assert len(re.findall(r"<body\b[^>]*>", src)) == 1, mod


def test_html_without_a_body_is_refused_not_guessed():
    with pytest.raises(ValueError):
        ap.with_strip_html("<html>no body</html>", "S")


def test_the_strip_says_what_happens_if_you_do_nothing():
    assert "tomorrow's email will cover today too" in ap.strip_text("u", OTHERS, "daily")
    assert "nobody else gets this week's review" in ap.strip_text("u", OTHERS, "weekly")


# ── the token ───────────────────────────────────────────────────────────────────────
def test_the_token_is_long_random_and_rides_in_the_fragment():
    t1, t2 = ap.new_token(), ap.new_token()
    assert t1 != t2 and len(t1) >= 43 and re.fullmatch(r"[A-Za-z0-9_\-]+", t1)
    url = ap.approve_url("https://p.example/", t1)
    assert url == f"https://p.example/digest/approve#{t1}", "a fragment is never sent to the server"
    assert "?" not in url


def test_the_stored_hash_is_the_migrations_own_formula():
    assert ap.token_hash("abc") == hashlib.sha256(b"abc").hexdigest()
    sql = open(MIG, encoding="utf-8").read()
    assert sql.count("encode(sha256(convert_to(coalesce(p_token, ''''), ''UTF8'')), ''hex'')") == 2


def test_the_fingerprint_covers_subject_html_and_text():
    f = ap.fingerprint("s", "h", "t")
    assert f != ap.fingerprint("s", "h", "t ") != ap.fingerprint("s ", "h", "t")
    assert ap.fingerprint("ab", "c", "") != ap.fingerprint("a", "bc", "")


def test_nothing_prints_the_token_or_an_address():
    """These repos' Actions logs are public."""
    for fn in (ra._gate_and_send, ra._send_approved):
        src = inspect.getsource(fn)
        calls = re.findall(r"(?<![\w.])print\((.*?)\)\n", src, re.S)
        assert calls, fn.__name__
        for call in calls:
            assert "token" not in call, (fn.__name__, call)
            assert "others}" not in call and "recipients}" not in call and "approver}" not in call, call


# ── when the gate applies ───────────────────────────────────────────────────────────
def _main(monkeypatch, argv, env):
    monkeypatch.setattr(sys, "argv", ["run_alerter.py", *argv])
    base = {"SUPABASE_DSN": "postgresql://unused", "ALERTER_FROM": "s@x.com", "ALERTER_FROM_NAME": "X",
            "ALERTER_TO": "howiehow@mac.com,dklaiss@x.com", "ALERTER_APPROVER": ""}
    base.update(env)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    called = []
    monkeypatch.setattr(ra.psycopg, "connect", lambda *a, **k: called.append(1) or (_ for _ in ()).throw(SystemExit(9)))
    try:
        rc = ra.main()
    except SystemExit as e:
        rc = ("connected", e.code)
    return rc, called


def test_a_real_digest_with_no_approver_sends_nothing_and_never_connects(monkeypatch, capsys):
    for argv in ([], ["--weekly"]):
        rc, called = _main(monkeypatch, argv, {})
        assert rc == 0 and not called
    assert "ALERTER_APPROVER not set" in capsys.readouterr().err


def test_a_dry_run_and_a_test_send_are_not_gated(monkeypatch):
    for argv in (["--dry-run"], ["--preview"]):
        rc, called = _main(monkeypatch, argv, {})
        assert rc == ("connected", 9) and called, argv


def test_with_an_approver_a_real_digest_goes_ahead(monkeypatch):
    rc, called = _main(monkeypatch, [], {"ALERTER_APPROVER": "howiehow@mac.com"})
    assert rc == ("connected", 9) and called


def test_the_sender_needs_only_the_sender_identity(monkeypatch):
    rc, called = _main(monkeypatch, ["--send-approved"], {"ALERTER_TO": ""})
    assert rc == ("connected", 9) and called
    rc, called = _main(monkeypatch, ["--send-approved"], {"ALERTER_FROM": ""})
    assert rc == 0 and not called


def test_an_approval_digest_writes_its_runs_row_only_when_it_goes_out():
    src = inspect.getsource(ra.main)
    assert "if record and not gate:" in src
    assert "SQL_INSERT_RUN_START" not in inspect.getsource(ra._gate_and_send)
    assert "_told_record" not in inspect.getsource(ra._gate_and_send)
    s = inspect.getsource(ra._send_approved)
    assert "SQL_INSERT_RUN_START" in s and "_told_record" in s and "SQL_PENDING_CLAIM" in s


def test_building_a_digest_retires_the_older_one_of_its_kind_only():
    assert "WHERE kind = %s AND status IN ('awaiting', 'approved')" in ra.SQL_PENDING_SUPERSEDE
    assert "FOR UPDATE SKIP LOCKED" in ra.SQL_PENDING_CLAIM


# ── the workflows ───────────────────────────────────────────────────────────────────
def test_the_sender_workflow():
    p = os.path.join(WF, "digest-send.yml")
    wf = open(p, encoding="utf-8").read()
    assert "run_alerter.py --send-approved" in wf
    assert re.search(r"cron:\s*\"3-53/10 \* \* \* \*\"", wf), "every 10 minutes, off the hour"
    assert "workflow_dispatch:" in wf, "the portal fires it the moment Howie presses Send"
    assert "group: digest-send" in wf, "never shares the digest's concurrency group"
    assert "pyyaml" in wf and "psycopg" in wf
    for v in ("SUPABASE_DSN", "MAIL_PROVIDER", "SMTP_PASS", "SENDGRID_API_KEY", "ALERTER_FROM", "ALERTER_FROM_NAME"):
        assert v in wf, v
    assert "ALERTER_TO" not in wf, "the stored digest carries its own recipients"


def test_the_digest_workflow_passes_the_approver():
    wf = open(os.path.join(WF, "alerter.yml"), encoding="utf-8").read()
    assert re.search(r"ALERTER_APPROVER:\s+\$\{\{ vars\.ALERTER_APPROVER \}\}\n", wf), \
        "from the repo variable, with no fallback"
