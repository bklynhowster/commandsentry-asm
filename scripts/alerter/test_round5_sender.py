"""(KB 12 job 3l round 5, 2026-10-27) The two buttons, the gates, the sender's Slack half.

Howie, 08:46: two buttons, each its own decision. 08:47: his copy is the email exactly as the
others get it. Review: M3 (never retry a public post), M4 (never an exception's text, which can
carry the webhook, into a column the portal reads), M5/M6 (name the gates; Command byte for
byte as today with every switch unset), m7 (the switches are public variables).
"""
from __future__ import annotations

import inspect
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))
WF = os.path.join(HERE, "..", "..", ".github", "workflows")

import approval as ap  # noqa: E402
import run_alerter as ra  # noqa: E402

HTML = "<html><body><p>x</p></body></html>"


# ── the copy ─────────────────────────────────────────────────────────────────────────────
def test_with_no_slack_half_the_copy_is_the_3l_one_with_its_button_under_the_email():
    u = "https://p/digest/approve#t"
    a = ap.approver_copy("S", HTML, "T", url=u, others=["a@x"], kind="daily")
    b = (ap.approval_subject("S"),
         ap.with_bottom_html(ap.with_strip_html(HTML, ap.strip_html(u, ["a@x"], "daily")),
                             ap.bottom_html(u, "Send to the others", "daily")),
         ap.with_bottom_text(ap.with_strip_text("T", ap.strip_text(u, ["a@x"], "daily")),
                             ap.bottom_text(u, "Send to the others", "daily")))
    assert a == b and 'data-approval-strip="1"' in a[1] and "Post to Slack" not in a[1]
    assert a[1].index("<p>x</p>") < a[1].index(u), "the button is under the email"


def test_with_a_slack_half_two_buttons_each_its_own_link_and_the_draft_under_it():
    slack = {"channel": "#on-call", "wired": True, "payload_text": "*What changed*\n• valorep went quiet.",
             "url": "https://p/digest/approve#SLACKTOKEN"}
    s, html, text = ap.approver_copy("S", HTML, "T", url="https://p/digest/approve#EMAILTOKEN", others=["a@x", "b@x"],
                                     kind="daily", slack=slack, notes=["Written from the fallback today (x)."])
    assert 'data-approval-strip="2"' in html
    assert "Approve for email" in html and "#EMAILTOKEN" in html
    assert "Post to Slack" in html and "#SLACKTOKEN" in html
    # Howie 2026-10-29: each button under what it sends. The Slack draft, then its button, on top;
    # the email, then its button, below.
    assert html.index("valorep went quiet.") < html.index("#SLACKTOKEN") < html.index("<p>x</p>") < html.index("#EMAILTOKEN")
    assert html.count("Approve for email") == 1 and 'data-approval-strip="bottom"' in html
    assert "valorep went quiet." in html and "What #on-call would get" in html
    assert "Written from the fallback today" in html and "Written from the fallback today" in text
    assert "exactly as the others would get it" in html
    assert html.endswith("</html>") and "<p>x</p>" in html, "the email itself is untouched below the strip"
    assert "Post to Slack (#on-call): https://p/digest/approve#SLACKTOKEN" in text
    assert text.index("#SLACKTOKEN") < text.index("\nT\n") < text.index("Approve for email (a@x, b@x): https://p/digest/approve#EMAILTOKEN")


def test_no_post_today_and_not_wired_are_said_and_have_no_slack_button():
    s, html, text = ap.approver_copy("S", HTML, "T", url="u", others=["a@x"], kind="daily",
                                     slack={"channel": "#on-call", "wired": True, "payload_text": "", "url": ""})
    assert "Nothing for #on-call today" in html and "Post to Slack" not in html and "Nothing for #on-call today." in text
    s, html, text = ap.approver_copy("S", HTML, "T", url="u", others=["a@x"], kind="daily",
                                     slack={"channel": "#on-call", "wired": False, "payload_text": "draft", "url": "x"})
    assert "not wired yet" in html and 'href="x"' not in html and "not wired yet" in text


def test_the_expiry_is_per_instance_and_defaults_to_36():
    assert ap.daily_expires_hours({}) == 36
    assert ap.daily_expires_hours({"DIGEST_DAILY_EXPIRES_HOURS": "24"}) == 24
    assert ap.daily_expires_hours({"DIGEST_DAILY_EXPIRES_HOURS": "nope"}) == 36
    assert ap.daily_expires_hours({"DIGEST_DAILY_EXPIRES_HOURS": "0"}) == 36
    assert ap.daily_expires_hours({"DIGEST_DAILY_EXPIRES_HOURS": ""}) == 36


def test_a_test_send_shows_the_slack_draft_and_the_notes_with_no_button():
    """Howie 15:33: "You've yet to show me what we're going to throw into Slack." A preview
    test send carries the #on-call draft and the notes on top, and no button of any kind."""
    s, html, text = ap.preview_copy("[TEST] S", HTML, "T", slack={"channel": "#on-call", "payload_text": "*What changed*\n• valorep went quiet."},
                                    notes=["Written from the fallback today (x)."])
    assert s == "[TEST] S" and 'data-approval-strip="test"' in html
    assert "What #on-call would get" in html and "valorep went quiet." in html and "Written from the fallback today" in html
    assert "Approve for email" not in html and "Post to Slack" not in html and "href=" not in html
    assert "Nothing was sent to anyone else and nothing was posted" in html and html.endswith("</html>") and "<p>x</p>" in html
    assert text.startswith("TEST SEND. Nothing was sent to anyone else and nothing was posted.\nWhat #on-call would get:\n*What changed*") and text.endswith("T")
    s2, html2, text2 = ap.preview_copy("[TEST] S", HTML, "T", slack={"channel": "#on-call", "payload_text": ""})
    assert "Nothing for #on-call today" in html2 and "Nothing for #on-call today." in text2
    assert ap.preview_copy("[TEST] S", HTML, "T", slack=None) == ("[TEST] S", HTML, "T"), "no Slack half and no notes: the plain test email"
    src = inspect.getsource(ra.main)
    i = src.index("subject = preview_subject(subject)\n            if slack_on or notes:")
    assert "_ap.preview_copy(" in src[i:i + 500] and "_ds.preview_text(slack_payload)" in src[i:i + 500]


# ── the gates (M5, M6, G4) ────────────────────────────────────────────────────────────────
def test_both_switches_are_off_unless_set_and_independent(monkeypatch):
    for k in ("ALERTER_VOICE", "ALERTER_SLACK"):
        monkeypatch.delenv(k, raising=False)
    assert not ra._voice_on() and not ra._slack_on()
    monkeypatch.setenv("ALERTER_VOICE", "howie")
    assert ra._voice_on() and not ra._slack_on()
    monkeypatch.setenv("ALERTER_VOICE", "yes")
    assert not ra._voice_on(), "only the exact word turns the writer on"
    monkeypatch.setenv("ALERTER_SLACK", "on")
    assert ra._slack_on()


def test_with_the_switches_off_the_daily_path_never_reaches_the_voice_or_slack_code():
    src = inspect.getsource(ra.main)
    i = src.index("voice_on, slack_on = _voice_on(), _slack_on()")
    block = src[i:src.index("if args.preview:", i)]
    assert block.lstrip().startswith("voice_on, slack_on = _voice_on(), _slack_on()\n        if voice_on or slack_on:")
    for call in ("_dv.write(", "_dv.render_html(", "_ds.select(", "_ds.payload(", "SQL_OPEN_PROBLEMS", "_read_slack_told(",
                 "quiet_news=_ds.quiet_news(not_responding, window_start, window_end)",
                 "fb_problems = _dv.check(out, fct, portal_url=portal_url)", "The fallback itself tripped the check"):
        assert call in block, call
    assert block.index("out = _dv.fallback(fct)") < block.index("fb_problems = _dv.check(out, fct"), "the fallback is checked too (Qwen MF1)"
    before = src[:i]
    assert "subject = _dd.subject(model, from_name)" in before and "_dd.render_html(model" in before, \
        "the 3l rendering happens first; the voice replaces it only when the switch is on"


def test_the_gate_stores_the_slack_half_only_when_slack_is_on_and_keeps_the_3l_insert_otherwise():
    src = inspect.getsource(ra._gate_and_send)
    assert "if slack_on:" in src and "SQL_PENDING_INSERT_V2" in src.split("if slack_on:")[1].split("else:")[0]
    assert "SQL_PENDING_INSERT," in src.split("else:")[1]
    assert "_ap.daily_expires_hours()" in src


# ── the sender (M3, M4) ───────────────────────────────────────────────────────────────────
def test_post_slack_never_puts_an_exception_or_the_url_in_the_note():
    hook = "https://hooks.slack.com/services/T/B/VERYSECRET"
    ok, note = ra._post_slack(hook, {"text": "x"}, post=lambda u, b: (_ for _ in ()).throw(RuntimeError("boom " + u)))
    assert not ok and "VERYSECRET" not in note and "hooks.slack.com" not in note and "RuntimeError" in note
    ok, note = ra._post_slack(hook, {"text": "x"}, post=lambda u, b: 500)
    assert not ok and note == "Slack answered HTTP 500"
    ok, note = ra._post_slack(hook, {"text": "x"}, post=lambda u, b: 200)
    assert ok and note == "posted"
    assert ra._post_slack("", {"text": "x"}, post=lambda u, b: 200) == (False, "no webhook set")


def test_a_slack_post_gets_one_attempt_and_is_never_retried():
    src = inspect.getsource(ra._post_approved)
    assert "SQL_PENDING_SLACK_CLAIM" in src and "SQL_PENDING_SLACK_FAILED" in src
    assert "retry" not in src.lower().replace("not retried", "").replace("never retried", "")
    claim = " ".join(ra.SQL_PENDING_SLACK_CLAIM.split())
    assert "WHERE p.slack_status = 'approved'" in claim and "FOR UPDATE SKIP LOCKED" in claim
    stale = " ".join(ra.SQL_PENDING_SLACK_STALE.split())
    assert "SET slack_status = 'failed', slack_error = 'not sure it posted: the post was started and never finished' WHERE slack_status = 'posting' AND coalesce(slack_approved_at, built_at) < now() - interval '10 minutes' RETURNING id" in stale
    assert "'approved'" not in stale, "a stale post is never put back for another try"
    email_stale = " ".join(ra.SQL_PENDING_EMAIL_STALE.split())
    assert "SET status = 'failed', error = 'not sure it sent: the send was started and never finished' WHERE status = 'sending' AND coalesce(approved_at, built_at) < now() - interval '30 minutes'" in email_stale
    assert "'approved'" not in email_stale, "a send that may have gone out is never sent again (Qwen M-C6)"
    src = inspect.getsource(ra._send_approved)
    assert src.count("conn.commit()") >= 2 and 'for label, sql in (("digest", SQL_PENDING_EMAIL_STALE), ("slack post", SQL_PENDING_SLACK_STALE))' in src, \
        "the two sweeps are separate transactions: one failing leaves the other"


def test_the_note_about_a_failed_post_says_what_it_said_and_does_not_claim_a_carry_over():
    src = inspect.getsource(ra.main)
    i = src.index("SQL_PENDING_SLACK_LAST_FAILED, (\"daily\", \"daily\"))")
    block = src[i:i + 900]
    assert "Today's draft does not repeat it" in block and "this is what it said" in block and "_ds.preview_text(" in block
    assert "includes what it had" not in src, "Qwen M-C5: section 1 is the window's news; a failed post's news is not carried over"
    assert "slack_payload FROM public.digest_pending" in " ".join(ra.SQL_PENDING_SLACK_LAST_FAILED.split())


def test_the_record_is_written_only_after_a_post_that_worked():
    src = inspect.getsource(ra._post_approved)
    assert src.index("if ok:\n            recs") > src.index("_post_slack(")
    after_ok = src.split("if ok:\n            recs")[1].split("else:")[0]
    assert "_slack_told_record(conn" in after_ok and "SQL_PENDING_SLACK_POSTED" in src.split("_slack_told_record(conn")[0]


# ── the workflows (m7: public variables; the secrets stay secrets) ───────────────────────
def test_the_workflows_pass_the_switches_as_variables_and_the_two_secrets():
    wf = open(os.path.join(WF, "alerter.yml"), encoding="utf-8").read()
    for v in ("ALERTER_VOICE", "ALERTER_SLACK", "DIGEST_DAILY_EXPIRES_HOURS"):
        assert re.search(rf"{v}:\s+\$\{{\{{ vars\.{v} \}}\}}\n", wf), f"{v} is a repo variable with no fallback"
    assert re.search(r"ANTHROPIC_API_KEY:\s+\$\{\{ secrets\.ANTHROPIC_API_KEY \}\}", wf)
    assert re.search(r"SLACK_ONCALL_WEBHOOK:\s+\$\{\{ secrets\.SLACK_ONCALL_WEBHOOK \}\}", wf)
    send = open(os.path.join(WF, "digest-send.yml"), encoding="utf-8").read()
    assert re.search(r"SLACK_ONCALL_WEBHOOK:\s+\$\{\{ secrets\.SLACK_ONCALL_WEBHOOK \}\}", send)
    assert "ANTHROPIC_API_KEY" not in send, "the sender writes nothing; it needs no writer key"


def test_a_host_that_stopped_answering_is_not_in_the_still_or_nudge_picks():
    """Howie 2026-10-28 09:37: "If valor is gone then no need to report its vulnerabilities."
    The alerter drops the not-responding roster's hosts from the open rows before any pick."""
    whole = open(ra.__file__).read()
    i = whole.index('open_rows = _soft("open problems", SQL_OPEN_PROBLEMS)')
    block = whole[i:i + 900]
    assert "quiet = {r[0] for r in (not_responding or [])}" in block
    assert "open_rows = [r for r in open_rows if r[1] not in quiet]" in block
    assert block.index("not in quiet]") < block.index("_open_items(open_rows")
    # and the picks themselves: a quiet host's rows leave the still list
    rows = [("f1", "valorep.prodexlabs.com", "Obsolete 3DES/IDEA ciphers offered", "MODERATE", "open", "commandsentry_light", None, "", [], None),
            ("f2", "cooked.prodexlabs.com", "Obsolete 3DES/IDEA ciphers offered", "MODERATE", "open", "commandsentry_light", None, "", [], None)]
    quiet = {"valorep.prodexlabs.com"}
    kept = [r for r in rows if r[1] not in quiet]
    assert [r[1] for r in kept] == ["cooked.prodexlabs.com"]


def test_a_long_email_keeps_its_button_on_top_too_so_gmail_never_hides_it():
    """Gmail clips at about 102 KB and the email's button is at the end (10-29). A long email
    (a big weekly) gets the button in the top strip as well; a normal daily gets it once."""
    big = "<html><body><p>" + "x" * (ap.CLIP_SAFE_CHARS + 1) + "</p></body></html>"
    slack = {"channel": "#on-call", "wired": True, "payload_text": "*What changed*\n• a.", "url": "https://p/s#S"}
    for kw, label in (({}, "Send to the others"), ({"slack": slack}, "Approve for email")):
        _, small_h, _ = ap.approver_copy("S", HTML, "T", url="https://p/a#E", others=["a@x"], kind="weekly", **kw)
        _, big_h, _ = ap.approver_copy("S", big, "T", url="https://p/a#E", others=["a@x"], kind="weekly", **kw)
        assert small_h.count('href="https://p/a#E"') == 1 and small_h.count(label) == 1
        assert big_h.count('href="https://p/a#E"') == 2 and big_h.count(label) == 2
        assert big_h.index('href="https://p/a#E"') < big_h.index("xxxx") < big_h.rindex('href="https://p/a#E"')
