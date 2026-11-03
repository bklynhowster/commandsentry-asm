"""(KB 12 job 4r, 2026-11-03) An alias is not a mail server.

`dig +short MX <name>` on a name that is an alias prints the alias chain first, one bare name
per line, then any real MX records of the name at the end of the chain. check_dns_posture
counted every line as a mail server, so every aliased name became a "sending host" (confidence
"high") and got SPF and DMARC findings it cannot own. On Command that was 12 names and 24
MODERATE findings (pay.commandmi.com, the Unimac sites on Azure, email.commandcompanies.com,
www.commandmarketinginnovations.com); each parent domain already carries its own finding for
the real gap. Howie, 2026-11-03 09:36 (A-D1): only real mail-server entries count.

Pins:
  * split_mx_answer keeps "<preference> <exchange>" lines as MX and the bare names as the
    alias chain; dig's own ";;" messages and a bare number are neither;
  * end to end in check_dns_posture: pay.commandmi.com's exact answers -> not a sender, no
    SPF / DMARC finding, the chain recorded in the dns_posture record;
  * unchanged: an alias that leads to real MX records (www.commandcompanies.com) is still a
    sender and still gets its DMARC finding; a plain subdomain with its own MX still emits;
    an apex with no SPF still emits;
  * (review round 1, Kimi K3.1 Pro, must-fix 1) an MX lookup that failed or came back unreadable
    is not "no mail servers": the name stays a sender (fail-safe) and the check is degraded.

Every dig answer below was measured on 2026-11-03 through 8.8.8.8.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import run_light as rl  # noqa: E402

# ── Measured 2026-11-03, 8.8.8.8 ────────────────────────────────────────────────────────────
PAY_CHAIN = ("paylinks.commerce.godaddy.com.\n"
             "t1k.poynt.net.\n"
             "t1kpay-hapro-brerpx815yxp-ac89608e147b66ef.elb.us-east-1.amazonaws.com.\n")
CMDMI_DMARC = ('"v=DMARC1; p=none; pct=100; rua=mailto:dkimreport@commandcompanies.com; '
               'ruf=mailto:dkimalert@commandcompanies.com"\n')
WWW_CMDCO_MX = ("commandcompanies.com.\n"
                "10 mx1.hc3765-17.iphmx.com.\n"
                "20 mx2.hc3765-17.iphmx.com.\n")
WWW_CMDCO_TXT = ("commandcompanies.com.\n"
                 '"0ed1fe018a0b51be5c4cd34ee5b2364c6b3de8d430"\n'
                 '"v=spf1 exists:%{i}.spf.hc3765-17.iphmx.com -all"\n'
                 '"MS=ms93622757"\n'
                 '"apple-domain-verification=cWkfjNKuM61a3EZ6"\n')
CMDCO_DMARC = CMDMI_DMARC
PORTAL_CHAIN = ("umpisiteslive.azurewebsites.net.\n"
                "waws-prod-blu-157.sip.azurewebsites.windows.net.\n"
                "waws-prod-blu-157.eastus.cloudapp.azure.com.\n")
CMDMI_MX = "10 mx1.hc3765-17.iphmx.com.\n20 mx2.hc3765-17.iphmx.com.\n"


# ── The pure split ─────────────────────────────────────────────────────────────────────────

def test_an_alias_chain_is_not_a_mail_server():
    mx, chain = rl.split_mx_answer(PAY_CHAIN)
    assert mx == []
    assert chain == ["paylinks.commerce.godaddy.com.", "t1k.poynt.net.",
                     "t1kpay-hapro-brerpx815yxp-ac89608e147b66ef.elb.us-east-1.amazonaws.com."]


def test_an_alias_to_real_mail_servers_keeps_them():
    mx, chain = rl.split_mx_answer(WWW_CMDCO_MX)
    assert mx == ["10 mx1.hc3765-17.iphmx.com.", "20 mx2.hc3765-17.iphmx.com."]
    assert chain == ["commandcompanies.com."]


def test_plain_mx_answers_are_unchanged():
    assert rl.split_mx_answer(CMDMI_MX) == (["10 mx1.hc3765-17.iphmx.com.",
                                              "20 mx2.hc3765-17.iphmx.com."], [])
    assert rl.split_mx_answer("") == ([], [])
    assert rl.split_mx_answer("\n  \n") == ([], [])


def test_dig_messages_are_neither():
    out = ";; connection timed out; no servers could be reached\n"
    assert rl.split_mx_answer(out) == ([], [])


def test_a_bare_number_is_neither():           # review round 1, minor
    assert rl.split_mx_answer("10\n") == ([], [])
    assert rl.split_mx_answer("10\n20 mx.example.net.\n") == (["20 mx.example.net."], [])


def test_the_old_reading_would_have_called_the_chain_mail_servers():
    # The line check_dns_posture used before 4r, kept here so the pin says what changed.
    old = [l.strip() for l in PAY_CHAIN.splitlines() if l.strip()]
    assert rl.is_sending_host("pay.commandmi.com", False, old)["is_sending_host"] is True
    assert rl.is_sending_host("pay.commandmi.com", False,
                              rl.split_mx_answer(PAY_CHAIN)[0])["is_sending_host"] is False


# ── End to end through check_dns_posture ───────────────────────────────────────────────────

def _ctx(asset_id, apex, typ="single_host"):
    return rl.ScanContext(descriptor={"asset": {"apex_domain": apex, "type": typ}},
                          hostname=asset_id, asset_id=asset_id, scan_run_id="t-4r",
                          queue_id="q-4r", intensity="light")


def _fake_dig(answers):
    """run_cmd stand-in: answers {(qtype, name): stdout or (rc, stdout)}; anything else is an
    empty answer with rc 0."""
    def run_cmd(cmd, timeout=30, input_str=None):
        assert cmd[:2] == ["dig", "+short"], cmd
        a = answers.get((cmd[2], cmd[3]), "")
        rc, out = a if isinstance(a, tuple) else (0, a)
        return rc, out, ""
    return run_cmd


def _posture(ctx):
    recs = [json.loads(c) for (tool, _fmt, c) in ctx.artifacts if tool == "dns_posture"]
    assert len(recs) == 1
    return recs[0]


def _keys(ctx):
    return sorted(f.check_name for f in ctx.findings)


def test_pay_commandmi_gets_no_email_findings(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "pay.commandmi.com"): PAY_CHAIN,
        ("TXT", "pay.commandmi.com"): PAY_CHAIN,
        ("TXT", "_dmarc.commandmi.com"): CMDMI_DMARC,
    }))
    ctx = _ctx("pay.commandmi.com", "commandmi.com")
    rl.check_dns_posture(ctx)
    rec = _posture(ctx)
    assert _keys(ctx) == []
    assert rec["mx"] == []
    assert rec["alias_chain"][0] == "paylinks.commerce.godaddy.com."
    assert rec["sending_host"]["is_sending_host"] is False
    assert rec["spf_suppressed"] == "non_sending_subdomain_apex_owns_the_gap"
    assert rec["dmarc_suppressed"] == "apex_owns_the_gap"
    assert ctx.tool_status["dns_posture"] == {"ok": True}


def test_an_azure_app_alias_gets_no_email_findings(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "portal.unimacgraphics.com"): PORTAL_CHAIN,
        ("TXT", "portal.unimacgraphics.com"): PORTAL_CHAIN,
    }))
    ctx = _ctx("portal.unimacgraphics.com", "unimacgraphics.com")
    rl.check_dns_posture(ctx)
    assert _keys(ctx) == []
    assert _posture(ctx)["alias_chain"] == [l for l in PORTAL_CHAIN.splitlines()]


def test_an_alias_to_real_mail_servers_still_gets_its_dmarc_finding(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "www.commandcompanies.com"): WWW_CMDCO_MX,
        ("TXT", "www.commandcompanies.com"): WWW_CMDCO_TXT,
        ("TXT", "_dmarc.commandcompanies.com"): CMDCO_DMARC,
    }))
    ctx = _ctx("www.commandcompanies.com", "commandcompanies.com")
    rl.check_dns_posture(ctx)
    rec = _posture(ctx)
    assert _keys(ctx) == ["dns-missing-dmarc"]          # as before 4r: p=none protects nothing
    assert rec["sending_host"]["signals"]["mx_present"] is True
    assert rec["alias_chain"] == ["commandcompanies.com."]


def test_a_subdomain_with_its_own_mx_still_emits(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "billing.example.com"): "10 mx.example.net.\n",
    }))
    ctx = _ctx("billing.example.com", "example.com")
    rl.check_dns_posture(ctx)
    assert _keys(ctx) == ["dns-missing-dmarc", "dns-missing-spf"]
    assert _posture(ctx)["alias_chain"] == []


def test_an_apex_with_no_spf_still_emits(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({}))
    ctx = _ctx("example.com", "example.com", typ="apex_domain")
    rl.check_dns_posture(ctx)
    assert _keys(ctx) == ["dns-missing-dmarc", "dns-missing-spf"]


def test_the_call_site_uses_the_split():
    src = (Path(__file__).parent / "run_light.py").read_text()
    assert src.count("mx_records, alias_chain = split_mx_answer(mx_out)") == 1
    assert "mx_records = [l.strip() for l in mx_out.splitlines() if l.strip()]" not in src


# ── Review round 1, must-fix 1: a failed MX lookup keeps the fail-safe ─────────────────────

def _assert_failsafe(ctx):
    rec = _posture(ctx)
    assert _keys(ctx) == ["dns-missing-dmarc", "dns-missing-spf"]
    assert rec["mx_unread"] is True
    assert rec["sending_host"]["is_sending_host"] is True
    assert rec["sending_host"]["inference_confidence"] == "mx_unread"
    assert "spf_suppressed" not in rec and "dmarc_suppressed" not in rec
    assert ctx.tool_status["dns_posture"] == {"degraded": "mx_query_failed"}


def test_a_failed_mx_lookup_keeps_the_name_a_sender(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "www.example.com"): (9, ";; connection timed out; no servers could be reached\n"),
    }))
    ctx = _ctx("www.example.com", "example.com")
    rl.check_dns_posture(ctx)
    _assert_failsafe(ctx)


def test_a_failed_mx_lookup_with_no_output_too(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({("MX", "www.example.com"): (1, "")}))
    ctx = _ctx("www.example.com", "example.com")
    rl.check_dns_posture(ctx)
    _assert_failsafe(ctx)


def test_unreadable_mx_output_with_rc_0_too(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "www.example.com"): ";; connection timed out; no servers could be reached\n",
    }))
    ctx = _ctx("www.example.com", "example.com")
    rl.check_dns_posture(ctx)
    _assert_failsafe(ctx)


def test_an_empty_clean_answer_is_not_a_failure(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({}))
    ctx = _ctx("www.example.com", "example.com")
    rl.check_dns_posture(ctx)
    rec = _posture(ctx)
    assert rec["mx_unread"] is False and _keys(ctx) == []
    assert ctx.tool_status["dns_posture"] == {"ok": True}


def test_a_resolver_failure_on_spf_keeps_its_own_reason(monkeypatch):
    monkeypatch.setattr(rl, "run_cmd", _fake_dig({
        ("MX", "www.example.com"): (9, ""),
        ("TXT", "www.example.com"): (9, ""),
    }))
    ctx = _ctx("www.example.com", "example.com")
    rl.check_dns_posture(ctx)
    assert ctx.tool_status["dns_posture"] == {"degraded": "spf_query_failed"}
