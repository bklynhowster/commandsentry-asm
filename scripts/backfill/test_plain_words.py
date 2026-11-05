#!/usr/bin/env python3
"""Tests for plain_words.py (KB 12 job 4u, plan v2, 2026-11-04). The AI and the database are faked:
no API spend, no network.

What is pinned: the answer checker, one test per rule with an answer that breaks it, and real-shaped
good answers that pass; the off switch on every path (the normal run, --finding-id, --force, and a
switch set during the run), including when the query fails to filter it; the worker writes only its
six columns and never the switch; when words are (re)written and when they are not (the hash);
a failed answer is retried once, then the words are cleared and the inputs recorded so they are not
paid for again; an API error writes nothing; keyset paging past 500 with the count check; the
scheduled step's limit; the workflow step.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import plain_words as pw  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "enrich-finding-descriptions.yml")

GOOD = {
    "what": "This site squeezes its pages so they load faster, which nearly every website does. "
            "In a narrow case, squeezed pages can give away a secret a page holds, like a sign-in code.",
    "worry": "Low. It would take someone watching a visitor's connection and much more, and the scan "
             "saw no secret on the page.",
    "todo": "Nothing now. Next time your web developer works on this site, they can turn squeezing off "
            "on pages that hold secrets.",
}
GOOD_DMARC = {
    "what": "Anyone can send an email that claims to come from this company's address. A short public "
            "setting tells other mail systems what to do with fakes.",
    "worry": "It matters: without it, many mail systems deliver the fake.",
    "todo": "Your IT team adds an email-protection setting (DMARC), first in report-only mode.",
}
GOOD_CERT = {
    "what": "Its security certificate, what makes the padlock show in the browser, runs out in about "
            "54 days.",
    "worry": "Not yet. If it runs out, visitors see a warning instead of the site.",
    "todo": "Your IT team renews it before then; many sites renew on their own.",
}


# ─── (a) the checker ────────────────────────────────────────────────────────

@pytest.mark.parametrize("good", [GOOD, GOOD_DMARC, GOOD_CERT])
def test_real_shaped_good_answers_pass(good):
    assert pw.check_answer(good) == []


def _with(**over):
    d = dict(GOOD)
    d.update(over)
    return d


BREAKS = [
    ("names a CVE, CWE or standard", "It is listed as CVE-2013-3587."),
    ("names a CVE, CWE or standard", "It falls under CWE-310."),
    ("names a CVE, CWE or standard", "The rule is RFC 7627."),
    ("names a CVE, CWE or standard", "See ISO 27001 for more."),
    ("names a CVE, CWE or standard", "It is in ISO/IEC 27002."),
    ("names a CVE, CWE or standard", "The NIST guide covers it."),
    ("names a CVE, CWE or standard", "Its CVSS score is low."),
    ("names a CVE, CWE or standard", "An OWASP list names it."),
    ("names a CVE, CWE or standard", "A PCI audit would flag it."),
    ("names a CVE, CWE or standard", "A SOC 2 audit would flag it."),
    ("names an address, port or hostname", "The box at 24.157.51.84 answers."),
    ("names an address, port or hostname", "It answers on port 8443."),
    ("names an address, port or hostname", "It answers on the :8443 door."),
    ("names an address, port or hostname", "The site prodexlabs.com does this."),
    ("names an address, port or hostname", "The page at www.example does this."),
    ("names an address, port or hostname", "See https://example for more."),
    ("names a file, setting or command", "Change /etc/nginx/nginx.conf to fix it."),
    ("names a file, setting or command", "Edit the .htaccess file."),
    ("names a file, setting or command", "Turn off ssl_ciphers."),
    ("names a file, setting or command", "Run `gzip off` to fix it."),
    ("uses an attack nickname", "This is the BREACH problem (BREACH)."),
    ("uses an attack nickname", "It is like POODLE."),
    ("uses an attack nickname", "A known trick (LUCKY13) applies."),
    ("uses an attack nickname", "A known trick (SWEET32) applies."),
    ("uses the word breach or Heartbleed", "This is not a breach."),
    ("uses the word breach or Heartbleed", "Breach risk is low."),
    ("uses the word breach or Heartbleed", "Nothing was breached."),
    ("uses the word breach or Heartbleed", "It is unlike Heartbleed."),
    ("has a line break, list or markdown", "First line.\nSecond line."),
    ("has a line break, list or markdown", "This is **important**."),
    ("uses an abbreviation without plain words first", "The TLS setting is old."),
    ("uses an abbreviation without plain words first", "It uses SHA1 still."),
    # code review (Kimi, handoff 006): the false acceptances
    ("uses an attack nickname", "It is like Poodle."),
    ("uses an attack nickname", "It is like poodle."),
    ("uses an attack nickname", "A Logjam weakness."),
    ("uses an attack nickname", "The lucky13 trick."),
    ("uses an attack nickname", "The Sweet 32 trick."),
    ("uses an attack nickname", "A known Robot problem."),
    ("uses an attack nickname", "A known Freak problem."),
    ("names a file, setting or command", "Edit nginx.conf to fix it."),
    ("names a file, setting or command", "Edit wp-config.php to fix it."),
    ("names a file, setting or command", "Change Content-Security-Policy."),
    ("names a file, setting or command", "Set X-Frame-Options."),
    ("names an address, port or hostname", "The site example.cloud does this."),
    ("names an address, port or hostname", "The site shop.example.museum does this."),
    ("names an address, port or hostname", "It answers at mailhost:8443 too."),
    ("uses an abbreviation without plain words first", "It uses (TLS) still."),
    ("uses an abbreviation without plain words first", "Use TLS (TLS) now."),
    ("uses an abbreviation without plain words first", "(DMARC) is missing."),
    # its re-check (Kimi, handoff 008): every capitalization
    ("uses an attack nickname", "It is like CrIME."),
    ("uses an attack nickname", "A rObOt trick."),
    ("uses an attack nickname", "The dRoWn trick."),
    ("uses an attack nickname", "The BeAsT trick."),
    ("uses an attack nickname", "The fReAk trick."),
    ("uses an attack nickname", "The PoOdLe trick."),
    ("uses an attack nickname", "The bReAcH trick."),
    ("names a file, setting or command", "Edit NGINX.CONF to fix it."),
    ("names a file, setting or command", "Edit Nginx.Conf to fix it."),
    ("names a file, setting or command", "Edit WP-CONFIG.PHP to fix it."),
    ("names a file, setting or command", "Set x-frame-options to fix it."),
    ("names a file, setting or command", "Add a strict-transport-security rule."),
    ("names a file, setting or command", "Add a Cross-Origin-Opener-Policy rule."),
    ("names a file, setting or command", "Turn on Clear-Site-Data at sign-out."),
    # its final re-check (Kimi, handoff 010): lower-case header names
    ("names a file, setting or command", "Add a cross-origin-opener-policy rule."),
    ("names a file, setting or command", "Add a Cross-origin-opener-policy rule."),
    ("names a file, setting or command", "Add a CROSS-ORIGIN-OPENER-POLICY rule."),
    ("names a file, setting or command", "Add a cross-origin-embedder-policy rule."),
    ("names a file, setting or command", "Add a cross-origin-resource-policy rule."),
    ("names a file, setting or command", "Its access-control-allow-origin is too open."),
    ("names a file, setting or command", "It sends an x-powered-by line."),
    ("names a file, setting or command", "It sends an x-custom-debug-header line."),
    ("names a file, setting or command", "Add an expect-ct rule."),
    ("names a file, setting or command", "Its feature-policy is old."),
    ("names an address, port or hostname", "The site EXAMPLE.CLOUD does this."),
    ("names an address, port or hostname", "The site Example.Cloud does this."),
]


@pytest.mark.parametrize("text", [
    "Your IT team renews it by 12:30 on Friday.",                       # a time is not a port
    "Search engines send robots to read this site.",                    # ordinary words stay ordinary
    "Old settings can drown out the new ones; nothing to fear.",
    "It works on Wi-Fi and at the office, a low-risk item.",
    "It uses an old version of the padlock technology (TLS 1.0).",
    "Your IT team adds an email-protection setting (DMARC) in report-only mode.",
    "The site is fine. Its sign-in page uses an older method (SHA1) to check passwords.",
    "No crime is involved; a beast of a setting can freak people out, but nothing will drown.",
    "Bots and robots read public pages all the time.",
    "Its report-only mode and low-risk sign-in page are fine.",
    "An x-ray of the site found a well-known, up-to-date set-up; cross-checking is easy.",
])
def test_ordinary_answers_are_not_refused(text):
    for key in ("what", "worry", "todo"):
        assert pw.check_answer(_with(**{key: text})) == [], (key, text, pw.check_answer(_with(**{key: text})))


@pytest.mark.parametrize("why,text", BREAKS)
def test_each_rule_refuses_an_answer_that_breaks_it(why, text):
    for key in ("what", "worry", "todo"):
        problems = pw.check_answer(_with(**{key: text}))
        assert any(p.startswith(f'"{key}" {why}') for p in problems), (key, text, problems)


def test_an_abbreviation_in_parentheses_after_plain_words_is_allowed():
    assert pw.check_answer(_with(what="It uses an old version of the padlock technology (TLS 1.0).")) == []
    assert pw.check_answer(_with(todo="Your IT team can do it; an AI wrote this OK.")) == []


def test_the_nickname_rule_is_stricter_than_the_abbreviation_rule():
    # In parentheses an abbreviation is fine; a nickname never is (plan v2, Howie 15:29).
    assert pw.check_answer(_with(what="An old trick (BREACH) applies.")) != []
    assert pw.check_answer(_with(what="An old method (RC4) is allowed.")) == []


@pytest.mark.parametrize("key", ["what", "worry", "todo"])
def test_empty_or_too_long_parts_are_refused(key):
    assert any("is empty" in p for p in pw.check_answer(_with(**{key: "  "})))
    assert any("longer than" in p for p in pw.check_answer(_with(**{key: "a" * (pw.CAPS[key] + 1)})))
    assert pw.check_answer(_with(**{key: "a" * pw.CAPS[key]})) == []


def test_the_caps():
    assert pw.CAPS == {"what": 300, "worry": 200, "todo": 200}


def test_not_an_object_is_refused():
    assert pw.check_answer(None) and pw.check_answer(["a"]) and pw.check_answer({"what": "x"})


def test_the_prompt_carries_the_rules():
    sp = pw.SYSTEM_PROMPT
    for must in ("never alarming, never dismissive", "No site names, web addresses, IP addresses or port numbers",
                 "BREACH", "never the word \"breach\" in any form", "might matter in a narrow case",
                 "say what was seen and what else would have to be true", "JSON only"):
        assert must in sp, must


# ─── fakes ──────────────────────────────────────────────────────────────────

class _B:
    """A PostgREST builder double that records the filters, in order, and applies them."""

    def __init__(self, db, table, rows, chain=None, head=False, honour_switch=True):
        self.db, self.table, self.rows, self.head = db, table, rows, head
        self.chain = chain if chain is not None else []
        self.honour_switch = honour_switch
        self.payload = None

    def _c(self, rows=None, step=None):
        b = type(self)(self.db, self.table, self.rows if rows is None else rows,
                       self.chain + ([step] if step else []), self.head, self.honour_switch)
        b.payload = self.payload
        return b

    def select(self, cols, count=None, head=False):
        b = self._c(step=("select", cols))
        b.head = head
        return b

    def is_(self, col, val):
        rows = self.rows
        if val == "null" and (col != pw.SWITCH or self.honour_switch):
            rows = [r for r in rows if not r.get(col)]
        return self._c(rows, ("is_", col, val))

    def in_(self, col, vals):
        return self._c([r for r in self.rows if r.get(col) in vals], ("in_", col, tuple(vals)))

    def eq(self, col, val):
        return self._c([r for r in self.rows if r.get(col) == val], ("eq", col, val))

    def gt(self, col, val):
        return self._c([r for r in self.rows if r[col] > val], ("gt", col, val))

    def order(self, col, desc=False):
        return self._c(sorted(self.rows, key=lambda r: r.get(col) or "", reverse=desc), ("order", col, desc))

    def limit(self, n):
        return self._c(self.rows[: min(n, 1000)], ("limit", n))

    def update(self, payload):
        b = self._c(step=("update",))
        b.payload = payload
        return b

    def execute(self):
        self.db.calls.append((self.table, self.chain, self.payload))
        if self.payload is not None:
            for r in self.rows:
                r.update(self.payload)
            self.db.updates.append((self.chain, dict(self.payload), [r["finding_id"] for r in self.rows]))
            return type("R", (), {"data": list(self.rows), "count": len(self.rows)})()
        if self.head:
            return type("R", (), {"data": [], "count": len(self.rows)})()
        return type("R", (), {"data": [dict(r) for r in self.rows], "count": len(self.rows)})()


class _DB:
    def __init__(self, findings, history=None, honour_switch=True):
        self.findings, self.history = findings, history or []
        self.calls, self.updates = [], []
        self.honour_switch = honour_switch

    def table(self, name):
        rows = {"findings": self.findings, "finding_history": self.history}[name]
        return _B(self, name, rows, honour_switch=self.honour_switch)


class _AI:
    def __init__(self, answers):
        self.answers = list(answers)
        self.sent = []
        self.messages = self

    def create(self, **kw):
        self.sent.append(kw)
        a = self.answers.pop(0) if self.answers else pw.json.dumps(GOOD)
        if isinstance(a, Exception):
            raise a
        text = a if isinstance(a, str) else pw.json.dumps(a)
        return type("Resp", (), {"content": [type("T", (), {"text": text})()]})()


def _row(i, **over):
    r = {"finding_id": f"f{i:05d}", "asset_id": "a.example.com", "title": f"title {i}", "severity": "LOW",
         "category": "tls", "current_status": "detected", "description": "scanner text",
         "description_synth": "synth", "impact": "impact", "remediation": "fix",
         "plain_what": None, "plain_worry": None, "plain_todo": None, "plain_input_hash": None,
         "plain_model": None, "plain_written_at": None, pw.SWITCH: None}
    r.update(over)
    return r


def _current(i, **over):
    r = _row(i, plain_what="w", plain_worry="x", plain_todo="y", plain_model=pw.MODEL_ID, **over)
    r["plain_input_hash"] = pw.input_hash(r)
    return r


def _run(db, ai, **kw):
    kw.setdefault("now", "2026-11-04T22:00:00+00:00")
    return pw.run(db, ai, **kw)


# ─── (b) the off switch, on every path ─────────────────────────────────────

def test_the_switch_is_the_first_filter_on_the_count_probe_and_every_page():
    db = _DB([_row(i) for i in range(3)])
    _run(db, _AI([]))
    reads = [chain for t, chain, p in db.calls if t == "findings" and p is None]
    assert reads, "no findings reads recorded"
    for chain in reads:
        filters = [s for s in chain if s[0] in ("is_", "in_", "eq", "gt")]
        assert filters[0] == ("is_", pw.SWITCH, "null"), chain


def test_the_scope_is_open_findings_at_low_and_above():
    rows = [_row(1), _row(2, severity="INFO"), _row(3, current_status="remediated"),
            _row(4, current_status="closed_reclassified"), _row(5, severity="MODERATE", current_status="regressed")]
    db = _DB(rows)
    _run(db, _AI([]))
    assert sorted(f for _, _, ids in db.updates for f in ids) == ["f00001", "f00005"]
    assert "INFO" not in pw.SEVERITIES and set(pw.OPEN_STATUSES) == {"detected", "confirmed", "open", "regressed"}


@pytest.mark.parametrize("force", [False, True])
def test_a_switched_off_row_is_never_written_even_if_the_query_lets_it_through(force):
    rows = [_row(1, **{pw.SWITCH: "2026-11-04T20:00:00Z"}), _row(2)]
    db = _DB(rows, honour_switch=False)         # the query "forgets" the switch: the loop must not
    ai = _AI([])
    st = _run(db, ai, force=force)
    assert [ids for _, _, ids in db.updates] == [["f00002"]]
    assert st["wrote"] == 1 and len(ai.sent) == 1


def test_a_targeted_run_on_a_switched_off_row_says_so_and_calls_nothing(capsys):
    db = _DB([_row(1, **{pw.SWITCH: "2026-11-04T20:00:00Z"})])
    ai = _AI([])
    for force in (False, True):
        st = _run(db, ai, finding_id="f00001", force=force)
        assert st["wrote"] == 0 and db.updates == [] and ai.sent == []
    assert "f00001: switched off at 2026-11-04T20:00:00Z" in capsys.readouterr().out


@pytest.mark.parametrize("force", [False, True])
def test_needs_words_is_never_true_for_a_switched_off_row(force):
    assert not pw.needs_words(_row(1, **{pw.SWITCH: "2026-11-04T20:00:00Z"}), force=force)
    assert not pw.needs_words(_current(1, **{pw.SWITCH: "2026-11-04T20:00:00Z"}), force=force)


def test_the_loop_gate_holds_even_if_the_query_and_needs_words_do_not(monkeypatch):
    monkeypatch.setattr(pw, "needs_words", lambda row, force: True)
    db = _DB([_row(1, **{pw.SWITCH: "2026-11-04T20:00:00Z"}), _row(2)], honour_switch=False)
    ai = _AI([])
    _run(db, ai, force=True)
    assert [ids for _, _, ids in db.updates] == [["f00002"]] and len(ai.sent) == 1


def test_a_targeted_run_on_an_ordinary_row_writes_it():
    db = _DB([_row(1), _row(2)])
    st = _run(db, _AI([]), finding_id="f00002")
    assert st["wrote"] == 1 and [ids for _, _, ids in db.updates] == [["f00002"]]


def test_a_switch_set_during_the_run_wins():
    rows = [_row(1)]
    db = _DB(rows)

    class _AISwitches(_AI):
        def create(self, **kw):
            rows[0][pw.SWITCH] = "2026-11-04T21:59:00Z"     # Howie's script lands mid-call
            return super().create(**kw)

    st = _run(db, _AISwitches([]))
    assert st["switched_off_mid_run"] == 1 and st["wrote"] == 0
    assert rows[0]["plain_what"] is None
    (chain, payload, ids), = db.updates
    assert ("is_", pw.SWITCH, "null") in chain and ids == []


# ─── (c) the only columns it writes ─────────────────────────────────────────

def test_it_writes_only_its_six_columns_and_never_the_switch():
    changed = _current(2)
    changed["title"] = "now different"                   # the hash no longer matches: a rewrite
    db = _DB([_row(1), changed, _row(3)])
    st = _run(db, _AI([GOOD, GOOD, {"what": "x"}, {"what": "y"}]))   # the third fails twice: cleared
    assert st["wrote"] == 2 and st["cleared"] == 1 and len(db.updates) == 3
    for chain, payload, ids in db.updates:
        assert set(payload) <= set(pw.PLAIN_COLUMNS), payload
        assert pw.SWITCH not in payload
        assert [s for s in chain if s[0] == "eq"] == [("eq", "finding_id", ids[0])]
        assert ("is_", pw.SWITCH, "null") in chain
    assert pw.PLAIN_COLUMNS == ("plain_what", "plain_worry", "plain_todo",
                                "plain_input_hash", "plain_model", "plain_written_at")


def test_write_row_refuses_any_other_column():
    db = _DB([_row(1)])
    for bad in ({"description_synth": "x"}, {pw.SWITCH: None}, {"impact": "x"}, {"description_source": "manual"}):
        with pytest.raises(RuntimeError):
            pw.write_row(db, "f00001", bad)


def test_the_d029_columns_are_untouched_after_a_run():
    rows = [_row(1)]
    before = {k: rows[0][k] for k in ("description_synth", "impact", "remediation", "description")}
    _run(_DB(rows), _AI([]))
    assert {k: rows[0][k] for k in before} == before and rows[0]["plain_what"] == GOOD["what"]


# ─── (d) when words are written, and when they are not ──────────────────────

def test_the_hash_follows_what_the_words_are_written_from():
    base = _row(1)
    h = pw.input_hash(base)
    for k in ("title", "severity", "description", "description_synth", "impact", "remediation"):
        assert pw.input_hash(dict(base, **{k: "changed"})) != h, k
    for k in ("asset_id", "category", "current_status", "plain_what", "plain_model"):
        assert pw.input_hash(dict(base, **{k: "changed"})) == h, k


def test_a_new_prompt_version_rewrites_everything(monkeypatch):
    r = _current(1)
    assert not pw.needs_words(r, force=False)
    monkeypatch.setattr(pw, "PROMPT_VERSION", "4u-2")
    assert pw.needs_words(r, force=False)


def test_current_words_are_left_alone_and_a_changed_d029_section_brings_a_rewrite():
    rows = [_current(1), _current(2)]
    rows[1]["impact"] = "D-029 rewrote this"
    db = _DB(rows)
    st = _run(db, _AI([]))
    assert st["current"] == 1 and st["wrote"] == 1 and [ids for _, _, ids in db.updates] == [["f00002"]]


def test_force_rewrites_current_words():
    db = _DB([_current(1)])
    assert _run(db, _AI([]), force=True)["wrote"] == 1


# ─── (e) a failed answer, an API error ──────────────────────────────────────

def test_a_bad_first_answer_is_retried_once_and_told_what_it_broke():
    db = _DB([_row(1)])
    ai = _AI([_with(what="It is CVE-2013-3587."), GOOD])
    st = _run(db, ai)
    assert st["wrote"] == 1 and len(ai.sent) == 2
    retry = ai.sent[1]["messages"][-1]["content"]
    assert "names a CVE, CWE or standard" in retry and ai.sent[1]["messages"][1]["role"] == "assistant"


def test_two_failed_answers_clear_old_words_and_record_the_inputs():
    rows = [_current(1)]
    rows[0]["severity"] = "MODERATE"                       # the finding changed: the old words are stale
    db = _DB(rows)
    st = _run(db, _AI(["not json at all", _with(worry="This is a breach.")]))
    assert st["cleared"] == 1 and st["wrote"] == 0
    r = rows[0]
    assert r["plain_what"] is r["plain_worry"] is r["plain_todo"] is None
    assert r["plain_model"] == "failed-check:" + pw.MODEL_ID and r["plain_input_hash"] == pw.input_hash(r)
    # ...and the same inputs are not paid for again on the next run
    ai2 = _AI([])
    assert _run(db, ai2)["pending"] == 0 and ai2.sent == []


def test_an_api_error_writes_nothing_and_the_next_run_tries_again():
    db = _DB([_row(1)])
    st = _run(db, _AI([RuntimeError("overloaded")]))
    assert st["errors"] == 1 and db.updates == []
    assert _run(db, _AI([]))["wrote"] == 1


def test_main_exits_nonzero_when_there_were_api_errors(monkeypatch):
    monkeypatch.setattr(pw, "run", lambda *a, **k: {"errors": 2})
    for n in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.setenv(n, "x")
    fake_anthropic = type(sys)("anthropic")
    fake_anthropic.Anthropic = lambda api_key: None
    fake_supabase = type(sys)("supabase")
    fake_supabase.create_client = lambda u, k: None
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)
    monkeypatch.setitem(sys.modules, "supabase", fake_supabase)
    with pytest.raises(SystemExit) as e:
        pw.main([])
    assert e.value.code == 1


def test_main_refuses_without_its_environment(monkeypatch):
    for n in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(n, raising=False)
    with pytest.raises(SystemExit) as e:
        pw.main([])
    assert "SUPABASE_URL" in str(e.value.code)


def test_a_dry_run_writes_nothing():
    db = _DB([_row(1)])
    st = _run(db, _AI([]), dry_run=True)
    assert st["wrote"] == 1 and db.updates == []


def test_the_excerpt_goes_to_the_model_cut_short_and_the_longest_wins():
    hist = [{"finding_id": "f00001", "raw_excerpt": "short", "observed_at": "1"},
            {"finding_id": "f00001", "raw_excerpt": "L" * 3000, "observed_at": "2"},
            {"finding_id": "f00001", "raw_excerpt": "M" * 80, "observed_at": "3"}]
    ai = _AI([])
    _run(_DB([_row(1)], history=hist), ai)
    prompt = ai.sent[0]["messages"][0]["content"]
    assert "L" * pw.EXCERPT_CHARS in prompt and "L" * (pw.EXCERPT_CHARS + 1) not in prompt
    assert ai.sent[0]["system"] == pw.SYSTEM_PROMPT and ai.sent[0]["model"] == pw.MODEL_ID


# ─── (f) paging, (g) the limit ──────────────────────────────────────────────

def test_it_walks_past_500_with_a_keyset_cursor():
    rows = [_current(i) for i in range(1200)] + [_row(1200)]
    db = _DB(rows)
    st = _run(db, _AI([]))
    assert st["in_scope"] == 1201 and st["wrote"] == 1
    cursors = [s for _, chain, p in db.calls for s in chain if s[0] == "gt"]
    assert [c[2] for c in cursors] == ["f00499", "f00999"]


class _ShortB(_B):
    def limit(self, n):                                   # a page clamped below what the count said
        return self._c(self.rows[:3], ("limit", n))


class _ShortDB(_DB):
    def table(self, name):
        if name != "findings":
            return super().table(name)
        return _ShortB(self, name, self.findings, honour_switch=self.honour_switch)


def test_a_short_read_stops_the_run_before_any_write():
    db = _ShortDB([_row(i) for i in range(10)])
    with pytest.raises(SystemExit) as e:
        _run(db, _AI([]))
    assert "cannot see its whole queue" in str(e.value.code) and db.updates == []


def test_the_scheduled_limit_is_100_and_says_when_it_was_reached(capsys):
    assert pw.PER_RUN_LIMIT == 100
    db = _DB([_row(i) for i in range(130)])
    st = _run(db, _AI([]))
    assert st["wrote"] == 100 and st["left_for_next_run"] == 30
    assert "the limit of 100 was reached" in capsys.readouterr().out
    assert _run(db, _AI([]))["wrote"] == 30


def test_limit_zero_means_everything_pending():
    db = _DB([_row(i) for i in range(130)])
    assert _run(db, _AI([]), limit=0)["wrote"] == 130


# ─── (h) the workflow step ──────────────────────────────────────────────────

def _steps():
    text = open(WORKFLOW).read()
    return text, re.split(r"\n      - name: ", text)


def test_the_workflow_runs_the_plain_step_after_the_d029_worker_whatever_it_did():
    text, steps = _steps()
    names = [s.split("\n", 1)[0].strip() for s in steps[1:]]
    assert "Run synthesis worker" in names and "Write plain words (job 4u)" in names
    assert names.index("Write plain words (job 4u)") > names.index("Run synthesis worker")
    step = steps[1 + names.index("Write plain words (job 4u)")]
    assert "if: ${{ !cancelled() }}" in step
    assert "python scripts/backfill/plain_words.py" in step
    assert "--force" not in step and "--limit" not in step   # the scheduled ceiling is PER_RUN_LIMIT
    assert '--finding-id "${{ github.event.inputs.finding_id }}"' in step
    assert "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}" in step
    assert "SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}" in step


def test_the_plain_step_points_at_this_repos_database():
    text, steps = _steps()
    urls = set(re.findall(r'SUPABASE_URL: "(https://[a-z]+\.supabase\.co)"', text))
    assert len(urls) == 1, urls                              # the precheck's and the plain step's agree
    names = [s.split("\n", 1)[0].strip() for s in steps[1:]]
    step = steps[1 + names.index("Write plain words (job 4u)")]
    assert f'SUPABASE_URL: "{urls.pop()}"' in step


def test_python_and_its_packages_are_there_even_when_the_d029_worker_was_skipped():
    text, steps = _steps()
    names = [s.split("\n", 1)[0].strip() for s in steps[1:]]
    setup = steps[1 + names.index("Set up Python for the plain words")]
    deps = steps[1 + names.index("Install the plain words' packages")]
    for s in (setup, deps):
        assert "!cancelled() && steps.precheck.outputs.should_run == 'false'" in s
    assert "anthropic<1.0" in deps and "supabase" in deps
