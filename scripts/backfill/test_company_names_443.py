"""443: each scanner repo's AI write-ups name its own company and product, carry no disclaimer,
and never name the other Sentry instance's company.

Howie, 2026-11-14 11:51, on a Prodex finding: "you call it the command sentry scanner..thats
incorrect...in this case, its the prodex sentry scanner." Prodex's copy of the writer had carried
Command's prompt since the fork: 132 Prodex write-ups named Command, some telling ProDex staff to
check "other Command Companies assets (Command Digital, Unimac, SCI)". The same write-up ended with
"This is a missing compensating control, not a confirmed exploit: the scanner could not
authenticate and did not test anything behind the login" (no disclaimers, Howie 2026-11-12).

This file is byte-identical in both repos; what differs is read from the module.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import synthesize_finding_descriptions as sfd  # noqa: E402
from test_synthesize_fetch_pagination import _FakeSB, _thin_row  # noqa: E402

PRODEX = sfd.DEFAULT_SUPABASE_URL == "https://bxcvzpbmxsdtalyfanee.supabase.co"
COMMAND = sfd.DEFAULT_SUPABASE_URL == "https://hdygktppfvuspnumpfuq.supabase.co"
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "enrich-finding-descriptions.yml")


def test_this_copy_is_one_of_the_two_instances():
    assert PRODEX != COMMAND


# ── whose write-ups ────────────────────────────────────────────────────────────

def test_each_copy_names_its_own_company_and_product():
    if PRODEX:
        assert (sfd.COMPANY, sfd.PRODUCT) == ("ProDex Labs", "Prodex Sentry")
        assert set(sfd.OTHER_COMPANY_WORDS) >= {"command sentry", "commandsentry", "command companies",
                                                "command digital", "unimac"}
    else:
        assert (sfd.COMPANY, sfd.PRODUCT) == ("Command Companies", "Command Sentry")
        assert sfd.OTHER_COMPANY_WORDS == ("prodex",)
    assert all(w == w.lower() and w.strip() == w and w for w in sfd.OTHER_COMPANY_WORDS)


def test_the_prompt_never_names_the_other_company():
    assert sfd.names_other_company(sfd.SYSTEM_PROMPT) is None, sfd.names_other_company(sfd.SYSTEM_PROMPT)
    assert sfd.names_other_company(sfd.USER_PROMPT_TEMPLATE) is None
    assert sfd.SYSTEM_PROMPT.startswith(sfd.ROLE_LINE + "\n\nYou will receive structured data")


def test_the_prompt_names_this_company_in_every_place_it_used_to_say_command():
    p = sfd.SYSTEM_PROMPT
    assert f"For {sfd.COMPANY}, the frameworks that always need consideration are:" in p
    assert f"in the form {sfd.COMPANY} actually uses" in p
    assert "«" not in p and "»" not in p
    if PRODEX:
        assert not re.search(r"\bcommand\b", p, re.I), "Prodex's prompt says Command somewhere"


def test_the_prompt_says_what_the_scanner_is_called_and_forbids_disclaimers():
    p = sfd.SYSTEM_PROMPT
    assert f"The scanner is {sfd.PRODUCT}. When a section mentions the scanner, call it {sfd.PRODUCT}" in p
    assert (f"Never name any company other than {sfd.COMPANY} and its own organisations as the owner of these "
            "sites or the maker of this scan; name the software and vendors involved as usual") in p
    assert "No disclaimers about what the scan did not or could not do" in p
    assert "not a confirmed exploit" in p and "could not authenticate" in p


def test_the_role_line_is_this_company():
    assert sfd.COMPANY in sfd.ROLE_LINE
    if PRODEX:
        assert "Command" not in sfd.ROLE_LINE and "Unimac" not in sfd.ROLE_LINE


# ── what the writer is told the source is ────────────────────────────────────

@pytest.mark.parametrize("source,want", [
    ("commandsentry_light", "quick scan"), ("commandsentry_medium", "medium scan"),
    ("commandsentry_heavy", "deep scan"), ("CommandSentry_Heavy", "deep scan"),
])
def test_the_scanners_own_tool_names_become_the_product_name(source, want):
    assert sfd.source_label(source) == f"{sfd.PRODUCT} {want}"


@pytest.mark.parametrize("source,want", [
    ("testssl", "testssl"), ("nuclei", "nuclei"), ("advisory_watch", "advisory_watch"),
    ("", "unknown"), (None, "unknown"), ("  nikto ", "nikto"),
])
def test_other_sources_are_passed_as_recorded(source, want):
    assert sfd.source_label(source) == want


def _finding(**over):
    kw = dict(finding_id="a.example.test:commandsentry_heavy:waf-absent-differential:0a3b775",
              title="No enforcing WAF in front of the sign-in", severity="MODERATE",
              asset_id="a.example.test", description="Three attack-shaped requests got the same redirect.",
              cve=[], cwe=[], category="config", source="commandsentry_heavy", references=[],
              asset_name="a.example.test", organization="Example", asset_type="subdomain",
              best_excerpt=None, cvss=None)
    kw.update(over)
    return sfd.FindingInput(**kw)


def test_the_prompt_shows_the_product_name_not_the_tool_name():
    text = _finding().to_prompt()
    assert f"Source scanner: {sfd.PRODUCT} deep scan" in text
    assert "commandsentry" not in text.lower().replace(_finding().finding_id.lower(), "")


def test_the_input_hash_still_uses_the_recorded_source():
    """The label changes what the writer reads, not the hash kept beside each write-up."""
    import hashlib
    import json
    f = _finding()
    blob = json.dumps({"title": f.title, "description": f.description, "cve": [], "cwe": [],
                       "category": f.category, "source": "commandsentry_heavy", "best_excerpt": None},
                      sort_keys=True)
    assert f.input_hash() == hashlib.sha256(blob.encode()).hexdigest()


# ── the guard ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [w.upper() for w in sfd.OTHER_COMPANY_WORDS] + [
    f"Re-run the {w.title()} scan." for w in sfd.OTHER_COMPANY_WORDS])
def test_any_casing_of_the_other_company_is_caught(text):
    assert sfd.names_other_company(text)


@pytest.mark.parametrize("text", ["", None, f"The {sfd.PRODUCT} deep scan saw it.", f"{sfd.COMPANY} owns this site."])
def test_this_company_is_not_the_other_company(text):
    assert sfd.names_other_company(text) is None


class _Stop(Exception):
    pass


def _run_main(monkeypatch, result, findings=None):
    """main() with the network replaced: one finding, synthesize_one returns `result`."""
    written = []
    monkeypatch.setattr(sfd, "_import_deps", lambda: None)
    fake_anthropic = type(sys)("anthropic"); fake_anthropic.Anthropic = lambda api_key: object()
    fake_supabase = type(sys)("supabase"); fake_supabase.create_client = lambda u, k: object()
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)
    monkeypatch.setitem(sys.modules, "supabase", fake_supabase)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-not-a-key")
    monkeypatch.setattr(sfd, "fetch_findings", lambda sb, **kw: findings or [_finding()])
    monkeypatch.setattr(sfd, "synthesize_one", lambda client, f: result)
    monkeypatch.setattr(sfd, "write_synthesis", lambda *a, **kw: written.append(a))
    monkeypatch.setattr(sys, "argv", ["synthesize_finding_descriptions.py"])
    code = 0
    try:
        sfd.main()
    except SystemExit as e:
        code = e.code
    return written, code


def _result(**over):
    r = {"what_is_this": f"The {sfd.PRODUCT} deep scan saw no firewall block the test requests.",
         "what_could_it_do": "Attack-shaped requests reach the sign-in unfiltered.",
         "how_do_i_fix_it": "1. Turn on the firewall rules.\n2. Re-run the deep scan."}
    r.update(over)
    return r


@pytest.mark.parametrize("key", sfd.PROSE_KEYS)
def test_a_write_up_naming_the_other_company_is_never_written(monkeypatch, capsys, key):
    bad = f"Check other {sfd.OTHER_COMPANY_WORDS[0].title()} assets too."
    written, code = _run_main(monkeypatch, _result(**{key: bad}))
    assert written == [], "a write-up naming the other company reached the database"
    assert code == 1, "the run must say it failed"
    assert "names another company" in capsys.readouterr().out


def test_a_clean_write_up_is_written(monkeypatch):
    written, code = _run_main(monkeypatch, _result())
    assert len(written) == 1 and code in (0, None)


# ── rewriting the ones already written (--names-other-company) ───────────────

def _ai_row(i, text):
    r = _thin_row(i)
    r.update(description="A full scanner description of what was seen. It has sentences.",
             description_synth=text, impact="Impact text.", remediation="1. Fix it.",
             description_source="ai_synthesized")
    return r


def test_the_rewrite_picks_only_ai_write_ups_that_name_the_other_company():
    word = sfd.OTHER_COMPANY_WORDS[0]
    rows = [_ai_row(1, f"The {word.title()} scanner saw it."),        # names it: picked
            _ai_row(2, f"The {sfd.PRODUCT} deep scan saw it."),         # clean: left alone
            dict(_ai_row(3, f"{word} again"), description_source="manual"),   # a person's text: never
            dict(_ai_row(4, f"{word} again"), description_source="scanner",   # the scanner's own text: never
                 impact="x", remediation="y"),
            dict(_ai_row(5, f"{word} again"), description_synth_reviewed_at="2026-11-01T00:00:00Z"),  # rejected: never
            _ai_row(6, f"The {sfd.PRODUCT} deep scan saw it."),         # clean in every section: never
            _ai_row(7, "A command-line tool reported it; see the sentry log.")]  # the server's wider match only: never
    rows[1]["impact"] = f"Ask the {word.upper()} team."                # a clean description, a bad impact: picked
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False, other_company=True)
    assert sorted(f.finding_id for f in out) == sorted([rows[0]["finding_id"], rows[1]["finding_id"]])
    assert ("description_source", "ai_synthesized") in sb.state["eq"]
    assert sb.state["or_"] == sfd.OTHER_COMPANY_FILTER
    assert ("description_synth_reviewed_at", "null") in sb.state["is_"]


def test_the_rewrite_filter_covers_every_word_and_every_section():
    f = sfd.OTHER_COMPANY_FILTER
    for col in ("description_synth", "impact", "remediation"):
        for w in sfd.OTHER_COMPANY_WORDS:
            assert f"{col}.ilike.*{w.replace(' ', '*')}*" in f
    assert " " not in f and '"' not in f, "a value PostgREST would need quoted"
    assert f.count(".ilike.") == 3 * len(sfd.OTHER_COMPANY_WORDS)


def test_without_the_flag_nothing_changes_for_a_written_row():
    word = sfd.OTHER_COMPANY_WORDS[0]
    sb = _FakeSB([_ai_row(1, f"The {word} scanner saw it.")])
    assert sfd.fetch_findings(sb, severities=None, finding_id=None, force=False) == []


def test_the_flag_reaches_fetch_findings(monkeypatch):
    seen = {}
    monkeypatch.setattr(sfd, "_import_deps", lambda: None)
    for name, attr, val in (("anthropic", "Anthropic", lambda api_key: object()),
                            ("supabase", "create_client", lambda u, k: object())):
        m = type(sys)(name); setattr(m, attr, val); monkeypatch.setitem(sys.modules, name, m)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-not-a-key")
    monkeypatch.setattr(sfd, "fetch_findings", lambda sb, **kw: seen.update(kw) or [])
    monkeypatch.setattr(sys, "argv", ["x", "--names-other-company"])
    sfd.main()
    assert seen.get("other_company") is True and seen.get("force") is False


# ── the workflow ─────────────────────────────────────────────────────────────

def test_the_workflow_can_start_the_rewrite():
    y = open(WORKFLOW, encoding="utf-8").read()
    assert "      other_company:\n        description: 'One-off (443): rewrite the AI write-ups that name the other Sentry company.'" in y
    assert ("if: ${{ github.event.inputs.force != 'true' && github.event.inputs.finding_id == '' "
            "&& github.event.inputs.other_company != 'true' }}") in y
    assert ('if [[ "${{ github.event.inputs.other_company }}" == "true" ]]; then\n'
            '            ARGS+=(--names-other-company)') in y
