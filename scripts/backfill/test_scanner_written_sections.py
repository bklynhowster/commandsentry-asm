"""Text the scanner wrote in code is never rewritten by an AI, and an out-of-date
finding's plain words never say more than the finding does (D-077 step 2, 2026-11-12).

advisory_watch.py writes all three page sections of a sign-in's out-of-date finding in
code (signin_flaws.py: wording Howie approved, each claim attributed to its source) and
leaves description_source at 'scanner'. Two AI workers run over every finding:

  * synthesize_finding_descriptions.py fills description_synth / impact / remediation.
    It must leave such a row alone on every path: the queue, --finding-id and --force.
  * plain_words.py writes the "What does this mean?" box. For a finding titled
    "Runs ...: out of date" its answer may not say, or deny, that the site can be
    attacked, crashed, taken offline or taken over.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import plain_words as pw  # noqa: E402
import synthesize_finding_descriptions as sfd  # noqa: E402
from test_synthesize_fetch_pagination import _FakeSB, _thin_row  # noqa: E402

LEAD = ("This sign-in shows OAuth2 Proxy 7.15.5. Its maker says release 7.15.6 (Nov 5) fixes 18 published "
        "flaws; 6 are described as crash or overload flaws.")
TITLE = "Runs OAuth2 Proxy 7.15.5: out of date — 18 published flaws fixed in later versions; update it"


def written_row(i=1, **over) -> dict:
    """The row advisory_watch's sign-in track writes: three sections, source 'scanner'."""
    r = _thin_row(i)
    r.update(title=TITLE, severity="MODERATE", source="advisory_watch",
             description=LEAD + "\n\n" + "- CVE-2026-70000 (CVSS 7.5): A crafted request causes a panic.\n" * 8
             + "\nFix: Update OAuth2 Proxy to 7.15.6 or later.",
             description_synth=LEAD, impact="The publishers of these 18 flaws describe them this way.",
             remediation="Update OAuth2 Proxy to 7.15.6 or later.", description_source="scanner")
    r.update(over)
    return r


# ── the synthesis worker ─────────────────────────────────────────────────────

def test_the_queue_no_longer_holds_a_scanner_row_with_all_three_sections():
    """Server side: 'scanner' is in the fourth clause's list, so a scanner row is queued
    only when a section is NULL (the first three clauses), which is every scanner row
    the parsers write. The yml precheck is pinned equal by test_synthesize_fetch_pagination."""
    assert sfd.THIN_PREDICATE == (
        "description_synth.is.null,impact.is.null,remediation.is.null,"
        "description_source.not.in.(ai_synthesized,ai_synthesized_reviewed,manual,scanner),"
        "description_source.is.null")
    assert sfd._ATTESTED_SOURCES == ("ai_synthesized", "ai_synthesized_reviewed", "manual"), \
        "'scanner' is not attested AI text: it is only left alone when all three sections are filled"


@pytest.mark.parametrize("over,want", [
    ({}, True),
    ({"description_synth": None}, False), ({"impact": None}, False), ({"remediation": None}, False),
    ({"description_synth": "   "}, False), ({"impact": ""}, False), ({"remediation": "\n"}, False),
    ({"description_source": "ai_synthesized"}, False), ({"description_source": "manual"}, False),
    ({"description_source": None}, False), ({"impact": 7}, False),
])
def test_only_a_scanner_row_with_three_filled_sections_counts_as_scanner_written(over, want):
    assert sfd.scanner_wrote_all_three(written_row(**over)) is want


@pytest.mark.parametrize("kwargs", [
    dict(severities=None, finding_id=None, force=False),
    dict(severities=None, finding_id=None, force=True),                      # --force re-runs the machine's own text only
    dict(severities=None, finding_id=written_row(1)["finding_id"], force=False),
    dict(severities=None, finding_id=written_row(1)["finding_id"], force=True),
])
def test_a_scanner_written_row_is_never_synthesised_on_any_path(kwargs):
    assert sfd.fetch_findings(_FakeSB([written_row(1)]), **kwargs) == []


def test_a_scanner_row_with_a_section_missing_is_still_ordinary_work():
    """The parsers' rows (description only) and a half-written row both still get the AI's
    sections, exactly as before."""
    half = written_row(2, impact=None)
    blank = written_row(3, remediation="")
    thin = _thin_row(4)
    got = sfd.fetch_findings(_FakeSB([written_row(1), half, blank, thin]), None, None, False)
    assert [f.finding_id for f in got] == [half["finding_id"], blank["finding_id"], thin["finding_id"]]


def test_an_attested_ai_row_is_still_resynthesised_by_force_as_before():
    ai = written_row(5, description_source="ai_synthesized")
    assert sfd.fetch_findings(_FakeSB([ai]), None, None, False) == []
    assert [f.finding_id for f in sfd.fetch_findings(_FakeSB([ai]), None, None, True)] == [ai["finding_id"]]


# ── the plain words ──────────────────────────────────────────────────────────

GOOD = {"what": "This site's sign-in software is an older version. Its maker has released a newer one that "
                "fixes 18 published flaws.",
        "worry": "Moderate. Six of those flaws are described by their publishers as crash or overload flaws.",
        "todo": "Ask your IT team to update the sign-in software to the newest version."}


def _with(**kw):
    return dict(GOOD, **kw)


@pytest.mark.parametrize("title,want", [
    (TITLE, True),
    ("Runs PHP 8.1.2: out of date — 3 published flaws fixed in later versions; update it", True),
    ("Runs Fortinet FortiGate (FortiOS), firmware built Mar 2024: out of date — 2 published since; update it", True),
    ("Runs PHP, version not shown", False), ("Missing security header", False),
    ("It runs old software: out of date", False), (None, False), (7, False),
])
def test_which_findings_are_out_of_date_findings(title, want):
    assert pw.is_out_of_date(title) is want


def test_a_plain_answer_that_says_only_what_was_seen_passes():
    assert pw.check_answer(GOOD, TITLE) == []


@pytest.mark.parametrize("key,text", [
    ("what", "This site is vulnerable to 18 known flaws."),
    ("worry", "An attacker could crash the sign-in page."),
    ("worry", "Attackers may use these flaws."),
    ("worry", "A hacker could use this."),
    ("worry", "A stranger could knock the sign-in out."),
    ("worry", "It can be crashed remotely."),
    ("worry", "A remote user could overload it."),
    ("worry", "The sign-in page could be taken offline."),
    ("worry", "The sign-in could go off-line."),
    ("worry", "These flaws can be exploited."),
    ("worry", "The flaws are exploitable."),
    ("worry", "The sign-in could be compromised."),
    ("what", "This site is affected by 18 flaws."),
    ("worry", "These flaws affect the sign-in."),
    ("worry", "Someone could take over the sign-in."),
    ("worry", "The sign-in could be taken over."),
    ("worry", "This puts the site at risk."),
    ("worry", "The site is not vulnerable, so there is little to worry about."),     # a denial is as unproven
    ("worry", "It is not remotely exploitable."),
    ("worry", "This site can be attacked through these flaws."),                      # any form of the word
    ("worry", "Nothing shows the site was attacked."),
    ("worry", "Known vulnerabilities remain until it is updated."),
    ("worry", "This site is unaffected for now."),
    ("worry", "The sign-in could crash."),                                            # a prediction about the site
    ("worry", "It can be crashed by a bad request."),
    ("worry", "The sign-in page might be overloaded."),
    ("worry", "Someone may knock the sign-in out."),
    ("worry", "The sign-in could go down."),
    ("worry", "It won’t crash, so there is no hurry."),
    ("worry", "A hacked sign-in is a serious problem."),
    ("worry", "The flaws work remotely."),
    ("worry", "This could, after a great deal of very careful consideration and some delay, eventually crash."),
])
def test_an_out_of_date_answer_may_not_say_or_deny_more_than_was_seen(key, text):
    problems = pw.check_answer(_with(**{key: text}), TITLE)
    assert problems == [f'"{key}" {pw.OUT_OF_DATE_WHY}'], problems


@pytest.mark.parametrize("text", [
    "Moderate. Six of those flaws are described by their publishers as crash or overload flaws.",
    "Moderate. Some of the flaws are described as crash flaws. Updating removes them.",
    "Moderate. The maker's newer version fixes them, so plan the update soon.",
])
def test_repeating_how_the_flaws_are_described_is_not_a_claim_about_the_site(text):
    assert pw.check_answer(_with(worry=text), TITLE) == []


def test_the_same_words_are_not_refused_for_any_other_finding():
    """The rule belongs to out-of-date findings alone; no other explanation changes."""
    said = _with(worry="An attacker could read the page remotely.")
    assert pw.check_answer(said, "Missing security header") == []
    assert pw.check_answer(said) == []
    assert pw.check_answer(said, TITLE) != []


def test_a_title_that_names_cisas_exploited_list_may_be_explained_in_those_words():
    listed = "Runs PHP 8.1.2: out of date — 3 published flaws fixed in later versions, 1 on CISA’s exploited list; update it"
    said = _with(worry="Moderate-high. One of the flaws is on a government list of flaws exploited elsewhere.")
    assert pw.check_answer(said, listed) == []
    assert pw.check_answer(said, TITLE) != []
    assert pw.check_answer(_with(worry="An attacker could use the listed flaw."), listed) != []
    # only as the list's own statement: never a claim about this site
    for claim in ("This site can be exploited.", "It is exploitable.", "It is on the list and is exploitable.",
                  "One flaw is on a government list. It is being exploited here.",
                  "Listed or not, it could be exploited.",
                  "It is on the list, so it might, sooner or later and without any warning at all, be exploited."):
        assert pw.check_answer(_with(worry=claim), listed) != [], claim


def test_only_an_out_of_date_finding_gets_the_added_line_and_the_shared_prompt_is_untouched():
    row = {"title": TITLE, "severity": "MODERATE", "category": "supply_chain", "description": LEAD,
           "description_synth": LEAD, "impact": "x", "remediation": "y"}
    other = dict(row, title="Missing security header")
    assert pw.build_prompt(row, None).endswith(pw.OUT_OF_DATE_NOTE)
    assert pw.build_prompt(row, None).startswith(pw.build_prompt(other, None).replace("Missing security header", TITLE))
    assert pw.OUT_OF_DATE_NOTE not in pw.build_prompt(other, None)
    assert pw.PROMPT_VERSION == "4u-1", "no other finding's explanation may be rewritten by this change"
    assert "out-of-date" not in pw.SYSTEM_PROMPT and "out of date" not in pw.SYSTEM_PROMPT


class _Client:
    """Hands back canned answers in order, and keeps what it was asked."""

    def __init__(self, answers):
        self.answers, self.asked = list(answers), []


def test_write_one_checks_against_the_findings_own_title(monkeypatch):
    import json
    bad = json.dumps(_with(worry="An attacker could crash it remotely."))
    good = json.dumps(GOOD)
    row = {"title": TITLE, "severity": "MODERATE", "category": "supply_chain", "description": LEAD}

    def ask(client, messages):
        client.asked.append([m["content"] for m in messages])
        return client.answers.pop(0)
    monkeypatch.setattr(pw, "ask", ask)
    c = _Client([bad, good])
    parts, problems = pw.write_one(c, row, None)
    assert parts == GOOD and problems == []
    assert pw.OUT_OF_DATE_WHY in c.asked[1][-1], "the retry is told what the first answer broke"
    c = _Client([bad, bad])
    parts, problems = pw.write_one(c, row, None)
    assert parts is None and problems == [f'"worry" {pw.OUT_OF_DATE_WHY}'], "left empty, never shown"
    # the same bad answer for a finding that is not out of date is not this rule's business
    c = _Client([bad])
    parts, problems = pw.write_one(c, dict(row, title="Missing security header"), None)
    assert parts is not None and problems == []
