"""A slow answer from NVD never costs a site its finding (437, 2026-11-13).

The first real run of the sign-in track, 2026-11-13 10:27 UTC on Prodex: the deep scan had
read OAuth2 Proxy 7.15.5, the release list and the advisory database answered, and then one
of eighteen NVD reads timed out. The lookup was all-or-nothing, so no finding was written
and that morning's email said nothing. The log line did not say which source it was.

NVD only feeds "k are described as crash or overload flaws". The finding's facts (the
version shown, the flaws a later release fixes, the release to update to) come from the
maker's release notes and the open advisory database. Pinned here:

  * an NVD read that fails leaves that one flaw unread: the finding is still written, with
    the count left off (never understated); the release list and the advisory database
    still fail the whole lookup;
  * after three failed NVD reads in a row the run stops asking it, and says so once;
  * a finding that already has its count keeps its words on a day NVD answers slowly,
    unless something real changed;
  * a source that does not answer is named by its host, never by its path or query.

Every record below is made up for the test, in the shape the public sources use.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import advisory_watch as aw  # noqa: E402
import signin_flaws as sf  # noqa: E402
from test_signin_flaws import (  # noqa: E402
    APPROVED_LEAD, CVES, FID, KEY, SHORT_SECTION, Conn, Get, a_door, desc_of, door, door_row,
    existing, finding_row, nvd, one_release_get, release, run, sources)

LEAD_NO_COUNT = "This sign-in shows OAuth2 Proxy 7.15.5. Its maker says release 7.15.6 (Nov 5) fixes 18 published flaws."
SECTION_NO_COUNT = SHORT_SECTION.split("\n", 1)[1]
FIX = "Update OAuth2 Proxy to 7.15.6 or later."
TITLE = "Runs OAuth2 Proxy 7.15.5: out of date — 18 published flaws fixed in later versions; update it"


def look(get=None, version="7.15.5", budget=None, src=None):
    budget = {"nvd": 100} if budget is None else budget
    return aw.door_lookup(src or sources(get or one_release_get()), KEY, version, set(), budget), budget


def fields(lk, **kw):
    return sf.finding_fields(KEY, "7.15.5", lk, 2026, **kw)


FULL = fields(look()[0])            # what a day NVD answers every read writes


# ── one read fails ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("cve", [CVES[0], CVES[9], CVES[17]])      # a crash flaw, a middle one, the last
def test_one_nvd_read_that_fails_still_gives_the_finding_without_the_count(cve):
    g = one_release_get(fail=[cve])
    lk, budget = look(g)
    assert len(lk.flaws) == 18 and [f.id for f in lk.flaws.values() if not f.read] == [cve]
    assert sf.crash_count(lk.flaws) is None, "left off, never understated"
    f = fields(lk)
    assert (f["title"], f["description_synth"], f["impact"], f["remediation"]) == (TITLE, LEAD_NO_COUNT,
                                                                                    SECTION_NO_COUNT, FIX)
    assert f["severity"] == FULL["severity"] and f["cve"] == FULL["cve"] and f["tags"] == FULL["tags"]
    assert "crash" not in f["description"] and "overload" not in f["description"]
    assert budget["nvd_missed"] == [f"{cve} (HTTPError: HTTP Error 503)"] and not budget.get("nvd_down")
    assert len([c for c in g.calls if "cveId=" in c[0]]) == 18, "every other flaw was still asked about"
    assert budget["nvd"] == 100 - 18, "a read that failed is still a read spent"


def test_the_day_it_went_wrong_now_writes_the_finding():
    """2026-11-13: the last of the eighteen reads timed out. Before: SourceError, nothing written."""
    conn = Conn(doors=[door_row()])
    n, logs = run(conn, one_release_get(fail=[CVES[17]]))
    (ins,) = conn.sqls(aw.DOOR_UPSERT_SQL)
    assert (ins["title"], ins["description_synth"], ins["remediation"]) == (TITLE, LEAD_NO_COUNT, FIX)
    assert ins["impact"] == SECTION_NO_COUNT and ins["finding_id"] == FID
    assert n["upsert"] == 1 and n["failed"] == [], "the lookup did not fail: NVD is not one of its sources of fact"
    assert not any("lookup failed" in m for m in logs)
    (warn,) = [m for m in logs if m.startswith("::warning::NVD did not hand over")]
    assert warn == (f"::warning::NVD did not hand over 1 flaw description(s): {CVES[17]} (HTTPError: HTTP Error 503). "
                    "The crash-or-overload count is left off where a description was not read; nothing else changes.")


def test_a_day_every_read_answers_says_nothing_about_nvd_and_writes_the_approved_words():
    conn = Conn(doors=[door_row()])
    n, logs = run(conn)
    (ins,) = conn.sqls(aw.DOOR_UPSERT_SQL)
    assert ins["description_synth"] == APPROVED_LEAD and ins["impact"] == SHORT_SECTION
    assert not any("NVD did not hand over" in m for m in logs)


def test_an_nvd_answer_in_a_shape_nobody_expected_is_one_flaw_unread_not_a_failed_lookup():
    records = {c: nvd(c, desc_of(c)) for c in CVES}
    records[CVES[3]] = "not a record"
    lk, budget = look(one_release_get(nvd_records=records))
    assert [f.id for f in lk.flaws.values() if not f.read] == [CVES[3]]
    assert budget["nvd_missed"] == [f"{CVES[3]} (NVD {CVES[3]}: unexpected answer)"]
    assert fields(lk)["description_synth"] == LEAD_NO_COUNT


class _Odd(Get):
    """NVD answers these CVEs in shapes nobody expected, at different depths."""

    def __init__(self, odd, **kw):
        g = one_release_get(**kw)
        self.__dict__.update(g.__dict__)
        self.odd = odd

    def __call__(self, url, headers=None, body=None):
        if "cveId=" in url and url.split("cveId=")[1] in self.odd:
            self.calls.append((url, headers, body))
            return self.odd[url.split("cveId=")[1]]
        return super().__call__(url, headers=headers, body=body)


def test_an_nvd_answer_malformed_at_any_depth_is_one_flaw_unread():
    """The outside review, 2026-11-13: only the read was guarded, so a record that made the
    reading of it raise still failed the whole lookup."""
    odd = {CVES[2]: {"vulnerabilities": "not a list of records"},          # the envelope
           CVES[7]: ["a list, not an object"],
           CVES[11]: {"vulnerabilities": [["not a record"]]}}              # an entry
    g = _Odd(odd)
    lk, budget = look(g)
    assert sorted(f.id for f in lk.flaws.values() if not f.read) == sorted(odd)
    assert len(budget["nvd_missed"]) == 3 and not budget.get("nvd_down")
    assert all(any(m.startswith(f"{c} (") for m in budget["nvd_missed"]) for c in odd)
    assert fields(lk)["description_synth"] == LEAD_NO_COUNT


def test_a_record_that_cannot_be_read_through_is_one_flaw_unread_and_never_half_read(monkeypatch):
    real = sf.describe

    def picky(flaw, record, kev_ids):
        if flaw.id == CVES[1]:
            flaw.read, flaw.crash = True, True                   # got part of the way, then fell over
            raise KeyError("cvssData")
        return real(flaw, record, kev_ids)
    monkeypatch.setattr(sf, "describe", picky)
    lk, budget = look()
    assert (lk.flaws[CVES[1]].read, lk.flaws[CVES[1]].crash) == (False, False), "unread, not half read"
    assert budget["nvd_missed"] == [f"{CVES[1]} (KeyError: 'cvssData')"]
    assert sum(1 for f in lk.flaws.values() if f.read) == 17 and sf.crash_count(lk.flaws) is None
    conn = Conn(doors=[door_row()])
    n, logs = run(conn)
    assert n["upsert"] == 1 and n["failed"] == [] and not any("lookup failed" in m for m in logs)
    assert conn.sqls(aw.DOOR_UPSERT_SQL)[0]["description_synth"] == LEAD_NO_COUNT


def test_an_answer_already_held_that_cannot_be_read_is_listed_once_and_is_not_nvd_being_down():
    g = _Odd({CVES[2]: {"vulnerabilities": [{"cve": "not a record"}]}})
    src = sources(g)
    lk, budget = look(src=src)
    assert budget["nvd_missed"] == [f"{CVES[2]} (NVD {CVES[2]}: unexpected answer)"]
    for _ in range(4):                                           # four more sites, the same product and version
        lk, budget = look(src=src, budget=budget)
    assert budget["nvd_missed"] == [f"{CVES[2]} (NVD {CVES[2]}: unexpected answer)"], "listed once"
    assert not budget.get("nvd_down") and budget["nvd_failed_in_a_row"] == 0
    assert budget["nvd"] == 100 - 18, "an answer already held costs nothing, readable or not"
    assert sum(1 for f in lk.flaws.values() if f.read) == 17


def test_a_read_that_failed_is_asked_again_by_the_next_lookup_and_one_that_answered_is_not():
    g = one_release_get(fail=[CVES[5]])
    src = sources(g)
    lk, budget = look(src=src)
    assert sf.crash_count(lk.flaws) is None
    g.fail.clear()                                       # NVD answers now
    again, budget = look(src=src, budget=budget)
    assert sf.crash_count(again.flaws) == 6 and fields(again)["description_synth"] == APPROVED_LEAD
    asked = [c[0].split("cveId=")[1] for c in g.calls if "cveId=" in c[0]]
    assert asked.count(CVES[5]) == 2 and all(asked.count(c) == 1 for c in CVES if c != CVES[5])
    assert budget["nvd"] == 100 - 19


# ── NVD is down ──────────────────────────────────────────────────────────────

def test_after_three_failed_reads_in_a_row_the_run_stops_asking_nvd():
    assert aw.NVD_GIVE_UP_AFTER == 3
    g = one_release_get(fail=["nvd"])
    lk, budget = look(g)
    assert len([c for c in g.calls if "cveId=" in c[0]]) == 3, "three tries, then no more this run"
    assert budget["nvd_down"] is True and len(budget["nvd_missed"]) == 3
    assert not any(f.read for f in lk.flaws.values())
    f = fields(lk)
    assert (f["title"], f["description_synth"], f["remediation"]) == (TITLE, LEAD_NO_COUNT, FIX)
    # and the next lookup in the same run does not ask either
    src = sources(g)
    before = len([c for c in g.calls if "cveId=" in c[0]])
    look(budget=budget, src=src)
    assert len([c for c in g.calls if "cveId=" in c[0]]) == before and budget["nvd_down"] is True


def test_nvd_down_for_the_whole_run_still_writes_the_finding_and_says_so_once():
    conn = Conn(doors=[door_row()])
    g = one_release_get(fail=["nvd"])
    n, logs = run(conn, g)
    (ins,) = conn.sqls(aw.DOOR_UPSERT_SQL)
    assert ins["description_synth"] == LEAD_NO_COUNT and n["upsert"] == 1 and n["failed"] == []
    warns = [m for m in logs if m.startswith("::warning::NVD did not hand over")]
    assert len(warns) == 1 and "3 flaw description(s)" in warns[0] and ". Stopped asking it for this run." in warns[0]
    assert len([c for c in g.calls if "cveId=" in c[0]]) == 3


def test_failures_that_are_not_in_a_row_do_not_stop_the_reads():
    bad = [CVES[0], CVES[1], CVES[3], CVES[4], CVES[6], CVES[7]]          # never three running
    g = one_release_get(fail=bad)
    lk, budget = look(g)
    assert not budget.get("nvd_down") and len(budget["nvd_missed"]) == 6
    assert len([c for c in g.calls if "cveId=" in c[0]]) == 18
    assert sorted(f.id for f in lk.flaws.values() if not f.read) == bad
    assert budget["nvd_failed_in_a_row"] == 0, "the count starts again at every read that answers"


def test_the_third_failure_in_a_row_is_the_one_that_stops_it():
    g = one_release_get(fail=[CVES[4], CVES[5], CVES[6]])
    lk, budget = look(g)
    assert budget["nvd_down"] is True
    assert len([c for c in g.calls if "cveId=" in c[0]]) == 7, "four answered, three failed, the rest not asked"
    assert sum(1 for f in lk.flaws.values() if f.read) == 4


def test_what_nvd_already_handed_over_is_still_used_after_the_run_stops_asking():
    g = one_release_get(fail=[CVES[10], CVES[11], CVES[12]])
    src = sources(g)
    lk, budget = look(src=src)
    assert budget["nvd_down"] is True and sum(1 for f in lk.flaws.values() if f.read) == 10
    asked = len([c for c in g.calls if "cveId=" in c[0]])
    again, budget = look(src=src, budget=budget)          # another site, the same product and version
    assert sum(1 for f in again.flaws.values() if f.read) == 10, "the ten it holds cost nothing and are used"
    assert len([c for c in g.calls if "cveId=" in c[0]]) == asked, "and NVD is not asked again"


class _Clock:
    """Each NVD read takes `per` seconds on this clock."""

    def __init__(self, get, per):
        self.t, self.get, self.per = 0.0, get, per

    def __call__(self):
        return self.t

    def read(self, url, headers=None, body=None):
        if "cveId=" in url:
            self.t += self.per
        return self.get(url, headers=headers, body=body)


def test_a_slow_nvd_is_asked_for_ten_minutes_and_no_longer():
    """Every read answers, slowly. Without a limit eighteen slow reads (and their retries) could
    run the job past its own time limit, and every finding that run was going to write is lost."""
    assert aw.NVD_SECONDS_MAX == 600
    g = one_release_get()
    ck = _Clock(g, per=100)
    budget = {"nvd": 100}
    lk = aw.door_lookup(sources(ck.read), KEY, "7.15.5", set(), budget, clock=ck)
    asked = [c for c in g.calls if "cveId=" in c[0]]
    assert len(asked) == 6, "six reads fill the ten minutes; no read is started once they are up"
    assert budget["nvd_down"] is True and budget["nvd_out_of_time"] is True and not budget.get("nvd_missed")
    assert sum(1 for f in lk.flaws.values() if f.read) == 6 and sf.crash_count(lk.flaws) is None
    assert fields(lk)["description_synth"] == LEAD_NO_COUNT and len(lk.flaws) == 18
    # reads that fit in the time are all made
    g = one_release_get()
    ck = _Clock(g, per=30)
    budget = {"nvd": 100}
    lk = aw.door_lookup(sources(ck.read), KEY, "7.15.5", set(), budget, clock=ck)
    assert sf.crash_count(lk.flaws) == 6 and not budget.get("nvd_down") and budget["nvd_until"] == 600.0


def test_the_time_limit_is_said_in_the_run_log_and_the_finding_is_still_written(monkeypatch):
    g = one_release_get()
    ck = _Clock(g, per=100)
    real = aw.door_lookup
    monkeypatch.setattr(aw, "door_lookup", lambda *a, **kw: real(*a, clock=ck, **kw))
    conn = Conn(doors=[door_row()])
    logs = []
    n = aw.run(conn, sources(ck.read), log=logs.append, Json=lambda x: x)
    (ins,) = conn.sqls(aw.DOOR_UPSERT_SQL)
    assert ins["description_synth"] == LEAD_NO_COUNT and n["upsert"] == 1 and n["failed"] == []
    assert ("::warning::NVD was slow. Stopped asking it for this run after 10 minutes. The crash-or-overload count "
            "is left off where a description was not read; nothing else changes.") in logs


@pytest.mark.parametrize("fail", ["github", "osv"])
def test_the_two_sources_of_fact_still_fail_the_whole_lookup(fail):
    conn = Conn(doors=[door_row()], existing=[finding_row("open")])
    n, logs = run(conn, one_release_get(fail=[fail]))
    assert conn.sqls(aw.DOOR_UPSERT_SQL) == [] and conn.sqls(aw.CLOSE_SQL) == [] and n["failed"] == [KEY]
    assert any(m.startswith("::warning::oauth2_proxy 7.15.5: lookup failed (SourceError: ") for m in logs)


# ── a finding that has its count keeps its words ─────────────────────────────

def row(description=FULL["description"], status="open", version="7.15.5"):
    r = existing(status, version)
    r[FID]["description"] = description
    return r


def planned(get, exist, doors=None):
    asked = []

    def lookup(key, version):
        asked.append((key, version))
        return aw.door_lookup(sources(get), key, version, set(), {"nvd": 100})
    acts = aw.plan_doors(doors or a_door(latest=door()), exist, lookup, today_year=2026, log=lambda *a: None)
    return acts


@pytest.mark.parametrize("unread", [[CVES[0]], [CVES[9]], [CVES[0], CVES[1], CVES[9], CVES[17]], "nvd"])
def test_a_slow_nvd_day_does_not_take_the_count_off_a_finding_that_had_it(unread):
    """The upsert still runs (it keeps the finding's last-seen time fresh) and carries the
    very words the finding already has."""
    fail = [unread] if unread == "nvd" else unread
    (act,) = planned(one_release_get(fail=fail), row())
    assert act.kind == "upsert" and act.fields == FULL
    assert act.fields["description_synth"] == APPROVED_LEAD and act.fields["impact"] == SHORT_SECTION


def test_without_a_finding_yet_a_slow_day_writes_the_shorter_words():
    (act,) = planned(one_release_get(fail=[CVES[0]]), {})
    assert act.fields["description_synth"] == LEAD_NO_COUNT
    for r in (existing("open"), row(description=None), row(description=""), row(description=7)):
        (act,) = planned(one_release_get(fail=[CVES[0]]), r)
        assert act.fields["description_synth"] == LEAD_NO_COUNT, r


def test_a_finding_written_on_a_slow_day_gets_its_count_the_first_day_every_read_answers():
    short = fields(look(one_release_get(fail=[CVES[0]]))[0])
    (act,) = planned(one_release_get(), row(description=short["description"]))
    assert act.fields == FULL
    # and on another slow day it simply stays as it is: nothing to carry over, nothing invented
    (act,) = planned(one_release_get(fail=[CVES[1]]), row(description=short["description"]))
    assert act.fields == short


def test_a_real_change_on_a_slow_day_writes_todays_reading():
    # another version shown: the finding's words are about 7.15.4
    old = sf.finding_fields(KEY, "7.15.4", look(version="7.15.4")[0], 2026)
    (act,) = planned(one_release_get(fail=[CVES[0]]), row(description=old["description"], version="7.15.4"))
    assert act.fields["description_synth"] == LEAD_NO_COUNT and act.fields["affected_component_version"] == "7.15.5"
    # another flaw in the maker's notes
    more = Get([release("v7.15.6", cves=CVES + ["CVE-2026-79999"]), release("v7.15.5", "2026-10-01")],
               nvd_records={**{c: nvd(c, desc_of(c)) for c in CVES}, "CVE-2026-79999": nvd("CVE-2026-79999", "x y z")},
               fail=[CVES[0]])
    (act,) = planned(more, row())
    assert act.fields["title"].startswith("Runs OAuth2 Proxy 7.15.5: out of date — 19 published flaws")
    assert "crash" not in act.fields["description"]
    # another release to update to
    later = Get([release("v7.15.7", "2026-11-12", cves=CVES[:2]), release("v7.15.6", cves=CVES[2:]),
                 release("v7.15.5", "2026-10-01")], fail=[CVES[9]])
    (act,) = planned(later, row())
    assert act.fields["remediation"] == "Update OAuth2 Proxy to 7.15.7 or later." and "crash" not in act.fields["description"]


def test_a_description_read_today_that_differs_is_a_real_change():
    """One of the six no longer uses the crash words, and another flaw was not read: the
    finding's old count is not carried over a description that was read and differs."""
    records = {c: nvd(c, desc_of(c)) for c in CVES}
    records[CVES[0]] = nvd(CVES[0], "A path check can be bypassed.")
    (act,) = planned(one_release_get(nvd_records=records, fail=[CVES[9]]), row())
    assert act.fields["description_synth"] == LEAD_NO_COUNT and act.fields != FULL
    # and when everything is read, today's count stands
    (act,) = planned(one_release_get(nvd_records=records), row())
    assert "5 are described as crash or overload flaws" in act.fields["description_synth"]


def test_a_complete_reading_always_stands_whatever_the_finding_said():
    (act,) = planned(one_release_get(), row(description="anything at all"))
    assert act.fields == FULL
    (act,) = planned(one_release_get(), row())
    assert act.fields == FULL


def test_a_hidden_footer_on_a_slow_day_keeps_its_words_too():
    hidden = a_door(latest=door(version=None, grade="looks_like"), shown_version="7.15.5", shown_key=KEY,
                    shown_day="2026-11-12")
    full = sf.finding_fields(KEY, "7.15.5", look()[0], 2026, last_shown_day="2026-11-12", no_longer_shown=True)
    assert "6 are described as crash or overload flaws" in full["description_synth"]
    (act,) = planned(one_release_get(fail=[CVES[2]]), row(description=full["description"]), hidden)
    assert act.fields == full
    # the day the footer is first hidden is a real change: today's (shorter) reading is written
    (act,) = planned(one_release_get(fail=[CVES[2]]), row(), hidden)
    assert act.fields["description_synth"].startswith("This sign-in last showed OAuth2 Proxy 7.15.5 on Nov 12; ")
    assert "crash" not in act.fields["description"]


def test_the_existing_rows_read_hands_the_findings_own_text_to_the_plan():
    assert "affected_component_version AS version, description" in " ".join(aw.EXISTING_SQL.split())
    conn = Conn(doors=[door_row()], existing=[dict(finding_row("open"), description=FULL["description"])])
    n, logs = run(conn, one_release_get(fail=[CVES[0]]))
    (ins,) = conn.sqls(aw.DOOR_UPSERT_SQL)
    assert ins["description"] == FULL["description"] and ins["description_synth"] == APPROVED_LEAD
    assert n["upsert"] == 1 and any("NVD did not hand over 1 flaw description(s)" in m for m in logs)
    # a row with no text of its own (or none read) takes today's reading
    conn = Conn(doors=[door_row()], existing=[finding_row("open")])
    run(conn, one_release_get(fail=[CVES[0]]))
    assert conn.sqls(aw.DOOR_UPSERT_SQL)[0]["description_synth"] == LEAD_NO_COUNT


# ── the parts ────────────────────────────────────────────────────────────────

def test_the_crash_line_is_read_back_exactly_as_it_is_written():
    full = look()[0]
    assert sf.crash_ids_listed(sf.flaw_text("OAuth2 Proxy", "7.15.5", full, "x")) == set(CVES[:6])
    assert sf.crash_ids_listed(FULL["description"]) == set(CVES[:6]), "found inside the whole description"
    one = Get([release("v7.15.6", cves=CVES[5:8]), release("v7.15.5", "2026-10-01")])
    text = sf.flaw_text("OAuth2 Proxy", "7.15.5", look(one)[0], "x")
    assert text.startswith(f"The one described as a crash or overload flaw: {CVES[5]}.\n")
    assert sf.crash_ids_listed(text) == {CVES[5]}
    none = Get([release("v7.15.6", cves=CVES[6:9]), release("v7.15.5", "2026-10-01")])
    assert sf.crash_ids_listed(sf.flaw_text("OAuth2 Proxy", "7.15.5", look(none)[0], "x")) == set()
    for odd in (None, 7, "", "The 6 described as crash or overload flaws", "Its maker’s notes place all 18 in X.",
                f"Not the line: The 6 described as crash or overload flaws: {CVES[0]}."):
        assert sf.crash_ids_listed(odd) == set(), odd


def test_carried_over_fills_only_what_was_not_read_and_changes_nothing_it_was_given():
    lk, _ = look(one_release_get(fail=[CVES[0], CVES[9]]))
    before = {i: (f.read, f.crash) for i, f in lk.flaws.items()}
    got = sf.carried_over(lk, FULL["description"])
    assert {i: (f.read, f.crash) for i, f in lk.flaws.items()} == before, "the reading it was given is untouched"
    assert got is not lk and got.releases == lk.releases and got.osv_count == lk.osv_count
    assert (got.flaws[CVES[0]].read, got.flaws[CVES[0]].crash) == (True, True), "the finding listed it"
    assert (got.flaws[CVES[9]].read, got.flaws[CVES[9]].crash) == (True, False), "the finding did not"
    assert sf.crash_count(got.flaws) == 6
    # a flaw read today keeps today's answer even when the finding listed it
    records = {c: nvd(c, desc_of(c)) for c in CVES}
    records[CVES[1]] = nvd(CVES[1], "A path check can be bypassed.")
    lk, _ = look(one_release_get(nvd_records=records, fail=[CVES[9]]))
    assert sf.carried_over(lk, FULL["description"]).flaws[CVES[1]].crash is False
    # with nothing to read back, an unread flaw counts as read and not a crash flaw: the caller only
    # ever compares the result with the finding's own text, and that text has no count to match
    assert sf.crash_count(sf.carried_over(look(one_release_get(fail=[CVES[0]]))[0], None).flaws) == 5


def test_a_flaw_nvd_is_never_asked_about_is_never_carried_over():
    """A flaw with no CVE number is read from the advisory database's own record. One whose
    record says nothing stays unread: no later read could fill it, so nothing is carried."""
    def osv(**text):
        return {"vulns": [dict({"id": "GHSA-aaaa-bbbb-cccc", "aliases": [],
                                "affected": [{"package": {"name": "github.com/oauth2-proxy/oauth2-proxy/v7",
                                                          "ecosystem": "Go"},
                                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                                                       {"fixed": "7.15.6"}]}]}]},
                               **text)]}
    lk, _ = look(one_release_get(osv=osv()))
    assert lk.flaws["GHSA-aaaa-bbbb-cccc"].read is False and len(lk.flaws) == 19
    got = sf.carried_over(lk, FULL["description"])
    assert got.flaws["GHSA-aaaa-bbbb-cccc"].read is False and sf.crash_count(got.flaws) is None
    said, _ = look(one_release_get(osv=osv(summary="An open redirect in the callback.")))
    assert said.flaws["GHSA-aaaa-bbbb-cccc"].read is True, "read from its own record, as before"


def test_door_fields_is_todays_reading_unless_the_carried_one_is_the_findings_own_words():
    slow, _ = look(one_release_get(fail=[CVES[0]]))
    today = fields(slow)
    assert aw.door_fields(None, KEY, "7.15.5", slow, 2026) == today
    assert aw.door_fields({}, KEY, "7.15.5", slow, 2026) == today
    assert aw.door_fields({"description": FULL["description"]}, KEY, "7.15.5", slow, 2026) == FULL
    assert aw.door_fields({"description": FULL["description"] + " "}, KEY, "7.15.5", slow, 2026) == today, "exactly, or not at all"
    assert aw.door_fields({"description": "x"}, KEY, "7.15.5", look()[0], 2026) == FULL


# ── which source did not answer ──────────────────────────────────────────────

class _Slow:
    def __init__(self):
        self.asked = []

    def __call__(self, req, timeout=None):
        self.asked.append(req.full_url)
        raise TimeoutError("The read operation timed out")


@pytest.mark.parametrize("url,host", [
    (aw.nvd_cve_url("CVE-2026-70017"), "services.nvd.nist.gov"),
    (aw.releases_url("oauth2-proxy/oauth2-proxy", 1), "api.github.com"),
    (aw.OSV_QUERY, "api.osv.dev"),
])
def test_a_source_that_does_not_answer_is_named_by_its_host_and_nothing_more(url, host):
    slow = _Slow()
    with pytest.raises(aw.SourceError) as e:
        aw.http_get_json(url, opener=slow, sleep=lambda s: None, headers={"Authorization": "Bearer made-up-token"})
    assert str(e.value) == f"{host}: TimeoutError: The read operation timed out"
    assert len(slow.asked) == 2, "one retry, as before"
    assert "made-up-token" not in str(e.value) and "cveId" not in str(e.value) and "/repos/" not in str(e.value)
