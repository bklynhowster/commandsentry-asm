#!/usr/bin/env python3
"""Backfill safety — relay 220. No DB, no network: a fake PostgREST.

The three properties that matter are the three ways this script could do harm:
  1. it could MISS rows (a clamped read that looks like a small result set);
  2. it could OVERWRITE a verdict a real scan wrote;
  3. it could INVENT a negative from a raw it could not read.

(1) is not hypothetical. The enrich worker was blind for weeks because
`max_rows=1000` silently clamped a `.limit(5000)` — the read returned a full page
and the caller treated it as the whole set.

⚠ The contract here CHANGED mid-build. The first draft stopped on a short page,
which a server-side `max_rows` below our page size defeats in exactly the same
way. It now stops only on an EMPTY page, and the two tests below were updated to
the new contract rather than left asserting the old one.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner"))

import backfill_stack_id_wafw00f as bf  # noqa: E402

FORTIWEB = "[+] The site https://x/ is behind FortiWeb (Fortinet) WAF.\n"
NO_WAF = "[-] No WAF detected by the generic detection\n"


class FakeRest:
    """Serves keyset pages and records inserts. Mirrors Rest's surface only."""

    def __init__(self, rows_by_path, page_size=None):
        self.rows_by_path = rows_by_path
        self.page_size = page_size or bf.PAGE
        self.inserted = []
        self.patched = []
        self.page_calls = 0

    def _key(self, path):
        for k in self.rows_by_path:
            if k in path:
                return k
        return None

    def page(self, path, after, order_col="artifact_id"):
        self.page_calls += 1
        rows = self.rows_by_path.get(self._key(path), [])
        rows = sorted(rows, key=lambda r: r[order_col])
        if after is not None:
            rows = [r for r in rows if r[order_col] > after]
        return rows[: self.page_size]

    def insert(self, path, rows):
        self.inserted.extend(rows)

    # ⛔ THE DOUBLE DID NOT HAVE THIS METHOD, SO THE RE-PARSE WRITE COULD NOT BE
    #   TESTED EVEN BY SOMEONE TRYING. `insert` covers the backfill path; the
    #   correction path calls `patch`. A fake that implements only the half of the
    #   interface the old tests used makes the other half unreachable — which is how
    #   the early return in front of it survived (relay 292).
    def patch(self, path, body):
        self.patched.append((path, body))


def _art(i, run, raw=None):
    d = {"artifact_id": f"a{i:04d}", "scan_run_id": run}
    if raw is not None:
        d["content_jsonb"] = {"raw": raw}
    return d


# ---------------------------------------------------------------------------
# 1. pagination — the enrich-worker failure mode
# ---------------------------------------------------------------------------

def test_paginate_walks_past_a_full_page():
    """⛔ THE ENRICH-WORKER SHAPE. 2 500 rows with a 1 000-row page must yield all
    2 500. A caller that stopped at the first full page would report 1 000 and look
    entirely healthy."""
    rows = [_art(i, f"r{i:04d}") for i in range(2500)]
    rest = FakeRest({"wafw00f": rows}, page_size=1000)
    got = list(bf.paginate(rest, "scan_run_artifacts?select=x&tool_name=eq.wafw00f"))
    assert len(got) == 2500, f"paginate stopped early: {len(got)}"
    assert len({r['artifact_id'] for r in got}) == 2500, "duplicate rows across pages"
    assert rest.page_calls == 4, "1000 + 1000 + 500 + an empty probe"


def test_paginate_probes_once_past_even_a_tiny_result_set():
    """The cost of not being clampable: one extra empty round-trip per read. That
    is the whole price, and it is worth paying — see the clamp test below."""
    rows = [_art(i, f"r{i:04d}") for i in range(10)]
    rest = FakeRest({"wafw00f": rows}, page_size=1000)
    got = list(bf.paginate(rest, "scan_run_artifacts?tool_name=eq.wafw00f"))
    assert len(got) == 10 and rest.page_calls == 2


def test_a_server_side_clamp_below_our_page_size_does_not_truncate(monkeypatch):
    """⛔ THE BUG THIS TEST FOUND IN ITS OWN SUBJECT.

    PostgREST enforces its own `max_rows`. The first draft of `paginate` stopped
    when `len(rows) < PAGE` — so a server capping at 20 while we ask for 1000
    returns a "short" page every time and the loop exits after ONE. A truncated
    read that looks like a small result set: the enrich-worker defect, reproduced
    inside the guard written to prevent it.

    Here the server clamps to 20 and there are 50 rows. Terminating only on an
    EMPTY page is what makes the clamp survivable."""
    rows = [_art(i, f"r{i:04d}") for i in range(50)]
    rest = FakeRest({"wafw00f": rows}, page_size=20)      # server caps below bf.PAGE
    got = list(bf.paginate(rest, "scan_run_artifacts?tool_name=eq.wafw00f"))
    assert len(got) == 50, f"a server-side clamp truncated the read: got {len(got)}"
    assert rest.page_calls == 4, "20 + 20 + 10 + an empty probe"


def test_an_exactly_full_final_page_is_not_mistaken_for_the_end():
    """The boundary: the last page is exactly the page size. One more call must
    happen and return empty."""
    rows = [_art(i, f"r{i:04d}") for i in range(40)]
    rest = FakeRest({"wafw00f": rows}, page_size=20)
    got = list(bf.paginate(rest, "scan_run_artifacts?tool_name=eq.wafw00f"))
    assert len(got) == 40
    assert rest.page_calls == 3, "20 + 20 + an empty probe"


# ---------------------------------------------------------------------------
# 2. never overwrite
# ---------------------------------------------------------------------------

def test_a_run_that_already_has_a_parsed_verdict_is_skipped(monkeypatch, capsys):
    """A real scan's verdict outranks anything reconstructed from text."""
    rest = FakeRest({
        "eq.wafw00f": [_art(1, "run-A", FORTIWEB), _art(2, "run-B", FORTIWEB)],
        "eq.stack_id_wafw00f": [_art(9, "run-A")],
    })
    monkeypatch.setattr(bf, "Rest", lambda *a, **k: rest)
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_test")
    monkeypatch.setattr(sys, "argv", ["bf", "--write"])
    bf.main()
    runs = {r["scan_run_id"] for r in rest.inserted}
    assert runs == {"run-B"}, f"must skip run-A, which already has one: {runs}"


def test_dry_run_writes_nothing(monkeypatch):
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-A", FORTIWEB)],
                     "eq.stack_id_wafw00f": []})
    monkeypatch.setattr(bf, "Rest", lambda *a, **k: rest)
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_test")
    monkeypatch.setattr(sys, "argv", ["bf"])          # no --write
    bf.main()
    assert rest.inserted == [], "dry-run must insert nothing"


# ---------------------------------------------------------------------------
# 3. never invent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "   \n  ", None])
def test_an_unreadable_raw_yields_no_verdict(raw):
    """⛔ THE WHOLE POINT. 'no verdict' and 'no WAF' are different facts. Returning
    a negative here would write `wafw00f_detected: False` on a host nobody looked
    at — a label from absent evidence, which is the defect family this repo has
    spent the week on."""
    assert bf.verdict_from_raw(raw) is None


def test_an_unreadable_raw_is_not_inserted(monkeypatch):
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-ok", FORTIWEB),
                                    _art(2, "run-bad", "   ")],
                     "eq.stack_id_wafw00f": []})
    monkeypatch.setattr(bf, "Rest", lambda *a, **k: rest)
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_test")
    monkeypatch.setattr(sys, "argv", ["bf", "--write"])
    bf.main()
    runs = {r["scan_run_id"] for r in rest.inserted}
    assert runs == {"run-ok"}, f"the unreadable raw must be skipped, not defaulted: {runs}"


# ---------------------------------------------------------------------------
# the parse itself — imported, and it must stay that way
# ---------------------------------------------------------------------------

def test_the_real_fortiweb_output_round_trips():
    """commandcommcentral.com, 2026-09-03, the verdict that was discarded."""
    v = bf.verdict_from_raw(
        "[*] Checking https://commandcommcentral.com/\n"
        "[+] The site https://commandcommcentral.com/ is behind FortiWeb (Fortinet) WAF.\n")
    assert v["wafw00f_detected"] is True and v["wafw00f_kind"] == "fortiweb"


def test_a_genuine_negative_is_preserved_as_a_negative():
    v = bf.verdict_from_raw(NO_WAF)
    assert v["wafw00f_detected"] is False and v["wafw00f_kind"] is None


def test_backfilled_rows_are_marked_as_such():
    """Provenance. The consumer reads only detected/kind, so this is inert to it —
    but a verdict recovered from text months later must not be indistinguishable
    from one a live scan wrote."""
    assert bf.verdict_from_raw(FORTIWEB)["backfilled_from_raw"] is True


def test_the_parse_is_imported_not_reimplemented():
    """A second copy of the regexes would be a third home for this defect class —
    the reason ruling 8 was FOLD and not register-a-pair."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "backfill_stack_id_wafw00f.py"), encoding="utf-8").read()
    assert "_medium._classify_wafw00f_output" in src
    assert "is behind" not in src, "the wafw00f signature regex has been copied in here"


def test_the_insert_shape_matches_a_real_artifact_row():
    """Column names verified against a live stack_id_wafw00f row, 2026-09-16:
    the table has `output_format`, NOT `content_type` — the psycopg draft had that
    wrong and would have failed on the first insert."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "backfill_stack_id_wafw00f.py"), encoding="utf-8").read()
    assert '"output_format": "json"' in src
    assert "content_type" not in src, "content_type is not a column on scan_run_artifacts"


# ---------------------------------------------------------------------------
# housekeeping (relay 236 item 4) — the two things that cost a real run
# ---------------------------------------------------------------------------

def test_the_usage_line_exports_the_env():
    """⛔ MEASURED THE HARD WAY, Command 2026-09-16. `.env` is bare KEY=value with no
    `export`, so `. ./.env` in zsh makes SHELL variables — os.environ sees nothing and
    the script exits telling you to source the file you just sourced. `set -a` is what
    marks them for export."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "backfill_stack_id_wafw00f.py"), encoding="utf-8").read()
    doc = src.split('"""')[1]
    assert "set -a && . ./.env && set +a" in doc, (
        "the usage line is back to `. ./.env`, which does not export in zsh")
    assert "\n    . ./.env && python3" not in doc, "a bare `. ./.env` usage line survives"


def test_the_error_message_says_how_to_actually_set_them():
    """The exit path is where someone lands when it fails; it has to carry the fix."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "backfill_stack_id_wafw00f.py"), encoding="utf-8").read()
    assert "set -a && . ./.env && set +a" in src.split("sys.exit(")[1]


def test_the_parser_is_silenced_while_reparsing(capsys):
    """93 rows x 2 log lines buried the PLAN — the only output a reviewer needs.
    A plan you have to scroll to find is a plan that gets skimmed."""
    import run_medium as _m
    v = bf.verdict_from_raw(FORTIWEB)
    assert v["wafw00f_kind"] == "fortiweb"          # it really did parse
    err = capsys.readouterr().err
    assert "WAF detected" not in err, f"parser chatter leaked into the plan: {err!r}"
    assert "stack_id_wafw00f (persist-only)" not in err


def test_the_scanner_log_is_restored_afterwards():
    """⚠ RESTORED IN A `finally`. A runner left permanently mute would silence the NEXT
    caller in the same process — these tests import run_medium alongside this module."""
    import run_medium as _m
    before = _m.log
    bf.verdict_from_raw(FORTIWEB)
    assert _m.log is before, "run_medium.log was not restored after the quiet block"


def test_the_scanner_log_is_restored_even_when_the_parse_raises():
    """The half that matters: an exception mid-row must not leave the process mute."""
    import run_medium as _m
    before = _m.log
    with pytest.raises(RuntimeError):
        with bf.quiet_parser():
            assert _m.log is not before      # it really was swapped
            raise RuntimeError("boom")
    assert _m.log is before


def test_quiet_parser_does_not_silence_our_own_output(capsys):
    """Plan output is stdout and ours; only the scanner's stderr narration is muted."""
    with bf.quiet_parser():
        print("  TO BACKFILL (no verdict yet)   : 68")
    assert "TO BACKFILL" in capsys.readouterr().out


# ══ THE RE-PARSE-ONLY RUN (relay 292) ════════════════════════════════════════
# ⛔ THE FIRST TIME THIS PATH WAS NEEDED, IT RETURNED EARLY. Howie ran
# `--reparse-generic` on Prodex after the vendor-agnostic parse landed:
#
#     runs 67 · already parsed 67 · TO BACKFILL 0 · TO RE-PARSE 56 · nothing to do.
#
# `if not todo:` exited before the re-parse plan, so 56 rows stayed wrong and the exit
# code said success. ⚠ NEVER EXERCISED UNTIL THEN: every earlier run had both sets
# non-empty (Command 68 + 8, Prodex 49 + 13), so `todo` was never empty while
# `relaundered` was not. A branch only one data shape can reach is a branch nobody
# checked — the same family as the verdicts that lived where no test could call them.

_GOOGLE_RAW = ("[+] The site https://prodexlabs.com/ is behind "
               "Google Cloud App Armor (Google Cloud) WAF.\n")


def _parsed(i, run, kind):
    """An EXISTING stack_id_wafw00f verdict row — the shape the re-parse corrects."""
    return {"artifact_id": f"p{i:04d}", "scan_run_id": run,
            "content_jsonb": {"schema": 1, "wafw00f_detected": True,
                              "wafw00f_kind": kind}}


def _env(monkeypatch, rest, argv):
    monkeypatch.setattr(bf, "Rest", lambda *a, **k: rest)
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_test")
    monkeypatch.setattr(sys, "argv", argv)


def test_a_reparse_only_run_still_prints_its_plan(monkeypatch, capsys):
    """Nothing to BACKFILL, something to RE-PARSE: the plan must appear, not
    'nothing to do'. This is the exact Prodex shape from 292."""
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-A", _GOOGLE_RAW)],
                     "eq.stack_id_wafw00f": [_parsed(1, "run-A", "google")]})
    _env(monkeypatch, rest, ["bf", "--reparse-generic"])          # dry-run
    rc = bf.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "TO RE-PARSE" in out and "RE-PARSE plan" in out, out[-800:]
    assert "nothing to do." not in out, "the early return is back"
    assert "google_cloud_app_armor" in out


def test_a_reparse_only_run_with_write_actually_writes(monkeypatch):
    """⚠ The plan printing is not the fix — the WRITE has to be reached too. Under the
    old guard this call returned before either."""
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-A", _GOOGLE_RAW)],
                     "eq.stack_id_wafw00f": [_parsed(1, "run-A", "google")]})
    _env(monkeypatch, rest, ["bf", "--reparse-generic", "--write"])
    bf.main()
    assert rest.patched, "the re-parse write never happened"
    path, body = rest.patched[0]
    assert "run-A" in path
    assert body["content_jsonb"]["wafw00f_kind"] == "google_cloud_app_armor"


def test_both_sets_empty_is_still_nothing_to_do(monkeypatch, capsys):
    """The guard must narrow, not disappear: with nothing to backfill AND nothing to
    re-parse, the run still says so and exits 0."""
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-A", FORTIWEB)],
                     "eq.stack_id_wafw00f": [_parsed(1, "run-A", "fortiweb")]})
    _env(monkeypatch, rest, ["bf", "--reparse-generic"])
    rc = bf.main()
    out = capsys.readouterr().out
    assert rc == 0 and "nothing to do." in out
    assert rest.inserted == [] and rest.patched == []


def test_a_legacy_alias_row_is_reparsed_but_a_named_product_is_not(monkeypatch, capsys):
    """One direction only. `google` is a key THIS parser wrote and moves forward;
    `fortiweb` already names a product and is never touched."""
    rest = FakeRest({"eq.wafw00f": [_art(1, "run-A", _GOOGLE_RAW), _art(2, "run-B", FORTIWEB)],
                     "eq.stack_id_wafw00f": [_parsed(1, "run-A", "google"),
                                             _parsed(2, "run-B", "fortiweb")]})
    _env(monkeypatch, rest, ["bf", "--reparse-generic", "--write"])
    bf.main()
    touched = " ".join(p for p, _ in rest.patched)
    assert "run-A" in touched and "run-B" not in touched, \
        f"run-B must not be re-parsed: {touched}"
