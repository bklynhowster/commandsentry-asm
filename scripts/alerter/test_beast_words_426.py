#!/usr/bin/env python3
"""push-426 — the BEAST cipher line's new title reads the same in the Slack note and the voice.

From 426 the TLS parser writes testssl's BEAST cipher record as "BEAST attack possible on TLS
1.0 — <ciphers>" (was "TLS · BEAST_CBC_TLS1: <ciphers>"), so it and the BEAST verdict can show
as one row in the higher one's words (test_twins_once_426.py). The rows already open keep the
old title until the migration or their next deep scan, so both titles must do what the old one
did: a developer item in Slack, merged with 3DES under "weak ciphers", and the voice's plain
words. The verdict ("BEAST attack vulnerability", LOW) is not pulled into either.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))

import digest_slack as ds  # noqa: E402
import digest_voice as dv  # noqa: E402

OLD = "TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA"
NEW = "BEAST attack possible on TLS 1.0 — ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA"
VERDICT = "BEAST attack vulnerability — VULNERABLE -- but also supports higher protocols TLSv1.1 TLSv1.2 (likely mitigated)"


def test_both_titles_are_developer_items():
    assert ds.is_developer(OLD, "")
    assert ds.is_developer(NEW, "")


def test_both_titles_merge_with_3des_as_weak_ciphers():
    assert ds.merge_key(OLD, "") == "weak ciphers"
    assert ds.merge_key(NEW, "") == "weak ciphers"
    assert ds.merge_key("Obsolete 3DES/IDEA ciphers offered", "") == "weak ciphers"


def test_the_verdict_is_not_pulled_in():
    assert not ds.is_developer(VERDICT, "")
    assert ds.merge_key(VERDICT, "") != "weak ciphers"
    assert dv._plain(VERDICT, "b", "f") == (VERDICT, "b", "f")


def test_the_voice_says_the_same_for_both():
    old = dv._plain(OLD, "", "")
    new = dv._plain(NEW, "", "")
    assert old == new
    assert old[0] == "Old CBC ciphers (BEAST) still offered"
