#!/usr/bin/env python3
"""push-426 (KB 12, five-visitor item 7) — twins counted once, higher wins.

Howie, 2026-11-09 14:20: "Once, higher wins." Two scans filing the same problem on one name at
different severities are one row, at the higher severity, naming both scans, counted once. The
portal and the emails already do that for rows that share a normalized_key
(v_open_findings_dedup); the twins never merged because the live deep scan's TLS parser wrote
every testssl row with no key. Pinned here, on the parser the deep scan ships:
  - the curated same-fact list (common.CROSS_SOURCE_EQUIVALENCE) gives:
      HSTS missing: the quick scan's "Missing security header: Strict-Transport-Security" and
        testssl's "HSTS not enabled" -> missing-header-strict-transport-security (the quick
        scan's own key);
      BEAST: testssl's verdict "BEAST attack vulnerability" and its cipher record, in the stored
        words "TLS · BEAST_CBC_TLS1: ..." and the plain ones from 426 -> tls-beast;
  - the live parser applies it to every event (OCSP too, the June entry), and the finding_id is
    the one the open rows already carry, so a rescan keys them in place;
  - the cipher record gets plain words: "BEAST attack possible on TLS 1.0 — <ciphers>";
  - the key is kept to its service (code review 2026-11-09, must-fix): the site's own https port
    (443, or none in the record) shares it; another port gets "<key>:port-<n>", so 443 and 8443
    stay two rows, as their finding_ids already are;
  - never merged: HSTS sent but weak, LUCKY13, the obsoleted-CBC list, 3DES and SWEET32
    (plan v3: two tests, not one fact), testssl's "Security headers missing or weak";
  - the keys are anchored: a title that only starts the same way, or another source, maps to
    nothing.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs_parsers.common import (  # noqa: E402
    CROSS_SOURCE_EQUIVALENCE,
    apply_cross_source_equivalence,
    stable_finding_id,
)
from cs_parsers.testssl import TITLE_LABELS, parse_testssl_file, shared_key_for_port  # noqa: E402

HSTS = "missing-header-strict-transport-security"
BEAST = "tls-beast"
OCSP = "tls-ocsp-stapling-missing"

# The open rows' own titles, read from both databases 2026-11-09 (Prodex cooked.prodexlabs.com,
# Command the same words): exactly what the parser writes today.
STORED = {
    "HSTS not enabled": HSTS,
    "BEAST attack vulnerability — VULNERABLE -- but also supports higher protocols TLSv1.1 TLSv1.2 (likely mitigated)": BEAST,
    "TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA": BEAST,
    "TLS · BEAST_CBC_TLS1: ECDHE-RSA-AES128-SHA DHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA": BEAST,
    "OCSP stapling not enabled": OCSP,
}
NEVER = (
    "HSTS max-age too short — max-age too short. 3 days (=259200 seconds) < 15552000 seconds",
    "HSTS preload not set",
    "HSTS includeSubDomains not set",
    "Multiple HSTS headers",
    "LUCKY13 timing attack possible — potentially vulnerable, uses TLS CBC ciphers",
    "TLS · cipherlist_OBSOLETED: offered",
    "Obsolete 3DES/IDEA ciphers offered",
    "SWEET32 — 64-bit block cipher — uses 64 bit block ciphers",
    "Security headers missing or weak",
    "TLS · TLS1: offered (deprecated)",
    "HSTS not enabled, but something else",   # starts the same way: anchored, so no
    "Old BEAST attack vulnerability",         # contains the words, does not start with them
    "TLS · BEAST",                            # no _CBC_: not the cipher record
)


def _rec(rid, sev, finding, cwe=None, ip="cooked.prodexlabs.com/203.0.113.10", port="443"):
    r = {"id": rid, "ip": ip, "port": port, "severity": sev, "finding": finding}
    if cwe:
        r["cwe"] = cwe
    return r


# testssl's own records behind the open rows on cooked.prodexlabs.com (their stored
# descriptions, read 2026-11-09): what a rescan of that name sends the parser.
COOKED = [
    _rec("HSTS", "LOW", "not offered"),
    _rec("BEAST_CBC_TLS1", "MEDIUM", "ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA", "CWE-20"),
    _rec("BEAST", "LOW", "VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)", "CWE-20"),
    _rec("LUCKY13", "LOW", "potentially vulnerable, uses TLS CBC ciphers", "CWE-310"),
    _rec("cipherlist_OBSOLETED", "LOW", "offered", "CWE-310"),
    _rec("cipherlist_3DES_IDEA", "MEDIUM", "offered", "CWE-310"),
    _rec("SWEET32", "LOW", "uses 64 bit block ciphers", "CWE-327"),
    _rec("OCSP_stapling", "LOW", "not offered"),
    _rec("HSTS_time", "LOW", "max-age too short. 3 days (=259200 seconds) < 15552000 seconds"),
]


def _events(tmp_path, records, asset_id="cooked.prodexlabs.com"):
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps(records))
    return parse_testssl_file(json_path=jf, asset_id=asset_id, scan_id="scan", scan_root=tmp_path,
                              fallback_observed_at="2026-11-09T12:00:00Z")


def _by_id(events):
    return {e.finding_id.split(":")[2]: e for e in events}


# ── the list ────────────────────────────────────────────────────────────────

def test_the_stored_titles_get_the_shared_keys():
    for title, key in STORED.items():
        assert apply_cross_source_equivalence("testssl", title) == key, title


def test_the_quick_scan_title_gets_its_own_key():
    assert apply_cross_source_equivalence(
        "commandsentry_light", "Missing security header: Strict-Transport-Security") == HSTS


def test_the_new_beast_words_get_the_beast_key():
    for t in ("BEAST attack possible on TLS 1.0 — ECDHE-RSA-AES128-SHA AES256-SHA",
              "BEAST attack possible on TLS 1.0",
              "BEAST attack possible on TLS 1.0  (2 reports)"):
        assert apply_cross_source_equivalence("testssl", t) == BEAST, t


def test_a_record_printed_twice_keeps_its_key():
    assert apply_cross_source_equivalence("testssl", "HSTS not enabled  (2 reports)") == HSTS
    assert apply_cross_source_equivalence("testssl", "BEAST attack vulnerability  (3 reports)") == BEAST


def test_never_merged():
    for title in NEVER:
        for src in ("testssl", "commandsentry_light", "manual_named", "commandsentry_medium"):
            assert apply_cross_source_equivalence(src, title) is None, (src, title)


def test_each_key_only_for_its_own_source():
    # testssl's words on another source, and the quick scan's words on testssl, map to nothing
    assert apply_cross_source_equivalence("commandsentry_light", "HSTS not enabled") is None
    assert apply_cross_source_equivalence("testssl", "Missing security header: Strict-Transport-Security") is None
    assert apply_cross_source_equivalence("commandsentry_medium", "TLS · BEAST_CBC_TLS1: AES128-SHA") is None
    assert apply_cross_source_equivalence("manual_named", "BEAST attack vulnerability") is None


def test_the_entries_are_exactly_these():
    by_key = {e["canonical_key"]: e for e in CROSS_SOURCE_EQUIVALENCE}
    assert sorted({s for s, _ in by_key[HSTS]["patterns"]}) == ["commandsentry_light", "testssl"]
    assert [s for s, _ in by_key[BEAST]["patterns"]] == ["testssl", "testssl", "testssl"]
    for entry in (by_key[HSTS], by_key[BEAST]):
        for _src, pat in entry["patterns"]:
            assert pat.pattern.startswith("^"), pat.pattern   # anchored, never a keyword


# ── the live parser ────────────────────────────────────────────────────────

def test_the_parser_keys_the_twins_and_leaves_the_rest(tmp_path):
    ev = _by_id(_events(tmp_path, COOKED))
    assert ev["HSTS"].normalized_key == HSTS
    assert ev["BEAST"].normalized_key == BEAST
    assert ev["BEAST_CBC_TLS1"].normalized_key == BEAST
    assert ev["OCSP_stapling"].normalized_key == OCSP
    for rid in ("LUCKY13", "cipherlist_OBSOLETED", "cipherlist_3DES_IDEA", "SWEET32", "HSTS_time"):
        assert ev[rid].normalized_key is None, rid


def test_the_severities_are_unchanged(tmp_path):
    ev = _by_id(_events(tmp_path, COOKED))
    assert ev["HSTS"].severity == "LOW"
    assert ev["BEAST"].severity == "LOW"
    assert ev["BEAST_CBC_TLS1"].severity == "MODERATE"   # the higher twin: it wins the merged row


def test_the_finding_ids_are_the_ones_the_open_rows_have(tmp_path):
    ev = _by_id(_events(tmp_path, COOKED))
    for rid in ("HSTS", "BEAST", "BEAST_CBC_TLS1"):
        assert ev[rid].finding_id == stable_finding_id("cooked.prodexlabs.com", "testssl", rid, "port-443")
        assert ev[rid].finding_id == f"cooked.prodexlabs.com:testssl:{rid}:33ad838", \
            "the id the open Prodex row carries (read 2026-11-09): the rescan keys it in place, no new row"


def test_the_beast_cipher_line_has_plain_words(tmp_path):
    assert TITLE_LABELS["BEAST_CBC_TLS1"] == "BEAST attack possible on TLS 1.0"
    ev = _by_id(_events(tmp_path, COOKED))
    assert ev["BEAST_CBC_TLS1"].title == (
        "BEAST attack possible on TLS 1.0 — ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA AES128-SHA AES256-SHA DES-CBC3-SHA")
    assert ev["HSTS"].title == "HSTS not enabled"
    assert ev["BEAST"].title.startswith("BEAST attack vulnerability — VULNERABLE")


def test_the_new_title_is_the_stored_one_reworded(tmp_path):
    """The migration rewrites the stored title the same way: label + " — " + the text after
    "TLS · BEAST_CBC_TLS1: ", cut to 100 characters (the parser keeps 100 after a label, 120
    after the raw id)."""
    long = " ".join(["ECDHE-RSA-AES128-SHA"] * 8)          # 167 characters
    ev = _by_id(_events(tmp_path, [_rec("BEAST_CBC_TLS1", "MEDIUM", long, "CWE-20")]))
    stored = f"TLS · BEAST_CBC_TLS1: {long[:120]}"
    reworded = "BEAST attack possible on TLS 1.0 — " + stored[len("TLS · BEAST_CBC_TLS1: "):][:100]
    assert ev["BEAST_CBC_TLS1"].title == reworded


def test_another_protocol_keeps_the_raw_words_and_still_gets_the_key(tmp_path):
    ev = _by_id(_events(tmp_path, [_rec("BEAST_CBC_SSL3", "MEDIUM", "DES-CBC3-SHA", "CWE-20")]))
    assert ev["BEAST_CBC_SSL3"].title == "TLS · BEAST_CBC_SSL3: DES-CBC3-SHA"
    assert ev["BEAST_CBC_SSL3"].normalized_key == BEAST


def test_a_name_with_no_twin_still_gets_the_key(tmp_path):
    """Command 2 names have only the TLS row: it is keyed, stands alone, and nothing else moves."""
    ev = _events(tmp_path, [_rec("HSTS", "LOW", "not offered")])
    assert [(e.normalized_key, e.severity, e.title) for e in ev] == [(HSTS, "LOW", "HSTS not enabled")]


# ── one service, one key (code review 2026-11-09, must-fix) ────────────────

def test_the_key_is_kept_to_its_port():
    assert shared_key_for_port(HSTS, 443) == HSTS
    assert shared_key_for_port(HSTS, None) == HSTS
    assert shared_key_for_port(HSTS, 8443) == f"{HSTS}:port-8443"
    assert shared_key_for_port(BEAST, 4443) == f"{BEAST}:port-4443"
    assert shared_key_for_port(None, 8443) is None


def test_two_ports_on_one_name_stay_two_rows(tmp_path):
    ev = _events(tmp_path, [_rec("HSTS", "LOW", "not offered", port="443"),
                            _rec("HSTS", "LOW", "not offered", port="8443"),
                            _rec("BEAST", "LOW", "VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)", "CWE-20", port="8443"),
                            _rec("BEAST_CBC_TLS1", "MEDIUM", "AES128-SHA", "CWE-20", port="8443")])
    keys = sorted((e.finding_id.split(":")[2], e.port, e.normalized_key) for e in ev)
    assert keys == [("BEAST", 8443, f"{BEAST}:port-8443"), ("BEAST_CBC_TLS1", 8443, f"{BEAST}:port-8443"),
                    ("HSTS", 443, HSTS), ("HSTS", 8443, f"{HSTS}:port-8443")]
    assert len({e.finding_id for e in ev}) == 4
    # the two BEAST records of one service still meet; the HSTS rows of two services do not


def test_a_record_without_a_port_is_the_default_port(tmp_path):
    ev = _events(tmp_path, [_rec("HSTS", "LOW", "not offered", port="")])
    assert [(e.port, e.normalized_key) for e in ev] == [(None, HSTS)]
