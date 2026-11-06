#!/usr/bin/env python3
"""KB 12 job 4v (ruled 2026-11-04, built 2026-11-06) — compressed pages alone are LOW.

testssl's BREACH check sees only that the home page comes back compressed. Howie, 2026-11-04
15:33: "Change it to a low. I agree with you." Pinned here, on the parser the deep scan ships:
  - the three texts the fleets carry today (gzip; gzip deflate; br gzip) come out LOW;
  - the finding_id is the one the open rows already have, so a rescan rewrites them in place;
  - any other BREACH wording keeps testssl's rating (MODERATE), and so do the other named
    checks that carry a CWE (LUCKY13 here): the exception is this one check, nothing wider;
  - "compression alone" is the whole text: a BREACH line that says compression AND anything
    more (secrets reflected, another page tested, an older or newer wording) keeps MODERATE
    (code review 2026-11-06, must-fix 1);
  - a BREACH record testssl itself rates OK is still dropped, and the rule never raises a rating.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs_parsers.common import stable_finding_id  # noqa: E402
from cs_parsers.testssl import breach_is_compression_only, parse_testssl_file  # noqa: E402

# Says compression, but not compression alone: each keeps testssl's rating (code review must-fix 1).
MORE_THAN_COMPRESSION = (
    "VULNERABLE, secrets reflected; HTTP compression detected",
    "potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested; secrets reflected",
    "potentially VULNERABLE, gzip HTTP compression detected; token reflected  - only supplied '/' tested",
    "VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, gzip and a secret HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, gzip HTTP compression detected  - tested '/' and '/login'",
    "potentially NOT ok, uses gzip HTTP compression.",
    "potentially VULNERABLE, GZIP HTTP compression detected  - only supplied '/' tested",
    "Test failed: HTTP compression check timed out",
)

# testssl's own words on the two fleets, read 2026-11-06 (Prodex 22 + 2 open, Command 3 + 3 open)
FLEET_TEXTS = (
    "potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, gzip deflate HTTP compression detected  - only supplied '/' tested",
    "potentially VULNERABLE, br gzip HTTP compression detected  - only supplied '/' tested",
)


def _rec(rid="BREACH", sev="MEDIUM", finding=FLEET_TEXTS[0], ip="bitec.prodexlabs.com/1.2.3.4",
         port="443", cwe="CWE-310", cve="CVE-2013-3587"):
    r = {"id": rid, "ip": ip, "port": port, "severity": sev, "finding": finding}
    if cwe:
        r["cwe"] = cwe
    if cve:
        r["cve"] = cve
    return r


def _events(tmp_path, records, asset_id="bitec.prodexlabs.com", cloud_endpoint=False):
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps(records))
    return parse_testssl_file(json_path=jf, asset_id=asset_id, scan_id="scan", scan_root=tmp_path,
                              fallback_observed_at="2026-11-06T12:00:00Z", cloud_endpoint=cloud_endpoint)


def test_the_fleet_texts_come_out_low(tmp_path):
    for text in FLEET_TEXTS:
        ev = _events(tmp_path, [_rec(finding=text)])
        assert [(e.severity, e.cwe) for e in ev] == [("LOW", [310])], text
        assert ev[0].title.startswith("BREACH attack vulnerability check — potentially VULNERABLE")


def test_the_finding_id_is_the_one_the_open_rows_have(tmp_path):
    ev = _events(tmp_path, [_rec()])
    assert ev[0].finding_id == stable_finding_id("bitec.prodexlabs.com", "testssl", "BREACH", "port-443")
    assert ev[0].finding_id == "bitec.prodexlabs.com:testssl:BREACH:33ad838", \
        "the id the open Prodex row carries (read 2026-11-06): the rescan rewrites it, no new row"


def test_other_wording_and_other_named_checks_keep_testssl_rating(tmp_path):
    ev = _events(tmp_path, [_rec(finding="VULNERABLE, secrets reflected in compressed response")])
    assert [e.severity for e in ev] == ["MODERATE"], "not compression alone: testssl's rating stands"
    ev = _events(tmp_path, [_rec(rid="LUCKY13", finding="potentially vulnerable, uses obsolete CBC ciphers",
                                 cwe="CWE-310", cve="CVE-2013-0169")])
    assert [e.severity for e in ev] == ["MODERATE"], "the exception is BREACH only"
    ev = _events(tmp_path, [_rec(sev="HIGH")])
    assert [e.severity for e in ev] == ["HIGH"], "only MODERATE is lowered; the rule never touches others"


def test_ok_is_still_dropped_and_low_stays_low(tmp_path):
    ok = _rec(sev="OK", finding="no gzip/deflate/compress/br HTTP compression (OK)  - only supplied '/' tested")
    assert _events(tmp_path, [ok]) == []
    assert [e.severity for e in _events(tmp_path, [_rec(sev="LOW")])] == ["LOW"]


def test_a_cloud_endpoint_changes_nothing_here(tmp_path):
    assert [e.severity for e in _events(tmp_path, [_rec()], cloud_endpoint=True)] == ["LOW"]


def test_compression_and_something_more_keeps_testssl_rating(tmp_path):
    for text in MORE_THAN_COMPRESSION:
        assert not breach_is_compression_only("BREACH", text), text
        assert [e.severity for e in _events(tmp_path, [_rec(finding=text)])] == ["MODERATE"], text


def test_the_rule_itself():
    for text in FLEET_TEXTS + (
            "potentially VULNERABLE, gzip HTTP compression detected - only supplied '/' tested",
            "potentially VULNERABLE, compress zstd HTTP compression detected  - only supplied \"/\" tested",
            "  potentially VULNERABLE, deflate HTTP compression detected  - only supplied '/index.html' tested  "):
        assert breach_is_compression_only("BREACH", text), text
    assert not breach_is_compression_only("BREACH", "")
    assert not breach_is_compression_only("BREACH", None)
    assert not breach_is_compression_only("CRIME_TLS", FLEET_TEXTS[0]), "BREACH only"
    assert not breach_is_compression_only("breach", FLEET_TEXTS[0]), "testssl id, exact"
