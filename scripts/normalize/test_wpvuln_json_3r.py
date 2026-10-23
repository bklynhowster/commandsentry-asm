"""(KB 12 job 3r, 2026-10-23) A hand-run scan's wpvulnerability file: out of date, not proven.

The old keyword hints rated "Arbitrary File Upload" HIGH and any XSS MODERATE-HIGH from the
advisory's name alone. A plugin version on an advisory's list is out of date: MODERATE.
"""
import json

from cs_parsers import wpscan, wpvuln_json


def test_every_actionable_entry_is_moderate_and_never_says_vulnerable(tmp_path):
    root = tmp_path / "scan"
    (root / "phase02-versions").mkdir(parents=True)
    f = root / "phase02-versions" / "wpvuln-revslider.json"
    f.write_text(json.dumps({"type": "plugin", "slug": "revslider", "installed_version": "6.7.54",
                             "vulnerabilities": [
                                 {"name": "Slider Revolution [revslider] < 7.0.11 - Arbitrary File Upload (RCE)",
                                  "fixed_in": "7.0.11", "cves": ["CVE-2026-6692"], "status": "VULNERABLE"},
                                 {"name": "Slider Revolution [revslider] < 7.0.10 - Unauthenticated Stored XSS",
                                  "fixed_in": "7.0.10", "cves": ["CVE-2026-6728"], "status": "VULNERABLE"},
                                 {"name": "Slider Revolution [revslider] < 6.0 - old", "fixed_in": "6.0",
                                  "cves": [], "status": "PATCHED"}]}))
    evs = wpvuln_json.parse_wpvuln_file(f, "cc.example.com", "s1", root, None)
    assert [e.severity for e in evs] == ["MODERATE", "MODERATE"]
    assert all("vulnerable" not in e.description.lower() for e in evs)
    assert all("out of date" in e.description for e in evs)
    assert not hasattr(wpvuln_json, "_hint_severity")


def test_the_wpscan_text_reader_writes_no_advisory_and_guesses_no_severity(tmp_path):
    """3r second check (Grok, 09:05): the WPScan text reader still carried a keyword severity
    guesser. It was dead - every advisory block is skipped before it (since 2026-05-24) - and
    is now gone. Pinned: an advisory block written in its scariest words yields no finding,
    and nothing this reader writes is rated above LOW."""
    root = tmp_path / "scan"
    root.mkdir()
    f = root / "wpscan.txt"
    f.write_text("[+] URL: https://cc.example.com/\n\n"
                 "[+] [CVE-2026-6692] Slider Revolution < 7.0.11 - Critical Unauthenticated Remote Code Execution\n"
                 " | Fixed in: 7.0.11\n | CVSS: 9.8 high\n\n"
                 "[+] revslider\n | Location: https://cc.example.com/wp-content/plugins/revslider/\n"
                 " | Latest Version: 7.0.16\n | Version: 6.7.54 (80% confidence)\n\n"
                 "[+] XML-RPC seems to be enabled: https://cc.example.com/xmlrpc.php\n\n")
    evs = wpscan.parse_wpscan_file(f, "cc.example.com", "s1", root, None)
    assert not any(e.cve for e in evs) and not any("CVE" in e.title for e in evs)
    assert {e.severity for e in evs} <= {"INFO", "LOW"} and len(evs) == 2
    assert not hasattr(wpscan, "_severity_for_cve_block")
