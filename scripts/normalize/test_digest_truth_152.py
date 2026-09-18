#!/usr/bin/env python3
"""T1-T3 of relay 152 — the digest's TRUTH items, re-measured before building.

⛔ WHY THESE THREE ARE ONE FILE. Howie read digest #130 line by line: 20 findings, all
real, all counts true — and three of them were still wrong ABOUT THEMSELVES. A tool
describing its own reliability, a deployment choice, and an inventory were sitting at
LOW beside actual defects. None of that is a counting bug, which is why rule 9 closed on
the digest lane and these still needed fixing: a list where a policy decision looks like
a weakness is a list that gets skimmed.

⚠ RE-MEASURED 2026-09-18 BEFORE BUILDING (relay 301's instruction — the 152 counts are
09-15 counts). T1's phrases were NOT yet in the skip set; `cert_trust_wildcard` was NOT
in the hygiene set and resolved LOW; the grouped cipher title was still "(N reports)".
So all three were live, and each is fixed here.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs_parsers import nikto, testssl  # noqa: E402


def _dropped(line: str) -> bool:
    return any(p.search(line) for p in nikto.SKIP_PATTERNS)


# ══ T1 — a tool describing its own reliability is not a finding ══════════════

_NIKTO_999967 = ("/: Web Server returns a valid response with junk HTTP methods "
                 "which may cause false positives.")


def test_the_junk_http_methods_self_assessment_is_dropped():
    assert _dropped(_NIKTO_999967)


def test_both_phrasings_drop_independently():
    """Two patterns, because nikto prints the sentence in more than one shape and a
    single regex over the whole sentence would miss a reworded one."""
    assert _dropped("Server returns a valid response with junk HTTP methods.")
    assert _dropped("This may cause false positives in the results below.")


def test_the_keep_corpus_survives_unchanged():
    """⛔ THE HALF THAT MATTERS. A drop rule is only as good as what it does NOT drop.
    Every line here is a real nikto finding from the estates."""
    keep = [
        "/.git/config: Git config file found, may leak sensitive information.",
        "/phpinfo.php: Output from the phpinfo() function was found.",
        "/: Directory indexing found.",
        "/: The X-Content-Type-Options header is not set.",
        "/backup.zip: Backup file found.",
        "/: HTTP method OPTIONS returns allowed methods.",
        "Server banner changed from 'nginx' to 'nginx/1.2'.",
        "/: ETag header found, inode leak.",
    ]
    for line in keep:
        assert not _dropped(line), f"a real finding was dropped: {line!r}"


def test_a_finding_that_merely_mentions_false_positives_in_remediation_is_kept():
    """⚠ THE SCOPE OF THE RULE. What makes 999967 housekeeping is the TOOL talking
    about ITS OWN output — not the words 'false positive' appearing anywhere. A
    remediation note that says 'verify before acting, as false positives are possible'
    is a finding with advice attached."""
    assert not _dropped("/admin: Admin login page found. Verify manually; "
                        "automated checks can produce false positive results.")


# ══ T2 — a wildcard certificate is a policy choice ═══════════════════════════

def test_a_wildcard_certificate_is_INFO_not_a_weakness():
    assert testssl._cert_hygiene_severity("cert_trust_wildcard", "wildcard", "LOW") == "INFO"


def test_it_is_INFO_whatever_testssl_rated_it():
    """The demotion is a statement about the FACT, not a ceiling on the input."""
    for incoming in ("LOW", "MODERATE", "HIGH", "CRITICAL", "INFO"):
        assert testssl._cert_hygiene_severity("cert_trust_wildcard", "x", incoming) == "INFO"


def test_real_certificate_defects_are_untouched():
    """⛔ THE GUARD ON THE DEMOTION. A chain-of-trust failure is not a policy choice."""
    assert testssl._cert_hygiene_severity("cert_chain_of_trust", "self signed", "LOW") \
        == testssl.CERT_HYGIENE_MAX_SEVERITY
    assert testssl._cert_hygiene_severity("cert_expirationStatus", "30 days", "LOW") == "LOW"


def test_the_policy_set_holds_exactly_what_was_ruled():
    """One entry. A second is a decision someone makes in front of this test."""
    assert testssl._CERT_POLICY_IDS == frozenset({"cert_trust_wildcard"})


# ══ T3 — the cipher list is inventory, and says so ═══════════════════════════

def test_the_cipher_inventory_title_describes_the_SERVER_not_our_grouping():
    """"(22 reports)" described how WE collapsed the records. "22 suites accepted"
    describes the host — which is the thing the reader asked about."""
    assert testssl._cipher_protocol_label("cipher-tls1_2") == "TLS 1.2"
    assert testssl._cipher_protocol_label("cipher-tls1_3") == "TLS 1.3"


def test_an_unrecognised_cipher_group_does_not_invent_a_version():
    """⚠ A WRONG VERSION NUMBER IN A TITLE IS WORSE THAN NONE. Falls back to "TLS"."""
    assert testssl._cipher_protocol_label("cipher_x6b") == "TLS"
    assert testssl._cipher_protocol_label("") == "TLS"
    assert testssl._cipher_protocol_label("ssl3_ciphers") == "SSL 3"


def test_the_demotion_is_wired_where_the_grouping_happens():
    """Asked of the source: the severity is set from `is_cipher`, the same flag
    `_normalize_id` returns — not from a second guess at what a cipher id looks like."""
    import inspect
    src = inspect.getsource(testssl)
    assert "if is_cipher:" in src and 'canonical_sev = "INFO"' in src


def test_the_weakness_findings_are_NOT_demoted_with_the_inventory():
    """⛔ THE LINE THIS MUST NOT CROSS. cipherlist_OBSOLETED and LUCKY13 are findings
    about weak suites; only the per-suite INVENTORY is demoted. `_normalize_id` is what
    separates them, so this asserts the separation still holds."""
    gid_inv, is_cipher_inv = testssl._normalize_id("cipher-tls1_2_xc028")
    gid_weak, is_cipher_weak = testssl._normalize_id("cipherlist_OBSOLETED")
    assert is_cipher_inv is True
    assert is_cipher_weak is False, "a weakness id is being treated as inventory"
    assert gid_weak == "cipherlist_OBSOLETED"
