"""Tests for #36 — cross-source semantic dedup (DMARC + OCSP).

Three test classes, mirroring the spec:
  1. Map correctness — (source, title) → expected canonical_key; non-matching
     titles → None (unchanged).
  2. Idempotency — applying the map twice produces the same result; no churn.
  3. NEVER-MERGE regression guard — locks the conservative scope. Cipher,
     HSTS-present, HSTS-missing, CSRF, and nuclei `dmarc-detect` all keep
     their own keys (apply_cross_source_equivalence returns None for them).
     Future broadening of the map would have to break a test before it could
     ship.

Run:  pytest scripts/normalize/test_cross_source_equivalence.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/normalize/ importable so cs_parsers.common resolves the same
# way it does for run_normalize.py.
sys.path.insert(0, str(Path(__file__).parent))

from cs_parsers.common import (  # noqa: E402
    CROSS_SOURCE_EQUIVALENCE,
    apply_cross_source_equivalence,
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. MAP — positive cases for each entry. All four (source, title) pairs in
#    the curated map must map to the expected canonical key.
# ═══════════════════════════════════════════════════════════════════════════


def test_manual_named_no_dmarc_record_maps_to_dns_missing_dmarc():
    """manual_named F-07's exact title 'No DMARC Record' → dns-missing-dmarc."""
    assert apply_cross_source_equivalence(
        source="manual_named",
        title="No DMARC Record",
    ) == "dns-missing-dmarc"


def test_manual_named_no_dmarc_record_case_insensitive():
    """Pattern is ~* / re.IGNORECASE — lower/upper/mixed all match."""
    for title in ("no dmarc record", "NO DMARC RECORD", "No DMARC Record"):
        assert apply_cross_source_equivalence("manual_named", title) == "dns-missing-dmarc"


def test_light_dns_missing_dmarc_maps_to_dns_missing_dmarc():
    """commandsentry_light 'DNS Missing DMARC' → dns-missing-dmarc.

    This source already derives the canonical key in run_light.py at
    upsert time; the map entry is here so the normalize-time hook produces
    the same result, keeping the JSONL importer path consistent.
    """
    assert apply_cross_source_equivalence(
        source="commandsentry_light",
        title="DNS Missing DMARC",
    ) == "dns-missing-dmarc"


def test_manual_named_no_ocsp_stapling_maps_to_tls_ocsp_stapling_missing():
    """manual_named F-09 'No OCSP Stapling' → tls-ocsp-stapling-missing."""
    assert apply_cross_source_equivalence(
        source="manual_named",
        title="No OCSP Stapling",
    ) == "tls-ocsp-stapling-missing"


def test_testssl_ocsp_stapling_not_enabled_maps_to_tls_ocsp_stapling_missing():
    """testssl 'OCSP stapling not enabled' → tls-ocsp-stapling-missing."""
    assert apply_cross_source_equivalence(
        source="testssl",
        title="OCSP stapling not enabled",
    ) == "tls-ocsp-stapling-missing"


# ═══════════════════════════════════════════════════════════════════════════
# 1b. MAP — negative cases for SAME source, DIFFERENT title. Pin the
#     pattern precision: a title that's topically related but doesn't match
#     the exact phrase must NOT map. This is the "earn each entry within an
#     entry" precision lock.
# ═══════════════════════════════════════════════════════════════════════════


def test_manual_named_multi_issue_f02_does_NOT_map_to_dmarc():
    """F-02 'Domain Spoofing Enabled — No SPF, DMARC, or DKIM' is a multi-issue
    finding. The exact 'no dmarc record' phrase does NOT appear, so it stays
    unmapped. A broader 'dmarc' regex would wrongly fold SPF/DKIM into the
    DMARC group — that's the over-merge failure mode this precision prevents.
    """
    assert apply_cross_source_equivalence(
        source="manual_named",
        title="Domain Spoofing Enabled — No SPF, DMARC, or DKIM",
    ) is None


def test_manual_named_multi_issue_l05_does_NOT_map_to_dmarc():
    """L-05 'No SPF/DMARC/MX' — same multi-issue trap as F-02.

    The slash-separated list mentions DMARC but the finding is about the
    whole email-auth posture, not a single DMARC-record gap. Stays unmapped.
    """
    assert apply_cross_source_equivalence(
        source="manual_named",
        title="No SPF/DMARC/MX",
    ) is None


def test_manual_named_unrelated_title_does_NOT_map():
    """A manual_named finding that isn't about DMARC or OCSP at all
    (e.g. a TLS cert finding) stays unmapped."""
    assert apply_cross_source_equivalence(
        source="manual_named",
        title="TLS certificate chain incomplete",
    ) is None


# ═══════════════════════════════════════════════════════════════════════════
# 2. NEVER-MERGE — regression guard. These cases lock the conservative
#    scope. If a future PR widens the map to keyword-broad matching (e.g.
#    'cipher', 'hsts', 'csrf', 'dmarc' without exact phrase), these tests
#    fail and block the merge.
# ═══════════════════════════════════════════════════════════════════════════


def test_cipher_lucky13_does_NOT_map():
    """LUCKY13 is one specific cipher attack — distinct fix from
    'CBC enabled' or 'obsoleted'. Merging them would hide the per-cipher
    remediation. Must stay unmapped.
    """
    for src in ("testssl", "manual_named", "commandsentry_light"):
        assert apply_cross_source_equivalence(src, "LUCKY13 vulnerability") is None
        assert apply_cross_source_equivalence(src, "CBC cipher enabled") is None
        assert apply_cross_source_equivalence(src, "Obsoleted cipher suite") is None


def test_hsts_present_does_NOT_map():
    """HSTS-present is the OPPOSITE state from HSTS-missing. Merging them
    would silently hide whichever side gets bucketed away in the dedup view.
    Must stay distinct.
    """
    for src in ("testssl", "commandsentry_light"):
        assert apply_cross_source_equivalence(src, "HSTS header present") is None
        assert apply_cross_source_equivalence(src, "Strict-Transport-Security present") is None


def test_hsts_missing_does_NOT_map_under_dmarc_or_ocsp_keys():
    """HSTS-missing is a real finding, but it's NOT in the curated map (only
    DMARC + OCSP are). Confirm it stays unmapped — would only get pulled in
    if a future entry earns its way in.
    """
    for src in ("testssl", "commandsentry_light", "manual_named"):
        assert apply_cross_source_equivalence(src, "HSTS header missing") is None
        assert apply_cross_source_equivalence(src, "Strict-Transport-Security missing") is None


def test_csrf_does_NOT_map():
    """CSRF F-02 vs F-03 are distinct findings (different endpoints, different
    attack surfaces). Must stay distinct.
    """
    for src in ("manual_named", "commandsentry_light", "nuclei"):
        assert apply_cross_source_equivalence(src, "CSRF token missing") is None
        assert apply_cross_source_equivalence(src, "CSRF protection absent") is None


def test_nuclei_dmarc_detect_does_NOT_map_to_dns_missing_dmarc():
    """nuclei's `dmarc-detect` is an INFO DETECTION ("we found DMARC") — the
    OPPOSITE semantic of "missing." Folding it into dns-missing-dmarc would
    be the HSTS-opposites trap on a third source. Stays unmapped.

    This is the lesson Opus caught pre-build during the #36 spec verify:
    the original spec had a 3-source DMARC map with a 'dmarc' AND
    missing/absent context pattern for nuclei. Opus dropped the nuclei
    entry entirely after verifying that nuclei's actual emit is
    `dmarc-detect`, an INFO-detection title that wouldn't match the
    missing/absent pattern anyway — but the absence of an entry is the
    real safety. This test pins it.
    """
    for title in ("dmarc-detect", "DMARC Record Detected", "DMARC detect [https://example.com]"):
        assert apply_cross_source_equivalence("nuclei", title) is None


# ═══════════════════════════════════════════════════════════════════════════
# 3. IDEMPOTENCY — applying the function to its own output is stable.
#    Belt-and-suspenders for the migration's "re-runs touch 0 rows"
#    property at the application layer.
# ═══════════════════════════════════════════════════════════════════════════


def test_apply_twice_is_stable_for_mapped_findings():
    """Same (source, title) → same key on repeated calls.

    The function is pure — same input gives same output. Pinning this so
    a future caching/memoization optimization doesn't accidentally introduce
    state that drifts.
    """
    cases = [
        ("manual_named",        "No DMARC Record"),
        ("commandsentry_light", "DNS Missing DMARC"),
        ("manual_named",        "No OCSP Stapling"),
        ("testssl",             "OCSP stapling not enabled"),
    ]
    for source, title in cases:
        first = apply_cross_source_equivalence(source, title)
        second = apply_cross_source_equivalence(source, title)
        assert first == second
        assert first is not None  # sanity: these are the map's positive cases


def test_apply_returns_none_for_none_inputs():
    """Defensive — None source or None title returns None, doesn't raise."""
    assert apply_cross_source_equivalence(None, "No DMARC Record") is None
    assert apply_cross_source_equivalence("manual_named", None) is None
    assert apply_cross_source_equivalence(None, None) is None
    assert apply_cross_source_equivalence("", "title") is None
    assert apply_cross_source_equivalence("source", "") is None


# ═══════════════════════════════════════════════════════════════════════════
# 4. MAP SHAPE — assert the curated map hasn't drifted in size/structure.
#    Locks in the "two classes only" scope at the structural level so a
#    drive-by addition has to also break this test.
# ═══════════════════════════════════════════════════════════════════════════


def test_map_has_exactly_two_canonical_classes():
    """Two and only two canonical keys in the map: dns-missing-dmarc and
    tls-ocsp-stapling-missing. Adding a third entry requires updating this
    test, which forces a deliberate decision rather than a silent expansion.
    """
    canonical_keys = {entry["canonical_key"] for entry in CROSS_SOURCE_EQUIVALENCE}
    assert canonical_keys == {"dns-missing-dmarc", "tls-ocsp-stapling-missing"}


def test_dmarc_entry_has_exactly_two_sources():
    """DMARC map: manual_named + commandsentry_light. NOT nuclei (which was
    explicitly dropped during Opus pre-build verify — see test_nuclei_dmarc_
    detect_does_NOT_map_to_dns_missing_dmarc for the rationale).
    """
    dmarc = next(e for e in CROSS_SOURCE_EQUIVALENCE if e["canonical_key"] == "dns-missing-dmarc")
    sources = {src for src, _pat in dmarc["patterns"]}
    assert sources == {"manual_named", "commandsentry_light"}


def test_ocsp_entry_has_exactly_two_sources():
    """OCSP map: manual_named + testssl. Both NULL-keyed today; this entry
    is what gives them a canonical convergence point.
    """
    ocsp = next(e for e in CROSS_SOURCE_EQUIVALENCE if e["canonical_key"] == "tls-ocsp-stapling-missing")
    sources = {src for src, _pat in ocsp["patterns"]}
    assert sources == {"manual_named", "testssl"}
