"""
#037 (2026-09-13) — cert-hygiene severity ceiling.

Guards the rule Howie ratified after the daily digest emitted a CRITICAL for
ftp.sciimage.com off a missing intermediate certificate:

    NO certificate trust/expiry finding is ever CRITICAL.

CRITICAL is reserved for EXPLOITABLE criticals (RCE, auth bypass, exposed
secrets/data). Cert hygiene is a trust warning, not a compromise. An asset's
risk is its worst finding, so one inflated cert finding turns a whole host
CRITICAL on the digest — "telling people we have a critical when there is no
critical is a real bad thing."
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cs_parsers.testssl import (  # noqa: E402
    CERT_HYGIENE_IDS,
    CERT_HYGIENE_MAX_SEVERITY,
    SEVERITY_MAP,
    _cert_hygiene_severity,
)


def test_chain_incomplete_is_LOW_not_critical():
    # The exact finding that made ftp.sciimage.com CRITICAL.
    assert _cert_hygiene_severity(
        "cert_chain_of_trust", "failed (chain incomplete)", "CRITICAL") == "LOW"


def test_self_signed_is_MODERATE_both_spellings():
    # Substring match on purpose: testssl's phrasing varies by version, and a
    # version bump must not silently reclassify a finding.
    for text in ("failed (self signed)", "failed (self-signed)"):
        assert _cert_hygiene_severity(
            "cert_chain_of_trust", text, "CRITICAL") == "MODERATE"


def test_expired_chain_is_MODERATE():
    assert _cert_hygiene_severity(
        "cert_chain_of_trust", "failed (expired)", "CRITICAL") == "MODERATE"


def test_unknown_chain_variant_takes_the_CEILING_not_a_guess():
    # An unrecognised trust failure is not evidence of a SMALL problem; it is
    # absence of evidence either way. Ceiling, never defaulted down to LOW.
    got = _cert_hygiene_severity(
        "cert_chain_of_trust", "failed (some future variant)", "CRITICAL")
    assert got == CERT_HYGIENE_MAX_SEVERITY
    assert got not in ("HIGH", "CRITICAL")


def test_expiring_soon_early_warning_is_PRESERVED():
    # ⭐ The reason cert_expirationStatus is NOT dropped wholesale: the id
    # carries BOTH "expired" AND "expiring soon", and the latter is the single
    # most operationally useful TLS finding we emit — it is what prevents an
    # outage. Dropping the id to kill a duplicate would delete the early
    # warning with it.
    assert _cert_hygiene_severity(
        "cert_expirationStatus", "expires < 30 days", "LOW") == "LOW"


def test_no_cert_hygiene_input_can_EVER_yield_high_or_critical():
    """The rule as a property, not as three examples."""
    offenders = [
        (gid, text, sev)
        for gid in CERT_HYGIENE_IDS
        for text in ("failed (chain incomplete)", "failed (expired)",
                     "does not match supplied uri", "anything at all", "")
        for sev in SEVERITY_MAP.values()
        if _cert_hygiene_severity(gid, text, sev) in ("HIGH", "CRITICAL")
    ]
    assert offenders == [], f"cert-hygiene ceiling leaked: {offenders[:5]}"


def test_the_case_the_gate_must_PASS_real_criticals_untouched():
    """㉟ — test the case a gate should PASS, not only the ones it blocks.

    A ceiling that also suppressed genuine criticals would be the same defect
    with the sign flipped. These ids must not be in scope at all.
    """
    for gid in ("heartbleed", "ROBOT", "LOGJAM", "BREACH", "secret_exposed"):
        assert gid not in CERT_HYGIENE_IDS
