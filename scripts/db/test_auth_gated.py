"""Unit tests for #24 Phase 2 compute_auth_gated() detection.

The AND-gate: subdomain[0].reachability.title matches a login pattern
AND subdomain[0].services[443].cert.san matches an IdP SAN suffix.
Both signals required so a real app with a 'Sign In' link in its title
doesn't false-flag because its cert is its own domain, not an IdP's.

Pre-validated on real data (Howie 2026-06-15):
  myordersauth (Entra)         → auth_gated=true  (positive)
  test.commandcommcentral (FW) → auth_gated=false (negative — real app)

Run:  pytest scripts/db/test_auth_gated.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/db importable like the importer imports its siblings
sys.path.insert(0, str(Path(__file__).parent))

from import_asm_to_surface import (  # noqa: E402
    IDP_CERT_SAN_SUFFIXES,
    LOGIN_TITLE_PATTERNS,
    compute_auth_gated,
)


# ═══════════════════════════════════════════════════════════════════════
# Helper to build a minimal asm_doc fixture
# ═══════════════════════════════════════════════════════════════════════


def _doc(title: str | None, san: list[str] | None, *, port: int = 443) -> dict:
    """Build an asm_doc with one subdomain, one 443 service, given title
    and cert SAN. Mirrors the shape produced by normalize.py."""
    sub: dict = {
        "reachability": {"title": title, "live": title is not None},
        "services": [],
    }
    if san is not None:
        sub["services"] = [{
            "port": port,
            "cert": {"san": san},
        }]
    return {"subdomains": [sub]}


# ═══════════════════════════════════════════════════════════════════════
# Positive cases — Entra + other IdPs
# ═══════════════════════════════════════════════════════════════════════


def test_entra_login_microsoftonline_san_is_auth_gated():
    """The reference case — myordersauth-test on 2026-06-15:
    title 'Sign in to your account' + cert SAN login.microsoftonline.com.
    Must return True."""
    doc = _doc(
        title="Sign in to your account",
        san=["login.microsoftonline.com"],
    )
    assert compute_auth_gated(doc) is True


def test_b2clogin_san_is_auth_gated():
    """Azure AD B2C suffix coverage — *.b2clogin.com."""
    doc = _doc(
        title="Sign in",
        san=["yourtenant.b2clogin.com"],
    )
    assert compute_auth_gated(doc) is True


def test_okta_san_is_auth_gated():
    """Okta suffix coverage — *.okta.com."""
    doc = _doc(
        title="Sign In",
        san=["company.okta.com"],
    )
    assert compute_auth_gated(doc) is True


def test_auth0_regional_san_is_auth_gated():
    """Auth0 regional tenant — *.<region>.auth0.com — covered by .auth0.com suffix."""
    doc = _doc(
        title="Log in",
        san=["company.us.auth0.com"],
    )
    assert compute_auth_gated(doc) is True


def test_cognito_san_is_auth_gated():
    """AWS Cognito hosted UI — *.auth.<region>.amazoncognito.com."""
    doc = _doc(
        title="Sign in",
        san=["company.auth.us-east-1.amazoncognito.com"],
    )
    assert compute_auth_gated(doc) is True


def test_wildcard_san_normalized():
    """Wildcard SANs (*.okta.com) should match. Implementation strips
    leading *. when comparing — verify both wildcard and concrete forms."""
    doc = _doc(
        title="Sign in",
        san=["*.okta.com"],
    )
    assert compute_auth_gated(doc) is True


# ═══════════════════════════════════════════════════════════════════════
# Negative cases — the AND-gate guard
# ═══════════════════════════════════════════════════════════════════════


def test_real_app_with_signin_link_title_but_own_cert_is_NOT_auth_gated():
    """LOAD-BEARING — THE AND-gate guard. A real app whose title
    contains 'Sign in' (because it has a Sign In link in the nav) but
    whose cert is its OWN domain (not an IdP) MUST NOT be auth_gated.

    This is the safety check against false-positives on
    legitimately-scannable apps. Without the cert-AND-gate, every app
    with a Sign In link in its title would lose its medium scan
    coverage."""
    doc = _doc(
        title="MyCommandApp — Dashboard (Sign in)",  # title has 'sign in'
        san=["app.commandcompanies.com"],            # but cert is own domain
    )
    assert compute_auth_gated(doc) is False


def test_fortiweb_fronted_real_app_is_NOT_auth_gated():
    """The negative reference case from Howie's pre-validation
    2026-06-15: test.commandcommcentral.com — title 'CommandCommCentral'
    (not a login pattern) + own cert. The FortiWeb in front doesn't
    change the auth_gated determination — the AND-gate works on
    application-layer signals only. Real app, real cert, no IdP →
    auth_gated=False. Medium scan should run normally."""
    doc = _doc(
        title="CommandCommCentral",
        san=["test.commandcommcentral.com", "*.commandcommcentral.com"],
    )
    assert compute_auth_gated(doc) is False


def test_apex_with_unreachable_root_is_NOT_auth_gated():
    """Apex assets (e.g. unimacgraphics.com) usually have an
    unreachable root — reachability.title is None. The compute fails
    SAFELY to False, which is correct: subdomains under the apex are
    evaluated as their own asset_surface entries (per Q5 advisor
    note). The apex itself defaults to non-auth-gated."""
    doc = _doc(title=None, san=None)
    assert compute_auth_gated(doc) is False


def test_idp_cert_san_but_no_login_title_is_NOT_auth_gated():
    """One signal alone is insufficient — AND-gate semantics. A weird
    edge case (e.g. an asset with an IdP cert SAN but the title says
    something unrelated) should NOT be flagged. The AND-gate is the
    safety bar — both signals must agree."""
    doc = _doc(
        title="Dashboard — Welcome",
        san=["login.microsoftonline.com"],
    )
    assert compute_auth_gated(doc) is False


def test_login_title_but_no_idp_cert_is_NOT_auth_gated():
    """Other half of the AND-gate. A legitimate app with a 'Login'
    title but no IdP cert presence (e.g. a custom-built login page on
    own domain) is NOT classified auth_gated — medium tools could
    still find real findings (the custom login page might have its
    own attack surface). This is the documented Phase 2 limitation:
    custom-domain IdP not flagged."""
    doc = _doc(
        title="Login",
        san=["app.example.com"],
    )
    assert compute_auth_gated(doc) is False


# ═══════════════════════════════════════════════════════════════════════
# Defensive — malformed / missing data should fail SAFE (False)
# ═══════════════════════════════════════════════════════════════════════


def test_no_subdomains_is_NOT_auth_gated():
    """Asset with no subdomains[] entries (data quality issue) →
    fail-safe to False (run all tools), never raise."""
    assert compute_auth_gated({"subdomains": []}) is False
    assert compute_auth_gated({}) is False
    assert compute_auth_gated({"subdomains": None}) is False


def test_malformed_subdomain_is_NOT_auth_gated():
    """Subdomain entry that's not a dict (string, None, etc.) →
    fail-safe to False, never raise."""
    assert compute_auth_gated({"subdomains": ["not a dict"]}) is False
    assert compute_auth_gated({"subdomains": [None]}) is False


def test_non_https_port_cert_ignored():
    """The compute only inspects port 443 (or 8443) service cert SANs.
    A cert SAN on port 80 (somehow) or any other non-HTTPS port
    should NOT trigger the gate — only HTTPS-facing services matter
    for IdP-cert detection."""
    doc = _doc(
        title="Sign in",
        san=["login.microsoftonline.com"],
        port=80,  # NOT 443/8443
    )
    assert compute_auth_gated(doc) is False


def test_case_insensitive_title_match():
    """Title matching is case-insensitive — 'SIGN IN' / 'sign in' /
    'Sign In' all hit the same pattern."""
    for variant in ("SIGN IN", "sign in", "Sign In", "SiGn In"):
        doc = _doc(title=variant, san=["login.microsoftonline.com"])
        assert compute_auth_gated(doc) is True, (
            f"Title variant {variant!r} should match login pattern"
        )


# ═══════════════════════════════════════════════════════════════════════
# Lock-in tests for the canonical lists
# ═══════════════════════════════════════════════════════════════════════


def test_idp_cert_san_suffixes_complete():
    """Lock-in for the IdP suffix list per Howie 2026-06-15 advisor
    confirm. If anyone trims this list, the test surfaces the change."""
    expected = {
        "login.microsoftonline.com",
        "login.windows.net",
        "sts.windows.net",
        "login.microsoftonline.us",
        ".b2clogin.com",
        "accounts.google.com",
        ".okta.com",
        ".auth0.com",
        ".onelogin.com",
        ".pingidentity.com",
        ".pingone.com",
        ".amazoncognito.com",
    }
    assert set(IDP_CERT_SAN_SUFFIXES) == expected


def test_login_title_patterns_conservative():
    """Lock-in for the title pattern list. Conservative on purpose —
    the AND-with-cert is the safety, loose title substrings can't
    false-positive without the IdP cert also present."""
    expected = {
        "sign in to your account",
        "sign in",
        "log in",
        "login",
    }
    assert set(LOGIN_TITLE_PATTERNS) == expected
