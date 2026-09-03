"""Tests for canonical-host resolution (4.7 rulings 77-82).

The load-bearing test in this file is
`test_never_follows_redirect_off_registrable_domain` and its Microsoft-specific
sibling. Two live Command assets 302 to login.microsoftonline.com; a naive
"follow the redirect" implementation would point nuclei/nikto/ffuf at
Microsoft's identity service. Everything else here is coverage; that one is a
safety property.

Run: python -m pytest scripts/scanner/test_canonical_host.py -q
"""

from __future__ import annotations

import pytest

from canonical_host import (
    CanonicalVerdict,
    REDUNDANT_STUB,
    THIRD_PARTY,
    THIRD_PARTY_SSO,
    USE_ASSET_HOST,
    USE_CANONICAL,
    _host_from_location,
    redirect_target_authorized,
    registrable_apex,
    resolve_canonical_host,
    same_registrable_domain,
)

# ─── Fixture helpers ─────────────────────────────────────────────────────

APEX_IPS = ["8.232.147.166"]
PRESSABLE_IPS = ["199.16.172.68", "199.16.173.113"]


def mk(
    *,
    probe_result,
    ips=None,
    assets=(),
    sso=(),
):
    """Build the injected callables for resolve_canonical_host()."""
    ip_map = ips or {}

    def probe(host):
        if callable(probe_result):
            return probe_result(host)
        return probe_result

    def resolve_ips(host):
        return ip_map.get(host)

    def is_known_asset(host):
        return host in set(assets)

    return dict(
        probe=probe,
        resolve_ips=resolve_ips,
        is_known_asset=is_known_asset,
        known_sso_hosts=sso,
    )


# ─── THE SAFETY PROPERTY ─────────────────────────────────────────────────


def test_never_follows_redirect_off_registrable_domain():
    """A same-IP coincidence must NOT authorize an off-domain target."""
    ok, why = redirect_target_authorized(
        "myordersauth.unimacgraphics.com",
        "login.microsoftonline.com",
        target_is_known_asset=False,
        # Deliberately identical IPs: even then, off-domain must refuse.
        source_ips=["203.0.113.10"],
        target_ips=["203.0.113.10"],
    )
    assert ok is False, (
        "off-registrable-domain redirect was AUTHORIZED — this is the "
        "unauthorised-third-party-scan defect"
    )
    assert why == "target_off_registrable_domain"


def test_microsoft_sso_redirect_yields_third_party_not_a_followed_host():
    """End-to-end: the real Command shape must never scan Microsoft."""
    asset = "myordersauth.unimacgraphics.com"
    v = resolve_canonical_host(
        asset,
        **mk(
            probe_result=(301, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?x=1"),
            ips={asset: ["203.0.113.10"], "login.microsoftonline.com": ["20.190.1.1"]},
        ),
    )
    assert v.http_host == asset, "must NOT rewrite Host to Microsoft"
    assert "microsoftonline" not in v.http_host
    assert v.outcome == THIRD_PARTY
    assert v.skip_http is True, "third-party HTTP surface should GATE_SKIP"
    assert v.followed is False


def test_explicit_sso_marking_short_circuits_before_any_probe():
    """Defence in depth: marked assets refuse even if the boundary regressed."""
    probed = []

    def spy(host):
        probed.append(host)
        # A deliberately "authorised-looking" same-domain redirect.
        return (301, "https://www.unimacgraphics.com/")

    v = resolve_canonical_host(
        "myordersauth.unimacgraphics.com",
        probe=spy,
        resolve_ips=lambda h: ["1.2.3.4"],
        is_known_asset=lambda h: False,
        known_sso_hosts=["myordersauth.unimacgraphics.com"],
    )
    assert v.outcome == THIRD_PARTY_SSO
    assert v.skip_http is True
    assert probed == [], "must not even probe an explicitly-forbidden asset"


# ─── (A) the real coverage gap ───────────────────────────────────────────


def test_apex_to_www_same_box_is_followed():
    """prodexlabs.com -> www.prodexlabs.com, identical A records."""
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(
            probe_result=(301, "https://www.prodexlabs.com:443/"),
            ips={"prodexlabs.com": APEX_IPS, "www.prodexlabs.com": APEX_IPS},
        ),
    )
    assert v.http_host == "www.prodexlabs.com"
    assert v.outcome == USE_CANONICAL
    assert v.followed is True
    assert v.reason == "same_registrable_domain_same_ip_set"


def test_same_domain_different_ips_is_refused():
    """Same eTLD+1 is NOT sufficient — the IP set is the safety property."""
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(
            probe_result=(301, "https://www.prodexlabs.com/"),
            ips={
                "prodexlabs.com": ["8.232.147.166"],
                "www.prodexlabs.com": ["203.0.113.99"],  # different box
            },
        ),
    )
    assert v.http_host == "prodexlabs.com"
    assert v.outcome == USE_ASSET_HOST
    assert v.reason == "same_domain_different_infrastructure"


def test_unresolvable_ips_fail_closed():
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(probe_result=(301, "https://www.prodexlabs.com/"), ips={}),
    )
    assert v.http_host == "prodexlabs.com"
    assert v.reason == "ip_sets_unresolved"


# ─── (C) redundant stubs ─────────────────────────────────────────────────


def test_www_to_apex_where_apex_is_an_asset_is_a_redundant_stub():
    """The three Command www.* assets, verified same-box 2026-09-03."""
    v = resolve_canonical_host(
        "www.unimacgraphics.com",
        **mk(
            probe_result=(301, "https://unimacgraphics.com/"),
            ips={
                "www.unimacgraphics.com": PRESSABLE_IPS,
                "unimacgraphics.com": PRESSABLE_IPS,
            },
            assets=("unimacgraphics.com",),
        ),
    )
    assert v.outcome == REDUNDANT_STUB
    assert v.skip_http is True, "don't spend deep budget re-scanning the apex"
    assert v.http_host == "www.unimacgraphics.com", "identity unchanged"
    assert v.diag["canonical_target"] == "unimacgraphics.com"


def test_redundant_stub_wins_before_ip_comparison():
    """Condition 1 is sufficient on its own — no IP data needed."""
    v = resolve_canonical_host(
        "www.commandcompanies.com",
        **mk(
            probe_result=(301, "https://commandcompanies.com/"),
            ips={},  # nothing resolvable
            assets=("commandcompanies.com",),
        ),
    )
    assert v.outcome == REDUNDANT_STUB


# ─── Fail-closed behaviour (ruling 79) ───────────────────────────────────


@pytest.mark.parametrize(
    "probe_result,expected_reason",
    [
        (None, "probe_failed"),
        ((200, None), "status_200_not_canonical_redirect"),
        ((403, None), "status_403_not_canonical_redirect"),
        ((302, "https://www.prodexlabs.com/"), "status_302_not_canonical_redirect"),
        ((307, "https://www.prodexlabs.com/"), "status_307_not_canonical_redirect"),
        ((301, None), "redirect_without_usable_location"),
        ((301, ""), "redirect_without_usable_location"),
        (("nonsense", None), "probe_bad_status"),
    ],
)
def test_ambiguity_falls_back_to_asset_host(probe_result, expected_reason):
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(probe_result=probe_result, ips={"prodexlabs.com": APEX_IPS}),
    )
    assert v.http_host == "prodexlabs.com"
    assert v.followed is False
    assert v.reason == expected_reason


def test_302_is_not_treated_as_canonical():
    """302/307 are app-level (login flows), not a canonical-host statement.

    This is also why the Microsoft case is doubly safe: it is a 302 AND
    off-domain.
    """
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(
            probe_result=(302, "https://www.prodexlabs.com/"),
            ips={"prodexlabs.com": APEX_IPS, "www.prodexlabs.com": APEX_IPS},
        ),
    )
    assert v.followed is False


def test_probe_exception_fails_closed():
    def boom(host):
        raise TimeoutError("network")

    v = resolve_canonical_host(
        "prodexlabs.com",
        probe=boom,
        resolve_ips=lambda h: APEX_IPS,
        is_known_asset=lambda h: False,
    )
    assert v.http_host == "prodexlabs.com"
    assert v.reason == "probe_raised"
    assert v.diag["error"] == "TimeoutError"


def test_resolver_exception_fails_closed():
    def boom(host):
        raise OSError("dns")

    v = resolve_canonical_host(
        "prodexlabs.com",
        probe=lambda h: (301, "https://www.prodexlabs.com/"),
        resolve_ips=boom,
        is_known_asset=lambda h: False,
    )
    assert v.followed is False
    assert v.reason == "ip_sets_unresolved"


def test_self_redirect_is_not_followed():
    v = resolve_canonical_host(
        "prodexlabs.com",
        **mk(probe_result=(301, "https://prodexlabs.com/some/path")),
    )
    assert v.reason == "self_redirect"
    assert v.http_host == "prodexlabs.com"


# ─── Helpers ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host,apex",
    [
        ("prodexlabs.com", "prodexlabs.com"),
        ("www.prodexlabs.com", "prodexlabs.com"),
        ("a.b.c.prodexlabs.com", "prodexlabs.com"),
        ("PRODEXLABS.COM.", "prodexlabs.com"),
        ("localhost", "localhost"),
        ("", ""),
    ],
)
def test_registrable_apex(host, apex):
    assert registrable_apex(host) == apex


def test_same_registrable_domain_excludes_microsoft():
    assert same_registrable_domain("a.unimacgraphics.com", "unimacgraphics.com")
    assert not same_registrable_domain(
        "myordersauth.unimacgraphics.com", "login.microsoftonline.com"
    )


@pytest.mark.parametrize(
    "loc,host",
    [
        ("https://www.prodexlabs.com:443/", "www.prodexlabs.com"),
        ("http://x.example.com/a/b?c=d#e", "x.example.com"),
        ("//cdn.example.com/x", "cdn.example.com"),
        ("www.example.com", "www.example.com"),
        ("https://user:pw@h.example.com/x", "h.example.com"),
        ("/relative/path", None),
        ("", None),
        (None, None),
    ],
)
def test_host_from_location(loc, host):
    assert _host_from_location(loc) == host


def test_verdict_is_frozen():
    v = CanonicalVerdict(http_host="x", outcome=USE_ASSET_HOST, reason="r")
    with pytest.raises(Exception):
        v.http_host = "y"  # type: ignore[misc]
