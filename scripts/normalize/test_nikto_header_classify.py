"""Tests for 4.7 H3/H5 — nikto response-header disclosure classification.

Three buckets, and the boundary is load-bearing:
  1. fingerprint (bare tech name, no version) → collapse INFO via shared
     normalized_key "tech-header-disclosure".
  2. version-bearing → own LOW finding ("tech-version-disclosure") — a version
     string is a CVE-lookup shortcut, must stay VISIBLE, must NOT be swallowed
     into the fingerprint bucket (4.7 H3 load-bearing pushback).
  3. security/actionable header names → None (Bucket 3, untouched).

NEVER-SWALLOW regression guard: version-disclosure and security headers keep
their own disposition. Broadening the collapse bucket would have to break a test
before it could ship (the broad-filter-hides-real-findings under-detection guard).

Run:  pytest scripts/normalize/test_nikto_header_classify.py -v
  or: python3 scripts/normalize/test_nikto_header_classify.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/normalize/ importable so cs_parsers.nikto resolves the same way
# it does for run_normalize.py.
sys.path.insert(0, str(Path(__file__).parent))

from cs_parsers.nikto import (  # noqa: E402
    classify_header_disclosure,
    classify_nikto_header,
    extract_header_disclosure,
    _classify_header_line,
)


FINGERPRINT = [
    ("x-powered-by", "Next.js"),
    ("server", "nginx"),
    ("via", "1.1 google"),          # "1.1" is the HTTP protocol version, NOT software
    ("alt-svc", ""),                # HTTP/3 advertisement, not a version
    ("x-nextjs-cache", "HIT"),
    ("x-nextjs-prerender", "1,1"),
    ("x-nextjs-stale-time", "300"),
    ("cf-cache-status", "DYNAMIC"),
    ("x-vercel-cache", "MISS"),
]
VERSION = [
    ("x-powered-by", "PHP/7.2.14"),
    ("x-aspnet-version", "4.5.2"),
    ("x-aspnetmvc-version", "5.2"),
    ("server", "nginx/1.14.0"),
    ("server", "Apache/2.4.41 (Ubuntu)"),
]
NOT_FINGERPRINT = [   # Bucket 3 — security/actionable header names never collapse
    ("x-frame-options", "ALLOWALL"),
    ("x-content-type-options", "sniff"),
    ("strict-transport-security", "max-age=0"),
    ("content-security-policy", "default-src *"),
    ("referrer-policy", "unsafe-url"),
    ("permissions-policy", "geolocation=*"),
    ("access-control-allow-origin", "*"),
    ("set-cookie", "SID=x"),
    ("x-random-app-header", "whatever"),   # not in the closed allowlist
]


def test_fingerprint_bucket():
    for name, value in FINGERPRINT:
        assert classify_header_disclosure(name, value) == "fingerprint", (name, value)


def test_version_bucket_never_swallowed():
    # 4.7 H3 load-bearing: a version disclosure must be its OWN finding, not
    # collapsed into fingerprint. Under-detection here is a security-hygiene loss.
    for name, value in VERSION:
        assert classify_header_disclosure(name, value) == "version", (name, value)


def test_security_headers_never_collapse():
    for name, value in NOT_FINGERPRINT:
        assert classify_header_disclosure(name, value) is None, (name, value)


def test_line_dispositions():
    fp = _classify_header_line("Retrieved x-powered-by header: Next.js")
    assert fp == ("INFO", "info_disclosure", "class:tech-header-disclosure",
                  "Technology disclosed via response headers")
    ver = _classify_header_line("Retrieved server header: nginx/1.14.0")
    assert ver[0] == "LOW" and ver[2] == "class:tech-version-disclosure"
    unc = _classify_header_line(
        "Uncommon header(s) 'x-nextjs-cache' found, with contents: HIT")
    assert unc[2] == "class:tech-header-disclosure"
    alt = _classify_header_line(
        "An alt-svc header was found which is advertising HTTP/3. The endpoint is: ':443'.")
    assert alt[2] == "class:tech-header-disclosure"
    # Bucket 3 / non-header lines → None (caller keeps default handling)
    assert _classify_header_line("Retrieved x-frame-options header: ALLOWALL") is None
    assert _classify_header_line("Suggested security header missing: x-frame-options") is None
    assert _classify_header_line("Server is using a wildcard certificate") is None


def test_classify_nikto_header_ssot():
    # 4.7 I1/I2 — the SSOT pure fn returns (bucket, class-prefixed normalized_key).
    assert classify_nikto_header("x-powered-by", "Next.js") == ("fingerprint", "class:tech-header-disclosure")
    assert classify_nikto_header("server", "nginx/1.14.0") == ("version", "class:tech-version-disclosure")
    assert classify_nikto_header("x-frame-options", "ALLOWALL") == ("actionable", None)


def test_extraction_agreement_across_parser_formats():
    # 4.7 I1 — the shared extractor must yield the SAME (name, value) whether given
    # a bare nikto description (cs_parsers path) OR a stored run_medium title
    # ("nikto: [id] /: desc"). Prevents extraction drift between the two parsers +
    # the backfill (I4) — divergence there would give one finding two class keys.
    cases = [
        ("Retrieved x-powered-by header: Next.js", ("x-powered-by", "Next.js")),
        ("Uncommon header(s) 'x-nextjs-cache' found, with contents: HIT", ("x-nextjs-cache", "HIT")),
        ("Retrieved x-powered-by header: PHP/7.2.14", ("x-powered-by", "PHP/7.2.14")),
        ("Retrieved via header: 1.1 google", ("via", "1.1 google")),
    ]
    for desc, expected in cases:
        bare = extract_header_disclosure(desc)
        titled = extract_header_disclosure(f"nikto: [999100] /: {desc}")
        assert bare == titled == expected, (desc, bare, titled)


def test_extraction_spares_non_header_lines():
    # 4.7 I8 coverage port — the retired Prodex roll-up's "spares real findings"
    # set. These are NOT header disclosures, so extract_header_disclosure returns
    # None and they never receive a class-collapse key (stay Bucket 3 / own row).
    for line in (
        'The Content-Encoding header is set to "deflate" which may mean that the '
        "server is vulnerable to the BREACH attack.",
        "Server may leak inodes via ETags, header found with file /, fields: 0x123",
        "/admin/: This might be interesting.",
        "",
    ):
        assert extract_header_disclosure(line) is None, line


if __name__ == "__main__":
    test_fingerprint_bucket()
    test_version_bucket_never_swallowed()
    test_security_headers_never_collapse()
    test_line_dispositions()
    test_classify_nikto_header_ssot()
    test_extraction_agreement_across_parser_formats()
    test_extraction_spares_non_header_lines()
    print("all nikto header-classify anchor tests PASSED")
