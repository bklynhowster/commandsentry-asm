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
    assert fp == ("INFO", "info_disclosure", "tech-header-disclosure",
                  "Technology disclosed via response headers")
    ver = _classify_header_line("Retrieved server header: nginx/1.14.0")
    assert ver[0] == "LOW" and ver[2] == "tech-version-disclosure"
    unc = _classify_header_line(
        "Uncommon header(s) 'x-nextjs-cache' found, with contents: HIT")
    assert unc[2] == "tech-header-disclosure"
    alt = _classify_header_line(
        "An alt-svc header was found which is advertising HTTP/3. The endpoint is: ':443'.")
    assert alt[2] == "tech-header-disclosure"
    # Bucket 3 / non-header lines → None (caller keeps default handling)
    assert _classify_header_line("Retrieved x-frame-options header: ALLOWALL") is None
    assert _classify_header_line("Suggested security header missing: x-frame-options") is None
    assert _classify_header_line("Server is using a wildcard certificate") is None


if __name__ == "__main__":
    test_fingerprint_bucket()
    test_version_bucket_never_swallowed()
    test_security_headers_never_collapse()
    test_line_dispositions()
    print("all nikto header-classify anchor tests PASSED")
