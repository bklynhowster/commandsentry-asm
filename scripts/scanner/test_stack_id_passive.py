"""Unit tests for the P0 passive stack-id collectors in run_heavy.py
(Obsidian 146; 4.7 R1/R2). Pure parsers only — the live openssl/httpx invocations
are validated on the first real runner scan (the phase is non-fatal by design, so
a bad httpx -irh field name just yields cert-only signals, never a broken scan).

Fixtures are the ACTUAL artifacts captured while proving the method 2026-07-18/19:
the SCI cert (O=Strategic Content Imaging), FortiWeb's cookiesession1, the IIS
origin behind commandcommcentral.com.
"""
import run_heavy as h


def test_cert_parse_first_party_o_and_cns():
    out = (
        "subject=C = US, ST = New Jersey, L = Secaucus, "
        "O = Strategic Content Imaging, CN = *.commandcommcentral.com\n"
        'issuer=C = US, ST = Arizona, O = "GoDaddy.com, Inc.", '
        "CN = Go Daddy Secure Certificate Authority - G2"
    )
    c = h._parse_cert_subject_issuer(out)
    assert c["subject_o"] == "Strategic Content Imaging"      # SCI = Command, first-party
    assert c["subject_cn"] == "*.commandcommcentral.com"
    assert c["issuer_cn"].startswith("Go Daddy")
    # KNOWN LIMITATION: an issuer O with an embedded comma parses partially
    # ("GoDaddy.com"); the phase stores cert_raw alongside as ground truth for P1.
    assert c["issuer_o"] == "GoDaddy.com"


def test_set_cookie_names_only_never_values_dict():
    names = h._extract_set_cookie_names(
        {"Set-Cookie": ["cookiesession1=678A3E;Path=/;Secure;HttpOnly",
                        ".SCI.Session=CfDJ8xyz;Path=/"]})
    assert names == ["cookiesession1", ".SCI.Session"]           # NAMES only
    assert not any(("678A3E" in n or "CfDJ8" in n) for n in names)  # no values leak


def test_set_cookie_names_raw_header_block():
    assert h._extract_set_cookie_names(
        "HTTP/1.1 200\r\nSet-Cookie: incap_ses_9=abc; Path=/\r\nServer: x"
    ) == ["incap_ses_9"]


def test_vendor_header_subset_server_value_plus_presence():
    hh = h._vendor_header_subset(
        {"Server": ["Microsoft-IIS/10.0"], "X-Powered-By": "ASP.NET",
         "Via": "1.1 google", "Content-Type": "text/html"})
    assert hh["server"] == "Microsoft-IIS/10.0"
    assert hh["x-powered-by"] is True and hh["via"] is True      # presence-only
    assert "content-type" not in hh                              # non-vendor header dropped


def test_all_parsers_none_safe():
    assert h._parse_cert_subject_issuer("") == {}
    assert h._extract_set_cookie_names({}) == []
    assert h._extract_set_cookie_names(None) == []
    assert h._vendor_header_subset(None) == {}
