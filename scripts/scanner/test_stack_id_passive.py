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
         "Via": "1.1 google", "Content-Type": "text/html",
         "CF-Ray": "abc123-SJC", "X-Amz-Cf-Id": "opaque", "Cache-Control": "max-age=0"})
    assert hh["server"] == "Microsoft-IIS/10.0"
    assert hh["via"] == "1.1 google"                             # 4.7 cloud-edge: Via VALUE kept (Google edge tell)
    assert hh["x-powered-by"] is True                           # generic x- header -> presence-only
    assert hh["cf-ray"] is True and hh["x-amz-cf-id"] is True    # cloud-edge markers captured (value-free presence)
    assert hh["cache-control"] is True                          # caching evidence -> CDN tie-break
    assert "content-type" not in hh                             # non-vendor header still dropped


def test_all_parsers_none_safe():
    assert h._parse_cert_subject_issuer("") == {}
    assert h._extract_set_cookie_names({}) == []
    assert h._extract_set_cookie_names(None) == []
    assert h._vendor_header_subset(None) == {}


# --- curl -sSI raw-header path (the P0-validation fix, heavy #1061) ------------
# Fixture mirrors the real commandcommcentral.com HEAD response we captured: a
# blank Server (WAF strip), several Set-Cookie incl. the FortiWeb cookiesession1.
_CURL_HEAD = (
    "HTTP/1.1 200 OK\r\n"
    "Cache-Control: no-cache,no-store\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Server: \r\n"
    "Set-Cookie: .AspNetCore.Antiforgery.1vbe=CfDJ8x; path=/; secure; httponly\r\n"
    "Set-Cookie: .SCI.Session=CfDJ8y; path=/; secure; httponly\r\n"
    "X-Frame-Options: DENY\r\n"
    "Set-Cookie: CCC=rs2|alwil; path=/; HttpOnly; Secure\r\n"
    "Set-Cookie: cookiesession1=678A3E0DA665D8473E81B59D15A638BF;Path=/;Secure;HttpOnly\r\n"
)


def test_parse_raw_headers_collects_multi_set_cookie():
    hd = h._parse_raw_headers(_CURL_HEAD)
    assert isinstance(hd["set-cookie"], list) and len(hd["set-cookie"]) == 4
    assert hd.get("x-frame-options") == "DENY"


def test_curl_path_captures_fortiweb_cookie_name():
    # The whole point of the fix: cookiesession1 (FortiWeb) must now be captured
    # (heavy #1061 got cookies=0 via httpx; curl -sSI is the proven method).
    names = h._extract_set_cookie_names(h._parse_raw_headers(_CURL_HEAD))
    assert "cookiesession1" in names
    assert names == [".AspNetCore.Antiforgery.1vbe", ".SCI.Session", "CCC", "cookiesession1"]
    assert not any(("678A3E" in n or "CfDJ8" in n) for n in names)   # names only, no values


def test_parse_raw_headers_keeps_last_response_block():
    hd = h._parse_raw_headers(
        "HTTP/1.1 301 Moved\r\nLocation: https://x/\r\n\r\nHTTP/1.1 200 OK\r\nServer: IIS\r\n")
    assert hd.get("server") == "IIS" and "location" not in hd
