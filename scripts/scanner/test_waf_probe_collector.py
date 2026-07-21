"""Unit tests for the differential WAF-presence collector (4.7 Cloud Armor Q1–Q8).
The PURE decision is tested in test_waf_differential.py; here we pin the collector's
own pure helpers: the safe request shape (Q4), the response shaping that feeds the
classifier (status/size from curl's sentinel, app-context cookie/token extraction),
and the affirmative 'no enforcing WAF' gate. Live firing + the DB opt-in are validated
end-to-end on a live scan (same as the fwbbot probe)."""
import run_heavy as h
from waf_differential import classify_waf_differential


def test_dry_run_is_the_default():
    # shares the fwbbot rig — ships DRY-RUN (fires nothing) unless ACTIVE_PROBE_LIVE is set.
    assert h._ACTIVE_PROBE_LIVE is False


# ── 4.7 Q4: the safe request shape ───────────────────────────────────────────
def test_request_is_get_detect_only_no_post_no_redirect():
    args = h._waf_probe_curl_args("host.example", "qab123", "1' OR '1'='1", False,
                                  "/tmp/b", "vpn", "")
    assert args[0] == "curl"
    assert "-I" not in args                       # GET, not HEAD
    assert "-L" not in args                       # detect-only: never follow the redirect
    assert "-d" not in args and "--data" not in args and "-X" not in args   # GET-only, no POST
    assert args[args.index("-o") + 1] == "/tmp/b"  # body captured (needed for size/tokens)
    assert "-D" in args                            # headers dumped (Set-Cookie + any redirect)


def test_self_identifying_probe_header_and_no_browser_accepts():
    args = h._waf_probe_curl_args("host.example", "q1", "x", False, "/tmp/b", "vpn", "")
    hdr_vals = [args[i + 1] for i, a in enumerate(args) if a == "-H"]
    assert "X-CS-Stack-ID-Probe: 1" in hdr_vals    # Q4 self-identifying marker (our own traffic)
    assert "Accept:" in hdr_vals and "Accept-Language:" in hdr_vals and "Accept-Encoding:" in hdr_vals


def test_status_size_sentinel_is_requested():
    args = h._waf_probe_curl_args("h", "q1", "x", False, "/tmp/b", "vpn", "")
    w = args[args.index("-w") + 1]
    assert "CS_STATUS:%{http_code}" in w and "CS_SIZE:%{size_download}" in w


def test_single_param_and_specials_url_encoded():
    args = h._waf_probe_curl_args("host.example", "qXY", "1' OR '1'='1", False,
                                  "/tmp/b", "vpn", "")
    url = args[-1]
    assert url.startswith("https://host.example/?qXY=")   # exactly one query param
    assert "%27" in url                                    # the quote is encoded
    assert "'" not in url and " " not in url               # no raw specials survive into the URL


def test_lfi_preencoded_is_not_double_encoded():
    # LFI arrives pre-percent-encoded per Q4 — sending it must NOT turn %2f into %252f.
    args = h._waf_probe_curl_args("h", "q1", "..%2f..%2f..%2fetc%2fpasswd", True,
                                  "/tmp/b", "vpn", "")
    url = args[-1]
    assert url.endswith("=..%2f..%2f..%2fetc%2fpasswd")
    assert "%252f" not in url


def test_payload_classes_are_exactly_the_independent_set():
    # the collector must fire precisely the classes the classifier scores (SQLi/XSS/LFI),
    # or the >=2-independent-class bar silently can't be met.
    assert tuple(c for c, _ in h._WAF_PAYLOADS) == h.INDEPENDENT_CLASSES


# ── egress A/B toggle (per-asset, 4.7 Q1) — same contract as the fwbbot probe ──
def test_egress_direct_with_interface_binds_it():
    args = h._waf_probe_curl_args("h", "q", "v", False, "/tmp/b", "direct", "eth0")
    assert "--interface" in args and args[args.index("--interface") + 1] == "eth0"


def test_egress_vpn_never_binds_interface():
    args = h._waf_probe_curl_args("h", "q", "v", False, "/tmp/b", "vpn", "eth0")
    assert "--interface" not in args


# ── response shaping: status/size from curl's own truth, not a header re-parse ─
def test_parse_status_size_from_sentinel():
    stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\nCS_STATUS:200 CS_SIZE:2991"
    d = h._parse_waf_probe(stdout, "<html><title>x</title></html>")
    assert d["status"] == 200 and d["size"] == 2991


def test_parse_size_falls_back_to_body_len_without_sentinel():
    d = h._parse_waf_probe("no sentinel present", "abcde")
    assert d["status"] == 0 and d["size"] == 5


def test_cookie_names_lowercased_from_set_cookie():
    stdout = ("HTTP/1.1 200 OK\r\nSet-Cookie: cookiesession1=abc; Path=/\r\n"
              "Set-Cookie: .SCI.session=xyz; HttpOnly\r\n\nCS_STATUS:200 CS_SIZE:10")
    d = h._parse_waf_probe(stdout, "")
    assert d["headers"] == {"cookiesession1", ".sci.session"}


def test_body_tokens_capture_title_and_class():
    body = ('<html><head><title>ACME Portal Login</title></head>'
            '<body class="app-home main-wrap"></body></html>')
    toks = h._waf_body_tokens(body)
    assert {"t:acme", "t:portal", "t:login"} <= toks
    assert {"c:app-home", "c:main-wrap"} <= toks


def test_body_tokens_are_capped():
    body = "".join(f'<div class="uniqcls{i:03d}">' for i in range(60))
    toks = h._waf_body_tokens(body)
    assert len(toks) == h._WAF_TOKEN_CAP          # stops at the cap, doesn't grow unbounded


def test_app_deny_shares_tokens_edge_deny_does_not():
    # the Q2 gate-4 tell: an app-rendered 403 carries the app's title/classes; a generic
    # edge deny carries none. This is exactly what distinguishes them in the classifier.
    base = h._parse_waf_probe("CS_STATUS:200 CS_SIZE:5000",
                              '<title>ACME Portal</title><div class="acme-nav">')
    app_403 = h._parse_waf_probe("CS_STATUS:403 CS_SIZE:4800",
                                 '<title>ACME Portal</title><div class="acme-nav">Access denied')
    edge_403 = h._parse_waf_probe("CS_STATUS:403 CS_SIZE:120",
                                  "<html><body>403 Forbidden</body></html>")
    assert base["tokens"] & app_403["tokens"]         # app deny overlaps the app fingerprint
    assert not (base["tokens"] & edge_403["tokens"])  # edge deny overlaps nothing


# ── the affirmative 'no enforcing WAF' gate ──────────────────────────────────
def test_no_waf_proven_clean_baseline_zero_blocked():
    assert h._no_waf_proven({"status": 200}, {"waf_present": False, "blocked": []}) is True


def test_no_waf_not_proven_when_waf_present():
    assert h._no_waf_proven({"status": 200},
                            {"waf_present": True, "blocked": ["sqli", "xss"]}) is False


def test_no_waf_not_proven_on_single_class_block():
    # one class blocking is an app input-validator, not proof of "no WAF" AND not a WAF.
    assert h._no_waf_proven({"status": 200}, {"waf_present": False, "blocked": ["sqli"]}) is False


def test_no_waf_not_proven_on_non_2xx_baseline():
    # a dead/erroring origin can't prove anything about a WAF (inconclusive, not "no WAF").
    assert h._no_waf_proven({"status": 504}, {"waf_present": False, "blocked": []}) is False


# ── end-to-end: the collector's shaping drives the classifier on the REAL fixtures ─
def test_demo_negative_shapes_to_no_waf_finding():
    # demo.prodexlabs.com (2026-07-20): benign + every class byte-identical 200/2991 -> no
    # WAF, and the affirmative 'no enforcing WAF' gate fires (the PCI 6.4.2 / SC-7 HIGH).
    def probe(status, size):
        return h._parse_waf_probe(f"CS_STATUS:{status} CS_SIZE:{size}", "<title>demo</title>")
    base = probe(200, 2991)
    payloads = [{**probe(200, 2991), "cls": c} for c in h.INDEPENDENT_CLASSES]
    verdict = classify_waf_differential(base, payloads)
    assert verdict["waf_present"] is False
    assert h._no_waf_proven(base, verdict) is True


def test_ccc_positive_shapes_to_presence_not_no_waf():
    # commandcommcentral.com / FortiWeb (2026-07-20): benign 200/39460, attacks 500/39116
    # -> WAF present (presence-only), and the 'no enforcing WAF' gate correctly stays shut.
    base = h._parse_waf_probe("Set-Cookie: cookiesession1=x\nCS_STATUS:200 CS_SIZE:39460",
                              "<title>ccc</title>")
    edge = lambda c: {**h._parse_waf_probe("CS_STATUS:500 CS_SIZE:39116", "<html>500</html>"),
                      "cls": c}
    verdict = classify_waf_differential(base, [edge("sqli"), edge("xss")])
    assert verdict["waf_present"] is True
    assert verdict["evidence_class"] == "presence_only"    # never names FortiWeb here (Q3)
    assert h._no_waf_proven(base, verdict) is False
