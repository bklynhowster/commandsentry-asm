"""Unit tests for the differential WAF-presence collector (4.7 Cloud Armor Q1–Q8).
The PURE decision is tested in test_waf_differential.py; here we pin the collector's
own pure helpers: the safe request shape (Q4), the response shaping that feeds the
classifier (status/size from curl's sentinel, app-context cookie/token extraction),
and the affirmative 'no enforcing WAF' gate. Live firing + the DB opt-in are validated
end-to-end on a live scan (same as the fwbbot probe)."""
import re  # noqa: E402
import io  # noqa: E402  (relay 533 item 3 prose pin)
import run_heavy as h
from waf_differential import classify_waf_differential
import waf_differential as wd


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


def test_every_fired_class_is_counted():
    """⛔ THE SAFETY PROPERTY, and the direction relay 525 caught: a class we FIRE but do
    not COUNT is invisible to the tally. On commandcommcentral that meant the only two
    vectors FortiWeb refuses were discarded and a demonstrably protected host scored
    waf_present=False. Firing without counting must never be possible."""
    fired = set(c for c, _ in h._WAF_PAYLOADS)
    counted = set(h.INDEPENDENT_CLASSES)
    assert fired <= counted, f"fired but not counted: {sorted(fired - counted)}"


def test_counted_set_is_ahead_of_the_fired_set_pending_item_3():
    """⚠ DELIBERATELY INCOMPLETE, and this test exists so the gap cannot go quiet.

    relay 525 expanded INDEPENDENT_CLASSES to include log4shell-param and ssrf-metadata —
    the two vectors Howie measured FortiWeb actually blocking. The collector does not fire
    them yet: that is 523 item 3 (payload set 3 -> 15 across five surfaces), which is being
    re-specced.

    ⛔ CORRECTED 2026-09-30 (relay 533 item 3). This docstring used to assert, as
    documented fact, that the device stops the canonical traversal form while the
    dot-encoded one slips past — and therefore that the classes we fire arrive in a
    shape it never inspects. That was a vault claim repeated as evidence, and the
    measurement went the other way: canonical `../` and slash-encoded `..%2f` BOTH
    return the FortiWeb block page with the SAME Attack ID 20000008 (relay 528/530),
    so the device demonstrably decodes before it inspects, and the exact wire format
    this collector sends IS blocked.

    ⚠ The retraction PARAPHRASES the old sentence rather than quoting it. A false
    claim quoted verbatim stays searchable in the tree, and the next reader who greps
    for those words finds them without the correction wrapped around them.

    ⚠ What is still genuinely unknown: the vault's claim concerns DOT-encoding
    (`%2e%2e`), and we tested SLASH-encoding. Dot-encoding remains unmeasured — and it is
    a side question, because nothing here ever sends that form.

    ⇒ Until item 3 lands, the expansion is INERT: nothing fires the new classes, so no
    verdict can change. ⛔ When item 3 does land, THIS TEST FAILS and must be deleted
    deliberately — which is the point. A gap someone has to close by hand cannot rot."""
    fired = set(c for c, _ in h._WAF_PAYLOADS)
    counted = set(h.INDEPENDENT_CLASSES)
    assert fired == {"sqli", "xss", "lfi"}
    assert counted - fired == {"log4shell-param", "ssrf-metadata"}


def test_the_finding_sentence_counts_what_we_FIRED_not_what_we_COUNT():
    """⛔ relay 533 item 1, asserted on the EMITTED DESCRIPTION.

    The HIGH finding's own words. While the counted set is ahead of the fired set, a
    sentence built from len(INDEPENDENT_CLASSES) tells the customer FIVE attack
    classes reached their origin when we sent THREE — an overstatement of our own
    evidence, in the one place a customer reads it.

    ⚠ THE FIRST DRAFT OF THIS PIN TESTED THE INGREDIENT AND NOT THE DISH. It
    exercised `_waf_classes_tested_label()` and the two set sizes and never read the
    finding text, so reverting the description f-string back to
    len(INDEPENDENT_CLASSES) SURVIVED it — found by driving the mutation, not by
    re-reading the test. Same shape as the sentence it is guarding: the number moved
    with the constant, the words did not. It now builds a real context, emits the
    real finding, and reads the string a customer would see."""
    ctx = h.HeavyScanContext(descriptor={}, hostname="host.example", asset_id="a1",
                             scan_run_id="s1", queue_id="q1", intensity="heavy")
    h._maybe_emit_no_waf_finding(ctx, {"status": 200},
                                 {"waf_present": False, "blocked": []})
    assert len(ctx.findings) == 1, "the affirmative gate did not emit"
    desc = ctx.findings[0].description

    m = re.search(
        r"all (\d+) independent attack-payload classes tested \(([^)]*)\)", desc)
    assert m, f"the sentence's shape changed; read it and re-pin on purpose:\n{desc}"

    fired = [c for c, _ in h._WAF_PAYLOADS]
    assert m.group(1) == str(len(fired)), (
        f"the finding claims {m.group(1)} classes reached the origin; we fired "
        f"{len(fired)}")
    assert m.group(2) == h._waf_classes_tested_label() == "SQLi, XSS, LFI"

    # while the two sets differ, the sentence must not be quoting the counted one
    assert len(fired) != len(h.INDEPENDENT_CLASSES), (
        "the sets have converged — item 3 landed; re-derive this pin deliberately")
    assert m.group(1) != str(len(h.INDEPENDENT_CLASSES))

    # and no counted-but-unfired class may be named in it
    for c in set(h.INDEPENDENT_CLASSES) - set(fired):
        assert h._WAF_CLASS_LABEL[c] not in desc, (
            f"{c} is named in a sentence about payloads that passed through to the "
            f"origin, and we never sent it")


def test_an_unlabelled_new_class_is_visibly_unfinished_not_silently_wrong():
    """A class added to _WAF_PAYLOADS with no label must render as its uppercase key.
    The failure mode being excluded: it silently inherits a neighbour's name and the
    finding describes an attack we did not send.

    ⚠ THIS TEST WAS VACUOUS ON ITS FIRST DRAFT. It asserted
    `_WAF_CLASS_LABEL.get("xxe", "xxe".upper()) == "XXE"`, which tests dict.get and
    cannot fail whatever the code does — shape ⑩ in doctrine 278, a guard that
    passes without exercising anything. It now drives the real function."""
    saved = h._WAF_PAYLOADS
    try:
        h._WAF_PAYLOADS = saved + (("xxe", "<!ENTITY x SYSTEM 'file:///etc/passwd'>"),)
        label = h._waf_classes_tested_label()
        assert label.endswith("XXE"), label
        assert "XXE" in label
    finally:
        h._WAF_PAYLOADS = saved
    assert h._waf_classes_tested_label() == "SQLi, XSS, LFI"


def test_the_encoding_docstring_states_no_undocumented_bypass_as_fact():
    """⛔ relay 533 item 3, pinned so the sentence cannot come back. The module
    docstring above used to assert, as documented fact, that the device stops the
    canonical traversal form while the dot-encoded one slips past — a vault claim
    repeated as evidence, and the measurement went the other way (both forms
    blocked, same Attack ID 20000008). Paraphrased here for the same reason as
    above: a false claim quoted verbatim stays greppable without its correction.

    Rule 15: nothing we assert may rest on inside knowledge. Prose is where that
    rule gets broken, so prose is what this pins."""
    src = io.open(__file__, encoding="utf-8").read()
    # ⚠ The needle is SPLIT on purpose. Written as one literal it appears in this
    # very file, so the search would always find itself and the pin could never
    # pass — which is exactly what happened on the first draft.
    needle = "documented to " + "block raw"
    assert needle not in src, (
        "the dot-encoding bypass is stated as documented fact again; we measured "
        "the opposite for the form this collector actually sends")


def test_the_live_flag_parse_reads_what_the_scheduled_path_delivers():
    """⛔ relay 533 item 2. `_ACTIVE_PROBE_LIVE` is computed at import, so nothing
    exercised its parse. These are the exact strings scanner.yml can hand it."""
    assert h._env_flag_armed("true") is True      # what cron delivers today
    assert h._env_flag_armed("false") is False     # the repo-var kill switch
    assert h._env_flag_armed(None) is False        # env absent -> dry-run
    assert h._env_flag_armed("") is False
    assert h._env_flag_armed("  TRUE  ") is True   # trimmed, case-folded
    assert h._env_flag_armed("1") is True
    assert h._env_flag_armed("yes") is True


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
    # commandcommcentral.com / FortiWeb. ⚠ CORRECTED THREE TIMES — see
    # test_ccc_fortiweb_blocks_all_five_by_two_mechanisms. The 500s carry a FortiWeb block
    # page (relay 528, measured), so real coverage is 5 of 5.
    base = h._parse_waf_probe("Set-Cookie: cookiesession1=x\nCS_STATUS:200 CS_SIZE:39460",
                              "<title>ccc</title>")
    PAGE = ("<html><title>Web Page Blocked!</title>Client IP: 1.2.3.4 "
            "Attack ID: 20000008 Message ID: 000180461326</html>")
    def resp(cls, code, size, body):
        return {**h._parse_waf_probe(f"CS_STATUS:{code} CS_SIZE:{size}", body), "cls": cls}
    verdict = classify_waf_differential(base, [
        resp("sqli", 500, 39121, PAGE), resp("xss", 500, 39120, PAGE),
        resp("lfi", 500, 39131, PAGE),
        resp("log4shell-param", 403, 15, "denied"), resp("ssrf-metadata", 403, 15, "denied")])
    assert verdict["waf_present"] is True
    assert len(verdict["blocked"]) == 5
    assert verdict["evidence_class"] == "presence_only"    # never names FortiWeb here (Q3)
    assert h._no_waf_proven(base, verdict) is False


def test_parse_sets_block_tell_from_the_body():
    PAGE = ("<title>Web Page Blocked!</title> Attack ID: 20000008")
    r = h._parse_waf_probe("CS_STATUS:500 CS_SIZE:39121", PAGE)
    assert r["block_tell"] == "FortiWeb"
    # FAILING DIRECTION: an ordinary app error page must NOT be tagged
    r2 = h._parse_waf_probe("CS_STATUS:500 CS_SIZE:39121", "<title>Server Error</title>")
    assert r2["block_tell"] == ""


def test_block_tell_needs_two_markers_not_one():
    # "blocked" alone is ordinary app copy and must never be enough
    assert h._waf_block_page_tell("<html>your account is blocked</html>") == ""
    assert h._waf_block_page_tell("<html>Web Page Blocked!</html>") == ""      # no incident id
    assert h._waf_block_page_tell("<html>Web Page Blocked! Attack ID: 7</html>") == "FortiWeb"


# ── relay 516: capture the deny, keep the verdict identical ──────────────────
# The four classifier keys are untouched and neither _payload_blocked nor
# classify_waf_differential iterates keys, so extra fields CANNOT move a verdict.
# That is the claim; rule 14 says prove it, so the proof is below and it carries a
# vacuity floor (two fixtures that are actually different).

_DENY_STDOUT = (
    "HTTP/2 403\n"
    "server: AkamaiGHost\n"
    "cf-ray: 8d2f11aabbcc-EWR\n"
    "x-azure-ref: 20260929T120000Z-abc123\n"
    "set-cookie: SESSIONID=s3cr3t-do-not-store; Path=/; HttpOnly\n"
    "set-cookie: ak_bmsc=AAAA-REAL-VALUE-BBBB; Domain=.example\n"
    "\nCS_STATUS:403 CS_SIZE:512 CS_TIME:0.081 CS_CONNECT:0.030\n"
)


def test_timing_sentinel_is_requested():
    args = h._waf_probe_curl_args("host.example", "q1", "x", False, "/tmp/b", "vpn", "")
    w = args[args.index("-w") + 1]
    assert "%{time_total}" in w and "%{time_connect}" in w
    assert "%{http_code}" in w and "%{size_download}" in w   # the originals survive


def test_parse_extracts_timing():
    r = h._parse_waf_probe(_DENY_STDOUT, "body")
    assert r["time_total"] == 0.081 and r["time_connect"] == 0.030


def test_parse_timing_absent_is_none_not_an_exception():
    # FAILING DIRECTION: an old-shape sentinel (no CS_TIME) must not raise.
    r = h._parse_waf_probe("\nCS_STATUS:200 CS_SIZE:10\n", "body")
    assert r["time_total"] is None and r["time_connect"] is None
    assert r["status"] == 200 and r["size"] == 10


def test_capture_is_off_by_default():
    r = h._parse_waf_probe(_DENY_STDOUT, "<html>deny</html>")
    assert "raw_headers" not in r and "body_head" not in r


def test_capture_keeps_the_vendor_self_naming_tells():
    r = h._parse_waf_probe(_DENY_STDOUT, "<html>deny</html>", capture=True)
    raw = r["raw_headers"].lower()
    for tell in ("server: akamaighost", "cf-ray:", "x-azure-ref:"):
        assert tell in raw, f"lost the tell {tell!r} — this capture exists for exactly these"
    assert r["body_head"] == "<html>deny</html>"


def test_capture_never_stores_a_cookie_value():
    # FAILING DIRECTION FIRST: the secrets must be ABSENT, names PRESENT.
    r = h._parse_waf_probe(_DENY_STDOUT, "b", capture=True)
    raw = r["raw_headers"]
    assert "s3cr3t-do-not-store" not in raw
    assert "AAAA-REAL-VALUE-BBBB" not in raw
    assert "SESSIONID=<redacted>" in raw and "ak_bmsc=<redacted>" in raw
    assert h._waf_cookie_names(_DENY_STDOUT) == {"sessionid", "ak_bmsc"}   # gate 5 unaffected


def test_capture_strips_the_curl_sentinel_line():
    r = h._parse_waf_probe(_DENY_STDOUT, "b", capture=True)
    assert "CS_STATUS:" not in r["raw_headers"]


def test_capture_truncates_oversized_body_and_headers():
    """⚠ Bound, not an exact length. Since relay 531 the body capture is head + tail around
    an elision marker, so it lands a few bytes over the raw cap — the property that matters
    is that it is BOUNDED and that both ends survive, not that it equals one number."""
    big_body = "A" * (h._WAF_CAPTURE_BODY_MAX * 3) + "TAILMARK"
    big_hdrs = "x-pad: " + "B" * (h._WAF_CAPTURE_HEADERS_MAX * 3) + "\nCS_STATUS:403 CS_SIZE:1\n"
    r = h._parse_waf_probe(big_hdrs, big_body, capture=True)
    assert len(r["body_head"]) <= h._WAF_CAPTURE_BODY_MAX + 64   # bounded
    assert len(big_body) > len(r["body_head"])                   # the cap actually bit
    assert r["body_head"].startswith("A")                        # head kept
    assert r["body_head"].endswith("TAILMARK")                   # ⭐ and the TAIL kept —
    assert len(r["raw_headers"]) == h._WAF_CAPTURE_HEADERS_MAX


def test_capture_on_empty_response_is_empty_not_an_exception():
    r = h._parse_waf_probe("", "", capture=True)
    assert r["raw_headers"] == "" and r["body_head"] == ""
    assert r["status"] == 0 and r["size"] == 0


def _fixture_pair():
    """One fixture set in the OLD shape (4 keys) and the NEW shape (4 keys + capture)."""
    base_old = {"status": 200, "size": 9000, "tokens": {"acme", "portal"}, "headers": {"acme_sess"}}
    pay_old = [
        {"cls": "sqli", "status": 403, "size": 400, "tokens": set(), "headers": set()},
        {"cls": "xss", "status": 403, "size": 410, "tokens": set(), "headers": set()},
        {"cls": "lfi", "status": 200, "size": 9000, "tokens": {"acme"}, "headers": {"acme_sess"}},
    ]
    extra = {"time_total": 0.08, "time_connect": 0.03,
             "raw_headers": "server: AkamaiGHost\ncf-ray: 8d2f", "body_head": "<html>deny</html>"}
    base_new = dict(base_old, time_total=0.4, time_connect=0.05)
    pay_new = [dict(p, **extra) for p in pay_old]
    return base_old, pay_old, base_new, pay_new


def test_extra_capture_fields_cannot_move_the_verdict():
    base_old, pay_old, base_new, pay_new = _fixture_pair()

    # VACUITY FLOOR — the two shapes must genuinely differ, or this proves nothing.
    assert pay_new[0] != pay_old[0], "fixtures identical: the comparison below would be free"
    assert set(pay_new[0]) - set(pay_old[0]) == {"time_total", "time_connect",
                                                 "raw_headers", "body_head"}

    old = classify_waf_differential(base_old, pay_old)
    new = classify_waf_differential(base_new, pay_new)
    assert old == new, f"capture moved the verdict: {old} != {new}"
    assert old["waf_present"] is True and old["blocked"] == ["sqli", "xss"]


def test_extra_capture_fields_cannot_move_a_per_payload_gate():
    base_old, pay_old, base_new, pay_new = _fixture_pair()
    for p_old, p_new in zip(pay_old, pay_new):
        assert wd._payload_blocked(base_old, p_old) == wd._payload_blocked(base_new, p_new), \
            f"gate moved for {p_old['cls']}"


# ── relay 531: the block page as the HOST serves it, not as a fixture wishes ──
# ⛔ Gate 2b shipped inert. _waf_block_page_tell searched body[:20000]; FortiWeb's live page
# is 39,638 B with a ~38 KB inline base64 logo at offset 579, pushing its own markers to
# 39,338 and 39,553 — the last 300 bytes. 44 tests passed while the host still scored
# waf_present=False, because every fixture put the markers at offset ~10.
# ⇒ A fixture that cannot fail the way the host fails is not a pin.

def _fortiweb_page_as_served() -> str:
    """The measured layout: inline logo first, vendor text last."""
    return ("<html><head><img src=\"data:image/png;base64," + "A" * 38600 + "\">"
            + " " * 100 + "Web Page Blocked!" + " " * 190
            + "Client IP: 108.27.160.47 Attack ID: 20000008 "
            + "Message ID: 000180461326</html>")


def test_block_tell_is_found_past_any_fixed_window():
    page = _fortiweb_page_as_served()
    # the fixture must actually have the property that broke it
    assert page.find("Web Page Blocked!") > 20000, "fixture too small to reproduce the bug"
    assert "web page blocked" not in page[:20000].lower()   # the OLD window sees nothing
    assert h._waf_block_page_tell(page) == "FortiWeb"       # the new search does


def test_captured_evidence_contains_the_markers_not_a_png_fragment():
    """⛔ body_head was body[:2048] — on this page, bytes 579-2048 of a base64 logo. The
    capture exists to EVIDENCE the verdict; a fragment of an image evidences nothing."""
    r = h._parse_waf_probe("CS_STATUS:500 CS_SIZE:39638", _fortiweb_page_as_served(),
                           capture=True)
    assert "Web Page Blocked!" in r["body_head"]
    assert "Attack ID" in r["body_head"]
    assert len(r["body_head"]) <= h._WAF_CAPTURE_BODY_MAX + 64   # still bounded
    assert "AAAAAAAAAA" not in r["body_head"]                    # the blob did not survive


def test_inline_blob_stripping_keeps_text_and_drops_the_blob():
    body = "before <img src=\"data:image/png;base64," + "Z" * 2000 + "\"> after"
    out = h._waf_strip_inline_blobs(body)
    assert "before" in out and "after" in out
    assert "Z" * 100 not in out
    # FAILING DIRECTION: a short base64-looking string is NOT stripped
    short = "data:image/png;base64,ZZZZ"
    assert h._waf_strip_inline_blobs(short) == short


def test_end_to_end_the_served_page_classifies_as_blocked():
    """The whole chain on the page as served: parse -> block_tell -> verdict."""
    base = h._parse_waf_probe("Set-Cookie: cookiesession1=x\nCS_STATUS:200 CS_SIZE:39460",
                              "<title>ccc</title>")
    page = _fortiweb_page_as_served()
    mk = lambda c: {**h._parse_waf_probe(f"CS_STATUS:500 CS_SIZE:39638", page), "cls": c}
    verdict = classify_waf_differential(base, [mk("sqli"), mk("xss"), mk("lfi")])
    assert verdict["waf_present"] is True
    assert set(verdict["blocked"]) == {"sqli", "xss", "lfi"}
