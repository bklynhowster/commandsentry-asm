"""Tests for the catch-all false-positive fixes (Fix A + Fix B).

Spec: prodexsentry-asm/CATCHALL_FP_FIX_SPEC.md (4.7-reviewed, verdict REVISE;
this file is 4.7 must-fix #6 / Hole 9, and the biggest-risk anchor).

What these lock:
  - Fix A (run_light.check_common_paths) VERIFY-THEN-SUPPRESS ordering — a
    HIGH content-marker match ALWAYS wins over catch-all suppression, so a
    real /.env is never silently eaten (anchor commit 59ad6a13). The
    load-bearing case is test_resolve_disposition_high_marker_wins_over_catchall.
  - Fix A catch-all detection (_is_catchall): two-probe, both-2xx, hash-match.
  - Fix A per-file secret markers (verify_secret_content): a bare 200 serving
    HTML is not a leak; the body must carry the secret's shape.
  - Fix B (run_medium) calibration retry + FAIL-CLOSED: retry-exhaustion must
    surface calib_ok=False so the caller SKIPS ffuf (marks it degraded), never
    silently falls through to per-path emit (Hole 5 — the whole point of Fix B).

Run:  pytest scripts/scanner/test_catchall_fp.py -v
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import run_light as L  # noqa: E402
import run_medium as M  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════
# Fix A — _is_catchall (pure two-probe catch-all decision, hole 2)
# ═══════════════════════════════════════════════════════════════════════

def test_is_catchall_both_2xx_same_hash_is_true():
    assert L._is_catchall((200, 200), ("hA", "hA")) is True


def test_is_catchall_2xx_variants_204_206_count():
    # 204/206 are 2xx too — a catch-all could answer with either.
    assert L._is_catchall((204, 206), ("hA", "hA")) is True


def test_is_catchall_different_hashes_is_false():
    # Both 200 but bodies differ → host discriminates → NOT a catch-all.
    assert L._is_catchall((200, 200), ("hA", "hB")) is False


def test_is_catchall_one_non_2xx_is_false():
    # A 404 on one probe means the host DOES 404 random paths → discriminates.
    assert L._is_catchall((200, 404), ("hA", "hA")) is False


def test_is_catchall_redirect_is_not_2xx_is_false():
    assert L._is_catchall((301, 301), ("hA", "hA")) is False


# ═══════════════════════════════════════════════════════════════════════
# Fix A — verify_secret_content (per-file markers + Content-Type gate)
# A 200 is NOT a leak: the body must carry the real secret's shape AND not be
# app-rendered HTML. Returns a verdict (VERIFY_SECRET / VERIFY_APP_HTML /
# VERIFY_NO_MATCH) since the 2026-07-21 Content-Type discriminator (Obsidian
# 152). A text/plain body carrying the marker is a real secret → VERIFY_SECRET.
# ═══════════════════════════════════════════════════════════════════════

def test_verify_env_two_assignment_lines_is_secret():
    assert L.verify_secret_content(
        "/.env", "API_KEY=abc\nDB_URL=xyz", "text/plain") == L.VERIFY_SECRET


def test_verify_env_html_body_is_no_match():
    # The catch-all SPA index served for /.env — marker fails on the HTML.
    assert L.verify_secret_content(
        "/.env", "<html>Loading…</html>", "text/html") == L.VERIFY_NO_MATCH


def test_verify_env_single_line_is_no_match():
    # >= 2 assignment lines required (hole 4): a lone `foo=bar` false-positives
    # on random HTML/JS.
    assert L.verify_secret_content("/.env", "single_var=lonely") == L.VERIFY_NO_MATCH


def test_verify_env_ignores_comment_lines():
    # Comments don't count toward the 2-line floor, but two real vars do.
    assert L.verify_secret_content(
        "/.env", "# comment\nAPI_KEY=abc\nDB=1", "text/plain") == L.VERIFY_SECRET


def test_verify_git_config_core_marker_is_secret():
    assert L.verify_secret_content(
        "/.git/config", "[core]\n\trepositoryformatversion = 0",
        "text/plain") == L.VERIFY_SECRET


def test_verify_git_config_html_is_no_match():
    assert L.verify_secret_content(
        "/.git/config", "<html>nope</html>", "text/html") == L.VERIFY_NO_MATCH


def test_verify_git_head_ref_is_secret():
    assert L.verify_secret_content(
        "/.git/HEAD", "ref: refs/heads/main", "text/plain") == L.VERIFY_SECRET


def test_verify_git_head_detached_sha_is_secret():
    assert L.verify_secret_content(
        "/.git/HEAD", "0123456789abcdef0123456789abcdef01234567\n",
        "text/plain") == L.VERIFY_SECRET


def test_verify_git_head_html_is_no_match():
    assert L.verify_secret_content(
        "/.git/HEAD", "<html>404</html>", "text/html") == L.VERIFY_NO_MATCH


def test_verify_wpconfig_bak_db_marker_is_secret():
    assert L.verify_secret_content(
        "/wp-config.php.bak", "<?php define('DB_PASSWORD', 'hunter2');",
        "text/plain") == L.VERIFY_SECRET


def test_verify_wpconfig_bak_bare_php_is_no_match():
    # A bare <?php is table-stakes on any PHP host; require DB_* (hole 6).
    assert L.verify_secret_content(
        "/wp-config.php.bak", "<?php echo 1; ?>") == L.VERIFY_NO_MATCH


def test_verify_unknown_path_never_matches():
    # Path not in the marker table → cannot be a verified HIGH.
    assert L.verify_secret_content(
        "/robots.txt", "API_KEY=abc\nB=2", "text/plain") == L.VERIFY_NO_MATCH


def test_verify_empty_body_is_no_match():
    assert L.verify_secret_content("/.env", "", "text/plain") == L.VERIFY_NO_MATCH


# ═══════════════════════════════════════════════════════════════════════
# Content-Type discriminator (4.7 rulings 2026-07-21, Obsidian 152)
# _is_app_html two-signal gate + the verify APP_HTML / SECRET split. A real
# dotfile secret is served text/plain — never as app HTML; a text/html /.env is
# the SPA / error page, not a leak. TWO-SIGNAL so a misconfigured server serving
# a real .env as text/html (non-HTML body) still fires HIGH.
# ═══════════════════════════════════════════════════════════════════════

# The observed FP body, reconstructed: an SPA index that (a) opens with an HTML
# token and (b) carries >=2 line-start `word=` lines, so the OLD marker-only
# gate wrongly fired HIGH. Regression fixture for tour.prodexlabs.com /.env
# (confirmed FALSE POSITIVE by external probe, 2026-07-21).
_FLAGSHIP_SPA_INDEX = (
    "<!DOCTYPE html>\n"
    "<html><head><script>\n"
    "window_env=production\n"
    "build_hash=9f3a21c\n"
    "</script></head><body><div id=\"app\">PRODEX</div></body></html>"
)


def test_is_app_html_text_html_with_html_body_is_true():
    assert L._is_app_html("text/html; charset=utf-8", "<!DOCTYPE html><html>…") is True


def test_is_app_html_text_html_with_env_body_is_false():
    # LOAD-BEARING (ruling 1 correction): a real .env served with a wrong
    # text/html Content-Type has a non-HTML body shape → NOT app HTML → stays a
    # secret. Deleting this test must never merge.
    assert L._is_app_html("text/html", "API_KEY=abc\nDB_URL=xyz") is False


def test_is_app_html_plain_ctype_is_false():
    # Only app-markup content-types can be app HTML; text/plain never is.
    assert L._is_app_html("text/plain", "<!DOCTYPE html>") is False


def test_is_app_html_json_ctype_is_false():
    # ruling 3: application/json is NEVER downgraded (firebase.json-style leaks).
    assert L._is_app_html("application/json", "<!DOCTYPE html>") is False


def test_is_app_html_none_ctype_is_false():
    assert L._is_app_html(None, "<!DOCTYPE html>") is False


def test_is_app_html_xhtml_is_true():
    assert L._is_app_html("application/xhtml+xml", "<html><head></head></html>") is True


def test_verify_env_text_html_spa_is_app_html():
    # The exact observed FP: marker matches (>=2 word= lines) BUT text/html +
    # HTML body → APP_HTML, so the caller downgrades to INFO instead of HIGH.
    assert L.verify_secret_content(
        "/.env", _FLAGSHIP_SPA_INDEX, "text/html; charset=utf-8") == L.VERIFY_APP_HTML


def test_verify_env_misconfig_html_ctype_plain_body_stays_secret():
    # LOAD-BEARING (ruling 1 + Q6): server misconfigured to serve the REAL .env
    # as text/html; body is KEY=value (not HTML-shaped) → still a secret → HIGH.
    assert L.verify_secret_content(
        "/.env", "API_KEY=abc\nDB_URL=xyz", "text/html") == L.VERIFY_SECRET


def test_verify_env_missing_ctype_is_secret():
    # Server omits Content-Type entirely (None) → cannot be app HTML → secret.
    assert L.verify_secret_content(
        "/.env", "API_KEY=abc\nDB=1", None) == L.VERIFY_SECRET


def test_verify_env_unknown_ctype_not_downgraded():
    # ruling 3: an unusual Content-Type is NOT app-markup → not suppressed →
    # stays a secret (emitted HIGH with the ctype noted in evidence).
    assert L.verify_secret_content(
        "/.env", "API_KEY=abc\nDB=1", "application/vnd.custom") == L.VERIFY_SECRET


def test_flagship_spa_env_probe_regression():
    """Regression for the observed tour.prodexlabs.com /.env FP (2026-07-21):
    catch-all SPA served text/html for /.env. Must resolve APP_HTML (→ INFO),
    never SECRET (→ HIGH)."""
    assert L.verify_secret_content(
        "/.env", _FLAGSHIP_SPA_INDEX, "text/html") == L.VERIFY_APP_HTML


def test_is_known_secret_ctype_taxonomy():
    # ruling 3 allow-list: known secret types + None are "known"; app-markup and
    # unusual types are not (drives the unusual-ctype evidence note).
    assert L._is_known_secret_ctype("text/plain") is True
    assert L._is_known_secret_ctype("application/json") is True
    assert L._is_known_secret_ctype(None) is True
    assert L._is_known_secret_ctype("text/html") is False
    assert L._is_known_secret_ctype("application/vnd.custom") is False


# ═══════════════════════════════════════════════════════════════════════
# Fix A — resolve_path_disposition (VERIFY-THEN-SUPPRESS ordering)
# 4.7 BIGGEST RISK: this ordering getting inverted. Anchored here. Now takes a
# verify verdict (VERIFY_SECRET / VERIFY_APP_HTML / VERIFY_NO_MATCH) instead of
# a bool, since the Content-Type discriminator (Obsidian 152).
# ═══════════════════════════════════════════════════════════════════════

def test_resolve_disposition_high_secret_wins_over_catchall():
    """THE anchor (4.7 biggest-risk / commit 59ad6a13). On a catch-all host
    (matches_baseline=True) a CONFIRMED HIGH secret STILL emits HIGH — verify
    beats suppress. If this ever returns 'SUPPRESS', a real /.env is being
    eaten and the 59ad6a13 regression is back."""
    assert L.resolve_path_disposition("HIGH", L.VERIFY_SECRET,
                                      matches_baseline=True) == "HIGH"


def test_resolve_disposition_high_secret_no_baseline_is_high():
    assert L.resolve_path_disposition("HIGH", L.VERIFY_SECRET,
                                      matches_baseline=False) == "HIGH"


def test_resolve_disposition_high_app_html_is_info_even_on_catchall():
    # ruling 5: marker matched but body is the app page → INFO_APP_HTML (an
    # auditable downgrade), NOT silent SUPPRESS — even on a catch-all baseline.
    assert L.resolve_path_disposition("HIGH", L.VERIFY_APP_HTML,
                                      matches_baseline=True) == "INFO_APP_HTML"
    assert L.resolve_path_disposition("HIGH", L.VERIFY_APP_HTML,
                                      matches_baseline=False) == "INFO_APP_HTML"


def test_resolve_disposition_high_no_marker_on_catchall_suppresses():
    assert L.resolve_path_disposition("HIGH", L.VERIFY_NO_MATCH,
                                      matches_baseline=True) == "SUPPRESS"


def test_resolve_disposition_high_no_marker_no_baseline_is_info():
    # 2xx but body isn't the secret shape and isn't the catch-all page →
    # INFO for manual review, NOT HIGH.
    assert L.resolve_path_disposition("HIGH", L.VERIFY_NO_MATCH,
                                      matches_baseline=False) == "INFO"


def test_resolve_disposition_nonhigh_on_catchall_suppresses():
    assert L.resolve_path_disposition("MODERATE", L.VERIFY_NO_MATCH,
                                      matches_baseline=True) == "SUPPRESS"


def test_resolve_disposition_nonhigh_no_baseline_emits():
    assert L.resolve_path_disposition("INFO", L.VERIFY_NO_MATCH,
                                      matches_baseline=False) == "EMIT"


# ═══════════════════════════════════════════════════════════════════════
# Fix B — _probe_calibration_path retry (hole 5 half 1: transient blip recovers)
# ═══════════════════════════════════════════════════════════════════════

def _seq_probe(results):
    """Stub for _probe_calibration_path_once yielding `results` — now
    (status, loc, size) 3-tuples (edit #2) — in order, + a call counter."""
    calls = {"n": 0}

    def _stub(ctx):
        i = calls["n"]
        calls["n"] += 1
        return results[i]
    return _stub, calls


def test_calib_retry_recovers_after_two_transient_misses(monkeypatch):
    # [0, 0, 200] → the retry rides through two status-0 blips and returns 200.
    stub, calls = _seq_probe([(0, None, None), (0, None, None), (200, None, 870)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc, size = M._probe_calibration_path(object())
    assert (status, size) == (200, 870)   # size carried through the retry
    assert calls["n"] == 3


def test_calib_retry_exhaustion_returns_zero(monkeypatch):
    # [0, 0, 0] → all attempts miss → (0, None, None). Caller treats as
    # calibration failure, not "no catch-all".
    stub, calls = _seq_probe([(0, None, None), (0, None, None), (0, None, None)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc, size = M._probe_calibration_path(object())
    assert status == 0
    assert calls["n"] == M.CALIB_PROBE_ATTEMPTS  # exhausted the full budget


def test_calib_retry_first_hit_no_wasted_attempts(monkeypatch):
    # A clean first probe returns immediately — no retry, no sleep.
    stub, calls = _seq_probe([(403, None, 500)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc, size = M._probe_calibration_path(object())
    assert (status, calls["n"]) == (403, 1)


# ═══════════════════════════════════════════════════════════════════════
# detect_ffuf_catchall 4-tuple: calib_ok (Fix B) + baseline size (edit #2)
# ═══════════════════════════════════════════════════════════════════════

def _two_probe(first, second):
    """Stub _probe_calibration_path (the RETRYING wrapper) to return `first`
    then `second` — (status, loc, size) 3-tuples — on successive calls."""
    seq = [first, second]
    calls = {"n": 0}

    def _stub(ctx):
        r = seq[calls["n"]]
        calls["n"] += 1
        return r
    return _stub


def test_detect_ffuf_catchall_probe_exhaustion_is_calib_false(monkeypatch):
    """Hole 5: probe exhaustion (status 0) → calib_ok=False → caller fails
    closed and skips ffuf. Must NOT return calib_ok=True."""
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((0, None, None), (0, None, None)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, False, None)


def test_detect_ffuf_catchall_status_catchall_captures_stable_size(monkeypatch):
    # Both probes 200 AND same size 870 → status catch-all with a STABLE
    # baseline size (edit #2) carried so real different-size routes can survive.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (200, None, 870)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, 200, 870, True, None)


def test_detect_ffuf_catchall_status_catchall_variable_size_falls_back(monkeypatch):
    # Both 200 but DIFFERENT sizes → path-variable body → baseline_size None →
    # suppression falls back to status-only (no regression).
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (200, None, 915)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, 200, None, True, None)


def test_detect_ffuf_catchall_redirect_catchall_is_calib_true(monkeypatch):
    # Both probes 301 → same Location → redirect catch-all (size irrelevant).
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((301, "/x", None), (301, "/x", None)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == ("/x", None, None, True, None)


def test_detect_ffuf_catchall_discriminating_host_is_calib_true(monkeypatch):
    # 200 then 404 → host discriminates → no catch-all, calib clean.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (404, None, 400)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, True, None)


def test_detect_ffuf_catchall_both_404_is_not_catchall(monkeypatch):
    # 404==404 but 404 is excluded (expected random-path answer) → discriminates.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((404, None, 400), (404, None, 400)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, True, None)


def test_backward_compat_redirect_wrapper_unpacks_4_tuple(monkeypatch):
    """The #33 thin wrapper must unpack the new 4-tuple (else ValueError).
    Returns just the redirect Location on a redirect catch-all."""
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((307, "/go", None), (307, "/go", None)))
    assert M.detect_ffuf_catchall_redirect(types.SimpleNamespace(hostname="h")) == "/go"


# ── edit #2: should_suppress_ffuf_status size discrimination ─────────────
def test_suppress_status_stable_size_suppresses_only_matching_size():
    # 200-catch-all, stable soft-404 size 870: the soft-404 (200/870) suppresses;
    # a real same-status route (200/8) SURVIVES — the whole point of edit #2.
    assert M.should_suppress_ffuf_status(200, 200, "", result_size=870, baseline_size=870) is True
    assert M.should_suppress_ffuf_status(200, 200, "", result_size=8, baseline_size=870) is False


def test_suppress_status_no_baseline_size_is_status_only():
    # Path-variable body (baseline_size None) → status-only, pre-edit behavior.
    assert M.should_suppress_ffuf_status(200, 200, "", result_size=8, baseline_size=None) is True
    assert M.should_suppress_ffuf_status(200, 200, "") is True  # 3-arg back-compat


def test_suppress_status_distinct_status_never_suppressed():
    assert M.should_suppress_ffuf_status(403, 200, "", result_size=870, baseline_size=870) is False


# ═══════════════════════════════════════════════════════════════════════
# Medium classify_ffuf_severity regression pin.
# .env+200 → HIGH is INTENTIONAL and safe ONLY because Fix B suppresses ffuf
# entirely on a catch-all host upstream (calibration). On a DISCRIMINATING
# host, a 200 on /.env is a real hit and HIGH is correct. This pins the matrix
# so nobody "fixes" it by blanket-downgrading (that was the 59ad6a13 mistake).
# ═══════════════════════════════════════════════════════════════════════

def test_classify_secret_200_is_high():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 200) == "HIGH"


def test_classify_admin_200_is_moderate():
    assert M.classify_ffuf_severity("admin", "https://h/admin", 200) == "MODERATE"


def test_classify_secret_403_is_low():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 403) == "LOW"


def test_classify_generic_200_is_info():
    assert M.classify_ffuf_severity("about", "https://h/about", 200) == "INFO"


def test_classify_secret_redirect_is_info():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 301) == "INFO"


# ═══════════════════════════════════════════════════════════════════════
# Cloud Armor block detection (scanner edit #1, 2026-07-06)
# Armor blocks with HTTP 400 + a Google body, NOT 403 — the scanner was blind
# to it. Body below is VERBATIM from prosalud's heavy-probe capture.
# ═══════════════════════════════════════════════════════════════════════

_ARMOR_400_BODY = (
    "<html><head>\n"
    '<meta http-equiv="content-type" content="text/html;charset=utf-8">\n'
    "<title>400 Bad Request</title>\n</head>\n"
    "<body text=#000000 bgcolor=#ffffff>\n<h1>Error: Bad Request</h1>\n"
    "<h2>Your client has issued a malformed or illegal request.</h2>\n</body></html>"
)


def test_is_armor_block_real_body_is_true():
    assert M.is_armor_block(400, _ARMOR_400_BODY) is True


def test_is_armor_block_case_insensitive():
    assert M.is_armor_block(400, _ARMOR_400_BODY.upper()) is True


def test_is_armor_block_bare_400_is_false():
    # A legit malformed-request 400 from the app is NOT an Armor block.
    assert M.is_armor_block(400, "<html><body>Bad Request: missing field</body></html>") is False


def test_is_armor_block_wrong_status_is_false():
    # Same body but 403 — Armor's tell is the 400, so this isn't the Armor signature.
    assert M.is_armor_block(403, _ARMOR_400_BODY) is False


def test_is_armor_block_no_body_is_false():
    assert M.is_armor_block(400, None) is False


def test_waf_blocked_classic_ban_codes_need_no_body():
    for code in (403, 429, 503, 521, 522, 523):
        assert M.response_is_waf_blocked(code) is True


def test_waf_blocked_armor_400_with_body():
    assert M.response_is_waf_blocked(400, _ARMOR_400_BODY) is True


def test_waf_blocked_bare_400_is_not_a_block():
    assert M.response_is_waf_blocked(400, "ordinary 400") is False
    assert M.response_is_waf_blocked(400) is False  # no body → status-only signals


def test_waf_blocked_clean_200_is_false():
    assert M.response_is_waf_blocked(200, _ARMOR_400_BODY) is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

# ═══════════════════════════════════════════════════════════════════════════
# S3 Part 2 — the PATH-ECHOING catch-all (relay 177/182)
#
# ⛔ NOTE 92 SHIPPED AND RAN FOR THREE MONTHS AND STILL LET 98 PHANTOMS THROUGH,
# because its acceptance test named ONE host. ftp.sciimage.com redirects every
# path to a CONSTANT Location, so exact equality worked there. oauth2-proxy
# echoes the requested path in ?rd=, so the two calibration probes see different
# Locations and no catch-all is detected at all.
#
# ⇒ Every test below names which SHAPE it covers, and the constant case is
#   re-asserted here so this change cannot fix one shape by breaking the other.
# ═══════════════════════════════════════════════════════════════════════════

_OAUTH_BASE = "https://atlantis-gcp.prodexlabs.com/oauth2/start"
_FTP_CONST = "https://ftp.sciimage.com/Web/Account/Login.htm"


def test_shape_constant_still_detected_and_pattern_is_none():
    """SHAPE 1 — ftp.sciimage.com, the June host. Unchanged behaviour: the
    exact-equality branch fires and NO echo pattern is recorded."""
    monkey = M.detect_path_echo_pattern(_FTP_CONST, _FTP_CONST)
    assert monkey is None, "a constant Location must not be read as an echo"


def test_shape_path_echo_detected():
    """SHAPE 2 — oauth2-proxy. Two impossible probes, two different Locations,
    same base, one differing param, and that param carries the probed path."""
    pat = M.detect_path_echo_pattern(
        f"{_OAUTH_BASE}?rd=%2Fcs-calib-aaaaaaaaaaaa",
        f"{_OAUTH_BASE}?rd=%2Fcs-calib-bbbbbbbbbbbb",
    )
    assert pat == (_OAUTH_BASE, "rd")


def test_the_near_miss_a_nonce_is_not_a_path_echo():
    """⛔ THE TEST THAT GUARDS THE GUARD. Two probes, same base, one differing
    param — but the value is a per-request nonce, not the path. If this were
    read as an echo, every nonce-issuing host would have its real findings
    suppressed. Drop the contains-the-probed-path check and this fails."""
    assert M.detect_path_echo_pattern(
        f"{_OAUTH_BASE}?nonce=abc123", f"{_OAUTH_BASE}?nonce=def456") is None


def test_a_different_base_is_not_a_pattern():
    assert M.detect_path_echo_pattern(
        f"{_OAUTH_BASE}?rd=%2Fcs-calib-aaa",
        "https://elsewhere.example/login?rd=%2Fcs-calib-bbb") is None


def test_two_differing_params_is_not_a_pattern():
    """Ambiguous: we cannot say which one is the echo, so we do not guess."""
    assert M.detect_path_echo_pattern(
        f"{_OAUTH_BASE}?rd=%2Fcs-calib-aaa&t=1",
        f"{_OAUTH_BASE}?rd=%2Fcs-calib-bbb&t=2") is None


def test_no_query_string_is_not_a_pattern():
    assert M.detect_path_echo_pattern(
        "https://h.example/a", "https://h.example/b") is None


def test_the_oauth2_host_collapses_98_to_1():
    """⭐ THE ACCEPTANCE, IN THE FORM THE MEASUREMENT TOOK. 4.7 measured 98
    "Path exists (redirect → …)" rows on atlantis-gcp, one per wordlist path,
    all to the same base with the path echoed. Every one must suppress."""
    pat = (_OAUTH_BASE, "rd")
    paths = ["actuator", "admin", "analytics", "api", "backup", "config",
             "console", "debug", "env", "health", "metrics", "status"]
    suppressed = [
        p for p in paths
        if M.should_suppress_ffuf_redirect_pattern(
            f"{_OAUTH_BASE}?rd=%2F{p}", pat, p)
    ]
    assert suppressed == paths, f"these would still emit per-path: " \
        f"{sorted(set(paths) - set(suppressed))}"


def test_the_mixed_host_emits_the_real_signal():
    """⛔ A host can echo AND have real routes. Only the echoed redirects
    suppress; a 200, and a redirect to a DIFFERENT base, both survive."""
    pat = (_OAUTH_BASE, "rd")
    assert M.should_suppress_ffuf_redirect_pattern(
        f"{_OAUTH_BASE}?rd=%2Fadmin", pat, "admin") is True
    # ⛔ A DIFFERENT BASE, WITH THE SAME ECHO PARAM CARRYING THE SAME PATH.
    # This exact case is why the base check exists, and my first version of this
    # test used "https://cdn.example/assets/" — which has NO query string, so it
    # returned False whether or not the base was checked. The mutation sweep
    # caught it: removing `if r_base != base` left all 76 tests green. A test
    # that passes for the wrong reason is worth less than no test, because it
    # advertises coverage it does not have.
    assert M.should_suppress_ffuf_redirect_pattern(
        "https://someone-else.example/login?rd=%2Fadmin", pat, "admin") is False, \
        "a redirect to a DIFFERENT base must never be suppressed, even when its " \
        "echo param happens to carry the probed path"
    # and the no-query case too, which is a different failure
    assert M.should_suppress_ffuf_redirect_pattern(
        "https://cdn.example/assets/", pat, "assets") is False
    # same base but the echo param carries someone ELSE's path
    assert M.should_suppress_ffuf_redirect_pattern(
        f"{_OAUTH_BASE}?rd=%2Fsomething-else", pat, "admin") is False
    # no pattern calibrated at all -> never suppress
    assert M.should_suppress_ffuf_redirect_pattern(
        f"{_OAUTH_BASE}?rd=%2Fadmin", None, "admin") is False


def test_raw_and_encoded_slashes_both_match():
    pat = (_OAUTH_BASE, "rd")
    assert M.should_suppress_ffuf_redirect_pattern(
        f"{_OAUTH_BASE}?rd=/admin", pat, "admin") is True
    assert M.should_suppress_ffuf_redirect_pattern(
        f"{_OAUTH_BASE}?rd=%2Fadmin", pat, "/admin") is True


def test_the_exact_equality_predicate_is_untouched():
    """⛔ THE PIN THAT MATTERS MOST. #33's predicate keeps `==`. Loosening it to
    prefix/substring is what the 59ad6a13 regression did — a blanket filter that
    hid a real /admin. This change adds a SIBLING; it does not soften the
    original, and this asserts the original still refuses a near-match."""
    assert M.should_suppress_ffuf_redirect(_FTP_CONST, _FTP_CONST) is True
    assert M.should_suppress_ffuf_redirect(_FTP_CONST + "?x=1", _FTP_CONST) is False
    assert M.should_suppress_ffuf_redirect(f"{_OAUTH_BASE}?rd=%2Fadmin",
                                           f"{_OAUTH_BASE}?rd=%2Fother") is False


def test_calibration_returns_the_pattern_for_the_echoing_shape():
    """The wiring: detect_ffuf_catchall must surface the pattern as its 5th
    element, or ctx.ffuf_catchall_pattern is never set and the emit-site guard
    can never fire. Drives the real function with stubbed probes."""
    import types
    monkey = _two_probe(
        (302, f"{_OAUTH_BASE}?rd=%2Fcs-calib-aaaaaaaaaaaa", None),
        (302, f"{_OAUTH_BASE}?rd=%2Fcs-calib-bbbbbbbbbbbb", None),
    )
    import pytest as _pt
    mp = _pt.MonkeyPatch()
    try:
        mp.setattr(M, "_probe_calibration_path", monkey)
        out = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    finally:
        mp.undo()
    assert out == (None, None, None, True, (_OAUTH_BASE, "rd")), out


def test_calibration_still_returns_the_constant_for_the_june_shape():
    """And the other host in the acceptance: ftp.sciimage.com must STILL
    collapse via the unchanged exact-equality path, pattern None."""
    import types
    import pytest as _pt
    mp = _pt.MonkeyPatch()
    try:
        mp.setattr(M, "_probe_calibration_path",
                   _two_probe((302, _FTP_CONST, None), (302, _FTP_CONST, None)))
        out = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    finally:
        mp.undo()
    assert out == (_FTP_CONST, None, None, True, None), out



# ═══════════════════════════════════════════════════════════════════════
# relay 449 — the BODY-INDEPENDENT catch-all, and the existence marker
#
# Live defect: uat.prodexlabs.com, scan_run 9add84ef, finding
# `uat.prodexlabs.com:light:exposed-path-wp-admin-installphp` — MODERATE
# "Exposed path: /wp-admin/install.php (HTTP 200) — confirms WP install" on a
# Next.js SPA with no WordPress anywhere on it. The host 200s every path, but
# its shell carries a per-request CSP nonce so the two control bodies hashed
# DIFFERENTLY, _is_catchall said False, the baseline was null, and the non-HIGH
# branch (which relies solely on that flag) emitted unconditionally.
# ═══════════════════════════════════════════════════════════════════════

_SPA_A = "<!doctype html><html><head><meta nonce='aaaa1111'>PRODEX</head></html>"
_SPA_B = "<!doctype html><html><head><meta nonce='bbbb2222'>PRODEX</head></html>"


def _fake_two_probes(r1, r2):
    """(code, body, ctype) for control probe 1 then 2, then anything after."""
    calls = {"n": 0}

    def probe(_ctx, _path):
        calls["n"] += 1
        return r1 if calls["n"] == 1 else r2
    return probe


# ── _is_catchall_by_status — the new primitive ─────────────────────────

def test_449_status_catchall_is_true_when_bodies_DIFFER():
    """⭐ THE WHOLE FIX. Byte-equality was a PROXY for 'catch-all', not the
    definition, and every per-request-varying SPA defeats the proxy."""
    assert L._is_catchall_by_status((200, 200)) is True


def test_449_status_catchall_accepts_the_2xx_variants():
    assert L._is_catchall_by_status((204, 206)) is True


def test_449_status_catchall_is_FALSE_on_a_normal_host():
    """⛔ NO FALSE NEGATIVES. Detection is POSITIVE-ONLY: a host whose nonsense
    paths 404 is not a catch-all, nothing is suppressed, real exposed paths
    still emit exactly as before."""
    assert L._is_catchall_by_status((404, 404)) is False
    assert L._is_catchall_by_status((200, 404)) is False
    assert L._is_catchall_by_status((301, 301)) is False


def test_449_a_single_flaked_control_probe_disables_status_detection():
    """Documents WHY the existence marker exists as a SECOND guard: one
    transient non-2xx and this guard is gone."""
    assert L._is_catchall_by_status((200, 429)) is False


# ── the baseline primitive is deliberately NOT changed ─────────────────

def test_449_hash_based_is_catchall_still_requires_equal_hashes():
    """_is_catchall governs BASELINE ESTABLISHMENT, which genuinely needs a
    stable hash to compare per-path bodies against. 449 did not touch it."""
    assert L._is_catchall((200, 200), ("hA", "hB")) is False
    assert L._is_catchall((200, 200), ("hA", "hA")) is True


def test_449_detect_returns_both_answers_separately():
    """⛔ Before 449 one None did two jobs: 'bodies vary' was indistinguishable
    from 'not a catch-all'. The SPA case then took the wrong branch."""
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(L, "_probe_path_body",
                   _fake_two_probes((200, _SPA_A, "text/html"),
                                    (200, _SPA_B, "text/html")))
        baseline, is_catchall = L.detect_light_catchall(
            types.SimpleNamespace(hostname="uat.prodexlabs.com"))
    finally:
        mp.undo()
    assert baseline is None, "bodies differ, so there is no stable baseline"
    assert is_catchall is True, "but the host IS a catch-all — this is the fix"


def test_449_detect_on_a_normal_host_is_neither():
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(L, "_probe_path_body",
                   _fake_two_probes((404, "nope", "text/html"),
                                    (404, "nope", "text/html")))
        baseline, is_catchall = L.detect_light_catchall(
            types.SimpleNamespace(hostname="normal.example"))
    finally:
        mp.undo()
    assert baseline is None and is_catchall is False


# ── 4.7 fixture 1 — the reported defect, at the decision boundary ──────

def test_449_FIXTURE1_spa_catchall_suppresses_the_wp_install_path():
    """The exact uat.prodexlabs.com shape: catch-all by status, no baseline
    (bodies vary), non-HIGH path. MUST suppress."""
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=True) == "SUPPRESS"


# ── 4.7 fixture 2 — no new false negatives ────────────────────────────

def test_449_FIXTURE2_normal_host_still_emits_a_real_exposed_path():
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=False) == "EMIT"


# ── 4.7 fixture 3 — the 59ad6a13 invariant survives ───────────────────

def test_449_FIXTURE3_a_real_secret_still_wins_on_a_status_catchall():
    """⛔ LOAD-BEARING. A confirmed secret outranks every suppression path,
    including the new one."""
    assert L.resolve_path_disposition(
        "HIGH", L.VERIFY_SECRET, matches_baseline=True,
        host_is_catchall=True) == "HIGH"


def test_449_high_branch_is_byte_identical_under_the_new_flags():
    """⛔ THE REGRESSION I REFUSED TO SHIP. Folding host_is_catchall into the
    HIGH branch reads as a tidy simplification and would silently convert
    'INFO — checked, no secret found' into 'SUPPRESS' on exactly the paths that
    matter most. Every HIGH verdict must be INDIFFERENT to the new flags."""
    for verdict, expected in ((L.VERIFY_SECRET, "HIGH"),
                              (L.VERIFY_APP_HTML, "INFO_APP_HTML"),
                              (L.VERIFY_NO_MATCH, "INFO")):
        for catchall in (False, True):
            for unconfirmed in (False, True):
                assert L.resolve_path_disposition(
                    "HIGH", verdict, matches_baseline=False,
                    host_is_catchall=catchall,
                    marker_unconfirmed=unconfirmed) == expected, (
                        verdict, catchall, unconfirmed)


# ── the second, independent guard ─────────────────────────────────────

def test_449_existence_marker_is_opt_in_per_path():
    """A path with no declared marker can never be downgraded by this guard."""
    assert L.existence_unconfirmed("/robots.txt", "anything at all") is False
    assert L.existence_unconfirmed("/admin", "") is False


def test_449_wp_install_without_a_wordpress_marker_is_unconfirmed():
    assert L.existence_unconfirmed("/wp-admin/install.php", _SPA_A) is True


def test_449_a_REAL_wordpress_install_page_still_confirms():
    """⛔ NO FALSE NEGATIVE. WordPress's own install.php renders the string in
    its title and setup copy, so a genuine reachable install still EMITS."""
    body = "<html><title>WordPress &rsaquo; Installation</title></html>"
    assert L.existence_unconfirmed("/wp-admin/install.php", body) is False
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=False,
        marker_unconfirmed=L.existence_unconfirmed(
            "/wp-admin/install.php", body)) == "EMIT"


def test_449_unconfirmed_marker_downgrades_rather_than_suppressing():
    """⚠ DOWNGRADE, NOT DELETE. A 2xx on a probed path while nonsense paths
    404 is a real observation; only the CLAIM is unsupported."""
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=False, marker_unconfirmed=True) == "INFO_NO_MARKER"


def test_449_catchall_beats_the_marker_guard():
    """Order matters: on a catch-all the 2xx carries ZERO information, so there
    is nothing to report at all — suppression wins over downgrade."""
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=True, marker_unconfirmed=True) == "SUPPRESS"


def test_449_the_two_guards_fail_INDEPENDENTLY():
    """⭐ WHY THERE ARE TWO. Either alone closes the reported defect; together
    they cover the case where one control probe flakes and status detection
    silently reverts to False."""
    # guard 1 gone (a probe flaked) — guard 2 still downgrades the claim
    assert L._is_catchall_by_status((200, 429)) is False
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=False, marker_unconfirmed=True) == "INFO_NO_MARKER"
    # guard 2 gone (path declares no marker) — guard 1 still suppresses
    assert L.existence_unconfirmed("/admin", _SPA_A) is False
    assert L.resolve_path_disposition(
        "INFO", L.VERIFY_NO_MATCH, matches_baseline=False,
        host_is_catchall=True, marker_unconfirmed=False) == "SUPPRESS"


def test_449_defaults_preserve_the_pre_449_contract():
    """Both new params default False, so every pre-449 call site and test
    exercises exactly the old behaviour."""
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, False) == "EMIT"
    assert L.resolve_path_disposition(
        "MODERATE", L.VERIFY_NO_MATCH, True) == "SUPPRESS"


# ═══════════════════════════════════════════════════════════════════════
# relay 449 — END-TO-END through check_common_paths.
#
# ⛔ WHY THIS SECTION EXISTS, and it is the most important thing in the file.
# Every pure-function test above passed against a build where the call site
# read `host_is_catchall=False` — the primitives were all correct and the fix
# was WIRED TO NOTHING. A mutation proved it: 18/18 green, defect fully live.
# Testing the decision is not testing the scanner. These drive the real
# check_common_paths and assert on the FINDINGS IT EMITS.
# ═══════════════════════════════════════════════════════════════════════

def _ctx():
    return L.ScanContext(descriptor={}, hostname="uat.prodexlabs.com",
                         asset_id="uat.prodexlabs.com", scan_run_id="r",
                         queue_id="q", intensity="light")


def _run_common_paths(monkeypatch, responder):
    """Drive the REAL check_common_paths against a fake HTTP layer."""
    ctx = _ctx()
    monkeypatch.setattr(L, "_probe_path_body", responder)
    monkeypatch.setattr(L.time, "sleep", lambda *a, **k: None)
    L.check_common_paths(ctx)
    return ctx


def _spa_responder():
    """The uat.prodexlabs.com shape: 200 + a NONCE-VARYING shell for EVERY
    path, control probes included."""
    n = {"i": 0}

    def probe(_ctx, _path):
        n["i"] += 1
        return (200,
                f"<!doctype html><html><meta nonce='n{n['i']}'>PRODEX</html>",
                "text/html")
    return probe


def _normal_responder(exposed: dict):
    """404 for anything not in `exposed` — i.e. NOT a catch-all."""
    def probe(_ctx, path):
        if path in exposed:
            return exposed[path]
        return (404, "not found", "text/html")
    return probe


def test_449_E2E_spa_catchall_emits_NO_wp_install_finding(monkeypatch):
    """⭐ THE REPORTED DEFECT, reproduced end-to-end and closed. Pre-449 this
    emitted MODERATE 'Exposed path: /wp-admin/install.php (HTTP 200)'."""
    ctx = _run_common_paths(monkeypatch, _spa_responder())
    wp = [f for f in ctx.findings if "install.php" in f.title]
    assert wp == [], f"the false positive is back: {[f.title for f in wp]}"


def test_449_E2E_spa_catchall_emits_the_collapsed_summary_instead(monkeypatch):
    """Suppressed probes are ACCOUNTED FOR, not silently dropped."""
    ctx = _run_common_paths(monkeypatch, _spa_responder())
    summary = [f for f in ctx.findings
               if f.check_name == "catchall-suppressed-paths"]
    assert len(summary) == 1, [f.check_name for f in ctx.findings]
    assert "suppressed" in summary[0].title


def test_449_E2E_no_MODERATE_or_higher_survives_on_a_pure_catchall(monkeypatch):
    """A host that 200s literally everything must not produce a single
    actionable path finding — that is the whole claim."""
    ctx = _run_common_paths(monkeypatch, _spa_responder())
    loud = [f for f in ctx.findings
            if f.severity in ("MODERATE", "HIGH", "CRITICAL")]
    assert loud == [], [(f.severity, f.title) for f in loud]


def test_449_E2E_the_artifact_records_WHY_it_suppressed(monkeypatch):
    """⚠ catchall_baseline=null is how 4.7 diagnosed this from scan_run
    9add84ef. A null baseline alone could not tell 'not a catch-all' from
    'a catch-all whose body varies' — now the artifact says which."""
    import json as _json
    ctx = _run_common_paths(monkeypatch, _spa_responder())
    art = [a for a in ctx.artifacts if a[0] == "common_paths"]
    assert art, ctx.artifacts
    blob = _json.loads(art[0][2])
    assert blob["catchall_baseline"] is None, "bodies vary — no stable hash"
    assert blob["catchall_by_status"] is True, "but it IS a catch-all"
    assert blob["suppressed"] > 0


def test_449_E2E_normal_host_STILL_EMITS_a_real_exposed_path(monkeypatch):
    """⛔ NO NEW FALSE NEGATIVES — the guard that makes the fix safe. A real
    WordPress install page on a non-catch-all host still fires MODERATE."""
    ctx = _run_common_paths(monkeypatch, _normal_responder({
        "/wp-admin/install.php": (
            200, "<html><title>WordPress &rsaquo; Installation</title></html>",
            "text/html")}))
    wp = [f for f in ctx.findings if "install.php" in f.title]
    assert len(wp) == 1, [f.title for f in ctx.findings]
    assert wp[0].severity == "MODERATE", wp[0].severity
    assert wp[0].title.startswith("Exposed path:")


def test_449_E2E_normal_host_no_marker_is_DOWNGRADED_not_deleted(monkeypatch):
    """Second guard, end to end: reachable but unsupported claim -> INFO, and
    the title must not assert an install."""
    ctx = _run_common_paths(monkeypatch, _normal_responder({
        "/wp-admin/install.php": (200, "<html>some other app</html>",
                                  "text/html")}))
    wp = [f for f in ctx.findings if "/wp-admin/install.php" in f.title]
    assert len(wp) == 1, [f.title for f in ctx.findings]
    assert wp[0].severity == "INFO", wp[0].severity
    assert "no application marker" in wp[0].title


def test_449_E2E_a_REAL_SECRET_still_wins_on_a_catchall(monkeypatch):
    """⛔ THE 59ad6a13 INVARIANT, end to end and under the NEW suppressor. A
    genuine /.env served as octet-stream on a host that 200s everything must
    still surface HIGH."""
    n = {"i": 0}

    def probe(_ctx, path):
        n["i"] += 1
        if path == "/.env":
            return (200, "DB_PASSWORD=hunter2\nAPI_KEY=abcdef123456\n",
                    "application/octet-stream")
        return (200, f"<!doctype html><html><meta nonce='n{n['i']}'>X</html>",
                "text/html")

    ctx = _run_common_paths(monkeypatch, probe)
    env = [f for f in ctx.findings if "/.env" in f.title]
    assert len(env) == 1, [f.title for f in ctx.findings]
    assert env[0].severity == "HIGH", (env[0].severity, env[0].title)


def test_449_E2E_high_path_with_no_secret_is_still_INFO_not_suppressed(monkeypatch):
    """⛔ THE REGRESSION THE HIGH BRANCH GUARDS. On a VARYING catch-all a HIGH
    path with no marker must stay an auditable INFO row. If a refactor routes
    the HIGH branch through host_is_catchall it becomes SUPPRESS and the audit
    trail disappears on exactly the paths that matter most."""
    ctx = _run_common_paths(monkeypatch, _spa_responder())
    high_paths = [f for f in ctx.findings if "/.git/HEAD" in f.title]
    assert len(high_paths) == 1, [f.title for f in ctx.findings]
    assert high_paths[0].severity == "INFO"
    assert "no secret found" in high_paths[0].title
