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
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, False)


def test_detect_ffuf_catchall_status_catchall_captures_stable_size(monkeypatch):
    # Both probes 200 AND same size 870 → status catch-all with a STABLE
    # baseline size (edit #2) carried so real different-size routes can survive.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (200, None, 870)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, 200, 870, True)


def test_detect_ffuf_catchall_status_catchall_variable_size_falls_back(monkeypatch):
    # Both 200 but DIFFERENT sizes → path-variable body → baseline_size None →
    # suppression falls back to status-only (no regression).
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (200, None, 915)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, 200, None, True)


def test_detect_ffuf_catchall_redirect_catchall_is_calib_true(monkeypatch):
    # Both probes 301 → same Location → redirect catch-all (size irrelevant).
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((301, "/x", None), (301, "/x", None)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == ("/x", None, None, True)


def test_detect_ffuf_catchall_discriminating_host_is_calib_true(monkeypatch):
    # 200 then 404 → host discriminates → no catch-all, calib clean.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None, 870), (404, None, 400)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, True)


def test_detect_ffuf_catchall_both_404_is_not_catchall(monkeypatch):
    # 404==404 but 404 is excluded (expected random-path answer) → discriminates.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((404, None, 400), (404, None, 400)))
    assert M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h")) == (None, None, None, True)


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
