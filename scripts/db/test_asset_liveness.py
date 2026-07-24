"""Tests for the shared liveness layer (Obsidian 161, 4.7 Q2/Q3/Q4).

The load-bearing test is test_two_semantics_diverge_on_rst_only_host: 4.7's biggest-risk item is
someone collapsing the two liveness semantics into one. This pins that a RST-only host is
ALIVE for dark-alert suppression AND service_gone for the went_dark state flip — simultaneously,
on the SAME input. If a future edit unifies them, this fails.
"""
from datetime import datetime, timedelta, timezone

from asset_liveness import (
    has_any_response_for_alive_check,
    classify_ports_for_state_flip,
    verdict_booleans,
    is_verdict_fresh,
    infer_asset_type,
    select_probe_ports,
    SAFE_DEFAULT_PORTS,
    DEFAULT_VERDICT_MAX_AGE_H,
)

UTC = timezone.utc


# ── 4.7 Q3 — the two semantics, and the load-bearing divergence guard ─────────────
def test_alive_check_any_tcp_reply_counts():
    assert has_any_response_for_alive_check(["open"]) is True
    assert has_any_response_for_alive_check(["refused"]) is True          # RST = host answered
    assert has_any_response_for_alive_check(["noresponse", "open"]) is True
    assert has_any_response_for_alive_check(["noresponse", "refused"]) is True
    assert has_any_response_for_alive_check(["noresponse"]) is False      # all timeout = not responding
    assert has_any_response_for_alive_check([]) is False
    assert has_any_response_for_alive_check(None) is False


def test_state_flip_semantic():
    assert classify_ports_for_state_flip(["open", "noresponse"]) == "alive"
    assert classify_ports_for_state_flip(["refused", "refused"]) == "service_gone"
    assert classify_ports_for_state_flip(["noresponse", "noresponse"]) == "unreachable"
    assert classify_ports_for_state_flip(["refused", "noresponse"]) == "service_gone"  # mixed
    assert classify_ports_for_state_flip([]) == "service_gone"


def test_two_semantics_diverge_on_rst_only_host():
    # 4.7 RISK #1 (biggest): the ftp.unimacgraphics.com / ftp.sciimage.com shape — host up,
    # service ports closed (RST). The two semantics MUST disagree on this same input:
    rst_only = ["refused", "refused"]
    assert has_any_response_for_alive_check(rst_only) is True          # -> dark digest SUPPRESSES
    assert classify_ports_for_state_flip(rst_only) == "service_gone"   # -> went_dark writer may flip
    # ...and the all-timeout host is genuinely dark under BOTH:
    dead = ["noresponse", "noresponse"]
    assert has_any_response_for_alive_check(dead) is False             # -> digest ALERTS
    assert classify_ports_for_state_flip(dead) == "unreachable"


def test_single_source_of_truth_no_drift():
    # demotion_writer.classify_ports MUST be the same object as the canonical state fn — one source,
    # zero possibility of drift (4.7 risk #1 mitigation). If someone re-adds a local def, this fails.
    import demotion_writer
    assert demotion_writer.classify_ports is classify_ports_for_state_flip
    for case in (["open"], ["refused"], ["noresponse"], ["refused", "noresponse"], []):
        assert demotion_writer.classify_ports(case) == classify_ports_for_state_flip(case)


def test_verdict_booleans_match_the_two_semantics():
    # the two stored booleans (computed at write time) equal the two named fns
    for pr in (["open"], ["refused"], ["noresponse"], ["open", "refused"], ["refused", "noresponse"], []):
        responded, is_open = verdict_booleans(pr)
        assert responded == has_any_response_for_alive_check(pr)
        assert is_open == any(r == "open" for r in pr)
    # the unimac shape: responded but not open
    assert verdict_booleans(["refused", "refused"]) == (True, False)


# ── 4.7 Q4 — stale-verdict guard ──────────────────────────────────────────────────
def test_is_verdict_fresh_boundaries():
    now = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    assert is_verdict_fresh(now - timedelta(hours=1), now=now) is True
    assert is_verdict_fresh(now - timedelta(hours=13), now=now) is False           # > 12h stale
    assert is_verdict_fresh(now - timedelta(hours=DEFAULT_VERDICT_MAX_AGE_H), now=now) is True  # ==12h boundary
    assert is_verdict_fresh(None, now=now) is False
    # naive probed_at treated as UTC (no crash, correct math)
    assert is_verdict_fresh(datetime(2026, 7, 24, 11, 30), now=now) is True


# ── 4.7 Q2 — asset-type-aware port selection ──────────────────────────────────────
def test_infer_asset_type():
    assert infer_asset_type("ftp.unimacgraphics.com") == "ftp"
    assert infer_asset_type("mail.command.com") == "mail"
    assert infer_asset_type("mx01.command.com") == "mail"
    assert infer_asset_type("ns1.command.com") == "dns"
    assert infer_asset_type("www.command.com") == "web"
    assert infer_asset_type("") == "other"


def test_select_probe_ports_ftp_includes_sftp_and_ftps_plus_defaults():
    ports = select_probe_ports("ftp.unimacgraphics.com")
    for p in (22, 443, 990, 21):
        assert p in ports
    for p in SAFE_DEFAULT_PORTS:                    # safe defaults always union'd (wrong guess never blinds)
        assert p in ports


def test_select_probe_ports_known_open_first_and_deduped():
    ports = select_probe_ports("www.command.com", known_open_ports=[8443, 443])
    assert ports[0] == 8443                          # accumulated evidence probed first
    assert ports.count(443) == 1                     # de-duped across groups
    assert 80 in ports and 22 in ports               # web type + safe defaults present
