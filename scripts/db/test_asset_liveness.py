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
    gate_dark_decision,
    apply_liveness_gate,
    discovery_status_from_service_count,
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


# ── discovery_status verdict — the ONE rule shared by ASM ingestion + light-scan write-back ───────
def test_discovery_status_service_count_wins():
    # svc>0 -> confirmed_live, regardless of the other inputs (a service answered).
    assert discovery_status_from_service_count(1) == "confirmed_live"
    assert discovery_status_from_service_count(5, host_count=0, is_apex=False) == "confirmed_live"
    # DNS infra shape (ns01/ns02: one service, alive=False): still confirmed_live — svc is the signal.
    assert discovery_status_from_service_count(1, host_count=1, is_apex=True) == "confirmed_live"


def test_discovery_status_zero_service_split():
    # 0 service, but resolved to a host OR is a scoped apex -> dns_only
    assert discovery_status_from_service_count(0, host_count=1, is_apex=False) == "dns_only"
    assert discovery_status_from_service_count(0, host_count=0, is_apex=True) == "dns_only"
    # 0 service, never resolved, not an apex -> ct_ghost (passive/CT phantom)
    assert discovery_status_from_service_count(0, host_count=0, is_apex=False) == "ct_ghost"


def test_discovery_status_matches_ingestion_gate():
    # Pin equivalence to import_asm_to_surface.py's inlined gate (note 93). If the ingestion
    # rule is ever changed without changing this shared fn, this catches the drift.
    def ingestion_gate(svc_count, host_count, is_apex):
        if svc_count > 0:
            return "confirmed_live"
        if is_apex or host_count > 0:
            return "dns_only"
        return "ct_ghost"
    for svc in (0, 1, 3):
        for hc in (0, 1):
            for apex in (False, True):
                assert discovery_status_from_service_count(svc, host_count=hc, is_apex=apex) \
                    == ingestion_gate(svc, hc, apex)


def test_discovery_status_none_safe():
    # defensive: None counts coerce to 0 (the scanner passes len(open_ports); belt-and-suspenders)
    assert discovery_status_from_service_count(None) == "ct_ghost"
    assert discovery_status_from_service_count(None, host_count=None, is_apex=True) == "dns_only"


def test_ingestion_calls_shared_verdict_no_local_def():
    # SSOT: import_asm_to_surface must CALL the shared fn, not re-inline the if/elif ladder.
    # (mirrors test_single_source_of_truth_no_drift for the demotion path)
    import inspect
    import import_asm_to_surface as ing
    src = inspect.getsource(ing)
    assert "discovery_status_from_service_count" in src, \
        "ingestion must call the shared verdict"
    assert 'disc = "confirmed_live"' not in src, \
        "ingestion re-inlined the verdict — drift risk; call asset_liveness instead"


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


# ── 4.7 Q1/Q4/Q6 — the dark-signal gate ───────────────────────────────────────────
def test_gate_dark_decision():
    assert gate_dark_decision(None) == "defer"                                   # no verdict -> fail-safe
    assert gate_dark_decision({"any_port_responded": True, "any_port_open": True}) == "suppress"
    assert gate_dark_decision({"any_port_responded": True, "any_port_open": False}) == "suppress"  # RST/unimac
    assert gate_dark_decision({"any_port_responded": False, "any_port_open": False}) == "emit"


def _fixed_verdicts(mapping):
    return lambda a: mapping.get(a)


def test_apply_gate_dry_run_returns_all_unchanged_and_never_heals():
    events = [{"asset_id": "ftp.unimacgraphics.com"}, {"asset_id": "dead.example.com"}]
    verdicts = {"ftp.unimacgraphics.com": {"any_port_responded": True, "any_port_open": False},
                "dead.example.com": {"any_port_responded": False, "any_port_open": False}}
    healed = []
    out = apply_liveness_gate(events, live=False, get_verdict=_fixed_verdicts(verdicts),
                              heal=lambda a: healed.append(a), logfn=lambda *_: None)
    assert out == events                              # zero behaviour change during the soak
    assert healed == []                               # heal never fires in dry-run


def test_apply_gate_live_suppresses_alive_emits_dark_heals_only_suppressed():
    events = [{"asset_id": "ftp.unimacgraphics.com"},   # responded -> suppress + heal
              {"asset_id": "dead.example.com"},          # not responded -> emit
              {"asset_id": "flaky.example.com"}]         # no verdict -> defer (no heal)
    verdicts = {"ftp.unimacgraphics.com": {"any_port_responded": True, "any_port_open": False},
                "dead.example.com": {"any_port_responded": False, "any_port_open": False}}
    healed = []
    out = apply_liveness_gate(events, live=True, get_verdict=_fixed_verdicts(verdicts),
                              heal=lambda a: healed.append(a), logfn=lambda *_: None)
    assert [e["asset_id"] for e in out] == ["dead.example.com"]   # only the genuinely-dark emits
    assert healed == ["ftp.unimacgraphics.com"]                   # heal only the probe-alive suppression
    # the unimac false-dark is gone and its probe clock healed; the deferred flaky asset is NOT healed
