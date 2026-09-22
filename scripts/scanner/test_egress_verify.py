"""relay 446 — the pre-fire check. Every test here is a REFUSAL that must hold.

    python3 -m pytest scripts/scanner/test_egress_verify.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from egress_pool import resolve_cooldown_s  # noqa: E402
from egress_verify import (  # noqa: E402
    EgressVerifyError,
    fold_fire_outcome,
    observe_and_verify,
    verify_egress,
)

OK = dict(region="us-chi", actual_ip="1.2.3.4", exit_live=True)


def test_the_happy_path_returns_the_verified_ip():
    # Returning the IP (not True) means a caller cannot verify one exit and then
    # read the address from somewhere else.
    assert verify_egress(**OK) == "1.2.3.4"


# ── the five refusals ───────────────────────────────────────────────────────

def test_REFUSES_when_no_egress_ip_was_observed():
    for ip in (None, ""):
        with pytest.raises(EgressVerifyError) as e:
            verify_egress(region="us-chi", actual_ip=ip, exit_live=True)
        assert "fire blind" in str(e.value)


def test_REFUSES_when_the_tunnel_is_not_the_planned_one():
    with pytest.raises(EgressVerifyError) as e:
        verify_egress(region="us-chi", actual_ip="9.9.9.9",
                      expected_ip="1.2.3.4", exit_live=True)
    assert "435" in str(e.value), "the message should name the pin it catches"


def test_REFUSES_an_exit_ALREADY_USED_in_this_sweep():
    """⭐ THE CHECK THAT ACTUALLY CLOSES RELAY 435.

    vpn_bringup's fallback to the first config is SILENT — no error, no bad exit
    code. Its only tell is that the egress IP is the one the PREVIOUS host
    already used. And this fires even when expected_ip is unknown, which is
    precisely the case plan_sweep leaves optimistic.
    """
    with pytest.raises(EgressVerifyError) as e:
        verify_egress(region="us-lax", actual_ip="87.249.134.7",
                      used_ips={"87.249.134.7"}, exit_live=True)
    assert "ALREADY USED" in str(e.value)


def test_the_used_check_fires_even_with_NO_expected_ip():
    # The optimistic-plan case: region_to_ip had no entry, so there is nothing
    # to match against — the used-set is the only thing standing between the
    # sweep and a silent single-exit run.
    with pytest.raises(EgressVerifyError):
        verify_egress(region="us-lax", actual_ip="87.249.134.7",
                      expected_ip=None, used_ips={"87.249.134.7"}, exit_live=True)


def test_REFUSES_a_BURNED_exit():
    with pytest.raises(EgressVerifyError) as e:
        verify_egress(region="us-chi", actual_ip="1.2.3.4",
                      burned_ips={"1.2.3.4"}, exit_live=True)
    assert "BURNED" in str(e.value)


def test_REFUSES_a_dead_exit():
    with pytest.raises(EgressVerifyError) as e:
        verify_egress(region="us-chi", actual_ip="1.2.3.4", exit_live=False)
    assert "failed its liveness probe" in str(e.value)


def test_NOT_CHECKED_is_refused_exactly_like_FAILED():
    """⛔ THE DEFAULT MUST NOT BE PERMISSIVE. `exit_live=None` means nobody
    looked. If that passed, forgetting to wire the probe would silently disable
    the whole check while every test still went green."""
    with pytest.raises(EgressVerifyError) as e:
        verify_egress(region="us-chi", actual_ip="1.2.3.4")   # exit_live omitted
    assert "was not checked" in str(e.value)


def test_an_EgressVerifyError_is_catchable_as_a_SweepPlanError():
    """One except covers plan-time and fire-time refusals, so a caller cannot
    handle one and let the other through."""
    from egress_pool import SweepPlanError
    with pytest.raises(SweepPlanError):
        verify_egress(region="r", actual_ip=None)


# ── contract 5: the ledger stays current WITHIN the sweep ───────────────────

def test_a_reset_burns_the_exit_for_the_REST_of_the_sweep():
    """⛔ THE WRITE/READ GAP. active_probe_audit is written by the scan, but the
    next host is planned before that row is read back. Without folding the
    outcome forward, host N+1 gets handed the exit host N just banned."""
    burned = fold_fire_outcome(frozenset(), egress_ip="1.2.3.4",
                               result="network_reset")
    assert burned == {"1.2.3.4"}
    # and the next host is now refused that exit
    with pytest.raises(EgressVerifyError):
        verify_egress(region="us-lax", actual_ip="1.2.3.4",
                      burned_ips=burned, exit_live=True)


def test_a_NON_reset_outcome_does_NOT_burn_the_exit():
    for result in ("challenge_elicited", "no_challenge", "banned",
                   "path_mentioned_not_redirect", None):
        assert fold_fire_outcome(frozenset(), egress_ip="1.2.3.4",
                                 result=result) == frozenset(), result


def test_fold_is_additive_and_does_not_mutate_its_input():
    start = frozenset({"a"})
    out = fold_fire_outcome(start, egress_ip="b", result="network_reset")
    assert out == {"a", "b"} and start == {"a"}


# ── the I/O shell delegates, and never swallows a broken check ─────────────

def test_the_shell_gathers_facts_and_delegates():
    seen = {}

    def observe(region):
        seen["region"] = region
        return "1.2.3.4"

    def probe(ip):
        seen["probed"] = ip
        return True

    got = observe_and_verify(region="us-chi", expected_ip="1.2.3.4",
                             used_ips=frozenset(), burned_ips=frozenset(),
                             observe_ip=observe, probe_exit_live=probe)
    assert got == "1.2.3.4"
    assert seen == {"region": "us-chi", "probed": "1.2.3.4"}


def test_a_BROKEN_check_is_a_refusal_not_a_pass():
    """⛔ 'The check itself errored' is not evidence the exit is fine. Both
    callables are guarded, and neither failure may degrade into a fire."""
    def boom(_):
        raise RuntimeError("tunnel down")

    with pytest.raises(EgressVerifyError) as e:
        observe_and_verify(region="r", expected_ip=None, used_ips=frozenset(),
                           burned_ips=frozenset(), observe_ip=boom,
                           probe_exit_live=lambda _ip: True)
    assert "could not observe" in str(e.value)

    with pytest.raises(EgressVerifyError) as e:
        observe_and_verify(region="r", expected_ip=None, used_ips=frozenset(),
                           burned_ips=frozenset(),
                           observe_ip=lambda _r: "1.2.3.4",
                           probe_exit_live=boom)
    assert "broken check is not a passing check" in str(e.value)


# ── the nit: ONE cooldown, resolved from run_medium's own env var ──────────

def test_the_cooldown_follows_run_medium_and_fails_safe():
    assert resolve_cooldown_s({}) == 1800
    assert resolve_cooldown_s({"PATIENT_BAN_COOLDOWN_S": "3600"}) == 3600
    # set-but-EMPTY is the relay 202 trap; malformed must not become 0, which
    # would mark every burned exit clean.
    assert resolve_cooldown_s({"PATIENT_BAN_COOLDOWN_S": ""}) == 1800
    assert resolve_cooldown_s({"PATIENT_BAN_COOLDOWN_S": "abc"}) == 1800
    assert resolve_cooldown_s(None) == 1800


def test_the_cooldown_default_matches_run_medium_verbatim():
    """⛔ ONE SOURCE. If run_medium's default moves and this one doesn't, the
    burned-window and the rotation-wait diverge silently — the sweep calls an
    exit clean while the scanner is still waiting out its ban."""
    import pathlib
    import re
    src = (pathlib.Path(__file__).resolve().parent / "run_medium.py").read_text()
    m = re.search(r'PATIENT_BAN_COOLDOWN_S = int\(os\.environ\.get\(\s*'
                  r'"PATIENT_BAN_COOLDOWN_S"\s*\)\s*or\s*"(\d+)"\)', src)
    assert m, "run_medium's cooldown line changed shape — re-check the mirror"
    assert resolve_cooldown_s({}) == int(m.group(1))


def test_the_verifier_carries_no_IO_of_its_own():
    """⛔ AST, not a text scan (the prose trap, 5th occurrence). The shell takes
    its I/O as INJECTED callables; importing subprocess/requests here would mean
    the firing machinery migrated into the check."""
    import ast
    import inspect
    import egress_verify
    tree = ast.parse(inspect.getsource(egress_verify))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"subprocess", "requests", "urllib", "socket", "http", "psycopg",
              "os", "shutil"}
    assert not (imported & banned), f"the verifier gained I/O: {sorted(imported & banned)}"
