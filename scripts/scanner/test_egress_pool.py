"""relay 444 — the fresh-egress-per-fire planner, and the refusals that matter.

    python3 -m pytest scripts/scanner/test_egress_pool.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from egress_pool import (  # noqa: E402
    DEFAULT_BURN_COOLDOWN_S,
    SweepPlanError,
    build_sweep_preview,
    burned_egress_ips,
    plan_sweep,
)

NOW = 1_800_000_000


def _audit(ip, age_s, result="network_reset"):
    return {"egress_ip": ip, "created_at_epoch": NOW - age_s,
            "details": {"result": result}}


# ── the burned-exit ledger ──────────────────────────────────────────────────

def test_a_recent_network_reset_burns_that_exit():
    burned = burned_egress_ips([_audit("87.249.134.7", 60)], now_epoch=NOW)
    assert burned == {"87.249.134.7"}


def test_a_reset_older_than_the_cooldown_is_NOT_burned():
    # The ban is temporary — relay 435 measured it expiring between the 13:38
    # and 17:03 fires. Holding an exit out forever would shrink the pool to
    # nothing after one sweep.
    burned = burned_egress_ips([_audit("1.2.3.4", DEFAULT_BURN_COOLDOWN_S + 1)],
                               now_epoch=NOW)
    assert burned == set()


def test_only_a_RESET_burns_an_exit():
    # ⛔ A clean pass, a challenge, or a 403 does NOT mean the exit is unusable.
    # Burning on any outcome would retire the whole pool after one healthy sweep.
    rows = [_audit("1.1.1.1", 10, "no_challenge"),
            _audit("2.2.2.2", 10, "challenge_elicited"),
            _audit("3.3.3.3", 10, "banned"),
            _audit("4.4.4.4", 10, "network_reset")]
    assert burned_egress_ips(rows, now_epoch=NOW) == {"4.4.4.4"}


def test_unreadable_rows_are_skipped_not_guessed():
    rows = [{}, {"egress_ip": None}, {"egress_ip": "5.5.5.5"},            # no ts
            {"egress_ip": "6.6.6.6", "created_at_epoch": NOW, "details": None},
            {"egress_ip": "7.7.7.7", "created_at_epoch": "nonsense",
             "details": {"result": "network_reset"}},
            "not-a-dict"]
    assert burned_egress_ips(rows, now_epoch=NOW) == set()


def test_a_FUTURE_timestamp_is_treated_as_burned():
    """⚠ Clock skew must not read as 'long ago and therefore clean'. A negative
    age is not freshness; the conservative direction is to hold the exit out."""
    assert burned_egress_ips([_audit("8.8.8.8", -600)], now_epoch=NOW) == {"8.8.8.8"}


# ── the plan: one distinct clean exit per host ──────────────────────────────

def test_every_host_gets_its_OWN_region():
    plan = plan_sweep(["a.example", "b.example", "c.example"],
                      ["us-chi", "us-lax", "us-nyc"])
    assert [p["host"] for p in plan] == ["a.example", "b.example", "c.example"]
    assert len({p["region"] for p in plan}) == 3, "an exit was reused within the sweep"


def test_the_plan_is_DETERMINISTIC():
    # A dry-run preview an operator reads must match what actually runs.
    a = plan_sweep(["h1", "h2"], ["us-nyc", "us-chi", "us-lax"])
    b = plan_sweep(["h1", "h2"], ["us-lax", "us-nyc", "us-chi"])
    assert a == b


def test_a_BURNED_region_is_excluded_from_the_pool():
    plan = plan_sweep(["h1"], ["us-chi", "us-lax"],
                      region_to_ip={"us-chi": "87.249.134.7", "us-lax": "1.2.3.4"},
                      burned_ips={"87.249.134.7"})
    assert plan == [{"host": "h1", "region": "us-lax"}]


def test_a_region_with_an_UNKNOWN_ip_stays_usable():
    """We have no evidence it is burned. The live pre-fire check (contract 2)
    is the backstop — excluding unknowns would shrink the pool for no reason."""
    plan = plan_sweep(["h1"], ["us-chi"], region_to_ip={}, burned_ips={"9.9.9.9"})
    assert plan == [{"host": "h1", "region": "us-chi"}]


# ── the refusals — the whole point of the module ────────────────────────────

def test_REFUSES_when_the_clean_pool_is_smaller_than_the_host_list():
    """⛔ THE DEFECT THIS MODULE EXISTS TO PREVENT. Truncating or wrapping around
    would reuse an exit, and the reused hosts would read
    enforcement_corroborated=FALSE — a false negative that looks exactly like
    'not enforcing'. A sweep that cannot be run cleanly must REFUSE, loudly."""
    with pytest.raises(SweepPlanError) as e:
        plan_sweep(["h1", "h2", "h3"], ["us-chi", "us-lax"])
    assert "pool too small" in str(e.value)


def test_REFUSES_when_every_region_is_burned():
    with pytest.raises(SweepPlanError):
        plan_sweep(["h1"], ["us-chi"],
                   region_to_ip={"us-chi": "87.249.134.7"},
                   burned_ips={"87.249.134.7"})


def test_REFUSES_an_empty_host_list():
    for hosts in ([], None, ["", None]):
        with pytest.raises(SweepPlanError):
            plan_sweep(hosts, ["us-chi"])


def test_the_14_host_fortinet_sweep_needs_14_clean_exits():
    """The actual 429 coverage-table scenario, sized."""
    hosts = [f"h{i}.commandcommcentral.com" for i in range(14)]
    with pytest.raises(SweepPlanError) as e:
        plan_sweep(hosts, [f"r{i}" for i in range(13)])
    assert "14 host(s)" in str(e.value)
    ok = plan_sweep(hosts, [f"r{i}" for i in range(14)])
    assert len({p["region"] for p in ok}) == 14


# ── the preview is a description, never a request ───────────────────────────

def test_the_preview_is_always_dry_run_and_fires_nothing():
    prev = build_sweep_preview(["h1", "h2"], ["us-chi", "us-lax"])
    assert prev["dry_run"] is True
    assert prev["fired"] is False
    assert prev["one_host_per_run"] is True, (
        "mid-run rotation would measure reachability on a different exit than "
        "the probe fires from — see the module docstring")
    assert prev["count"] == 2


def test_the_preview_reports_what_it_excluded():
    prev = build_sweep_preview(
        ["h1"], ["us-chi", "us-lax"],
        region_to_ip={"us-chi": "87.249.134.7", "us-lax": "1.2.3.4"},
        burned_ips={"87.249.134.7"})
    assert prev["burned_excluded"] == ["87.249.134.7"]
    assert prev["plan"] == [{"host": "h1", "region": "us-lax"}]


def test_the_module_cannot_fire_anything():
    """⛔ INSTRUMENT-THEN-STOP, asserted rather than asserted-in-prose. A planner
    that grew a subprocess/HTTP call would be a firing path wearing a planner's
    name."""
    # ⛔ AST, NOT A TEXT SCAN. A substring search reds on this module's own
    # docstring, which says "no I/O, no DB, no subprocess" precisely in order to
    # promise the thing being asserted. That is the prose-contains-the-token
    # trap this codebase has now hit four times (relay 373, 382, 430, here), so:
    # read the IMPORTS and the CALL NAMES, which prose cannot fake.
    import ast
    import inspect
    import egress_pool
    tree = ast.parse(inspect.getsource(egress_pool))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"subprocess", "requests", "urllib", "socket", "http", "psycopg",
              "os", "shutil"}
    assert not (imported & banned), (
        f"the planner IMPORTS an I/O path: {sorted(imported & banned)}")

    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "run_cmd" not in called and "open" not in called, (
        f"the planner CALLS an I/O path: {sorted(called)}")
