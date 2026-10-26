#!/usr/bin/env python3
"""Regression tests for demotion_writer.py pure cores (no DB needed).

Covers the 4.7 load-bearing risks:
  - Q4 anti-single-probe: one flaky probe can never demote.
  - Q2 strengthened gate: partial outage / near-threshold / min-fleet / consecutive.
  - Q8 anti-drift: writer NOTICE_DAYS / DWELL_DAYS must equal v_asset_reachability's leaves_on
    (migration 20261026a; job 3t replaced the July function, which nothing called).
  - Job 3t: the notice floor (NULL = hold), the two clocks, stale checks, coming back.
  - Q5 classification: RST vs timeout -> service_gone vs unreachable.

Run: python3 scripts/db/test_demotion_writer.py   (or pytest).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from datetime import datetime, timedelta, timezone

import demotion_writer as dw

UTC = timezone.utc


# ── Q4: multi-probe aggregation — the anti-single-probe guard ──
def test_probe1_fail_probe2_success_stays_alive():
    # probe#1 says service_gone, probe#2 says alive -> MUST NOT demote.
    assert dw.aggregate_probes(["service_gone", "alive"], False)["decision"] == "alive"

def test_unanimous_concrete_demotes():
    r = dw.aggregate_probes(["service_gone", "service_gone", "service_gone"], False)
    assert r["decision"] == "demote_candidate" and r["reason"] == "service_gone"

def test_mixed_reasons_hold():
    assert dw.aggregate_probes(["dns_gone", "service_gone", "unreachable"], False)["decision"] == "mixed"

def test_importer_bump_midprobe_aborts():
    assert dw.aggregate_probes(["service_gone", "service_gone"], True)["decision"] == "alive"

def test_inconclusive_is_not_demotable():
    # resolver hiccup on a probe -> not unanimous-concrete -> HOLD, never demote.
    assert dw.aggregate_probes(["service_gone", "inconclusive", "service_gone"], False)["decision"] == "mixed"


# ── Q5: port outcome -> reason ──
def test_classify_ports():
    assert dw.classify_ports(["open", "refused"]) == "alive"
    assert dw.classify_ports(["refused", "refused"]) == "service_gone"
    assert dw.classify_ports(["noresponse", "noresponse"]) == "unreachable"
    assert dw.classify_ports(["refused", "noresponse"]) == "service_gone"  # ambiguous -> bounded
    assert dw.classify_ports([]) == "service_gone"


# ── Q2: strengthened sweep-health gate ──
def test_gate_healthy():
    g = dw.evaluate_gate(bumped=80, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert g["ok"] and g["reason"] == "healthy"

def test_gate_first_run_bootstraps():
    # First-ever sweep: no prior marker -> not consecutive -> ok False, but coverage_ok
    # True so the __sweep__ marker records healthy and run 2 can pass. Guards the deadlock
    # where sweep_healthy echoed the final gate decision and nothing ever went healthy.
    g = dw.evaluate_gate(bumped=80, denom=100, prev_healthy=None, prev_age_hours=None)
    assert not g["ok"] and g["coverage_ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_partial_outage_blocks():
    # 30% observed -> low fraction -> demote nothing (the failure the >=1-bump gate missed)
    g = dw.evaluate_gate(bumped=30, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert not g["ok"] and not g["coverage_ok"] and g["reason"] == "sweep_unhealthy_low_fraction"

def test_gate_near_threshold_human_review():
    g = dw.evaluate_gate(bumped=55, denom=100, prev_healthy=True, prev_age_hours=6.0)
    assert not g["ok"] and g["reason"] == "near_threshold_human_review"

def test_gate_no_consecutive_healthy():
    g = dw.evaluate_gate(bumped=90, denom=100, prev_healthy=False, prev_age_hours=6.0)
    assert not g["ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_prev_sweep_too_old():
    g = dw.evaluate_gate(bumped=90, denom=100, prev_healthy=True, prev_age_hours=20.0)
    assert not g["ok"] and g["reason"] == "no_consecutive_healthy_sweep"

def test_gate_min_fleet_requires_100():
    assert not dw.evaluate_gate(4, 5, True, 6.0)["ok"]          # 80% on tiny fleet -> blocked
    assert dw.evaluate_gate(5, 5, True, 6.0)["ok"]              # 100% on tiny fleet -> ok

def test_gate_empty_fleet():
    assert not dw.evaluate_gate(0, 0, True, 6.0)["ok"]


# ── Q8: writer/SQL constant parity (anti-drift) ──
def test_flip_at_values():
    # Job 3t D2 ("Cut it down to 7 days"): one clock for every reason; the July
    # 'unreachable' HOLD is gone.
    t = datetime(2026, 7, 1, tzinfo=UTC)
    assert dw.flip_at(t, "dns_gone", None) == t + timedelta(days=7)
    assert dw.flip_at(t, "service_gone", None) == t + timedelta(days=7)
    assert dw.flip_at(t, "unreachable", None) == t + timedelta(days=7)
    assert dw.flip_at(t, "service_gone", 30) == t + timedelta(days=30)  # override

def test_dwell_matches_sql_migration():
    """NOTICE_DAYS / DWELL_DAYS must equal v_asset_reachability's leaves_on (migration 20261026a).
    The July version of this test read 20260712a's CASE; that function is dropped by 20261026a."""
    mig = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "migrations", "20261026a_reachability.sql")
    sql = " ".join(open(mig).read().split())
    m = re.search(r"\+ make_interval\(days => greatest\(coalesce\(a\.dark_patience_override_days, (\d+)\), (\d+)\)\) END AS leaves_on", sql)
    assert m, "could not find leaves_on's day count in 20261026a"
    # the default AND the floor (D2: never sooner than 7 days; Qwen code review MF1)
    assert int(m.group(1)) == int(m.group(2)) == dw.NOTICE_DAYS == 7
    assert set(dw.DWELL_DAYS.values()) == {dw.NOTICE_DAYS}
    assert set(dw.DWELL_DAYS) == {"dns_gone", "service_gone", "unreachable"}


def test_first_observed_none_guard_present():
    """Regression: ASM Discover #369/#370 (2026-07-19). A freshly-discovered asset
    (e.g. the new perimeter-IP assets) has first_observed=NULL; run() MUST short-
    circuit None before `now() - first_observed`, or the whole job dies with
    `TypeError: unsupported operand type(s) for -: 'datetime.datetime' and 'NoneType'`.
    Source-level check because the eligibility math is inline in run() and run()
    needs a live DB (same static-test convention as the rest of this file)."""
    import inspect
    # Job 3t: the eligibility math moved from run() into the pure flip_decision().
    src = inspect.getsource(dw.flip_decision)
    assert "first_observed is None" in src, (
        "flip_decision() must guard first_observed=None before subtracting it — "
        "removing this guard reintroduces the #369/#370 crash."
    )
    t = datetime(2026, 11, 1, tzinfo=UTC)
    assert dw.flip_decision(notice_since=t - timedelta(days=9), leaves_on=t - timedelta(days=2),
                            first_observed=None, demoted_so_far=0, at=t) == "not_eligible_7d"


# ── Job 3t: the floor, the clocks, stale checks, coming back ──
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

def _dec(notice, leaves, first=T0 - timedelta(days=100), done=0, at=T0):
    return dw.flip_decision(notice_since=notice, leaves_on=leaves, first_observed=first,
                            demoted_so_far=done, at=at)

def test_null_notice_is_a_hold_never_floor_satisfied():
    # MF3: a host nobody was warned about is never removed, however long ago it last answered.
    assert _dec(None, None) == "no_notice_yet"
    assert _dec(None, T0 - timedelta(days=30)) == "no_notice_yet"

def test_within_the_week_holds_then_flips():
    notice = T0 - timedelta(days=6, hours=23)
    assert _dec(notice, notice + timedelta(days=7)) == "within_dwell"
    assert _dec(notice, None) == "within_dwell"            # a notice with no leave date still holds
    notice = T0 - timedelta(days=7, minutes=1)
    assert _dec(notice, notice + timedelta(days=7)) is None  # flip

def test_young_and_rate_limited_still_hold():
    n = T0 - timedelta(days=8)
    assert _dec(n, n + timedelta(days=7), first=T0 - timedelta(days=3)) == "not_eligible_7d"
    assert _dec(n, n + timedelta(days=7), done=dw.RATE_LIMIT) == "rate_limited"

def test_checks_are_fresh_is_twelve_hours():
    assert dw.checks_are_fresh(T0 - timedelta(hours=11, minutes=59), at=T0)
    assert not dw.checks_are_fresh(T0 - timedelta(hours=12, minutes=1), at=T0)
    assert not dw.checks_are_fresh(None, at=T0)
    assert dw.VERDICT_FRESH_HOURS == 12

def _sql(q):
    return " ".join(q.split())

def test_candidates_come_from_the_view_and_carry_the_raw_clock():
    q = _sql(dw.Q_CANDIDATES)
    assert "JOIN public.v_asset_reachability r ON r.asset_id = a.asset_id" in q
    assert "AND r.not_responding" in q
    assert q.startswith("SELECT a.asset_id, a.last_alive_at, a.first_observed, r.last_answer_at, "
                        "r.notice_since, r.leaves_on")
    assert "r.last_answer_at < now() - %(show)s::interval" in q

def test_the_race_guard_and_the_flip_lock_stay_on_the_raw_clock():
    # MF7: a fresh verdict must never look like "a scan bumped the clock mid-probe".
    assert _sql(dw.Q_LAST_ALIVE) == "SELECT last_alive_at FROM public.assets WHERE asset_id = %(a)s"
    assert "AND last_alive_at = %(eval)s" in _sql(dw.Q_FLIP)
    import inspect
    src = inspect.getsource(dw.run)
    assert "multi_probe(conn, asset_id, last_alive, ports)" in src
    assert 'cur.execute(Q_FLIP, {"a": asset_id, "reason": reason, "eval": last_alive})' in src

def test_the_writer_probes_the_workers_port_set():
    import inspect
    assert "select_probe_ports(asset_id, known_ports(conn, asset_id))" in inspect.getsource(dw.run)

def test_stale_checks_stop_everything_before_the_notice_step():
    import inspect
    src = inspect.getsource(dw.run)
    assert src.index("if not fresh:") < src.index("notices_and_come_backs(") < src.index("if not gate[\"ok\"]:")

def test_the_notice_is_stamped_on_not_responding_and_cleared_on_an_answer_or_a_hold():
    st, cl = _sql(dw.Q_STAMP_NOTICE), _sql(dw.Q_CLEAR_NOTICE)
    assert "SET fade_detected_at = now()" in st and "AND r.not_responding AND a.fade_detected_at IS NULL" in st
    assert "SET fade_detected_at = NULL" in cl
    assert "a.dark_hold_reason IS NOT NULL OR (r.last_answer_at IS NOT NULL AND r.last_answer_at > a.fade_detected_at)" in cl

def test_coming_back_uses_the_resurrection_hook_on_a_recent_answer():
    assert "r.discovery_status = 'went_dark' AND r.last_answer_at > now() - %(win)s::interval" in _sql(dw.Q_COME_BACK)
    assert dw.COME_BACK_HOURS == 24
    import inspect
    src = inspect.getsource(dw.notices_and_come_backs)
    assert "resurrect_if_dark(cur, asset_id" in src and "if write_enabled:" in src
    assert '"would_resurrect"' in src

def test_the_liveness_worker_probes_went_dark_hosts():
    import asset_liveness_probe as alp
    assert _sql(alp.Q_CONFIRMED_LIVE) == ("SELECT asset_id FROM public.assets "
                                         "WHERE discovery_status IN ('confirmed_live', 'went_dark')")


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run())


def test_a_refused_reprobe_is_an_answer_and_never_removes():
    """Howie 2026-10-25 10:00: "a host with any port that answers is UP". The view counts a
    refusal as an answer; so does the writer's own re-probe at the end of the week."""
    import inspect
    assert dw.REMOVABLE_REASONS == ("dns_gone", "unreachable")
    src = inspect.getsource(dw.run)
    i_hold = src.index('if reason not in REMOVABLE_REASONS:')
    assert src.index('emit(reason, False, "reprobe_refused_is_an_answer")') > i_hold
    assert i_hold < src.index("Q_SET_FADE") < src.index("flip_decision(") < src.index("Q_FLIP")


def test_the_twelve_hour_freshness_rule_is_the_views():
    """Qwen code review minor 3: the writer's stale-checks guard and the view's checks_fresh are
    one rule in two languages; this pins them together."""
    mig = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "migrations", "20261026a_reachability.sql")
    sql = " ".join(open(mig).read().split())
    assert sql.count("f.newest_check > now() - interval '12 hours'") == 2      # checks_fresh + not_responding
    assert dw.VERDICT_FRESH_HOURS == 12
