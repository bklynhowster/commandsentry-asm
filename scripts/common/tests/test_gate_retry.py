"""G5: assert MECHANISM (attempt counts, short-circuit, propagation),
not just outcome. Names carry MECHANISM_/OUTCOME_ per G5 correction."""
import gate_retry as g

FAILS = []
def check(name, cond, extra=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"   {extra}" if not cond else ""))
    if not cond: FAILS.append(name)

NOSLEEP = lambda _s: None
def budget(attempts=3): return g.GateBudget("t", attempts, (1,3), 1, 99)

# ── MECHANISM ────────────────────────────────────────────────────────────
calls={"n":0}
def verdict_deny():
    calls["n"]+=1; return g.Verdict(False,"not_on_allowlist")
v=g.run_with_transport_retry(verdict_deny,budget(),sleep=NOSLEEP)
check("MECHANISM_verdict_is_not_retried", calls["n"]==1 and v.attempts==1, f"calls={calls['n']}")
check("OUTCOME_verdict_deny_fails_closed", v.passed is False and v.is_real_answer)
check("MECHANISM_denied_verdict_is_not_flagged_unreadable", v.unreadable is False)

calls={"n":0}
def two_then_ok():
    calls["n"]+=1
    if calls["n"]<3: raise g.TransportFailure("timeout")
    return g.Verdict(True,"allowed")
v=g.run_with_transport_retry(two_then_ok,budget(),sleep=NOSLEEP)
check("MECHANISM_transport_retries_until_success", calls["n"]==3 and v.attempts==3, f"calls={calls['n']}")
check("OUTCOME_recovered_transport_returns_real_answer", v.passed and v.is_real_answer)

calls={"n":0}
def always_down():
    calls["n"]+=1; raise g.TransportFailure("connection timeout expired")
v=g.run_with_transport_retry(always_down,budget(),sleep=NOSLEEP)
check("MECHANISM_exhausts_exactly_attempts_times", calls["n"]==3 and v.attempts==3, f"calls={calls['n']}")
check("MECHANISM_exhausted_is_unreadable_not_verdict", v.unreadable and v.reason==g.UNREADABLE_REASON)
check("OUTCOME_unreadable_does_not_masquerade_as_a_real_answer", v.is_real_answer is False)

# the whole point: a denial and an unreadable are distinguishable
deny=g.run_with_transport_retry(verdict_deny,budget(),sleep=NOSLEEP)
check("MECHANISM_unreadable_distinguishable_from_denial",
      deny.reason!=v.reason and deny.unreadable!=v.unreadable)

# declared driver errors retry; programming errors DO NOT
calls={"n":0}
class DriverErr(Exception): pass
def driver_down():
    calls["n"]+=1; raise DriverErr("pooler")
v=g.run_with_transport_retry(driver_down,budget(),transport_errors=(DriverErr,),sleep=NOSLEEP)
check("MECHANISM_declared_driver_errors_retry", calls["n"]==3 and v.unreadable)

calls={"n":0}
def bug():
    calls["n"]+=1; raise AttributeError("typo")
try:
    g.run_with_transport_retry(bug,budget(),sleep=NOSLEEP); raised=False
except AttributeError: raised=True
check("MECHANISM_programming_errors_propagate_not_retried", raised and calls["n"]==1, f"calls={calls['n']}")

# backoff schedule actually used
slept=[]
calls={"n":0}
g.run_with_transport_retry(always_down,budget(),sleep=slept.append)
check("MECHANISM_backoff_schedule_applied", slept==[1,3], f"slept={slept}")

# single-attempt budget = no retry at all (regression guard for #1348 shape)
calls={"n":0}
v=g.run_with_transport_retry(always_down,budget(attempts=1),sleep=NOSLEEP)
check("MECHANISM_attempts_1_is_single_shot", calls["n"]==1 and v.unreadable)

# ── budget contract ──────────────────────────────────────────────────────
try:
    g.GateBudget("bad",3,(1,3),20,10).validate(); ok=False
except ValueError: ok=True
check("MECHANISM_budget_refuses_config_exceeding_its_ceiling", ok)
check("OUTCOME_shipped_tiers_are_within_ceilings",
      all(b.worst_case_s<=b.ceiling_s for b in (g.SAFETY,g.PROGRESS,g.FAST_CRON)))
check("OUTCOME_no_tier_is_single_shot",
      all(b.attempts>=3 for b in (g.SAFETY,g.PROGRESS,g.FAST_CRON)))

try:
    g.run_with_transport_retry(lambda:"nope",budget(),sleep=NOSLEEP); ok=False
except TypeError: ok=True
check("MECHANISM_non_verdict_return_is_a_hard_error", ok)

print(f"\n{'ALL PASS' if not FAILS else 'FAILURES: '+', '.join(FAILS)}")
raise SystemExit(1 if FAILS else 0)
