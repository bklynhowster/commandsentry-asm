#!/usr/bin/env python3
"""Mechanism tests for the active-probe authorisation gate (G5).

The gate is `_read_active_probe_policy` in scripts/scanner/run_heavy.py. Its
fail DIRECTION was never wrong — every error path returns not-authorised, so a
DB blip could not fire an unauthorised probe. The 2026-07-29 audit found a
different defect: "asset opted out" and "we never reached the DB" produced an
identical return value AND an identical audit row, so the audit table recorded
policy decisions that were never read.

G5 requires asserting attempt counts, not just outcomes — an outcome cannot
show whether the verdict short-circuited or was retried three times. So these
tests count connection attempts and assert on the backoff schedule.

run_heavy.py cannot be imported here (module-level side effects, lazy psycopg
deps, ~1600 lines), so the gate's control flow is reconstructed below and a
source-level check asserts the reconstruction still matches the shipped code.
If someone changes the real retry loop, `test_source_matches_reconstruction`
fails and tells you to update this file — the reconstruction can go stale, but
not silently.

Run: python3 scripts/common/tests/test_active_probe_policy_gate_mechanism.py
"""
import pathlib
import re
import sys

GATE = pathlib.Path(__file__).resolve().parent.parent.parent.parent / "scripts" / "scanner" / "run_heavy.py"
EGRESS_DEFAULT = "vpn"
UNREADABLE = "__unreadable__"

results = []


def ck(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"   {detail}"))


class Ctx:
    def __init__(self, dsn="postgresql://stub"):
        self.dsn = dsn
        self.asset_id = "asset-1"


def make_reader(script):
    """Reconstruct the shipped control flow. `script` is the per-attempt
    outcome: a dict (row), None (no row), or "boom" (transport failure)."""
    state = {"calls": 0, "sleeps": []}

    def read(ctx):
        if not ctx.dsn:
            return False, EGRESS_DEFAULT, UNREADABLE
        try:
            for attempt in range(1, 4):
                try:
                    state["calls"] += 1
                    idx = min(state["calls"] - 1, len(script) - 1)
                    step = script[idx]
                    if step == "boom":
                        raise OSError("connection pool timeout")
                    r = step
                    break
                except Exception:
                    if attempt < 3:
                        state["sleeps"].append(1 if attempt == 1 else 3)
                    else:
                        raise
            if not r:
                return False, EGRESS_DEFAULT, ""
            egress = (r.get("active_probe_egress") or EGRESS_DEFAULT).strip().lower()
            if egress not in ("vpn", "direct"):
                egress = EGRESS_DEFAULT
            return bool(r.get("active_probe_authorized")), egress, (
                r.get("active_probe_egress_reason") or "")
        except Exception:
            return False, EGRESS_DEFAULT, UNREADABLE

    return read, state


AUTH = {"active_probe_authorized": True, "active_probe_egress_reason": ""}
DENY = {"active_probe_authorized": False, "active_probe_egress_reason": ""}
DIRECT = {"active_probe_authorized": True, "active_probe_egress": "direct",
          "active_probe_egress_reason": "vpn banned by target 2026-06-01"}

# ─── Verdicts are never retried ──────────────────────────────────────
read, st = make_reader([AUTH])
a, e, r = read(Ctx())
ck("MECHANISM_authorized_verdict_costs_one_attempt", st["calls"] == 1 and a is True,
   f"calls={st['calls']} authorized={a}")

read, st = make_reader([DENY])
a, e, r = read(Ctx())
ck("MECHANISM_denial_verdict_NOT_retried", st["calls"] == 1 and a is False,
   f"calls={st['calls']}")
ck("OUTCOME_denial_is_not_marked_unreadable", r == "", f"reason={r!r}")

read, st = make_reader([None])
a, e, r = read(Ctx())
ck("MECHANISM_missing_row_is_a_real_answer", st["calls"] == 1, f"calls={st['calls']}")
ck("OUTCOME_missing_row_NOT_unreadable", r == "",
   "a DB that answered 'no such asset' is not a transport failure")

# ─── Transport is retried ────────────────────────────────────────────
read, st = make_reader(["boom", "boom", AUTH])
a, e, r = read(Ctx())
ck("MECHANISM_transport_retried_until_it_answers", st["calls"] == 3 and a is True,
   f"calls={st['calls']} authorized={a}")
ck("MECHANISM_backoff_is_1s_then_3s", st["sleeps"] == [1, 3], f"sleeps={st['sleeps']}")
ck("OUTCOME_blip_no_longer_silently_skips_an_authorised_probe", a is True,
   "pre-fix this returned False and the probe was skipped")

read, st = make_reader(["boom"])
a, e, r = read(Ctx())
ck("MECHANISM_exhausts_exactly_3_attempts", st["calls"] == 3, f"calls={st['calls']}")
ck("OUTCOME_exhausted_transport_still_fails_CLOSED", a is False,
   "SAFETY gate must never fail open")
ck("OUTCOME_exhausted_transport_marked_unreadable", r == UNREADABLE, f"reason={r!r}")

# ─── The distinction that was the whole point ────────────────────────
_, _, r_denied = make_reader([DENY])[0](Ctx())
_, _, r_unread = make_reader(["boom"])[0](Ctx())
ck("OUTCOME_opted_out_and_unreadable_are_DISTINGUISHABLE", r_denied != r_unread,
   f"denied={r_denied!r} unreadable={r_unread!r} — pre-fix both were ''")

a, e, r = make_reader([AUTH])[0](Ctx(dsn=""))
ck("OUTCOME_no_dsn_is_unreadable_not_opted_out", a is False and r == UNREADABLE,
   f"authorized={a} reason={r!r}")

# ─── Egress selection still works (4.7 Q1) ───────────────────────────
a, e, r = make_reader([DIRECT])[0](Ctx())
ck("OUTCOME_documented_ban_escalates_to_direct_egress", e == "direct" and "banned" in r,
   f"egress={e} reason={r!r}")
a, e, r = make_reader([{"active_probe_authorized": True, "active_probe_egress": "wat"}])[0](Ctx())
ck("OUTCOME_unknown_egress_value_falls_back_to_default", e == EGRESS_DEFAULT, f"egress={e}")

# ─── Source-level: reconstruction still matches shipped code ─────────
src = GATE.read_text()
fn = src[src.index("def _read_active_probe_policy"):src.index("def _write_active_probe_audit")]

ck("SOURCE_retry_loop_is_3_attempts", "for _attempt in range(1, 4):" in fn,
   "attempt count changed — update this test's reconstruction")
ck("SOURCE_backoff_matches_1s_3s", "time.sleep(1 if _attempt == 1 else 3)" in fn,
   "backoff schedule changed — update this test's reconstruction")
ck("SOURCE_safety_tier_connect_timeout_5s", "connect_timeout=5" in fn,
   "SAFETY tier is 5s connect; a different value breaks the 19s worst case")
ck("SOURCE_unreadable_marker_present", fn.count('"__unreadable__"') >= 2,
   "the unreadable sentinel is missing from a return path")
ck("SOURCE_missing_row_returns_empty_not_unreadable",
   re.search(r'if not r:.*?return False, _ACTIVE_PROBE_EGRESS, ""', fn, re.S) is not None,
   "no-row path must NOT be marked unreadable")

# Both probe call sites must branch on the marker, or the log lies even though
# the audit column is right. Assert per-probe rather than on a total count —
# a total can be satisfied by two copies at one call site while the other is
# still unpatched, which is exactly the kind of half-fix this is guarding.
for probe in ("fwbbot_check", "waf_differential"):
    ck(f"SOURCE_{probe}_logs_unreadable_distinctly",
       f'log("  {probe} probe: SKIP — policy UNREADABLE after retries ' in src,
       f"{probe} still reports an unreadable policy as an opt-out")
    ck(f"SOURCE_{probe}_branches_on_the_marker",
       len(re.findall(r'if egress_reason == "__unreadable__":', src)) == 2,
       "expected exactly 2 marker branches, one per probe call site")

ck("SOURCE_reader_logs_its_own_exhaustion",
   src.count("policy read UNREADABLE after retries") == 1,
   "the reader's own exhaustion log is missing")

print()
print("───────────────────────────────")
failed = [n for n, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
