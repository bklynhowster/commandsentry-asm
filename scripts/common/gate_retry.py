#!/usr/bin/env python3
"""
gate_retry.py — the verdict-vs-transport invariant, as a reusable library.
4.7 rulings G1/G3 (Obsidian 163), 2026-07-25.

    VERDICT-VS-TRANSPORT INVARIANT
    Any gate that makes a pass/fail decision from an external system's
    response must distinguish a VERDICT (the system answered) from a
    TRANSPORT failure (we never reached it). Verdicts fail-closed and are
    NEVER retried — retrying only re-fails with the same answer. Transport
    failures retry with backoff; if retries exhaust, the outcome is
    UNREADABLE, which is semantically distinct from "verdict = fail".

WHY THIS EXISTS. `check_migrations_applied.py` sat on the 10-minute scan
cron doing one connect, no retry, fail-closed. Scanner run #1348 hit a
transient `connection timeout expired` against a DB that was demonstrably
healthy (73/73 ledger rows matched minutes later; neighbouring ticks green
in 21-43s) and killed the tick. Fail-closed was right for a ledger
DISAGREEMENT; it was wrong for "I don't know yet."

G1 ruled this a SYSTEM-WIDE invariant and required a shared library rather
than per-gate reimplementation, because documentation-only discipline
decays and gates drift. Import this; do not hand-roll retry.

DESIGN NOTE — what is retried, deliberately narrow. Only `TransportFailure`
and the caller's declared `transport_errors` tuple retry. Every other
exception PROPAGATES. A programming error (AttributeError, KeyError) must
not be swallowed, retried three times, and then reported as "the database
was unreadable" — that would convert a code bug into a phantom infra
incident and send someone hunting the wrong thing.

USAGE
    def _read():
        # return a Verdict, or raise TransportFailure / a declared error
        ...
    v = run_with_transport_retry(_read, FAST_CRON, transport_errors=(OSError,))
    if v.unreadable:  ...
    if not v.passed:  ...
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence, Tuple, Type

__all__ = [
    "Verdict", "TransportFailure", "GateBudget",
    "SAFETY", "PROGRESS", "FAST_CRON",
    "run_with_transport_retry", "UNREADABLE_REASON",
]

UNREADABLE_REASON = "transport_unreadable_after_retries"


class TransportFailure(Exception):
    """We never got an answer. Retryable.

    Raise this (or declare your driver's error types via `transport_errors`)
    for connect timeouts, resets, DNS failures, pooler errors — anything
    that means the external system did not render a judgement.
    """


@dataclass(frozen=True)
class Verdict:
    """An ANSWER about gate state. Authoritative; never retried.

    `passed=False` from a real answer ("not on the allowlist", "migration
    unapplied") is a different thing from `passed=False` because we could
    not read — `unreadable` is what separates them, and callers MUST branch
    on it rather than on `passed` alone when deciding whether to alert.
    """

    passed: bool
    reason: str
    payload: object = None
    unreadable: bool = False
    attempts: int = 1

    @property
    def is_real_answer(self) -> bool:
        return not self.unreadable


@dataclass(frozen=True)
class GateBudget:
    """Time envelope for one gate. G3: budget is tiered by criticality.

    `ceiling_s` is the contract; `worst_case_s` is what this config actually
    costs. `validate()` refuses a config that cannot honour its own ceiling,
    so a budget can't silently drift past the tier it claims to be in.
    """

    name: str
    attempts: int
    backoffs_s: Sequence[float]
    connect_timeout_s: float
    ceiling_s: float
    note: str = ""

    @property
    def worst_case_s(self) -> float:
        used = list(self.backoffs_s)[: max(0, self.attempts - 1)]
        return self.attempts * self.connect_timeout_s + sum(used)

    def validate(self) -> None:
        if self.attempts < 1:
            raise ValueError(f"{self.name}: attempts must be >= 1")
        if len(self.backoffs_s) < self.attempts - 1:
            raise ValueError(f"{self.name}: need >= attempts-1 backoffs")
        if self.worst_case_s > self.ceiling_s:
            raise ValueError(
                f"{self.name}: worst case {self.worst_case_s}s exceeds "
                f"ceiling {self.ceiling_s}s"
            )


# ── Tiers (G3) ────────────────────────────────────────────────────────────
# SAFETY   — protects against real-world consequences (unauthorised scanning,
#            target impact). Can afford the largest budget; the downside of a
#            wrong proceed dwarfs the cost of a slow gate.
SAFETY = GateBudget(
    name="safety", attempts=3, backoffs_s=(1, 3), connect_timeout_s=5,
    ceiling_s=30,
    note="ROE, active-probe authorisation, VPN egress. Worst case 19s.",
)

# PROGRESS — affects operational velocity, not real-world consequences.
PROGRESS = GateBudget(
    name="progress", attempts=3, backoffs_s=(1, 3), connect_timeout_s=3,
    ceiling_s=15,
    note="Feature-flag / capability checks. Worst case 13s.",
)

# FAST_CRON — runs on a tight schedule; a slow gate eats the cadence.
#
# DELIBERATE DEVIATION FROM G3's LITERAL 10s. G3 set fast-cadence gates at a
# 10s total budget. That is not reachable against a remote pooler: a single
# connect attempt with any survivable timeout plus two retries exceeds it, so
# a literal 10s ceiling would force attempts=1 — which is exactly the
# single-shot behaviour that caused run #1348. Implemented at connect_timeout
# 4s + backoffs 1s/3s = 16s worst case, ~1.6x the letter of G3 and well inside
# the 10-MINUTE cron period it must not overrun. Flagged rather than silently
# obeying an infeasible number or silently keeping the old 70s.
FAST_CRON = GateBudget(
    name="fast_cron", attempts=3, backoffs_s=(1, 3), connect_timeout_s=4,
    ceiling_s=20,
    note="10-min scan-tick gates (migration ledger). Worst case 16s. "
         "See deviation note — G3 letter is 10s, infeasible vs a pooler.",
)

for _b in (SAFETY, PROGRESS, FAST_CRON):
    _b.validate()


def run_with_transport_retry(
    fn: Callable[[], Verdict],
    budget: GateBudget,
    transport_errors: Tuple[Type[BaseException], ...] = (),
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Verdict:
    """Run `fn` under the verdict-vs-transport invariant.

    `fn` returns a Verdict (authoritative, returned immediately) or raises
    TransportFailure / one of `transport_errors` (retried). Anything else
    propagates untouched — see the DESIGN NOTE above.

    Exhausted retries return a Verdict with unreadable=True and
    passed=False. Callers decide the FAIL DIRECTION: safety gates must
    treat unreadable as block (G4); progress gates MAY proceed, but only
    behind an explicit operator-set env var, never a code default.

    `attempts` on the returned Verdict is load-bearing for tests (G5) —
    it is how a test proves the verdict short-circuit actually fired
    rather than inferring it from an exit code.
    """
    budget.validate()
    retryable = (TransportFailure,) + tuple(transport_errors)
    last: Optional[BaseException] = None

    for attempt in range(1, budget.attempts + 1):
        try:
            v = fn()
        except retryable as e:
            last = e
            if attempt < budget.attempts:
                back = budget.backoffs_s[attempt - 1]
                if on_retry:
                    on_retry(attempt, e, back)
                sleep(back)
                continue
            break
        if not isinstance(v, Verdict):
            raise TypeError(
                f"gate fn must return Verdict, got {type(v).__name__}"
            )
        # A real answer — including a negative one. Do NOT retry.
        return Verdict(v.passed, v.reason, v.payload, False, attempt)

    return Verdict(
        passed=False,
        reason=UNREADABLE_REASON,
        payload=last,
        unreadable=True,
        attempts=budget.attempts,
    )
