# Gate Criticality Matrix

**Ratified 2026-07-25 (4.7 rulings G1–G5, Obsidian 163).** Classification drives retry
budget and — critically — **fail direction**. Any new gate must be added here before it
ships.

## The invariant every gate obeys

> Any gate that makes a pass/fail decision from an external system's response must
> distinguish a **VERDICT** (the system answered) from a **TRANSPORT** failure (we never
> reached it). Verdicts fail-closed and are **never retried** — retrying only re-fails with
> the same answer. Transport failures retry with backoff; exhausted retries produce
> **UNREADABLE**, which is semantically distinct from "verdict = fail".

Implementation lives in `scripts/common/gate_retry.py`. **Do not hand-roll retry in a
gate** — G1 required one shared library precisely so gates cannot drift apart.

## Tiers

| tier | budget | fail direction on UNREADABLE | may fail open? |
|---|---|---|---|
| **SAFETY** | 3 attempts, 5s connect, 1s/3s backoff — **19s** worst case (ceiling 30s) | **BLOCK. Always.** | **NEVER.** No env var. Not configurable. |
| **PROGRESS** | 3 attempts, 3s connect, 1s/3s backoff — **13s** (ceiling 15s) | BLOCK by default | Only via an explicit operator-set env var |
| **FAST_CRON** | 3 attempts, 4s connect, 1s/3s backoff — **16s** (ceiling 20s) | BLOCK by default | Only via an explicit operator-set env var |

**Deviation from G3, flagged deliberately.** G3 set fast-cadence gates at a **10s** total
budget. That is unreachable against a remote pooler — one connect attempt with any
survivable timeout plus two retries exceeds it, so a literal 10s ceiling forces
`attempts=1`, which is exactly the single-shot behaviour that caused run #1348. Shipped at
16s worst case: ~1.6× the letter of G3, and 0.03% of the 10-minute cron period it must not
overrun. Raise it in review if you disagree — do not silently revert to single-shot.

## Safety gates — fail-closed always, no fail-open switch exists

These protect against real-world consequences: unauthorised scanning, target impact,
egress over an unapproved network. A wrong *proceed* has consequences outside our system.
`gate_retry` exposes no fail-open path for these, and none may be added.

| gate | file | protects | status |
|---|---|---|---|
| ROE / ownership | `scripts/scanner/roe_gate.py` | no active scan without ownership on the allowlist | ✅ **fixed 2026-07-25** — SAFETY budget, retries transport, verdicts short-circuit, alert only after exhausted retries |
| active-probe authorisation | `run_heavy.py` (`active_probe_authorized`) | no intrusive probe without per-asset opt-in | ⬜ audit pending |
| VPN egress check | `scanner.yml` VPN bring-up + carve-out | no scan egressing over an unapproved network | ⬜ audit pending |

## Progress gates — may fail open, but only on an explicit operator decision

These affect operational velocity, not real-world consequences. Fail-open is permitted
because a false block costs cadence, not safety — but it must be a deliberate operational
choice via env var, **never a code default**, and it must be loud.

| gate | file | env to fail open | status |
|---|---|---|---|
| migration ledger | `scripts/db/check_migrations_applied.py` | `LEDGER_GATE_TRANSPORT_MODE=fail_open` | ✅ **fixed 2026-07-25**, refactored onto `gate_retry` |
| queue claim | `scripts/scanner/poll_queue.py` | *(none — see note)* | ✅ **fixed 2026-07-26** — FAST_CRON retry on connect. No fail-open switch: "proceed without a queue row" is meaningless, so unreadable still exits non-zero and no scan is claimed. |

## Not gates — scheduled writers

These do not authorise anything; they write state on a schedule. Their fail direction
("don't write") is already correct. They still deserve retry for **noise** reduction, not
correctness.

| script | note |
|---|---|
| `scripts/db/device_class_runner.py` | no retry; a blip = a failed classify run |
| `scripts/db/demotion_writer.py` | no retry; destructive-adjacent, keep fail-closed |
| `scripts/db/asset_liveness_probe.py` | no retry |

## The one that needs a real decision — `cloud_ip_check.py`

It **fails OPEN to DEEP** by 4.7 P5: any error → full top-1000 port sweep.

The rationale for P5 was coverage — missing a real origin's services (fail-closed) is worse
than a few phantoms. That reasoning is about *our data quality*, and by that measure
fail-open is right.

**But fail-open here means "scan the target harder."** Classified as an efficiency gate,
that is the safe direction. Classified as a target-impact control, it is the **unsafe**
direction — a DB blip escalates a curated 4-port probe into a 1000-port sweep against
someone else's infrastructure, which is the kind of thing ROE exists to prevent.

**Current call: efficiency gate, fail-open retained** — the ROE gate is what actually
authorises scanning that target, and it fails closed. `cloud_ip_check` only chooses depth
*within* an already-authorised scan, so it cannot cause an unauthorised scan.

**Worth revisiting if** the port-sweep depth ever becomes the thing a target complains
about. Then it moves to SAFETY and fails closed to SHALLOW. Flagged here rather than
settled silently, because the classification is the whole argument.

## Adding a gate

1. Classify it in this table **before** writing code.
2. Import `gate_retry`; pick the tier. Do not hand-roll retry.
3. Return `Verdict` for real answers; raise `TransportFailure` for anything else.
4. Branch on `.unreadable`, not on `.passed` alone, when deciding whether to alert.
5. Write **mechanism** tests (G5) — assert attempt counts, not just exit codes. An exit
   code cannot prove the verdict short-circuit fired.
6. Safety gate? Then no fail-open switch. Not "defaulting to closed" — *absent*.
