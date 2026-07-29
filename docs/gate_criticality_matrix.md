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
| active-probe authorisation | `run_heavy.py` (`_read_active_probe_policy`) | no intrusive probe without per-asset opt-in | ✅ **audited + fixed 2026-07-29** — fail direction was already correct; retry added and `__unreadable__` marker introduced so the audit stops recording an unread policy as a decision |
| VPN egress check | `scripts/scanner/vpn_bringup.sh` step 6 | no scan egressing over an unapproved network | ✅ **audited + fixed 2026-07-29** — **was failing OPEN**; now exits 4/5 rather than proceeding unverified |

### Audit findings, 2026-07-29

**VPN egress check — this one was live and wrong.** It ran a single `curl` to ipify; if
that one request failed it logged `"single curl probe didn't return an IP (continuing —
tunnel is up per wg-quick)"`, set `VPN_IP="<unknown>"`, and the comparison was then skipped
by the `!= "<unknown>"` guard. One flaky HTTP request was sufficient to run a scan with
egress **unverified** — potentially over the naked GitHub runner address, which is the one
outcome this gate exists to prevent. `wg-quick`'s exit code and `ip route` prove the
interface came up; they do not prove traffic leaves through it, and a wrong route table
satisfies both.

Two structural problems behind it: the verification probe was *weaker* than the baseline
measurement it verified against (1 provider vs 3), and the failure mode was written as a
log line rather than a verdict. Fixed by extracting `probe_egress_ip()` — used for **both**
baseline and verification — and replacing the fail-open with distinct exits:

| condition | classification | exit |
|---|---|---|
| IP changed | verdict pass | 0 |
| IP unchanged | verdict fail | 3 |
| IP unreadable after 3×3 probes | transport exhausted | **4** |
| no baseline captured | unverifiable | **5** |

**Active-probe authorisation — correct outcome, dishonest record.** Every error path already
returned not-authorised, so no DB blip could ever *fire* an unauthorised probe; the fail
direction never needed changing. The defect was epistemic: `"asset opted out"` and `"we
never reached the DB"` produced an identical return value *and* an identical audit row, so
the audit table recorded policy decisions that were never read. Now retries transport
(SAFETY budget) and returns `__unreadable__` in the reason slot, which flows to
`details.egress_reason` in the jsonb audit column. Both call sites — `fwbbot_check` and
`waf_differential` — log the distinction. A missing row stays a *real answer*, not
unreadable.

Neither gate uses `gate_retry.py` directly: one is bash, the other predates the library and
sits inside a lazy-import block. Both implement the SAFETY budget by hand and are covered by
mechanism tests (`scripts/common/tests/test_vpn_egress_gate_mechanism.sh`, `scripts/common/tests/test_active_probe_policy_gate_mechanism.py`).
**Port them onto `gate_retry` when either is next touched substantively.**

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
