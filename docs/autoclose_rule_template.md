# Autoclose Rule Template — mandatory checklist

**Ratified 2026-07-25 (4.7 rulings Q1–Q7, Obsidian 163).** Every proposed autoclose rule
fills this in. A rule that cannot answer all ten items does not ship.

> **Read Q1 first.** As of 2026-07-25 **no standing autoclose rule exists for infra
> artifacts, and that is the ruling, not an oversight.** The cert_trust and naabu artifact
> classes were fixed at source; empirical recurrence is zero; auto-closing HIGH findings is
> the highest-blast-radius automation in the system. We ship a **detector that reports**
> (`scripts/db/detect_infra_artifacts.py`) instead. This template exists so that *if* a
> future pattern ever justifies a rule, the discipline is already written down and does not
> get reinvented under time pressure.

## Ship boundary — read before proposing anything

The detector produces an operator review queue. **There is no code path from detector
output to write authority, and adding one is not a small change.** If you want autoclose,
you justify it from scratch against this template — you do not "wire up the detector we
already have." That path retains every risk of standing autoclose while claiming to be
conservative.

**Revisit trigger (Q1):** if the detector reports non-zero candidates for **4 consecutive
cycles**, that is the empirical signal that recurrence is no longer zero. Escalate to a
standing-rule design review with the fresh data. Until then, the answer is no.

---

## The ten items (Q5)

### 1. Predicate empirically grounded
Traceable to a specific source cause, with numbers. *"78% of the cert_trust surge was
IP-path invocation, adjudicated host-by-host with openssl under correct SNI"* qualifies.
*"These look like noise"* does not.

> **Rule:** ______

### 2. Predicate exact-match — NO substring matching (Q4)
Key on **structured columns**: `check_id`, `source`, `asset_type`, `device_class`, `port`.
Never on finding text.

```sql
-- BAD — this is the one that closed 18 wrong rows
WHERE finding_id ILIKE '%cert_trust%'          -- also matches cert_trust_wildcard

-- GOOD — structured, exact
WHERE check_id = 'cert_trust'
  AND EXISTS (SELECT 1 FROM assets a
              WHERE a.asset_id = findings.asset_id AND a.asset_type = 'ip_address')
```

If finding text is the *only* distinguishing signal, that is a signal to **add a structured
field to the finding**, not to substring-match. If text matching is genuinely unavoidable,
use full-string equality — it fails safely (closes nothing) when the producer's format
changes.

> **Known trap:** the naabu rows have `port` **NULL**, so `port NOT IN (...)` matched
> nothing. Parsing identity out of a string `finding_id` is a workaround, not a design.
> Fix the emitter first.

### 3. Predicate versioned (Q4/Q7)
`autoclose_<pattern>_v1`. Never mutate a predicate in place — **even a clarifying `NOT`
clause creates v2**, with v1 retired after v2 proves out. Extensions to scope (new severity
tier, new asset class) are a **new rule**, not an amendment.

### 4. Dry-run soak
7–14 days log-only before any write. The dry run must materialise the **same row set** via
CTE that the live run would update — not an approximation.

### 5. Rate ceiling
Max N closes per rule per day. Defence against runaway. **Threshold-abort:** refuse to run
at all if the match count exceeds N or M% of open findings.

### 6. Structured audit
Every close writes `admin_audit_log`: rule version, close reason, prior status, matched
fields. Non-human closes carry a **mandatory machine-enforced tag** so an automated close is
never indistinguishable from a human clicking "this is wrong."

### 7. Reversibility
Documented undo: manual reopen, plus a script to revert the last N closes by rule version.

### 8. Sweep-health gate
Do not run during scanner outages. Same discipline as the demotion writer.

### 9. Fleet-wide dry-run audit
Run the predicate against the **full fleet** before enabling. Verify the would-close set
matches expectation with **no unexpected matches**. This is the step that would have caught
the 18-of-25 over-match before it happened.

### 10. Monitor + retire
Track close rate. Rate drops to zero for N cycles → **retire the rule**, the source fix
made it moot. Rate spikes → investigate, the source fix regressed.

---

## Terminal status (Q2)

`false_positive` — **never `remediated`**.

- `remediated` = the vulnerability was real and has been fixed.
- `false_positive` = it was never real. A detection error.

An infra artifact was never real. Using `remediated` inflates remediation metrics with
findings nobody remediated.

Carry a structured reason: `status_reason: 'autoclose_cert_trust_ip_artifact_v1'`.

> **Backlog note (Q2 correction):** the *existing* coverage-matched autoclose
> (`20260626a`) writes `remediated` for "producer re-ran and no longer sees this" — which
> can mean either "fixed" or "the scanner stopped producing it for unrelated reasons."
> Arguably wrong, not urgent, logged here rather than fixed in flight.

## HIGH findings (Q3)

Automation **may identify** HIGH candidates. Automation **may not close** a HIGH finding
without operator confirmation.

Not a blanket prohibition — sometimes the automated conclusion is right and the finding is
HIGH (cert_trust artifacts are HIGH by testssl's default severity and are empirically
inapplicable). But the mechanism is: rule identifies candidate → pending queue → operator
reviews → operator confirms → close fires. That is **batch-close with automation-assisted
candidate identification**, not autoclose-with-review.

LOW/MEDIUM may fire-and-forget, still with dry-run soak and narrow predicates.

## The silent-success trap (Q6)

A rule that returns zero rows reports "0 closes, success." That is indistinguishable from a
rule whose predicate is **structurally broken** — a renamed column, a wrong join, a schema
change. Silent failure; the rule looks healthy while providing zero value.

**Every rule must health-check against a known fixture before running:**

```python
def health_check(self):
    """Prove the predicate can match SOMETHING before trusting a zero result."""
    if not execute_predicate(self.predicate, asset_id=self.fixture_asset_id):
        raise PredicateBrokenError(
            f"{self.version}: predicate does not match known fixture "
            f"{self.fixture_asset_id}. Rule aborted — NOT reporting 0-closes success."
        )
```

Fixtures are dedicated `is_fixture = true` rows, excluded from real close operations so the
rule cannot zero out its own health check. **Review fixtures periodically** — as producers
evolve, a fixture representing today's finding shape may not represent tomorrow's.

> Related trap, same family: a Supabase `UPDATE` without `RETURNING` prints *"Success. No
> rows returned"* regardless of how many rows changed. This bit us three times on
> 2026-07-25. **Always `RETURNING`, always verify with a follow-up `SELECT`.**

## Retired rules

Stay in `autoclose_rules_registry` with `retired_at`, `superseded_by_version`,
`retired_reason`. Forensic questions ("why was this old finding autoclosed?") need
traceable history.
