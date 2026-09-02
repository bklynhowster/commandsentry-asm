# ⛔ HARD BLOCKER — `asm_autoclose_stale_findings(false)` is blocked

**Status: BLOCKED for live (destructive) execution.**
Dry-run (`asm_autoclose_stale_findings()` / `(true)`) is safe and unaffected.

As of migration **`20260902a`** the block is a **runtime property of the
function**, not just this document: calling it with `p_dry_run = false` raises.
Removing that guard requires writing a new migration — deliberately, not by
edit. 4.7 rulings ⑰ + ⑳, decomposed per ㊺. Applies to **both instances**.

---

## What changed on 2026-09-02

`20260828a`'s coverage LATERAL was **any-match with `LIMIT 1`** — one tool
matching the source's producer pattern with `ok='true'` closed the finding.
`commandsentry_medium` maps to `ARRAY['nuclei%','ffuf','nikto','wafw00f']`, so a
clean `nuclei[php]` chunk satisfied it for a finding only `nuclei[critical,high]`
would ever have re-detected.

`20260902a` replaces it with **all-match**: every producer tool *present* in
`tools_run` must be `ok='true'`, plus a presence check so a run that exercised
none of them cannot satisfy it vacuously.

Absence of evidence is only meaningful **where we actually looked**. Any-match
did not respect that. All-match does.

## 🔴 A PREDICTION IN THE PREVIOUS VERSION OF THIS FILE WAS WRONG

The 2026-08-30 text said pure all-match meant *"every chunk must be clean, which
on WAF-fronted assets means never closing."* That was reasoning, not
measurement, and **it is false**. Measured 2026-09-02 with
`scripts/db/checks/autoclose_allmatch_compare.sql`:

| instance | any-match | all-match | over-closes removed |
|---|---|---|---|
| Command | 230 | **202** (88%) | 28 |
| Prodex | 42 | **39** | 3 |

All-match retains the large majority of closures. The reason the prediction
missed: nuclei is only one of four producers for `commandsentry_medium`, and it
is the only one that is frequently PARTIAL — `ffuf`, `nikto` and `wafw00f` all
measured 100% ok. A cut nuclei blocks *medium* closures specifically, not
closures generally.

Per-source detail:

| source | any | all | note |
|---|---|---|---|
| commandsentry_medium | 12 | **0** | every medium closure today is unsupported |
| commandsentry_light | 19 | 3 | 16 of 19 unsupported |
| commandsentry_heavy | 138 | 138 | naabu+fingerprintx, genuinely clean |
| nuclei | 28 | 28 | |
| testssl | 33 | 33 | |

## Under-closing is EXPECTED, not a bug

After `20260902a` the autocloser closes **less** than before. That is the point.
If someone reports "the autocloser barely fires," the answer is:

* all-match is intentionally conservative — it is strictly a subset of what
  any-match closed, so it can never over-close relative to the old behaviour;
* a low closure rate on a source means the fleet lacks clean coverage for that
  source, which is a finding about the **scanner**, not about the predicate;
* `commandsentry_light` closing almost nothing is currently explained by
  `httpx_tech` measuring **0% ok** — the WAF-403 tech-detect defect surfacing
  here. Fix the scanner, not the predicate.

Do not "fix" a low closure rate by loosening the predicate.

## Required before ANY live run — four gates

1. **All-match empirically validated as sufficient, OR precise-match ready.**
   Precise-match = autoclose only when the sub-unit that would actually have
   re-detected *this* finding ran clean. All-match is the conservative interim.
2. **Findings carry their producing sub-unit** (e.g. `findings.source_chunk` at
   emission, or a template→chunk mapping resolved at closure). Required for
   precise-match **only** — ⑰ did not need it.
3. **The 216 Command dry-run candidates reviewed** for calibration. Sampled
   review (~20–30 across categories) is sufficient; this is not blocking ⑰ but
   it is the corpus that should drive any precise-match design.
4. **A live-monitoring plan**, and an explicit decision that the autocloser
   should run live.

## ⑬ IS DEFERRED — revive only on a specific trigger

⑬ (per-chunk `tool_status` KEYS) and ⑯ (the `executed_phases` guard rework that
⑬ forces) were **decomposed out** on 2026-09-02 (4.7 ㊺). The ㊺ gate was
verified against live data: nuclei lands as ONE flattened `tool_status` entry
carrying its detail in `per_chunk`, so all-match needed no per-chunk keys.

**Revive ⑬ only if ONE of these is true:**

1. Precise-match predicate work becomes the priority — it needs per-chunk
   identity in the predicate join.
2. jsonb-path queries against the `per_chunk` array become prohibitively complex
   for real analysis work.
3. The ㊻ progress-only fix proves insufficient for a concrete operational need
   that specifically requires per-chunk KEYS rather than the `per_chunk` array.

**Do NOT revive it on general "we should update this eventually" grounds.**
⑯ falls out of scope with ⑬ — without ⑬'s merge writing per-chunk names into
`tools_run`, `run_phase`'s double-execution guard keeps working as-is.

The old ordering trap ("⑬ must not land before ⑰") is **discharged**: ⑰ has
landed, so the window ⑬ would have opened no longer exists.

## Not changed, deliberately

`commandsentry_heavy`'s pattern list stays `ARRAY['naabu','fingerprintx']`.
`run_heavy.py` can emit that source from three further producers
(`_emit_passive_cors_finding`, `_maybe_emit_no_waf_finding`,
`run_safe_exploit_phase`), but all **176** such findings on Command are
`Service inventory:` rows from naabu/fingerprintx, and none of the other three
has ever emitted. Widening the list would change behaviour on 176 correct
findings to guard against zero actual ones. **Latent, not live** — revisit only
if one of those producers starts emitting.

Likewise the **alias-vs-required-set ambiguity** in
`asm_autoclose_producer_patterns` is left alone: `testssl` →
`['testssl.sh','testssl']` is two aliases for one tool, while
`commandsentry_medium` → four names is a required set. The all-match reading
that required every *pattern* (ALL-B) was rejected because it can never be
satisfied for alias lists — it zeroed all 27 Prodex testssl closures. Fixing the
overload is its own piece of work.

---
4.7 ⑰/⑳ recorded 2026-08-30; shipped and corrected 2026-09-02 per ㊺/㊼.
Obsidian 201, 208.
