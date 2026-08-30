# ⛔ HARD BLOCKER — do not run `asm_autoclose_stale_findings(false)`

**Status: BLOCKED for live (destructive) execution as of 2026-08-30.**
Dry-run (`asm_autoclose_stale_findings()` / `(true)`) remains safe and is unaffected.

4.7 rulings ⑰ + ⑳ on Obsidian spec 201. Applies to **both instances**.

---

## Why

The coverage LATERAL in `20260828a` is **any-match with `LIMIT 1`** — it closes a
finding as soon as ONE tool matching the source's producer pattern has
`tool_status -> tool ->> 'ok' = 'true'`:

```sql
LATERAL unnest(sr.tools_run) AS t(tool),
LATERAL unnest(public.asm_autoclose_producer_patterns(e.source)) AS p(pattern)
WHERE t.tool LIKE p.pattern
  AND coalesce(sr.tool_status -> t.tool ->> 'ok', '') = 'true'
ORDER BY sr.completed_at ASC
LIMIT 1
```

`commandsentry_medium` maps to `ARRAY['nuclei%','ffuf','nikto','wafw00f']`. So a
clean `nuclei[php]` chunk satisfies the predicate for a finding that **only the
`nuclei[critical,high]` chunk would ever have re-detected** — and on WAF-fronted
assets that chunk is cut by the wall clock more often than not (Command run #2632:
3 of 6 nuclei chunks cut).

The result is a **silent over-close**: findings marked remediated because a
different part of the tool ran clean, not because anyone looked for them.

Absence of evidence is only meaningful **where we actually looked**. Any-match
does not respect that.

## Why it is not urgent, and what holds the line

Grepped `scripts/`, `.github/`, and the portal `src/` on 2026-08-30:
`asm_autoclose_stale_findings` has **no automatic caller anywhere** — no cron, no
workflow, no portal route, no scanner call. It appears only in two `run_heavy.py`
comments. It is a manual tool, dry-run by default, and has never been run
destructively. The harm is prospective, not active. This document is what holds
the line until the predicate is fixed.

## Required before ANY live run

1. **Predicate rewritten to precise-match** (4.7 ⑰): autoclose only when the
   sub-unit(s) that would actually have re-detected *this* finding ran clean.
   Neither any-match (any clean chunk closes anything) nor pure all-match (every
   chunk must be clean, which on WAF-fronted assets means never closing).
2. **Findings carry their producing sub-unit** — e.g. `findings.source_chunk`
   stamped at emission — or an equivalent template→chunk mapping resolved at
   closure time. Without it the predicate has nothing precise to match on.
3. **Ruling ⑬ landed**: per-chunk names restored as `tool_status` KEYS, with the
   `executed_phases` guard rework (⑯) that the merge requires. Until then
   `tool_status` is keyed by phase name and the granularity precise-match needs
   is only present inside the entry's `per_chunk` field.
4. **The 216 Command dry-run candidates reviewed.** They are a corpus of what the
   current predicate *would* have closed. Reviewing them gives the empirical
   false-close rate, which should drive the precise-match design rather than the
   theoretical analysis above. See [[project_autocloser_tool_success_fix]].
5. Migration applied (**halts all scanning until applied** — coordinate it).

## Note on the current flattening

Right now the registry path writes one phase-level `nuclei` entry with
`ok: false`, so nothing matches and nothing closes — the predicate is
*accidentally* safe. Ruling ⑬'s merge removes that accident by restoring
per-chunk keys. **⑬ must not land before ⑰**, or the window opens.

---
Recorded from 4.7 rulings ⑰/⑳, 2026-08-30. Obsidian 201.
