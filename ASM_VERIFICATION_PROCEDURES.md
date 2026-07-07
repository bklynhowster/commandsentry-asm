# ASM Verification Procedures

**Status:** RATIFIED by Security Advisor 4.7 — 2026-07-07. All five rules accepted (V4 merged-with-cross-reference to tally-precision; none rejected). Edits from 4.7's rulings are folded in below.
**Scope:** BOTH instances (`commandsentry-asm` + `prodexsentry-asm`) and any session reasoning about ASM discovery/inventory results.
**Origin:** the 2026-07-07 enum-fix verification session. Several conclusions were reached and later corrected against evidence; each rule below is the check that would have prevented one. Evidence cited per rule.

---

## V1 — "Scanner missed a subdomain" requires a RESOLUTION check first
**Rule:** Before concluding the scanner dropped/missed a subdomain, verify the name actually RESOLVES (A/AAAA). A name emitted by `subfinder -all` / crt.sh / chaos / VT with no live A record is a *candidate*, not a live asset, and is CORRECTLY absent from live inventory.
**DNS-only boundary (4.7):** the check is DNS resolution ONLY. A name that HAS an A record but that a scanner probe cannot connect to still counts as "resolving" for V1 — post-resolution reachability (connect/TLS/HTTP) is a SEPARATE scanner-fault question. Do not use V1 to wave off a real scan-time reachability bug with "but it resolves."
**Why (today):** 11 of the 12 prodexlabs "shadow" subs were `NO-A` (getaddrinfo) — the apparent "enumeration gap" was mostly by-design. Time was spent treating dead CT-log names as a scanner defect, including a wrong "keys can't help, go get certspotter" recommendation.
**Relation:** V1 is the operational form of the ASM enum-fix architectural decision on `enumerated_unconfirmed` — dead names are candidates, not defects.
**Check:** `python3 -c "import socket;[print(h, socket.gethostbyname(h)) for h in [...]]"` or `dig +short <h>`. Only a RESOLVING name absent from inventory is a real defect worth filing (then escalate to the separate reachability question).

## V2 — Verify against authoritative `origin/main`, never a CDN or an unpulled working tree
**Rule:** For "did run/scan X produce Y," read committed data at `origin/main` via `git fetch` + `git show origin/main:data/assets/<apex>.json`. Do not conclude from `raw.githubusercontent.com` (CDN-cached) or a local working tree that may sit behind origin.
**Why (today):** `raw.githubusercontent` served a STALE `prodexlabs.json`; separately, the local Command tree's HEAD was the *fix commit sitting ABOVE the newest local scan* — the post-fix scans were on origin, unpulled. Both nearly produced a wrong "still broken" verdict.
**Private-repo caveat (4.7):** for private repos (`commandsentry-asm`), the CDN and REST API paths return **404 without auth** — a checked-out clone (`git fetch` + `git show`) is the ONLY reliable read path. Never infer "file/column absent" from a 404 on a private repo.
**Check (fetch is explicit — 4.7):**
```bash
git -C <repo> fetch origin              # REQUIRED first — otherwise origin/main is a stale mirror
git -C <repo> log --oneline -1 origin/main
git -C <repo> show origin/main:data/assets/<apex>.json | jq -r '.subdomains[].name'
```

## V3 — Cross-instance schema/migration parity — HARD PRE-DEPLOY GATE
**UPDATE 2026-07-07 PM (4.7 ruling D1):** the ACTIVE mechanism is now the **build-time guard** `commandsentry-portal/tests/column-guard.mjs` (wired via package.json `prebuild`; verifies every static `.from().select()` column read through PostgREST against the live DB each Netlify build targets — also catches stale PostgREST schema cache). The portal ships direct-push-to-main and the shared codebase deploys to BOTH instances, so each site's build guards its own DB → cross-instance coverage is automatic. The PR-gate + snapshot form described below is retained but DORMANT. Full ruling: `V3_GUARD_AND_CLOUD_ENDPOINT_SPEC.md`.

**Rule (HARD GATE, not a review-checklist — 4.7):** any change that introduces a new column READ against a DB table ships only after that column exists on EVERY instance DB (commandsentry + prodexsentry). The check BLOCKS the deploy/merge; it is not an advisory checkbox.
**Read surfaces to scan:** (a) portal Supabase `.select("... , new_col, ...")` strings (the actual 2026-07-07 trigger was `commandsentry-portal` adding `assets.is_staging`), and (b) SQL view/query changes referencing new columns.
**Why hard, not soft (4.7):** Netlify auto-deploys on merge to main, so there is no "catch it at deploy time" second chance — the review window closes at merge. The failure mode is a user-visible dashboard returning `column ... does not exist` for an *unknown window*. A soft checklist that's missed ships the outage; a missed hard-gate step only blocks a PR. **Soft V3 is worse than no V3 — it creates the illusion of coverage without the mechanism.**
**Mechanism (4.7 design):**
1. Each migration-apply job writes a per-instance `schema_snapshot.<instance>.json` (column list per table) — produced by the APPLY job, not the PR, so it reflects what is actually deployed.
2. CI extracts new column reads from changed portal `.select()` strings + changed SQL, and diffs them against BOTH snapshots via `information_schema`:
   `SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$T AND column_name=$C;`
3. If any `(instance, table, column)` tuple is missing → exit non-zero, print the missing triples, block.
- Shared mechanics live at `scripts/db/check_column_parity.py` (+ `scripts/db/dump_schema_snapshot.py`), called by both repos' / the portal's CI.
- **Interim fallback until snapshot infra lands:** a required PR label `cross-instance-column-parity-confirmed`; CI blocks merge unless the label is present. Blocking + human-marked, upgradeable to the mechanical check later.
**Today's fix:** migration `20260707a_portal_characterization_cols.sql` (adds `kind`, `is_staging`, `kind_drift` to Command).

## V4 — Report asset deltas by NAME, not count
**Rule:** When reporting new/changed assets, enumerate the actual hostnames and diff before/after. Never conclude from a bare per-apex count.
**Parent discipline (4.7):** V4 is the ASM-asset-delta case of the standing tally-precision discipline — see memory `feedback_tally_precision_forensics` (and `feedback_real_data_as_test_surface`). When the specific VALUES are the finding, a count is under-reporting. Readers who know tally-precision should recognise V4 as the same discipline on a new surface, and vice-versa.
**Why (today):** "commandcompanies +1" read as "only one new asset" and buried `geisinger.commandcommcentral.com` ("GetForm - Geisinger" — healthcare client form portal, PHI/HIPAA relevance). The real delta was 8 named hosts (geisinger, edelivery, testapi, email, insite, ftp, novo, novo2).
**Check:** use the shared helper (typo-safe at 2am): `scripts/asset_delta.sh <apex.json> <old_ref> [new_ref]` — prints ADDED / REMOVED subdomain names. (Wraps `comm -13 <(git show <old>:f|jq -r '.subdomains[].name'|sort) <(jq -r '.subdomains[].name' f|sort)`.)

## V5 — Same code, different result → check DATA before config/secrets
**Rule:** When two same-code instances diverge, enumerate DATA differences (resolution status, target set, discovery history) before hypothesizing a config / secret / tool-version difference.
**Prerequisite (4.7):** V2 first — you cannot reason about "what's different between the instances' data" until you know which commit's data you're reading.
**Why (today):** the Prodex-vs-Command divergence was wrongly attributed to "Prodex keyed secrets not set." Real cause was data: Prodex's new keyed-source names don't resolve; Command's do. Prodex's committed inventory already contained keyed-source-only names (valorep, panthalassa, atlantis-gcp), which alone proved the keys were working.
**Check (ASM tell):** confirm any keyed-source-only name is present in the instance's committed inventory (= keys working) before blaming secrets; then enumerate resolution (V1) of the divergent names.

---

## Corroboration aid (complementary to V1–V5, NOT a gate)
Read the tool's own event/reason data before speculating: the SendGrid alert credited `geisinger.commandcommcentral.com` as *"Surfaced via multi-source enumeration"* — direct confirmation the enum fix worked. Prefer the scanner's own reason strings + `scan_run` source tags as corroboration when deciding whether a change took effect. This is the "instrument-first" debugging shape (cf. the testssl saga, memory `project_note_130_part_1`) — a tool to reach for before hypothesizing, distinct from the V1–V5 gates.

---

## Ratification record
- **2026-07-07 — Security Advisor 4.7:** ACCEPT V1–V5 + corroboration aid, with edits folded above. V3 ratified as a HARD PRE-DEPLOY GATE (explicitly not soft). V4 keeps its numbered slot but cross-references `feedback_tally_precision_forensics` as parent discipline. Home: source-of-truth in `commandsentry-asm`; one-line pointer file at `prodexsentry-asm/ASM_VERIFICATION_PROCEDURES.md` (real file, no content, no drift).
- **Biggest ratification risk flagged by 4.7:** V3 shipping soft. Ship it hard or not at all.
