# ASM Advisor Review — V3 build-guard mechanism + cloud-endpoint change-tracking

**Status:** RATIFIED by Security Advisor 4.7 — 2026-07-07 (PM). All D1–D10 accepted (D2 = fix `email_links` now; D9 = flag `email.commandcompanies.com` now). **Part 1 (V3 build-guard) SHIPPED** — `commandsentry-portal` `faafb3e`, first guarded build Published. **Part 2 (cloud-endpoint) PENDING** — D8 migration → D9 flag → D10 classifier.
**Scope:** `commandsentry-portal` (Part 1) + ASM change-detection/alerter on both instances (Part 2).
**Provenance:** both items surfaced this afternoon by applying the V1–V5 verification procedures 4.7 ratified this morning (dogfooding). Neither is a guess — evidence is inline.

---

## PART 1 — V3 enforcement: build-time column guard (shape change from the ratified PR gate)

### What changed since ratification
This morning 4.7 ratified V3 as a HARD gate implemented as a **PR-triggered** check (+ snapshot/label mechanism). Ground truth discovered since: **the portal ships by direct push to `main` → Netlify auto-build → deploy. There are no pull requests.** The `is_staging` outage itself shipped that way (portal commits `dcac4ec`, `2e71f5d` went straight to `main`; recent history has zero merge commits). A PR-triggered gate therefore never fires — it would be pure illusion-of-coverage, the exact thing 4.7 warned against.

This is a V5 moment (check the actual workflow before designing the control). The **hardness is unchanged**; only the **trigger** moves: PR-time → build-time.

### Proposed mechanism (built + validated)
`commandsentry-portal/tests/column-guard.mjs`, wired via `package.json` `"prebuild"` so it runs automatically before `next build`; a failure fails the build and Netlify never deploys the break. It:
- Parses **static** `.from('t').select('literal')` reads under `src/`.
- Verifies each referenced column **through PostgREST** against the live DB the build targets — so it also catches a **stale PostgREST schema cache** after a migration, not just a truly-missing column.
- Prefers the service-role key (verifies all tables), falls back to anon.
- Precision controls: relation embeds `rel(...)` stripped; only `.select` **immediately** following `.from` is paired (excludes `.update/.insert/.upsert` writes and cross-statement mis-pairs); dynamic template-literal selects reported + skipped; RLS-unreadable tables → "cannot verify" warn; missing env in CI → fail-closed.

### Validation (live Command DB, post-migration)
Verified clean across 20+ tables/views incl. `assets` (**18 columns, `is_staging` present**). Two parser false-positive classes (embeds; write-statement mis-pairs) were caught **by testing before wiring** and fixed. **The guard also caught a real pre-existing bug on its first run** (see below).

### Real bug the guard found
`src/app/assets/[asset_id]/preview/page.tsx` runs `.from("email_links").select("link_id, asset_id, link_status").eq("asset_id", assetId)`, but **`email_links` has no `asset_id`** (PostgREST returns HTTP 400 on `asset_id`, 200 on `link_target_id` — probed live). The table is polymorphic (`link_type` + `link_target_id`); the correct pattern is used in `src/lib/email/correspondence.ts` (`.eq("link_type","asset").eq("link_target_id", assetId)`). That asset-preview lookup 400s at runtime today.

### Decision points (Part 1)
- **D1 — Ratify the shift PR-gate → build-time guard** for the portal's direct-push flow? *Rec: ACCEPT.* Keep the pushed `column-parity-gate.yml` PR workflow as a dormant backstop (harmless; useful if PRs are ever adopted) or delete it — *Rec: keep, marked dormant.*
- **D2 — The pre-existing `email_links.asset_id` bug — how to ship the guard green:**
  - **(A)** fix the preview query (`asset_id` → `link_type='asset'` + `link_target_id`), re-run to green, then wire + push. *Rec.*
  - **(B)** grandfather it in a documented `KNOWN_MISSING` exception (guard warns, doesn't block), wire + push now, fix separately (ratchet).
  *Howie deferred this to 4.7. Please rule A or B.*
- **D3 — Precision/recall stance for a DEPLOY-blocking guard.** Proposed: **fail only on high-confidence missing-column on parseable static selects; warn (non-blocking) on dynamic/RLS/unparseable; fail-closed only when env is entirely absent in CI.** Rationale: a false-positive blocks *all* deploys (worse than a miss). Reconcile with the morning's "fail-closed / no illusion" ruling: fail-closed on *can't-verify-at-all*, precision-first on *individual* unparseable reads. *Confirm or tighten.*
- **D4 — Cross-instance coverage.** Each portal build verifies **its own** target DB. If `commandsentry-portal` code is *also* deployed to the Prodex instance (shared codebase, different DB), the guard must run against BOTH DBs. Topology needs confirming. *Rec: per-build-own-DB if separate repos/deploys; both-DBs if shared. I'll verify the deploy topology and report.*
- **D5 — Fate of the snapshot tooling** (`scripts/db/check_column_parity.py` + `dump_schema_snapshot.py`, from the morning's design). The live-DB build guard supersedes it for the portal (simpler, more faithful, no snapshot maintenance, catches PostgREST cache lag). *Rec: keep the scripts in-repo as an offline/CI complement, but designate the build guard as the ACTIVE V3 mechanism.*

---

## PART 2 — Cloud/rotating-endpoint change-tracking suppression

### Trigger + evidence
A `[COMMANDsentry] 95 surface change(s)` alert (2026-07-07 15:25 UTC, all **NOTICE, 0 WATCH**, **1 asset**): **31 IPs "removed" + 64 services "closed"** (mail ports 25/80/110/143/443/587/993/995), all on `email.commandcompanies.com`. Zero added; zero "went dark." **All 31 removed IPs are Microsoft 365 / Exchange Online ranges** (`52.96.x`, `40.104.x`, `2603:1036::`). Live resolve right now: the host is **UP** on a *different* set of O365 IPs (`40.104.46.50`, `52.96.122.18`, `52.96.165.130`, `52.96.182.18`).

### Root cause
`email.commandcompanies.com` is the Microsoft 365 mail endpoint. O365 load-balances across a large **rotating** IP pool by design. The ASM tracks the asset **per-IP**, so every scan resolves a different slice → mass add/remove IP churn + per-(IP,port) service flap. Not a security event, not an outage — recurring **noise** that will fire on every scan for any cloud/CDN-fronted asset.

### Proposal
Classify cloud/managed endpoints and **suppress per-IP surface-change alerting** for them; track them by DNS name / CNAME target / cert identity instead.

### Decision points (Part 2)
- **D6 — Detection method.** Options: (a) IP membership in known cloud ranges/ASNs (Microsoft/O365, Cloudflare, Akamai, AWS/Azure/GCP); (b) CNAME/MX target matches a known provider (outlook/office365, cloudflare, etc.); (c) volatility heuristic (≥N distinct IPs across M scans → mark volatile); (d) manual flag override. *Rec: (b) CNAME/MX-target match as primary (cheap, reliable) + (a) IP-range as secondary + (c) as a backstop for unknown providers + (d) manual override.*
- **D7 — Suppress what, keep what.** *Rec:* suppress per-IP add/remove and per-(IP,port) service open/close for cloud-classified assets; **KEEP** DNS-name-level changes (CNAME/MX target change), cert changes, and the **aggregate** observed-port *set* (not per-IP). A CNAME re-point or cert swap is still a real, alertable change.
- **D8 — Model as kind vs modifier.** *Rec:* a **modifier flag** (`is_cloud_endpoint` + `cloud_provider`), folded into Host Characterization exactly like `is_staging` — not a functional `kind`. Reuses the 20260705b column pattern.
- **D9 — Immediate stopgap.** `email.commandcompanies.com` is flapping now. *Rec: YES — manually flag it (and any obvious O365/CDN asset) as a cloud endpoint immediately to stop the noise while the general detection ships.*
- **D10 — Initial provider scope.** *Rec:* ship Microsoft/O365 (the live case) + Cloudflare + Akamai first; expand to AWS/Azure/GCP ranges next.

---

## For 4.7
Please return numbered rulings for **D1–D10** (accept / modify / reject + any conditions). Two are gating other work: **D2** (blocks wiring the guard) and **D9** (immediate noise stopgap). Note both parts are the same underlying pattern as the morning's `kind`/`is_staging` work — the ASM mis-modeling a host — and both were caught by the V1–V5 procedures in practice.
