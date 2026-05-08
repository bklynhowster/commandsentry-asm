# COMMANDsentry — Decision Log

Architecture decisions, kept in chronological order. ADR-lite format: each decision states what we picked, why, and what we're explicitly NOT doing.

---

## 2026-05-07 — D-001: Project naming

**Decision:** COMMANDsentry ASM
**Why:** Fits the COMMAND* family naming (COMMANDcentral). "Sentry" implies passive watching, which is the ASM mode of operation. "ASM" suffix for clarity vs. an unrelated Sentry product.
**Alternatives considered:** COMMANDscope, COMMANDscan, COMMANDview.

---

## 2026-05-07 — D-002: Repository visibility — PRIVATE

**Decision:** Single private GitHub repo `commandsentry-asm`.
**Why:** Findings JSON = exploit roadmap. Public history is forever. Risk dramatically outweighs the convenience of free Actions minutes.
**Trade-off accepted:** GitHub Free private = 2000 Actions minutes/mo. Will need GitHub Pro ($4/mo, 3000 min) or self-hosted runner once we go past ~3 nightly targets.
**Alternatives considered:**
- Public repo — rejected, too risky.
- Hybrid (engine public, data private) — deferred to Phase 2+ if engine becomes portfolio-worthy.

---

## 2026-05-07 — D-003: Orchestrator — GitHub Actions

**Decision:** GitHub Actions handles scheduling (cron) and ad-hoc runs (workflow_dispatch).
**Why:** Already on GitHub. Zero extra infra. Free tier sufficient for Phase 1. Can swap to self-hosted runner without changing the workflow file structure.
**NOT doing:** Netlify Scheduled Functions (26s timeout, no scanner binaries). Mac launchd (must be online; external scans shouldn't egress from Command LAN). AWS Lambda + EventBridge (more infra, no benefit at this scale).

---

## 2026-05-07 — D-004: Storage — JSON in repo (Phase 1)

**Decision:** Findings written as JSON files committed back to the repo by the scan workflow.
**Why:** Zero-infra. Git history = scan history. Free. Easy to diff. Dashboard reads files directly with no DB layer.
**Migration trigger:** When repo size > 500MB or scan history retention > 1 year, migrate raw artifacts to Cloudflare R2 (still free at <10GB), keep summary JSON in repo.

---

## 2026-05-07 — D-005: Target input model

**Decision:** Five target types — `fqdn`, `apex`, `ip`, `cidr`, `asn`. Apex and CIDR auto-discover and surface candidates to a `discovered[]` review queue. Every target requires `scope_verified: true` before any scan runs.
**Why:** Real attackers don't care about names. We need to be able to scan an IP that turns up in a netflow log without first hunting for a hostname. Scope-verification gate is the legal/abuse safety rail.
**NOT doing:** Open public scanner without scope verification (CFAA risk, abuse-as-a-service surface).

---

## 2026-05-07 — D-006: Brand template

**Decision:** Use the canonical Command brand kit (`~/Documents/Obsidian Vault/Brand & Design/00 - Command Brand Template System.md`). Reuse 70% of the existing vuln-report HTML template's CSS/JS for the dashboard.
**Why:** Already proven, brand-compliant, kinetic effects work. Saves 10+ hours of dashboard-from-scratch work.

---

## 2026-05-07 — D-007: Hard rule on risk ratings

**Decision:** `overall_risk` MUST be exactly one of `LOW`, `MODERATE`, `MODERATE-HIGH`, `HIGH`, `CRITICAL`. No compounds (`LOW-MODERATE` etc.).
**Why:** Inherited from existing vuln-report convention. Compound ratings are confusing and visually inconsistent in the dashboard.
**Validator:** `normalize.py` rejects writes with bad values. Workflow fails early.

---

## 2026-05-07 — D-008: Scope is ASM only — vuln scanning explicitly out

**Decision:** COMMANDsentry covers attack surface management only — discovery, inventory, exposure tracking. No CVE matching, no plugin/version vuln lookup, no DAST, no exploit testing.

**Why:** Earlier draft of this project conflated ASM with vuln scanning and tried to lift the entire deep-probe rig into the cloud. Howie called it out — they're different jobs. ASM is "what's exposed and what changed." Vuln scanning is "what known weaknesses are present." Cleaner to build them as separate systems and let them inform each other.

**Trade-off accepted:** COMMANDsentry won't tell us "Elementor 2.8.3 has CVE-2020-13126." It will tell us "this asset is running Elementor 2.8.3" — and we (or the deep-probe rig) take it from there.

**Tool stack reflects scope:**
- IN: subfinder, dnsx, httpx, naabu, fingerprintx, wafw00f, testssl, nuclei (exposure templates only — `-tags exposure,misconfig,disclosure`), whois
- OUT: nikto, wpscan, ZAP, Playwright, dalfox, retire.js, trufflehog, gau, gf, full nuclei CVE templates

**Schema reflects scope:** No `cvss`, no `cve_list`, no `proof_of_exploit`, no `cwe`. The schema describes asset state and exposure flags only. Severity is binary (`notice` / `watch`), not CVSS.

**NOT doing:** Adding "but also a couple of CVE checks" is slippery slope back to vuln-scanning-in-the-cloud. If we ever want that capability cloud-side, it's a separate project (or Module 9+ that runs the deep-probe rig in a separate workflow, with its own dashboard tab). Hold the line.

**Future scope expansion (deliberate):** The README's bottom section lists what CAN come later — once ASM is solid, vuln scanning could be wired in as an additive layer. Not now.

---

## 2026-05-07 — D-009: Engine is target-agnostic; "COMMAND" reflects origin not constraint

**Decision:** The COMMANDsentry application accepts any FQDN, IP, CIDR, or ASN target — Command-owned or otherwise — provided the operator has authorization (`scope_verified: true`). Nothing in the engine, schema, or scoring logic is Command-specific.

**Why:** Howie's clarification (2026-05-07): the intent is Command Digital coverage *first*, but the tool itself is general-purpose. Same code that scans `commanddigital.com` would scan any other authorized target identically. Naming reflects origin (Command is the first operator), not a hard scope.

**What this means in practice:**
- `asset.owner` is a free-form string tag, not an enum locked to "command_digital." Operators set it to whatever org/team owns the asset.
- Example targets.yml shows Command targets first, but the schema accepts anything.
- Scope verification (the legal/abuse rail) stays mandatory regardless of who the operator is.
- If we ever offer this as a service to Command's clients (Flavor B from earlier scoping) or as a public SaaS (Flavor C), the engine doesn't change — multi-tenancy + per-operator scope verification get layered on top.

**Trade-off accepted:** None significant. The constraint we DO keep — refusing to scan without scope verification — is the legal/abuse rail and applies universally.

**NOT doing:** Hard-coding any Command-Digital-specific assumptions into the engine, schema, dashboard, or alerting. Brand kit on the dashboard is a presentation layer concern, not an engine concern.

---

## (template for future entries)

## YYYY-MM-DD — D-NNN: Title

**Decision:**
**Why:**
**Trade-off accepted:**
**NOT doing:**
