# COMMANDsentry ASM

**A self-hosted, automated, dashboard-driven external attack surface monitor.**

> Owner: Howie Schneider
> Status: Module 1 complete (ASM-scoped)
> Last update: 2026-05-07

---

## What this is — and what it isn't

COMMANDsentry watches an external attack surface and tells you what's exposed and **what changed**. Nothing more.

**The application is target-agnostic.** It accepts any FQDN, IP, IP range, or (Phase 2) ASN as input — provided the operator has scope authorization to scan it. The system was built for Command Digital's own assets first, which is why it's named COMMANDsentry, but nothing in the engine is Command-specific. The same install can scan any attack surface its operator is authorized to test.

The only hard rule baked into the tool is the scope-verification gate: a target won't scan unless `scope_verified: true` is set, and verification means the operator owns the asset, controls its DNS, or holds written authorization to scan it. The tool refuses to be a free reconnaissance service for things you don't own.

**This is ASM. Not a vuln scanner.** Vuln scanning, CVE matching, DAST, plugin enumeration — all of that stays in the local deep-probe rig and the existing scan tools on the Mac. COMMANDsentry feeds *into* that workflow by surfacing what to look at next, but it doesn't try to replace it.

**ASM answers:**
- What assets do we own / are we exposing? (FQDNs, IPs, services)
- What's running on them? (tech, ports, certs, headers, WAF)
- What changed since last scan? (new subdomain, new port open, cert expiring, service disappeared)

**ASM does NOT answer:**
- Are there known CVEs in this version? *(deep-probe job)*
- Can I exploit this? *(pentest job)*
- Is the business logic broken? *(DAST/manual job)*

If we eventually want those answers in the cloud too, that's a future module — explicitly out of scope today.

## Architecture

```
┌─────────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│ DISCOVERY ENGINE        │ ───► │ STORAGE              │ ───► │ NETLIFY DASHBOARD   │
│ GitHub Actions cron     │      │ JSON in repo         │      │ Asset list,         │
│ runs asm-discover.sh    │      │ /data/assets/*.json  │      │ inventory grid,     │
│ per target              │      │                      │      │ exposure deltas,    │
│                         │      │ Per-asset record:    │      │ "what changed"      │
│ Tools (lean stack):     │      │ identity, inventory, │      │ view                │
│   subfinder, dnsx,      │      │ exposures, history   │      │                     │
│   httpx, naabu,         │      │                      │      │ Branded with        │
│   fingerprintx, wafw00f,│      │                      │      │ Command kit         │
│   testssl, nuclei       │      │                      │      │                     │
│   (exposure tpl only),  │      │                      │      │                     │
│   whois                 │      │                      │      │                     │
└─────────────────────────┘      └──────────────────────┘      └─────────────────────┘
```

## Tool stack — ASM-only

| Tool | Job |
|---|---|
| **subfinder** | Passive subdomain enum (apex targets) |
| **dnsx** | DNS resolution, A/AAAA/CNAME/MX/TXT/NS records |
| **httpx** | Live-host detection + HTTP tech fingerprinting (`-td`) |
| **naabu** | TCP port discovery (top 1000) |
| **fingerprintx** | Service identification on open ports |
| **wafw00f** | WAF/CDN detection |
| **testssl.sh** | TLS cert + protocol posture |
| **nuclei** | **Exposure templates only** (`-tags exposure,misconfig,disclosure`) — exposed admin panels, .git, .env, debug endpoints. **NOT CVE matching.** |
| **whois** | Registrar, ASN, IP-range owner |

Notably **NOT in this stack**: nikto, wpscan, ZAP, Playwright, dalfox, retire.js, trufflehog, gau, gf. Those are vuln-scanning / DAST tools — they live in the deep-probe rig.

## Modular build plan

| # | Module | Status | Where |
|---|---|---|---|
| 1 | Schemas & scaffold (ASM-scoped) | **complete** | Local |
| 2 | ASM discovery engine (`asm-discover.sh`) | next | Local |
| 3 | Dashboard skeleton | pending | Local |
| 4 | GitHub repo + Actions | pending | Cloud |
| 5 | Netlify wiring | pending | Cloud |
| 6 | First live discovery scan | pending | Cloud |
| 7 | Slack alerts (changes only) | pending | Cloud |
| 8 | Multi-target + IP/CIDR support | pending | Cloud |

Modules 1–3 build entirely locally. No cloud dependency until Module 4.

## Repo layout

```
COMMANDsentry/
├── README.md
├── .gitignore
├── .github/workflows/
│   └── asm-discover.yml          ← (Module 4) cron + manual dispatch
├── scanner/
│   ├── asm-discover.sh           ← (Module 2) the ASM engine
│   ├── normalize.py              ← (Module 2) tool outputs → asset JSON
│   └── profiles/                 ← scan profiles per target type
├── schemas/
│   ├── asset-schema.md           ← per-asset JSON shape
│   └── targets-schema.md         ← targets.yml shape
├── data/
│   ├── targets.yml               ← (gitignored)
│   ├── targets.yml.example       ← reference copy
│   └── assets/                   ← per-asset records
│       └── commanddigital-www.example.json
├── web/                          ← (Module 3) dashboard
├── docs/
│   ├── decisions.md
│   └── runbook.md
└── netlify.toml                  ← (Module 5)
```

## Target types

| Type | Example | What it produces |
|---|---|---|
| `fqdn` | `www.commanddigital.com` | One asset record (identity + inventory + exposures) |
| `apex` | `commanddigital.com` | Subdomain enum → one asset record per live sub |
| `ip` | `199.16.172.68` | One asset record, no DNS context |
| `cidr` | `198.51.100.0/29` | naabu sweep → one asset record per live host |
| `asn` | `AS54113` | (Phase 2) pull ranges, treat as CIDR |

Every target requires `scope_verified: true` before any scan runs.

## Discovery cadence

ASM is cheap to run, so we run it often:

| Target type | Default cadence |
|---|---|
| `fqdn` | Every 6 hours |
| `apex` | Daily (subdomain enum is the heavier op) |
| `ip` | Every 6 hours |
| `cidr` | Daily (sweep is heavier) |

Compare to vuln scanning which is daily-to-weekly. The point of ASM is *frequency* — catching changes fast.

## What changes trigger alerts

| Change | Severity |
|---|---|
| New subdomain discovered | Notice |
| New port opened on existing asset | **Watch** |
| Cert expires in < 30 days | Notice |
| Cert expires in < 7 days | **Watch** |
| WAF disappeared (was protected, now isn't) | **Watch** |
| Exposed admin panel / .git / .env detected | **Watch** |
| Asset disappeared (was up, now isn't) | Notice |
| Tech fingerprint changed | Notice |

No CVSS, no severity scores. ASM either flags a change or it doesn't.

## Stack

- **Engine:** the 9-tool stack above, all open-source, all installable in a GH Actions Ubuntu runner
- **Orchestrator:** GitHub Actions (cron every 6 hours + workflow_dispatch)
- **Storage:** JSON in repo (Phase 1)
- **Dashboard:** Static HTML/JS on Netlify
- **Brand:** Command Digital template kit

## Decision log

See `docs/decisions.md`. Key decisions:
- Private repo
- ASM-only scope (D-008) — vuln scanning stays local
- GitHub Actions for scheduling
- JSON-in-repo for storage
- Five target types (fqdn, apex, ip, cidr, asn)

## Naming and intent

The project is named COMMANDsentry because Command Digital is the first operator. The name reflects origin, not constraint — the engine treats any authorized target identically.

Internal name: COMMANDsentry ASM
Dashboard URL: TBD (`asm.commanddigital.com` or `commandsentry-asm.netlify.app`)

If this ever expands beyond a single-operator deployment (closed beta for Command's clients, or a public service — see earlier scoping discussion), the engine doesn't need to change. Multi-tenancy and per-operator scope verification are additive features for that future, not a redesign.
