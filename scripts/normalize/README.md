# Scan Data Normalization Pipeline

Converts raw scan output (COMMANDsentry asset JSON + per-target vuln scan output) into a single canonical JSONL format that can later be ingested into Supabase Postgres.

## Why this exists

Today the data lives in multiple incompatible shapes:
- COMMANDsentry: `web/data/<asset>.json` (apex with nested subdomains/hosts/services/history)
- Vuln scans: `~/Downloads/ISMS Procedures/Vulnerability Scanning/<target>/<scan-run>/` with mixed JSON, JSONL, and text outputs from 30+ tools
- Named findings (H-01, C-01, etc.): tracked in Obsidian Assessment Overview notes + per-scan SUMMARY.md files

To get cross-scan trend dashboards, regression alerting, and one CISO-facing view, we need a single canonical record format that anything can write to and anything can read from.

## Entity model (one schema for both sources)

| Entity | Source | Purpose |
|---|---|---|
| `organizations` | Manually maintained | Command Companies, Command Digital, Command Financial, Command Missouri, Command Marketing, Unimac, SCI |
| `assets` | COMMANDsentry + vuln scan targets | One row per assessed target (apex domain, IP, mail server, etc.) |
| `subdomains` | COMMANDsentry asset JSON | Nested under assets |
| `hosts` | COMMANDsentry asset JSON | IPs observed for an asset/subdomain |
| `services` | COMMANDsentry + nmap output | port + protocol on a host |
| `scans` | Walker scans the per-target dirs | One row per scan event (timestamp + type + tools that ran) |
| `scan_tool_runs` | Per-tool output detection | Which tools fired in each scan, success/fail/timeout |
| `findings` | Tool parsers + manual SUMMARY.md ingest | Vuln/issue with stable identity across scans |
| `finding_history` | Append-only state changes | Per-scan status: detected / confirmed / remediated / regressed / validated_remediated |
| `evidence_artifacts` | File pointers from per-scan dirs | .body, .headers, .meta.txt, evidence_*.html with sha256 |
| `alerts` | Extends COMMANDsentry alerts | Watch / notice / critical alerts for both ASM and finding events |

## Severity scale (hard rule)

Canonical severity is one of: `CRITICAL`, `HIGH`, `MODERATE-HIGH`, `MODERATE`, `LOW`, `INFO`.

NEVER use compound forms like `LOW-MODERATE` or `MODERATE-LOW`. Tool outputs get mapped TO this scale; this scale never gets mapped to anything else.

## Pipeline flow

```
                  ┌──────────────────┐
                  │  walker.py       │  → coverage manifest
                  │  (crawls dirs,   │
                  │   identifies     │
                  │   scan-runs)     │
                  └────────┬─────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   parsers/nuclei      parsers/zap        parsers/...
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                  ┌──────────────────┐
                  │ canonical records │
                  │  validated against│
                  │  JSON Schema      │
                  └────────┬─────────┘
                           ▼
              ~/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized/
              ├── assets.jsonl
              ├── scans.jsonl
              ├── findings.jsonl
              ├── evidence.jsonl
              ├── alerts.jsonl
              └── manifest.json  (coverage report)
```

Phase 2 (later): ingester reads JSONL → Postgres via `COPY FROM`.

## Running the pipeline

```bash
# From repo root
python3 scripts/normalize/walker.py \
  --scan-root "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning" \
  --commandsentry-data "$(pwd)/web/data" \
  --output "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized"
```

The walker emits the coverage manifest. Then each parser is run independently:

```bash
python3 scripts/normalize/parsers/nuclei.py \
  --scan-root "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning" \
  --output "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized"
```

A driver script (`scripts/normalize/run-all.sh`, coming once parsers exist) runs the walker, then dispatches to every parser.

## Status

| Component | Status |
|---|---|
| Schema definitions | TODO |
| Walker | TODO |
| Parser: nuclei JSONL | TODO |
| Parser: ZAP JSON | TODO |
| Parser: SAST/SCA cluster (semgrep, gitleaks, trivy, osv-scanner, trufflehog) | TODO |
| Parser: TLS (testssl.json, sslyze.json) | TODO |
| Parser: ASM-related JSON (subzy, theharvester, dnstwist, ffuf) | TODO |
| Parser: text fallbacks (nmap, nikto, wpscan, feroxbuster, whatweb, headers) | TODO |
| Parser: auth-scan structured (auth_state, session_tests, spa_drive) | TODO |
| Manual-finding ingest (Obsidian + SUMMARY.md) | TODO |
| COMMANDsentry asset JSON importer | TODO |
| Cross-source dedup + identity resolution | TODO |
| Tests + fixtures | TODO |

## Out of scope (this phase)

- NodeZero internal pentest data — separate program, separate normalization (if ever)
- Vendor questionnaire responses — different domain
- Cloud upload of evidence files to Supabase Storage (planned for Phase 2 after parsers stabilize)
