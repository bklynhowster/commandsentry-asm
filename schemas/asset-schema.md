# Asset JSON Schema (ASM)

Every scanned asset produces a single JSON file at `data/assets/{asset.id}.json`.
The dashboard reads these files. Module 2 (asm-discover.sh + normalize.py) writes them.

## What this schema is for

ASM-only data. Asset identity, inventory, and exposure flags. **Not vulnerability data.**

If you find yourself wanting to add a `cvss`, `cve_list`, or `proof_of_exploit` field — stop. That's vuln scanning, not ASM. Different module, different system.

## Top-level shape

```json
{
  "schema_version": "1.0",
  "asset": { ... },
  "scan": { ... },
  "inventory": { ... },
  "exposures": [ ... ],
  "deltas": { ... },
  "history": [ ... ]
}
```

## `asset`

```json
{
  "id": "commanddigital-www",
  "type": "fqdn",
  "value": "www.commanddigital.com",
  "owner": "command_digital",
  "tags": ["production", "marketing"],
  "notes": "...",
  "discovered_via": "manual"
}
```

`discovered_via`:
- `manual` — added by editing targets.yml
- `apex:{parent-id}` — found by an apex subdomain scan
- `cidr:{parent-id}` — found by a CIDR sweep

## `scan`

```json
{
  "id": "scan_2026-05-07T02:00:00Z_abc123",
  "started_at": "2026-05-07T02:00:00Z",
  "completed_at": "2026-05-07T02:08:42Z",
  "duration_seconds": 522,
  "engine_version": "1.0.0",
  "tools_run": ["dnsx", "whois", "subfinder", "naabu", "httpx",
                "fingerprintx", "wafw00f", "testssl", "nuclei-exposure"],
  "tool_versions": {
    "subfinder": "v2.6.5",
    "nuclei": "v3.2.1"
  }
}
```

## `inventory` — what this asset *is*

The factual record. No interpretation, no severity. Just what we observed.

```json
{
  "identity": {
    "ip_addresses": ["104.21.45.123", "172.67.180.45"],
    "reverse_dns": {
      "104.21.45.123": "104.21.45.123.cloudflare.com"
    },
    "asn": "AS13335",
    "asn_org": "Cloudflare, Inc.",
    "registrar": "NameCheap Inc.",
    "whois_creation": "2018-04-12",
    "whois_expiry":   "2027-04-12",
    "geo": { "country": "US", "city": null }
  },

  "dns": {
    "a":     ["104.21.45.123", "172.67.180.45"],
    "aaaa":  [],
    "cname": null,
    "mx":    [{ "priority": 1, "host": "aspmx.l.google.com" }],
    "ns":    ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "txt":   ["v=spf1 include:_spf.google.com ~all"],
    "spf":   "v=spf1 include:_spf.google.com ~all",
    "dmarc": null,
    "dkim_selectors_found": [],
    "dnssec": false
  },

  "subdomains": [
    { "name": "www.commanddigital.com",  "alive": true,  "discovered": "2026-05-07T02:00:00Z" },
    { "name": "blog.commanddigital.com", "alive": true,  "discovered": "2026-05-07T02:00:00Z" },
    { "name": "old.commanddigital.com",  "alive": false, "discovered": "2026-04-22T02:00:00Z" }
  ],

  "ports": [
    { "port": 80,  "protocol": "tcp", "state": "open" },
    { "port": 443, "protocol": "tcp", "state": "open" },
    { "port": 8080, "protocol": "tcp", "state": "filtered" }
  ],

  "services": [
    { "port": 443, "service": "https", "banner": "cloudflare", "tls": true },
    { "port": 80,  "service": "http",  "banner": "cloudflare", "tls": false }
  ],

  "http": {
    "live": true,
    "status_code": 200,
    "title": "Command Digital — ...",
    "server": "cloudflare",
    "powered_by": null,
    "technologies": [
      { "name": "WordPress",  "version": "6.9.1", "category": "cms" },
      { "name": "Elementor",  "version": "2.8.3", "category": "wp-plugin" },
      { "name": "OceanWP",    "version": "1.7.4", "category": "wp-theme" },
      { "name": "WP Engine",  "version": null,    "category": "hosting" },
      { "name": "Cloudflare", "version": null,    "category": "cdn" }
    ],
    "headers_present": [],
    "headers_missing": [
      "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
      "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security",
      "X-XSS-Protection"
    ],
    "cookies": [
      { "name": "PHPSESSID", "secure": false, "httponly": true, "samesite": null }
    ]
  },

  "tls": {
    "issuer": "Cloudflare Inc ECC CA-3",
    "subject": "*.commanddigital.com",
    "san": ["commanddigital.com", "*.commanddigital.com"],
    "not_before": "2026-02-15",
    "not_after":  "2026-05-15",
    "days_until_expiry": 8,
    "protocols_supported": ["TLSv1.2", "TLSv1.3"],
    "weak_ciphers": [],
    "self_signed": false
  },

  "waf": {
    "detected": true,
    "vendor": "Cloudflare",
    "confidence": "high"
  }
}
```

## `exposures[]` — flags worth looking at

Things ASM can detect just by looking at the surface. Each is a state, not a vulnerability.

```json
[
  {
    "id": "E-001",
    "type": "cert_expiring_soon",
    "category": "tls",
    "severity": "watch",
    "title": "Certificate expires in 8 days",
    "detail": "Cloudflare-managed cert; usually auto-renews but worth verifying.",
    "evidence": "not_after: 2026-05-15",
    "first_seen": "2026-05-07T02:00:00Z",
    "last_seen":  "2026-05-07T02:00:00Z",
    "status": "open"
  },
  {
    "id": "E-002",
    "type": "missing_dmarc",
    "category": "email",
    "severity": "notice",
    "title": "No DMARC record published",
    "detail": "Domain is spoofable beyond what SPF -all protects against.",
    "evidence": "dig TXT _dmarc.commanddigital.com → NXDOMAIN",
    "first_seen": "2026-03-28T18:42:11Z",
    "last_seen":  "2026-05-07T02:00:00Z",
    "status": "open"
  }
]
```

### Exposure types (canonical list)

| Type | Severity | Description |
|---|---|---|
| `new_subdomain` | notice | Subdomain that didn't exist last scan |
| `new_open_port` | watch | Port opened that wasn't open last scan |
| `cert_expiring_soon` | notice/watch | <30 days notice, <7 days watch |
| `cert_expired` | watch | Already expired |
| `cert_self_signed` | watch | Self-signed cert on internet-facing host |
| `weak_tls_protocol` | watch | TLS 1.0 / 1.1 / SSL enabled |
| `missing_dmarc` | notice | No DMARC record |
| `missing_dkim` | notice | No DKIM selector found |
| `missing_security_header` | notice | One per missing header |
| `cookie_no_secure_flag` | notice | Cookie without Secure attribute |
| `waf_disappeared` | watch | Was protected by WAF, now isn't |
| `exposed_admin_panel` | watch | Admin login reachable from internet (nuclei exposure) |
| `exposed_git_dir` | watch | /.git/ accessible (nuclei exposure) |
| `exposed_env_file` | watch | /.env or similar accessible (nuclei exposure) |
| `exposed_debug_endpoint` | watch | Debug page / phpinfo / status reachable (nuclei exposure) |
| `directory_listing` | notice | Directory listing enabled |
| `service_disappeared` | notice | Service was up last scan, now isn't |
| `tech_changed` | notice | Major framework version changed |
| `asset_offline` | notice | Asset not responding |

**Severity** is binary in ASM: `notice` (FYI) or `watch` (probably worth a look). No CVSS, no critical/high/medium. Vuln scanning has those — ASM doesn't pretend to.

## `deltas` — what changed since last scan

```json
{
  "since_scan": "scan_2026-05-06T02:00:00Z_xyz",
  "added": {
    "subdomains": ["staging.commanddigital.com"],
    "ports": [{ "asset": "104.21.45.123", "port": 8443 }],
    "exposures": ["E-014"]
  },
  "removed": {
    "subdomains": ["old.commanddigital.com"],
    "ports": [],
    "exposures": ["E-009"]
  },
  "changed": {
    "tech": [
      { "name": "WordPress", "from": "6.8.2", "to": "6.9.1" }
    ]
  }
}
```

This is the ASM superpower — the dashboard's "What changed?" view reads straight from here.

## `history[]`

```json
[
  { "scan_id": "scan_2026-05-06T02:00:00Z_xyz", "live": true, "ports_open": 2, "subdomains_alive": 1, "exposures_total": 9 },
  { "scan_id": "scan_2026-05-07T02:00:00Z_abc", "live": true, "ports_open": 2, "subdomains_alive": 1, "exposures_total": 9 }
]
```

Last 90 days, configurable. For trend charts.

## File location

```
data/assets/{asset.id}.json    ← latest scan result
data/history/{asset.id}/{scan_id}.json    ← archived scans (gitignored after 90d)
```

## Validation

`normalize.py` (Module 2) validates against this schema before writing.
Bad output blocks the GitHub Actions commit step — broken data never lands in the repo.
