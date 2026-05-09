# Asset JSON Schema (ASM v3)

**Asset = apex domain.** Subdomains are nested children, each with their own
hosts/services/cert/WAF/fingerprint. This matches how real ASM tools organize
data and matches how operators reason about their attack surface.

## Top-level shape

```json
{
  "schema_version": "3.0",
  "asset":         { ... },
  "scan":          { ... },
  "registration":  { ... },
  "summary":       { ... },
  "subdomains":    [ ... ],
  "deltas":        { ... },
  "history":       [ ... ]
}
```

## `asset`

```json
{
  "id": "commandcommcentral",
  "type": "apex",
  "value": "commandcommcentral.com",
  "owner": "command_digital",
  "tags": ["production"],
  "notes": "...",
  "discovered_via": "manual"
}
```

`type` values: `apex` (preferred), `fqdn`, `ip`, `cidr`. Apex is the canonical type — even single-FQDN scans should usually be modeled as an apex with one subdomain.

## `scan`

```json
{
  "id": "scan_2026-05-09T...",
  "started_at": "2026-05-09T03:50:07Z",
  "completed_at": "2026-05-09T04:01:12Z",
  "duration_seconds": 665,
  "engine_version": "3.0.0",
  "scanner_origin": "github-actions-ubuntu-azure",
  "tools_run": ["subfinder", "dnsx", "naabu", "fingerprintx", "httpx", "wafw00f", "testssl", "whois"]
}
```

## `registration`

Whois data for the apex domain. One per asset (not per subdomain).

```json
{
  "registrar": "GoDaddy",
  "registrar_url": "https://www.godaddy.com",
  "created":  "2003-04-15",
  "updated":  "2025-03-10",
  "expires":  "2027-04-15",
  "status":   "active"
}
```

## `summary`

Roll-up metrics across all subdomains. Drives the inventory card.

```json
{
  "subdomain_count":       2,
  "live_subdomain_count":  2,
  "host_count":            4,
  "service_count":         8,
  "newest_cert_expiry_days": 47,
  "top_hosting_org":       "SCI",
  "platforms":             ["FortiGate-protected .NET Core"]
}
```

`top_hosting_org` is the most-common ASN org across all subdomain hosts.

## `subdomains[]`

Each subdomain is a complete record of what's discovered at that hostname.

```json
[
  {
    "name": "commandcommcentral.com",
    "alive": true,
    "is_root": true,
    "discovered_via": "dnsx",
    "first_discovered": "2026-05-09T03:50:07Z",
    "last_seen":        "2026-05-09T03:50:07Z",
    "tags": [],

    "reachability": {
      "live": true,
      "http_status": 200,
      "title": "Command Communications Central"
    },

    "hosts": [
      {
        "ip": "12.34.56.78",
        "asn": "AS00000",
        "asn_org": "SCI",
        "country": "US",
        "region": "Texas",
        "city": "Houston",
        "reverse_dns": null,
        "is_private": false
      }
    ],

    "services": [
      {
        "ip": "12.34.56.78",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "banner": "Microsoft-IIS/10.0",
        "tls": true,
        "cert": {
          "subject": "*.commandcommcentral.com",
          "issuer": "Sectigo",
          "san": [...],
          "not_before": "...",
          "not_after":  "...",
          "days_to_expiry": 47,
          "self_signed": false
        }
      }
    ],

    "dns": {
      "a": [...], "aaaa": [...], "cname": null,
      "mx": [...], "ns": [...], "txt": [...],
      "spf": "v=spf1 ...", "dnssec": false
    },

    "fingerprint": {
      "server": "Microsoft-IIS/10.0",
      "platform_label": "Microsoft .NET Core 8 + IIS",
      "tech": [
        { "name": "ASP.NET Core", "version": "8.0", "category": "framework" }
      ]
    },

    "waf": { "detected": true, "vendor": "FortiGate", "confidence": "high" }
  },
  {
    "name": "test.commandcommcentral.com",
    "alive": true,
    "is_root": false,
    "discovered_via": "subfinder",
    "first_discovered": "...",
    "last_seen": "...",
    "tags": ["test"],
    "reachability": { ... },
    "hosts": [ ... ],
    "services": [ ... ],
    "dns": { ... },
    "fingerprint": { ... },
    "waf": { ... }
  }
]
```

`is_root: true` marks the apex itself. Sorted with root first, then alphabetical.

`discovered_via`: `dnsx` (the apex resolves directly), `subfinder` (passive enum), `manual` (explicit), `cidr` (from CIDR sweep).

## `deltas` — surface changes since previous scan

Now subdomain-aware: each delta entry references which subdomain it belongs to.

```json
{
  "since_scan": "scan_...",
  "added": {
    "subdomains": ["staging.commandcommcentral.com"],
    "services":   [{ "subdomain": "test.commandcommcentral.com", "ip": "...", "port": 8443 }],
    "hosts":      [{ "subdomain": "...", "ip": "..." }]
  },
  "removed": {
    "subdomains": [],
    "services":   [],
    "hosts":      []
  },
  "changed": {
    "fingerprint": [{ "subdomain": "...", "name": "WordPress", "from": "6.8", "to": "6.9" }],
    "cert":        [{ "subdomain": "...", "from": ["Sectigo"], "to": ["Let's Encrypt"] }]
  }
}
```

## `history[]`

Last 90 scans, summary metrics for trend rendering.

```json
[
  {
    "scan_id": "...",
    "subdomain_count": 2,
    "live_subdomain_count": 2,
    "host_count": 4,
    "service_count": 8
  }
]
```

## Adapter behavior per target type

| Target type | `subdomains[]` content |
|---|---|
| `apex`  | Root + everything subfinder finds, each scanned individually |
| `fqdn`  | Just the single FQDN as one entry (no subfinder run — backward compat) |
| `ip`    | One entry, name = the IP, no DNS |
| `cidr`  | One entry per live host in the range (Phase 2: full per-host scan) |

Either way the structure is uniform — clients always read `subdomains[]`.

## Migration

v2 records (which lacked nesting) are not forward-compatible. First scan after the v3 engine deploys produces a v3 record; old v2 files are overwritten on re-scan, removed otherwise.
