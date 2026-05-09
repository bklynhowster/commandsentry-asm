# Asset JSON Schema (ASM v2)

Per-asset record produced by `scanner/normalize.py`. Pure ASM — no vulnerability analysis,
no security posture scoring, no exposure flags. Just surface data: what's out there,
where it lives, and what it's serving.

## Top-level shape

```json
{
  "schema_version": "2.0",
  "asset":         { ... },
  "scan":          { ... },
  "reachability":  { ... },
  "hosts":         [ ... ],
  "services":      [ ... ],
  "subdomains":    [ ... ],
  "dns":           { ... },
  "registration":  { ... },
  "fingerprint":   { ... },
  "waf":           { ... },
  "deltas":        { ... },
  "history":       [ ... ]
}
```

## `asset`

```json
{
  "id": "unimacgraphics-www",
  "type": "fqdn",
  "value": "unimacgraphics.com",
  "owner": "command_digital",
  "tags": ["production", "subsidiary"],
  "notes": "Pressable shared hosting",
  "discovered_via": "manual"
}
```

## `scan`

```json
{
  "id": "scan_2026-05-09T03:50:07Z_e622225d",
  "started_at": "2026-05-09T03:50:07Z",
  "completed_at": "2026-05-09T03:52:54Z",
  "duration_seconds": 167,
  "engine_version": "2.0.0",
  "scanner_origin": "github-actions-ubuntu-azure",
  "tools_run": ["dnsx", "subfinder", "naabu", "fingerprintx", "httpx", "wafw00f", "testssl", "whois"]
}
```

## `reachability`

```json
{
  "live": true,
  "http_status": 200,
  "title": "Home - Unimac, a Command Company"
}
```

## `hosts[]` — IPs the asset resolves to, with attribution

```json
[
  {
    "ip": "199.16.172.68",
    "asn": "AS54017",
    "asn_org": "Pressable, Inc.",
    "country": "US",
    "region": "Oregon",
    "city": "Boardman",
    "reverse_dns": null,
    "is_private": false
  }
]
```

## `services[]` — what's listening on each (IP, port)

```json
[
  {
    "ip": "199.16.172.68",
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "banner": "nginx",
    "tls": false
  },
  {
    "ip": "199.16.172.68",
    "port": 443,
    "protocol": "tcp",
    "service": "https",
    "banner": "nginx",
    "tls": true,
    "cert": {
      "subject": "*.wpcomstaging.com",
      "issuer": "Let's Encrypt",
      "san": ["*.wpcomstaging.com", "wpcomstaging.com"],
      "not_before": "2026-04-01T00:00:00Z",
      "not_after":  "2026-06-30T00:00:00Z",
      "days_to_expiry": 47,
      "self_signed": false
    }
  }
]
```

Service strings produced by fingerprintx (preferred) or inferred from port number when fingerprintx is unavailable.

Common services: `http`, `https`, `ssh`, `ftp`, `sftp`, `smtp`, `imap`, `pop3`, `dns`,
`mysql`, `postgres`, `redis`, `mongodb`, `rdp`, `vnc`, `telnet`, `snmp`, `ldap`, `kerberos`.

## `subdomains[]`

```json
[
  {
    "name": "www.commanddigital.com",
    "alive": true,
    "first_discovered": "2026-05-08T00:30:56Z",
    "last_seen":        "2026-05-09T03:50:07Z"
  }
]
```

For `fqdn` targets: just the asset itself.
For `apex` targets: passive enum + liveness check.

## `dns`

```json
{
  "a":     ["199.16.172.68", "199.16.173.113"],
  "aaaa":  [],
  "cname": null,
  "mx":    [],
  "ns":    ["ns35.domaincontrol.com", "ns36.domaincontrol.com"],
  "txt":   ["v=spf1 exists:..."],
  "spf":   "v=spf1 exists:%{i}.spf.hc3765-17.iphmx.com -all",
  "dnssec": false
}
```

Informational only. ASM doesn't grade DMARC/DKIM presence — that's posture analysis.

## `registration`

```json
{
  "registrar": "GoDaddy",
  "registrar_url": "https://www.godaddy.com",
  "created":    "2003-04-15",
  "updated":    "2025-03-10",
  "expires":    "2027-04-15",
  "status":     "active"
}
```

Whois data, when parseable. Registrar-specific format — graceful when fields can't be extracted.

## `fingerprint`

```json
{
  "server": "nginx",
  "platform_label": "WordPress on wp.cloud (Pressable)",
  "tech": [
    { "name": "WordPress",        "version": null,    "category": "cms" },
    { "name": "Yoast SEO",        "version": "27.5",  "category": "wp-plugin" },
    { "name": "Slider Revolution","version": "6.7.54","category": "wp-plugin" },
    { "name": "Bootstrap",        "version": "5.1.3", "category": "frontend" },
    { "name": "Google Tag Manager","version": null,   "category": "tracking" }
  ]
}
```

Informational tech detection from httpx. ASM-relevant only as inventory — version-to-CVE
matching is a vuln-scanning concern (future module).

## `waf`

```json
{ "detected": true, "vendor": "Cloudflare", "confidence": "high" }
```

## `deltas` — what changed since the previous scan

```json
{
  "since_scan": "scan_2026-05-08T...",
  "added": {
    "subdomains": ["staging.example.com"],
    "hosts":      [{ "ip": "..." }],
    "services":   [{ "ip": "...", "port": 8443 }]
  },
  "removed": {
    "subdomains": [],
    "hosts":      [],
    "services":   []
  },
  "changed": {
    "fingerprint": [{ "name": "WordPress", "from": "6.8.2", "to": "6.9.1" }],
    "cert":        []
  }
}
```

This is what email alerts fire on. Surface changes — not posture interpretations.

## `history[]` — last N scans, for trend rendering

```json
[
  {
    "scan_id": "...",
    "live": true,
    "host_count": 2,
    "service_count": 4,
    "subdomain_count": 1
  }
]
```

## Legacy v1 fields (deprecated)

The old `inventory.*` and `exposures[]` fields from v1 are gone. Migration: re-scan
each asset to produce v2 records. Old v1 asset files will be overwritten on next scan.
