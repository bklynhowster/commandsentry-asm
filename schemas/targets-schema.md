# Targets YAML Schema

`data/targets.yml` is the input config — what gets scanned, when, and how.
The reference copy `targets.yml.example` is committed; the real one is gitignored.

## File shape

```yaml
version: 1
defaults: { ... }
targets: [ ... ]
discovered: [ ... ]   # auto-populated by apex/cidr scans
```

## `defaults`

Applied to every target unless overridden.

```yaml
defaults:
  schedule: nightly        # nightly | weekly | manual
  profile: deep-probe       # see scanner/profiles/
  rate_limit: normal        # gentle | normal | aggressive
  notify_on:
    - critical
    - high                  # severities that ping Slack
  retain_history_days: 365
```

## `targets[]`

```yaml
- id: commanddigital-www         # unique, used as filename for findings JSON
  type: fqdn                     # fqdn | apex | ip | cidr | asn
  value: www.commanddigital.com  # the actual target
  scope_verified: true           # MUST be true before any scan runs
  owner: command_digital         # for tagging/filtering in dashboard
  tags: [production, wordpress]
  notes: "..."

  # Optional overrides:
  schedule: weekly
  profile: deep-probe
  rate_limit: gentle
  notify_on: [critical]
  enabled: true                  # set false to pause without removing
```

### `type` semantics

| Type | Discovery? | Example | Notes |
|---|---|---|---|
| `fqdn` | No | `www.commanddigital.com` | Single host scan |
| `apex` | **Yes** | `commanddigital.com` | Subfinder enum first → adds new subs to `discovered` for review |
| `ip` | No | `199.16.172.68` | Skip DNS, port + service + nuclei |
| `cidr` | **Yes** | `198.51.100.0/29` | naabu sweep → live host enum → per-host scan |
| `asn` | **Yes** | `AS54113` | Pull all advertised ranges, treat as CIDR (Phase 2) |

### Scope verification

`scope_verified: true` is required for every target before first scan. The verification itself happens out-of-band:

| Verification method | When it applies |
|---|---|
| You own the domain (registered to Command) | Domains we registered |
| DNS TXT record check (`commandsentry-verify=...`) | Domains where we control DNS |
| HTTP file at `/.well-known/commandsentry-verify` | Webroot we control |
| Signed authorization letter | IPs/CIDRs we don't own (e.g., third-party hosting we have permission to test) |
| Internal-only flag | RFC1918 / corp network targets — never scan from cloud |

The scanner refuses to run if `scope_verified: false` — fails the workflow with a clear error.

## `discovered[]`

Auto-populated when an `apex` or `cidr` scan finds new assets. Pending review.

```yaml
discovered:
  - id: blog-commanddigital      # generated
    type: fqdn
    value: blog.commanddigital.com
    discovered_by: commanddigital-all
    discovered_at: 2026-05-07T02:14:09Z
    scope_verified: false        # you flip this true to promote into rotation
    notes: "Resolved during apex scan, returns WordPress login"
```

You promote a discovered asset by editing it in place — set `scope_verified: true`,
move it from `discovered:` to `targets:`, fill in tags/owner.

## Validation

Module 4's GitHub Action runs schema validation as a pre-flight check.
Bad YAML or missing `scope_verified` = workflow fails before any scanning happens.

## Adding a target — quick reference

```yaml
# 1. Add to data/targets.yml under targets:
- id: new-thing-prod
  type: fqdn
  value: new-thing.commanddigital.com
  scope_verified: true
  owner: command_digital
  tags: [production]

# 2. Commit + push. Next nightly scan picks it up.
# 3. Or trigger immediately via GitHub Actions "Run workflow" button.
```
