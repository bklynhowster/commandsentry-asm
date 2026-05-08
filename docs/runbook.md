# COMMANDsentry — Runbook (ASM)

Day-to-day operations for the ASM workflow. Adding targets, forcing re-scans, debugging, reviewing changes.

> **Scope reminder:** ASM only. If you're looking for "this vuln on this WordPress plugin," that's the local deep-probe rig in `~/Downloads/ISMS Procedures/Vulnerability Scanning/`, not COMMANDsentry.

---

## Adding a target

1. **Verify scope.** Pick one:
   - You own the domain → done
   - DNS TXT record → add `commandsentry-verify=<random>` to DNS
   - HTTP file → place under `/.well-known/commandsentry-verify`
   - Auth letter → store signed PDF in `docs/scope-auth/{target-id}.pdf`

2. **Edit `data/targets.yml`:**
   ```yaml
   - id: new-thing-prod
     type: fqdn
     value: new-thing.commanddigital.com
     scope_verified: true
     owner: command_digital
     tags: [production]
   ```

3. **Commit + push.**

4. **Choose:**
   - Wait for the next scheduled discovery run (every 6h for fqdn/ip, daily for apex/cidr), OR
   - Trigger now: GitHub UI → Actions → "ASM Discover" → Run workflow → pick target

---

## Forcing a re-scan

GitHub UI:
- Repo → Actions → "ASM Discover" → Run workflow → target ID (or `all`)

CLI (with `gh`):
```bash
gh workflow run asm-discover.yml -f target=commanddigital-www
```

---

## Pausing a target

```yaml
- id: target-id
  enabled: false   # add this line
  ...
```

Commit. Workflow skips disabled targets.

---

## Promoting a discovered asset

When an `apex` or `cidr` target finds a new asset, it lands in `discovered:` with `scope_verified: false`.

1. Verify scope (see above)
2. Edit the entry: `scope_verified: true`
3. Move from `discovered:` to `targets:`
4. Add tags/owner
5. Commit + push

---

## Debugging a failed scan

1. **GH Actions log** — Repo → Actions → click failing run → expand failed step
2. **Common failures:**
   - YAML schema error → check `targets.yml` against `schemas/targets-schema.md`
   - `scope_verified: false` → workflow refuses to run
   - Tool install failure → tools auto-update each run; check the install step
   - Schema validation failure → normalizer wrote malformed JSON, commit was blocked
3. **Reproduce locally:**
   ```bash
   cd ~/Downloads/ISMS\ Procedures/COMMANDsentry
   ./scanner/asm-discover.sh <target-id>
   # writes data/assets/{target-id}.json
   # serve dashboard locally:
   cd web && python3 -m http.server 8000
   ```

---

## Reviewing changes

Dashboard URL: TBD (`asm.commanddigital.com` or `commandsentry-asm.netlify.app`).

Default view shows:
- **Inventory** — every known asset, port count, tech fingerprint, WAF status
- **Watch list** — assets with open `watch`-severity exposures
- **What changed** — deltas across all assets since last scan (new subs, new ports, cert expiring, tech version changed)
- **Per-asset detail** — full inventory record + exposure list + change history

Per-exposure actions:
- **Acknowledge** → `acknowledged`, won't re-alert
- **Mark resolved** → next scan confirms or reverts
- **Dismiss** → `dismissed`, scanner stops re-flagging this exact match (use sparingly)

---

## Slack alerts (Module 7)

Alerts fire on **changes**, not on standing state. Default triggers:

| Event | Notify |
|---|---|
| New subdomain | yes |
| New port opened | yes |
| Cert < 7 days to expiry | yes |
| WAF disappeared | yes |
| Exposed admin/.git/.env detected | yes |
| Asset offline (was up, now isn't) | yes |
| New `notice`-severity exposure | no — too noisy |
| New `watch`-severity exposure | yes |

Format:
```
👁 [COMMANDsentry] watch on www.commanddigital.com
+ New port open: 8443/tcp (service: https)
View: https://asm.commanddigital.com/asset/commanddigital-www
```

Webhook URL stored as Actions secret `SLACK_WEBHOOK_URL`.

---

## Discovery cadence (defaults)

| Target type | Cadence | Why |
|---|---|---|
| `fqdn` | Every 6 hours | Cheap, surface changes fast |
| `ip` | Every 6 hours | Cheap, services come/go |
| `apex` | Daily | Subdomain enum is heavier |
| `cidr` | Daily | Sweep is heavier |
| `asn` | Weekly | Phase 2 |

Override per target via `schedule:`.

---

## Rate limiting

Profiles in `scanner/profiles/`:

| Profile | Concurrency | Delay | Use for |
|---|---|---|---|
| `gentle`     | 10 | 500ms | FortiWeb, Pressable, anything WAF-twitchy |
| `normal`     | 25 | 100ms | Default |
| `aggressive` | 50 | 0ms   | Lab / dev only |

Override per target via `rate_limit:`.

---

## Carryover gotchas (from local scanning experience)

- **Cloudflare blocks aggressive enum.** ASM's lighter touch should mostly avoid this, but if subfinder+httpx is getting rate-limited, drop to `gentle`.
- **Pressable shared hosting needs SNI:** `curl --resolve "domain:443:IP"`. Already baked into the discovery script for known shared-hosting IPs.
- **GitHub Actions IPs are Azure ranges** — some WAFs profile these. If a target's WAF starts blocking the runner, switch to a self-hosted runner.
- **`set -euo pipefail` kills multi-phase scripts.** Discovery script runs phases independently, intentional.

---

## Cost monitoring

Free-tier ceilings:
- GitHub Actions: 2000 min/mo (private). ASM scan ≈ 8-10 min. Plenty of headroom even at 6h cadence across 5 targets.
- Netlify: 100GB bandwidth, 300 build min/mo. Won't approach.
- Cloudflare R2 (if added): 10GB free.

Tripwires:
- Actions usage > 1500 min/mo → upgrade to Pro or self-host runner
- Repo > 500MB → migrate raw artifacts to R2
- Asset count > 500 → consider a real DB layer (Supabase/Neon)

---

## Disaster recovery

- Repo is system of record. GitHub clone = full backup.
- Lose Netlify? Re-deploy from repo, ~10 min.
- Lose GitHub? Local clone has everything. Push to a new private remote.
- Tool versions pinned in workflow YAML. Reproducible.

---

## When to graduate a finding to vuln scanning

ASM tells you "asset X runs Elementor 2.8.3." It does NOT tell you that's vulnerable.

If COMMANDsentry surfaces a tech version that smells outdated, the workflow is:
1. Acknowledge in COMMANDsentry
2. Run targeted deep-probe locally: `cd ~/Downloads/ISMS\ Procedures/Vulnerability\ Scanning/{target} && ./deep-probe-v2.sh`
3. CVE-match results go in the local vuln-report HTML, not the COMMANDsentry dashboard

This separation keeps the two systems honest. ASM stays fast and frequent. Vuln scanning stays deep and intentional.
