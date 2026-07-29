# Mail Transport — dual-provider, per-instance

**Ratified 2026-07-29 (4.7 rulings M1–M6, Obsidian 164).**

## The rule

`scripts/common/mailer.py` is the **only** send path. Both scanner-side senders —
`scripts/alerter/run_alerter.py` (daily digest) and `scripts/db/import_asm_to_surface.py`
(real-time asset-surface notifications) — delegate to it. **Do not POST a provider API
directly from a sender**; that is what caused the original defect.

`MAIL_PROVIDER` chooses transport at runtime:

| instance | provider | credentials |
|---|---|---|
| **Command** | `sendgrid` (also the default with no env set) | `SENDGRID_API_KEY` |
| **Prodex** | `smtp` — iCloud | `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` |

Env names are **identical to the portal's** (`src/lib/email.ts`) — verified, all six. The
portal mirrors this same branch in TypeScript. Do not rename on one side only.

## Why it was broken (the origin)

Both senders were **SendGrid-only, hardcoded, in both repos**. Prodex has never used
SendGrid. So **Prodex scanner-side mail had no working transport at all** — the digest and
real-time notifications could never send from that instance, and never could.

It hid because mail is best-effort by design (it must never fail a scan), so "not
configured" and "configured, nothing to say" produce the identical observable: nothing.

## M4 — dual-provider is deliberate. Do NOT unify.

Recurring proposal, ruled against:

- **Command's SendGrid is load-bearing.** IronPort-trusted, domain-verified for
  `commandcompanies.com` (D-031), with real recipients. Moving it to iCloud SMTP from a
  GitHub runner would lose that trust and break domain alignment — deliverability gets
  *worse* for the instance that actually needs it.
- **Prodex has no comparable requirement.** iCloud SMTP is sufficient for its recipient
  list.

Different transports because different delivery requirements. Revisit **only** if Prodex
grows a real external recipient list (board, external stakeholders).

## M2 — this is parity-preserving, and here's the mitigation

**The parity rule, clarified:** *code* in both repos must be byte-identical; **runtime
behaviour may differ per instance via environment configuration.** Env-driven divergence is
not code divergence. Forking the senders would have been the violation.

**But** it means each instance exercises only one branch in production, so a bug in the
other branch is invisible there. Mitigation, mandatory:

> **Both provider branches are tested on both instances' CI.** The SMTP tests run on
> Command even though Command uses SendGrid in prod, and vice versa. 40 mechanism tests,
> identical suite, both repos.

Do not skip a branch's tests on the instance that "doesn't use it" — that is precisely how
a latent bug waits for the day someone flips the provider.

## M5 — unconfigured is loud, failed is quiet

| state | behaviour | why |
|---|---|---|
| **Unconfigured** | `::warning::[MAIL_UNCONFIGURED]` at **startup**, naming the exact missing var | This instance can *never* deliver. Silence here is what hid the original bug. |
| **Configured but send failed** | logged, `(False, detail)` returned, no annotation | Transient. Best-effort contract: mail must never fail a scan. |

**`::warning::`, deliberately not `::error::`** — escalating would fail the workflow and
break the never-fail-a-scan contract. Checked at **startup**, not first send, so a typo
surfaces immediately rather than hours later.

Messages are differentiated per state (`SMTP provider selected but SMTP_HOST missing` vs
`SendGrid provider selected by default but SENDGRID_API_KEY missing`) so the operator fixes
the specific thing instead of investigating a generic "unconfigured".

## M6 — the canary is mandatory, not optional

`.github/workflows/mail-canary.yml`, daily at **11:00 UTC — one hour before the 12:00 UTC
digest**, so a failure leaves time to fix the credential before the mail that matters.

A startup config check verifies `SMTP_PASS` is *set*. It cannot verify it is still *valid*.
**iCloud app-specific passwords are revoked whenever the Apple ID password changes** — after
which every send fails auth, best-effort swallows it, and nobody notices the absence of an
informational digest. Only a canary catches that.

Two parts, both required: **send** (failure is `::error::` — the canary *is* the check, not
a scan step) and **watch** (verifies a canary was *received*; send-succeeded ≠
delivered). Both instances send their own so a failure is attributable to a provider.

`MAIL_CANARY_ADDRESS` **must be an address someone or something actually watches.** A canary
to an unwatched mailbox is not a signal.

### Canary runs on PRODEX ONLY — deliberate (2026-07-29)

4.7's M6 said both instances. In practice Command doesn't need it, and Howie caught this:

- **Command already has both signals.** The daily digest lands in his inbox (positive), and
  if the send fails `run_alerter` returns 1 → the workflow goes red → GitHub emails the
  failure (negative — verified: `status == "error"` → `return 1`). A canary there is a
  second daily email proving what the digest already proves.
- **Prodex has neither.** It has no `alerter.yml` and nothing scheduled that sends, which is
  exactly *why* its broken transport went unnoticed — nothing arrived whose absence you'd
  notice, and nothing failed red. For Prodex the canary is the **only** signal.

So `MAIL_CANARY_ADDRESS` is set on Prodex and deliberately **unset on Command**. The
workflow ships to both (parity) and no-ops where the address is absent. Do not "fix" this by
setting it on Command — that adds a redundant daily email, not coverage.

Known cosmetic wart, accepted: the unset case emits a daily `::warning::` on Command, so a
deliberate choice looks like a misconfiguration in the Actions log. Judged not worth a
commit.

**Known gap, stated rather than hidden:** the watchdog has no inbox reader wired, so it
reports `DELIVERY is NOT verified` instead of printing a green check it can't justify. Send
is verified; receipt is not. Wire a reader before treating it as green.

## M3 — credentials

`SMTP_PASS` is an **iCloud app-specific password** in `prodexsentry-asm` Actions secrets.
Accepted as the same security envelope as `SUPABASE_DSN` and the VPN credentials already
there — another secret in an existing envelope, not a new class. Note that repo is
**public**; Actions secrets are not exposed to fork PRs by default.

**Sequencing (ruled, then overridden 2026-07-29):** M3 said narrow the `cowork-push-ba`
broad PAT **before** adding `SMTP_PASS`, to avoid compounding long-lived credentials. Howie
chose to add `SMTP_PASS` first so Prodex mail could be proven working; the PAT narrowing
remains open.

Mitigating fact found during the PAT investigation: **no workflow in any of the three repos
references `cowork-push-ba`.** The workflow tokens are `GITHUB_TOKEN` (built-in,
auto-scoped), `ROE_ALERT_TOKEN`, `NETLIFY_AUTH_TOKEN` and `DISPATCH_TOKEN`; no git remote
carries an embedded credential. Its only apparent consumer is Cowork's own push path, which
points toward **retiring** it rather than narrowing it — and would make M3's gate moot
rather than merely deferred.

**Status:** `SMTP_PASS` is set on `prodexsentry-asm`. The same app-specific password is also
in Prodex's Netlify env for the portal, so **a rotation must update both** or the canary
starts failing on whichever lags.

**Rotation:** app-specific passwords die on Apple ID password change. The canary is the
detection mechanism. Quarterly rotation as hygiene, coordinated with password changes.

### Credential inventory — scanner repos

| secret | instance | purpose | rotation trigger | detection when broken |
|---|---|---|---|---|
| `SUPABASE_DSN` | both | DB access | manual | gates fail loudly (`gate_retry`) |
| `SENDGRID_API_KEY` | Command | mail transport | vendor | mail canary |
| `SMTP_PASS` | Prodex | mail transport (iCloud app-specific) | **Apple ID password change** | mail canary |
| `ROE_ALERT_TOKEN` | both | portal ROE-block alert auth | manual | alert silently skipped |
| `MULLVAD_ACCOUNT_NUMBER` | both | VPN egress | subscription | VPN bring-up fails |

## Repository variables required

Neither instance sends until these are set — that is the trade for removing cross-tenant
defaults: it fails safe, but it fails until configured.

**Both instances configured and verified 2026-07-29.** Prodex has all eight set; Command has
`PORTAL_BASE_URL`, `ALERTER_FROM`, `ALERTER_FROM_NAME` (it needs no `MAIL_PROVIDER` — sendgrid
is the default — and deliberately no `MAIL_CANARY_ADDRESS`, per the section above).

**End-to-end proof, Prodex, 2026-07-29:** canary run #1 green in 13s, log line
`canary sent [prodexsentry-asm] smtp smtp.mail.me.com:587 -> 1 recipient(s)`, and the message
**landed in the inbox** (not junk), branded PRODEXsentry. That is the first time Prodex
scanner-side mail has been demonstrated working end to end.

| variable | Command | Prodex |
|---|---|---|
| `MAIL_PROVIDER` | `sendgrid` (or omit) | `smtp` |
| `SMTP_HOST` | — | `smtp.mail.me.com` |
| `SMTP_PORT` | — | `587` |
| `SMTP_USER` | — | the iCloud account |
| `PORTAL_BASE_URL` | `https://commandsentry-portal.netlify.app` | `https://prodexsentry.netlify.app` |
| `ALERTER_FROM` | `CommandSentry@commandcompanies.com` | Prodex sender |
| `ALERTER_FROM_NAME` | `COMMANDsentry` | `PRODEXsentry` |
| `MAIL_CANARY_ADDRESS` | monitored address | monitored address |

`SMTP_PASS` and `SENDGRID_API_KEY` are **secrets**, not variables.
