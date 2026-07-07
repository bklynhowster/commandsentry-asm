# Advisor Review — E9 follow-up: cloud-endpoint provider-change alert (the hijack safety net)

**Status:** PROPOSED 2026-07-07 (PM) · awaiting 4.7 numbered rulings.
**Follows:** your E9 ruling in `CLOUD_CLASSIFIER_CODE_CHECK.md` (refactor the alerter to per-asset `is_cloud_endpoint` suppression, single-source) + my pushback that per-asset suppression is *less safe* than the shipped range-scoped alerter and that the CNAME-target-change net you named doesn't fit O365. This spec resolves that.
**Nothing shipped.** The alerter currently in prod (`33db13d`) is range-scoped and already suppresses the O365 churn safely; this changes nothing until ratified.

## The problem
Cloud/CDN endpoints churn per-IP by design, so we suppress per-IP alerts for them (D7). But suppression opens a **hijack blind spot**: if `email.commandcompanies.com` is re-pointed to an attacker, the per-IP change that would reveal it is suppressed. E9's per-asset suppression makes this worse than the shipped range-scoped version (which still fires on a re-point to a *non-cloud* IP). Your named safety net — a CNAME-target-change alert — **does not fit O365**: O365 mail resolves A/MX straight onto Microsoft ASNs; there is frequently no CNAME to watch.

## Proposed net: classified-provider-change alert
The signal that actually catches an O365 (or any cloud) hijack is the asset's **classified provider changing** — hosts moving off Microsoft/AS8075 onto something else, or off any known cloud entirely (→ raw attacker IP).

- **Signal = the normalized `cloud_provider` (from `derive_cloud_endpoint.py`) changing scan-over-scan**, including `→ NULL` (moved off all known cloud). Compare the stable enum, NOT raw `asn_org` strings (which vary: "Microsoft Corporation" vs "MICROSOFT-CORP-MSN-AS-BLOCK") — so "still Microsoft" never false-fires.
- **Detected where the classifier already runs** — the importer (`import_asm_to_surface.py`), which per E5/E7 already does a read-before-write. It has the previous DB `cloud_provider` and the freshly-derived one in hand; if they differ, record a `provider_change` surface event that the alerter surfaces. Co-located with the classifier = single source, no second interpretation.
- **Scope: cloud-flagged assets only.** For non-cloud/static assets the existing per-IP `host_removed`/`new_host` alerts already fire (they're not suppressed), so they're covered. The provider-change alert is specifically the net for assets where per-IP is suppressed.
- **Severity: WATCH** (a provider swap on a mail/edge endpoint is a potential hijack — highest signal class).

With this net in place, E9's per-asset suppression becomes safe: per-IP pool churn is silenced (noise gone, single-source via `is_cloud_endpoint`), while a provider change (hijack, any direction — including cloud-to-cloud, which the shipped range-scoped version misses) still fires WATCH.

## Decision points
- **F1 — Accept the provider-change alert as the cloud-endpoint safety net** (in place of the CNAME-target-change alert, which doesn't fit O365). *Rec: ACCEPT.*
- **F2 — Signal = normalized `cloud_provider` enum change (incl → NULL), not raw asn_org; scope to cloud-flagged assets; severity WATCH.** *Rec: ACCEPT.* Confirm the "→ NULL" (off-all-cloud) case is WATCH (it's the strongest hijack signal).
- **F3 — Detection site: the importer's existing read-before-write (E5/E7), emitting a `provider_change` event the alerter surfaces** — rather than re-deriving in the file-based alerter. *Rec: ACCEPT — co-locates with the classifier, single source.* (Implementation note: confirms feasibility — the importer already reads the prior row for drift; provider-change is the same read.)
- **F4 — Sequencing.** With F1–F3 in place, ratify E9's per-asset suppression to replace the shipped range-scoped prefixes — landing the provider-change alert + the E9 consolidation **atomically** (no window where per-asset suppression exists without the net). *Rec: atomic; until then, the shipped range-scoped alerter stays (it's safe).*
- **F5 — Interaction with cloud_drift (E7).** Provider-change (scan-over-scan, derived-vs-derived) is distinct from cloud_drift (derived-vs-manual). Keep them separate: `cloud_classification_drift` = your manual flag disagrees with derivation; `provider_change` = the provider itself moved. *Rec: two distinct events, confirm.*

## For 4.7
Return numbered rulings for **F1–F5**. F1 (accept the net) and F4 (atomic sequencing with E9) are load-bearing — they're what let the E9 consolidation ship without reintroducing the hijack blind spot.
