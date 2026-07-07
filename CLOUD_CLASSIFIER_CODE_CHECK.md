# Code Check — cloud-endpoint classifier (D6) + provider registry (D10)

**Status:** PROPOSED 2026-07-07 (PM) · awaiting 4.7 numbered rulings. NOTHING pushed/wired — the two files below are validated but uncommitted; they are inert until the importer hook (E5) lands, so nothing is live ahead of this review.
**Follows:** 4.7's ratification of D6/D10 (design-level) in `V3_GUARD_AND_CLOUD_ENDPOINT_SPEC.md`. This is the *implementation* check — it deviates from and under-delivers against that ruling in named ways below.

## What was built
- `scripts/asm/cloud_providers.yaml` (D10) — per-provider registry: `asns`, `asn_org_patterns`, `cname_suffixes`, `ip_prefixes`, `rotating`; plus a `rotating_cname_overrides` list. Providers: microsoft_o365, azure, cloudflare, akamai, aws, gcp.
- `scripts/normalize/derive_cloud_endpoint.py` (D6) — pure `classify(sub, registry) -> {cloud_provider, is_cloud_endpoint} | None`. Signal order **CNAME suffix → ASN/asn_org → IP prefix**; Microsoft disambiguated O365-vs-Azure; CloudFront/Azure-CDN CNAMEs override `rotating=false`.

## Validation (real fleet, `derive_cloud_endpoint.py` self-test — no DB writes)
- `email.commandcompanies.com` (asn_org "Microsoft Corporation", mail ports) → **microsoft_o365, is_cloud_endpoint=true** ✅ (the flapping asset — the one true rotating endpoint)
- Unimac Azure portals (`myorders`, `portal`, `zoetislabs`… — same "Microsoft" ASN, NO mail ports) → **azure, is_cloud_endpoint=false** ✅ (real IP changes still alert)
- Route 53 NS (`ns01/ns02`, "Amazon.com") → **aws, false** ✅ · Pressable/Cablevision/Verizon self-hosted → **None** ✅
- Clean across all 5 apex files; the one rotating endpoint is isolated, everything static is left alone.

## Decision points

- **E1 — DEVIATION: ASN/`asn_org` as a primary signal.** Your D6 order was CNAME/MX → IP → volatility → manual (+cert-SAN as b.5); ASN was not listed. The ASM already records `hosts[].asn` + `hosts[].asn_org` per IP, so it's a reliable, zero-cost signal — the validation above rides on it. Proposed order: **CNAME → ASN/asn_org → IP**. *Rec: ACCEPT the reordered priority (ASN slots between CNAME and IP).* Confirm or re-rank.
- **E2 — `rotating` two-level model.** `is_cloud_endpoint=true` ONLY for rotating providers (O365/Cloudflare/Akamai). AWS/Azure/GCP get `cloud_provider` recorded but `is_cloud_endpoint=false` (a stable cloud VM's IP change is meaningful). `rotating_cname_overrides` flips CloudFront/Azure-CDN back to rotating. *Rec: ACCEPT — separates "cloud-hosted" (informational) from "churns per-IP" (suppress).* 
- **E3 — O365-vs-Azure disambiguation** (shared Microsoft ASN): CNAME → mail-ports {25,465,587,993,995,110,143} → O365 IP-range → default Azure. *Rec: ACCEPT.*
- **E4 — DEFERRED ruled items.** Not in v1: cert-SAN signal (your b.5), volatility backstop (tier c), explicit weekly re-eval. v1 = CNAME/ASN/IP only, which classified the whole current fleet correctly. *Rec: ship v1 without them; add cert-SAN + volatility as a follow-up when a real case needs them.* Rule whether any are REQUIRED for v1.
- **E5 — Importer hook (prod-pipeline change).** `scripts/db/import_asm_to_surface.py`, statements `UPSERT_ASSET` + `UPSERT_NEW_SUBDOMAIN_ASSET`: add `is_cloud_endpoint / cloud_provider / cloud_source / cloud_endpoint_classified_at` to the payload (computed per-subdomain via `classify()`), with a sticky-manual guard `cloud_source = CASE WHEN public.assets.cloud_source='manual' THEN <keep manual is_cloud_endpoint/cloud_provider/cloud_source> ELSE <derived> END`, mirroring the existing `discovery_status` sticky-live + "preserve manually-flipped kind" pattern in that file. *Rec: ACCEPT this hook + sticky-manual mechanism.*
- **E6 — Re-eval cadence.** The importer re-derives on EVERY scan/import, so classification is continuously fresh — arguably supersedes your "weekly re-eval" (D6). `cloud_endpoint_classified_at` stamps each derivation. *Rec: per-import re-derivation replaces the weekly job; confirm.*
- **E7 — Derived-vs-manual drift (your D9).** On import, if the derived result disagrees with a sticky manual flag, write an `admin_audit_log` `cloud_classification_drift` entry (never auto-flip), mirroring `kind_drift`. *Rec: ADD this — it's not yet in the code.* Confirm shape.
- **E8 — Partial IP-prefix lists.** IP ranges in the yaml are a backstop only (ASN/CNAME carry the load); they're intentionally incomplete. *Rec: accept partial as backstop.* 
- **E9 — Alerter vs classifier: two sources of truth.** The shipped alerter (`post-email-alerts.py`, `33db13d`) hardcodes IP-prefixes; the classifier uses the yaml. *Rec: after this lands, refactor the alerter to read `cloud_providers.yaml` (single source), OR have the alerter read the DB `is_cloud_endpoint` the classifier populates.* Rule which consolidation you want (or defer).

## Still outstanding (separate, not in this check)
CNAME-target-change alert (your D7 caveat — the alerter has none today); Prodex parity (port 20260707b + alerter + classifier); reusable `flag_cloud_endpoint.py` (D9 helper — the manual flag was done via direct SQL this round).

## For 4.7
Return numbered rulings for **E1–E9** (accept / modify / reject + conditions). E1 (ASN-primary deviation) and E5 (importer hook) are the load-bearing ones; E4 decides v1 scope; E7 is a gap I'm flagging against myself.
