"""Shared passive stack-ID helpers — the ONE definition, imported by every tier.

Extracted from run_heavy.py (Obsidian 146 P0) 2026-09-14, unchanged, so the
LIGHT tier can reuse it instead of growing a second copy. Cross-repo duplication
of exactly this kind is what made the FortiGate host lists unguardable (#053b),
and a fourth copy (2 functions x 2 repos) was the alternative on the table.

⛔ LEAF MODULE BY CONTRACT — stdlib only. It is imported by run_heavy AND
run_light; any scanner import added here lands in both tiers' import graphs.

⚠ THE KEY-FORMAT HAZARD, stated here because this is where it bites:
`_vendor_header_subset` keys on `lk.startswith("x-")` — WIRE format, hyphens.
The light tier's httpx `-irh` map uses UNDERSCORES (`x_ac`, `x_powered_by`;
see run_light.httpx_header_key). Feeding it an un-normalised httpx map matches
NOTHING and silently yields only `server`/`via` — which survive solely because
they contain no hyphen. Callers MUST normalise keys to wire format FIRST.
Measured on live Command artifacts 2026-09-14: commandmarketinginnovations.com
carries `x_ac` under httpx and `x-ac` under the pre-2026-09-08 curl path.
"""

_EDGE_MARKER_HEADERS = frozenset({
    "cf-ray", "cf-cache-status",          # Cloudflare (cf- prefix — missed by the x- catch-all)
    "x-amz-cf-id",                        # AWS CloudFront
    "x-azure-ref", "x-azure-fdid",        # Azure Front Door
    "x-served-by", "x-timer",             # Fastly
    "x-akamai-transformed", "x-akamai-request-id",  # Akamai
    "x-goog-generation",                  # Google (GCS/edge)
    "x-cache", "age", "cache-control",    # caching evidence -> CDN vs LB tie-break (Q2)
})


def _vendor_header_subset(header_obj) -> dict:
    """Small, value-free header view for vendor fingerprinting (4.7 cloud-edge Q1/Q6):
    the Server + Via VALUES (the edge names itself there — GFE, 'via: 1.1 google',
    AkamaiGHost) + PRESENCE booleans for a curated set of cloud-edge / CDN marker headers
    (cf-ray, x-amz-cf-id, x-azure-ref, x-served-by, ... + caching headers for the CDN
    tie-break) and any other x-* header. Marker values are NOT persisted — name-presence
    is the tell — keeping the artifact lean and avoiding arbitrary-value leakage."""
    if not isinstance(header_obj, dict):
        return {}
    keep: dict = {}
    for k, v in header_obj.items():
        lk = k.lower()
        val = v[0] if isinstance(v, list) and v else v
        if lk in ("server", "via"):
            keep[lk] = str(val)[:80]
        elif lk in _EDGE_MARKER_HEADERS or lk == "x-powered-by" or lk.startswith("x-"):
            keep[lk] = True
    return keep
