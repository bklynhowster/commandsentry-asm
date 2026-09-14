"""Shared passive stack-ID helpers — the ONE definition, imported by every tier.

Extracted from run_heavy.py (Obsidian 146 P0) 2026-09-14 so the LIGHT tier can
reuse it instead of growing a second copy. Cross-repo duplication of exactly this
kind is what made the FortiGate host lists unguardable (#053b); a fourth copy
(2 functions x 2 repos) was the alternative on the table.

⛔ LEAF MODULE BY CONTRACT — zero imports. It is imported by run_heavy AND
run_light; anything added here lands in both tiers' import graphs.

⚠⚠ THE KEY-FORMAT HAZARD — read this before calling anything below.
Both `vendor_header_subset` and `extract_set_cookie_names` match WIRE-format
header names (hyphens): `startswith("x-")`, `== "set-cookie"`. They were written
against curl's raw header block. The LIGHT tier's httpx `-irh` map uses
UNDERSCORES (`x_ac`, `x_powered_by`, `set_cookie`; see run_light.httpx_header_key).

Fed an un-normalised httpx map they match NOTHING: every edge marker and every
cookie is dropped, and only `server`/`via` survive — because those two happen to
contain no hyphen. The result is a well-formed, non-empty artifact that silently
omits the signal it exists to carry.

⇒ CALLERS MUST `normalise_header_keys()` FIRST, THEN subset/extract.

Measured on live Command artifacts 2026-09-14: commandmarketinginnovations.com
carries `x_ac` under httpx and `x-ac` under the pre-2026-09-08 curl path — both
formats are in the live corpus, which is why the normaliser is idempotent.
"""

# The scan_run_artifacts.tool_name the LIGHT tier writes its passive posture
# under. ⛔ DELIBERATELY NOT in the `stack_id_passive%` namespace: the Command
# workflow seed-device-class.yml gates on `tool_name ilike 'stack_id_passive%'`
# as a proxy for "this asset has had its post-collector HEAVY". A light artifact
# matching that prefix would make every light-swept asset look already-seeded and
# silently stop seeding the assets that still need a heavy. Renamed rather than
# excluded, per feedback_naming_into_a_namespace_is_a_consumer_question.
LIGHT_PASSIVE_TOOL = "light_stack_passive"

EDGE_MARKER_HEADERS = frozenset({
    "cf-ray", "cf-cache-status",          # Cloudflare (cf- prefix — missed by the x- catch-all)
    "x-amz-cf-id",                        # AWS CloudFront
    "x-azure-ref", "x-azure-fdid",        # Azure Front Door
    "x-served-by", "x-timer",             # Fastly
    "x-akamai-transformed", "x-akamai-request-id",  # Akamai
    "x-goog-generation",                  # Google (GCS/edge)
    "x-cache", "age", "cache-control",    # caching evidence -> CDN vs LB tie-break (Q2)
})


def wire_header_key(key: str) -> str:
    """httpx `-irh` key -> wire-format header name. KEY ONLY, never values.

    Inverse of run_light.httpx_header_key (lowercase + hyphens -> underscores).

    IDEMPOTENT by construction: the output contains no underscores, so feeding a
    wire-format key back through returns it unchanged. That matters because the
    live artifact corpus spans the 2026-09-08 curl->httpx migration and holds
    BOTH formats.

    ⚠ Labelled DEFENSIVE HARDENING, not a defect being prevented. Verified
    2026-09-14: gather_observations reads only `stack_id_*` artifacts, heavy's
    collector is curl (wire format), so no live reader currently mixes formats.
    Recorded so a later reader neither deletes this as dead weight nor keeps it
    for a reason that was never true.
    """
    if not isinstance(key, str):
        return ""
    return key.strip().lower().replace("_", "-")


def normalise_header_keys(header_obj) -> dict:
    """{httpx-or-wire key: value} -> {wire key: value}. Values untouched.

    Values legitimately contain underscores (cookie names, ETags, tokens), so the
    substitution is applied to keys ONLY. Later keys win on collision, which can
    only happen if a map already holds both `x-ac` and `x_ac` — not observed.
    """
    if not isinstance(header_obj, dict):
        return {}
    return {wire_header_key(k): v for k, v in header_obj.items()}


def extract_set_cookie_names(header_obj) -> list:
    """Distinct Set-Cookie NAMES (token before '='), never values. httpx -irh
    puts response headers under 'header' (dict; a Set-Cookie may be str or list);
    also handles a raw header block (str)."""
    raw: list = []
    if isinstance(header_obj, dict):
        for k, v in header_obj.items():
            if k.lower() == "set-cookie":
                raw.extend(v if isinstance(v, list) else [v])
    elif isinstance(header_obj, str):
        for line in header_obj.splitlines():
            if line.lower().startswith("set-cookie:"):
                raw.append(line.split(":", 1)[1])
    names: list = []
    for c in raw:
        name = str(c).split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def vendor_header_subset(header_obj) -> dict:
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
        elif lk in EDGE_MARKER_HEADERS or lk == "x-powered-by" or lk.startswith("x-"):
            keep[lk] = True
    return keep
