"""Canonical-host resolution for HTTP-layer phases (4.7 rulings 77-82).

WHY THIS EXISTS
---------------
An apex that canonically redirects to `www` (or vice versa) is the most common
DNS/web layout there is, and it silently costs us scan depth. Measured on
`prodexlabs.com` 2026-09-03:

    dig +short A prodexlabs.com      -> 8.232.147.166
    dig +short A www.prodexlabs.com  -> 8.232.147.166      (identical, no CNAME)

    # same IP forced; ONLY the Host header differs:
    Host: prodexlabs.com      -> 301  https://www.prodexlabs.com:443/
    Host: www.prodexlabs.com  -> 200

One box, one cert, one app, with a server-level canonical redirect keyed on the
Host header. The scanner sends `Host: <asset_id>`, so every HTTP-layer phase
receives the 301. Consequence, straight from the run log:

    tech-detect rejected 1 row(s): ['redirect_status_301']
    tech NOT detected (tech_detect_blocked)
    target_class=standard (stack=<unknown>) -> 4-chunk plan (of 9 possible)
    WARN plan shrunk: 5 stack-specific chunk(s) were not planned

So the asset loses 5 of 9 nuclei chunks, on every scan, forever.

WHAT THIS MODULE DOES *NOT* DO
------------------------------
It does not "follow redirects". That would be actively dangerous: two Command
assets (`myordersauth.unimacgraphics.com`, `myordersauth-test...`) 302 to
**login.microsoftonline.com**. Following a redirect blindly would point
nuclei/nikto/ffuf at Microsoft's identity service -- a third party we have no
authorization to scan. That is not a coverage improvement, it is an
unauthorised scan of someone else's infrastructure.

THE AUTHORISATION BOUNDARY (4.7 ruling 78) -- two conditions, EITHER sufficient:

  1. the redirect target is already an owned + confirmed_live asset, OR
  2. the target is in the SAME registrable domain as the source AND resolves to
     the IDENTICAL IP set (i.e. provably the same box, different vhost).

Condition 2 is what fixes `prodexlabs.com` *without* registering a duplicate
`www` asset -- registering one would rescan the same IP/TLS/ports and double
that site's deep-scan budget for no new coverage.

    NOTE ON THE APEX COMPUTATION: registrable_apex() uses the naive
    "last two labels" rule, mirroring is_fqdn_in_scope() in
    scripts/normalize/cs_parsers/common.py. That is wrong for multi-label
    suffixes (.co.uk), so it is deliberately NOT the safety property here --
    the IP-set equality is. The apex test is a cheap pre-filter that keeps us
    from even resolving obviously-foreign hosts. Both must hold.

FAIL CLOSED (4.7 ruling 79)
---------------------------
Every uncertain outcome resolves to "use the asset's own host", which is
exactly today's behaviour (partial coverage). We never follow a redirect that
was resolved under ambiguity, a failed probe, or a partial outage.

This is the OPPOSITE direction from the reachability gate (ruling 66), which
fails SAFE toward *running* phases. Different risks, same principle -- fail
toward the outcome that cannot cause the feared harm:
  * reachability gate: feared harm = silently losing coverage  -> run phases
  * canonical resolution: feared harm = scanning someone else  -> don't follow

NOT PERSISTED (4.7 ruling 79)
-----------------------------
The verdict is recomputed every scan and never written to a `canonical_host`
column. Persisting a derived value is the failure class that produced the
device-class flip (a writer stamping `unknown` over `confirmed` from ABSENT
evidence). Re-resolution is self-correcting; a stored value goes stale silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# ─── Outcome vocabulary ──────────────────────────────────────────────────
# These strings land in tool_status / GATE_SKIPPED reasons, so they are part
# of the data contract. Keep them stable and distinct.

USE_ASSET_HOST = "asset_host"
USE_CANONICAL = "canonical_redirect"
REDUNDANT_STUB = "redundant_redirect_stub"
THIRD_PARTY = "http_surface_is_third_party"

# Deliberately distinct from the reachability gate's
# `asset_does_not_serve_http`: these hosts DO serve HTTP, the surface just
# isn't ours to scan.
THIRD_PARTY_SSO = "http_surface_is_third_party_sso"


@dataclass(frozen=True)
class CanonicalVerdict:
    """What the HTTP-layer phases should do for this asset, and why."""

    # The host HTTP-layer phases should send as Host / use in URLs.
    http_host: str
    # One of the outcome constants above.
    outcome: str
    # Free-text detail for tool_status diagnostics.
    reason: str
    # Observed redirect target host, when there was one.
    redirect_to: Optional[str] = None
    # True when HTTP-layer phases should be GATE_SKIPPED entirely.
    skip_http: bool = False
    # Diagnostics worth persisting alongside the phase entry.
    diag: dict = field(default_factory=dict)

    @property
    def followed(self) -> bool:
        return self.outcome == USE_CANONICAL


def registrable_apex(host: str) -> str:
    """Naive last-two-labels apex. See the module NOTE -- pre-filter only."""
    if not host:
        return ""
    parts = [p for p in host.strip().lower().rstrip(".").split(".") if p]
    if len(parts) < 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def same_registrable_domain(a: str, b: str) -> bool:
    apex_a, apex_b = registrable_apex(a), registrable_apex(b)
    return bool(apex_a) and apex_a == apex_b


def _norm_ips(ips: Optional[Iterable[str]]) -> frozenset[str]:
    return frozenset(i.strip() for i in (ips or []) if i and i.strip())


def redirect_target_authorized(
    source_host: str,
    target_host: str,
    *,
    target_is_known_asset: bool,
    source_ips: Optional[Iterable[str]] = None,
    target_ips: Optional[Iterable[str]] = None,
) -> tuple[bool, str]:
    """4.7 ruling 78. Returns (authorized, reason).

    Either condition suffices; neither -> refuse. Refusal is the default for
    every path through this function.
    """
    if not source_host or not target_host:
        return False, "missing_host"

    src = source_host.strip().lower().rstrip(".")
    tgt = target_host.strip().lower().rstrip(".")

    if src == tgt:
        return False, "self_redirect"

    # Condition 1 — explicitly in scope already.
    if target_is_known_asset:
        return True, "target_is_owned_asset"

    # Condition 2 — same registrable domain AND provably the same box.
    if not same_registrable_domain(src, tgt):
        # This is the branch that refuses login.microsoftonline.com.
        return False, "target_off_registrable_domain"

    s_ips, t_ips = _norm_ips(source_ips), _norm_ips(target_ips)
    if not s_ips or not t_ips:
        # Cannot prove same-box -> fail closed.
        return False, "ip_sets_unresolved"
    if s_ips != t_ips:
        return False, "same_domain_different_infrastructure"

    return True, "same_registrable_domain_same_ip_set"


def resolve_canonical_host(
    asset_host: str,
    *,
    probe: Callable[[str], Optional[tuple[int, Optional[str]]]],
    resolve_ips: Callable[[str], Optional[Iterable[str]]],
    is_known_asset: Callable[[str], bool],
    known_sso_hosts: Optional[Iterable[str]] = None,
) -> CanonicalVerdict:
    """Decide the Host for HTTP-layer phases. Pure apart from the injected
    `probe` / `resolve_ips` / `is_known_asset` callables, so the decision is
    unit-testable without network or DB.

    `probe(host)` must return `(status_code, location_host_or_url)` or None on
    any failure. `None` and every unexpected shape fail closed to the asset
    host.
    """
    host = (asset_host or "").strip().lower().rstrip(".")
    if not host:
        return CanonicalVerdict(
            http_host=asset_host, outcome=USE_ASSET_HOST, reason="no_asset_host"
        )

    # Defence in depth (4.7 ruling 81): assets explicitly marked as
    # third-party-SSO fronted never get their redirect followed, even if the
    # boundary logic below were to regress.
    forbidden = {h.strip().lower() for h in (known_sso_hosts or []) if h}
    if host in forbidden:
        return CanonicalVerdict(
            http_host=host,
            outcome=THIRD_PARTY_SSO,
            reason="asset_marked_third_party_sso",
            skip_http=True,
            diag={"boundary": "explicit_forbidden_list"},
        )

    try:
        probed = probe(host)
    except Exception as exc:  # noqa: BLE001 - any probe failure fails closed
        return CanonicalVerdict(
            http_host=host,
            outcome=USE_ASSET_HOST,
            reason="probe_raised",
            diag={"error": type(exc).__name__},
        )

    if not probed or len(probed) != 2:
        return CanonicalVerdict(
            http_host=host, outcome=USE_ASSET_HOST, reason="probe_failed"
        )

    status, location = probed
    try:
        status = int(status)
    except (TypeError, ValueError):
        return CanonicalVerdict(
            http_host=host, outcome=USE_ASSET_HOST, reason="probe_bad_status"
        )

    # Only permanent/canonical redirects are treated as canonicalisation.
    # 302/303/307 are frequently app-level (login flows, interstitials) and are
    # NOT a statement about the canonical host.
    if status not in (301, 308):
        return CanonicalVerdict(
            http_host=host,
            outcome=USE_ASSET_HOST,
            reason=f"status_{status}_not_canonical_redirect",
            diag={"status": status},
        )

    target = _host_from_location(location)
    if not target:
        return CanonicalVerdict(
            http_host=host,
            outcome=USE_ASSET_HOST,
            reason="redirect_without_usable_location",
            diag={"status": status},
        )
    if target == host:
        return CanonicalVerdict(
            http_host=host,
            outcome=USE_ASSET_HOST,
            reason="self_redirect",
            redirect_to=target,
            diag={"status": status},
        )

    target_is_asset = bool(is_known_asset(target))

    # (C) The target is already scanned in its own right, so THIS asset is a
    # redundant redirect stub. Do not double-scan the same application.
    if target_is_asset:
        return CanonicalVerdict(
            http_host=host,
            outcome=REDUNDANT_STUB,
            reason="canonical_target_is_separately_scanned_asset",
            redirect_to=target,
            skip_http=True,
            diag={"status": status, "canonical_target": target},
        )

    src_ips = _safe(resolve_ips, host)
    tgt_ips = _safe(resolve_ips, target)

    authorized, why = redirect_target_authorized(
        host,
        target,
        target_is_known_asset=False,
        source_ips=src_ips,
        target_ips=tgt_ips,
    )

    if not authorized:
        # Off-domain is the login.microsoftonline.com case: the asset's own
        # HTTP surface is a redirect into someone else's application, so there
        # is nothing here for us to scan.
        if why == "target_off_registrable_domain":
            return CanonicalVerdict(
                http_host=host,
                outcome=THIRD_PARTY,
                reason=why,
                redirect_to=target,
                skip_http=True,
                diag={"status": status, "canonical_target": target},
            )
        return CanonicalVerdict(
            http_host=host,
            outcome=USE_ASSET_HOST,
            reason=why,
            redirect_to=target,
            diag={
                "status": status,
                "canonical_target": target,
                "source_ips": sorted(_norm_ips(src_ips)),
                "target_ips": sorted(_norm_ips(tgt_ips)),
            },
        )

    # (A) Same box, different vhost -> scan the canonical Host.
    return CanonicalVerdict(
        http_host=target,
        outcome=USE_CANONICAL,
        reason=why,
        redirect_to=target,
        diag={
            "status": status,
            "asset_host": host,
            "canonical_host": target,
            "shared_ips": sorted(_norm_ips(src_ips)),
        },
    )


def _safe(fn: Callable[[str], Optional[Iterable[str]]], host: str):
    try:
        return fn(host)
    except Exception:  # noqa: BLE001 - unresolved -> fail closed upstream
        return None


def _host_from_location(location: Optional[str]) -> Optional[str]:
    """Extract a hostname from a Location header or a bare host."""
    if not location:
        return None
    loc = str(location).strip()
    if not loc:
        return None
    if "//" in loc:
        loc = loc.split("//", 1)[1]
    # Strip path, query, fragment, then userinfo, then port.
    for sep in ("/", "?", "#"):
        loc = loc.split(sep, 1)[0]
    if "@" in loc:
        loc = loc.rsplit("@", 1)[1]
    loc = loc.split(":", 1)[0]
    loc = loc.strip().lower().rstrip(".")
    return loc or None
