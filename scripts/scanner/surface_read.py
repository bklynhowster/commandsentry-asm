#!/usr/bin/env python3
"""Read discovery signals from asset_surface.surface_data (targeted-scan P1a).

Pure: dict -> (open_ports, fingerprint_tokens, has_http). No I/O, no DB. The
DB read itself lives in run_medium.run(); this module only interprets the jsonb
it returns, so it is fully unit-testable and cannot silently narrow coverage.

SCHEMA FIDELITY: this mirrors the EXACT surface_data shape that
scripts/normalize/derive_asset_kind.py consumes —
  surface_data.subdomains[].{name,is_root,reachability,fingerprint.tech[],services[],waf}
It is kept in the scanner package (NOT imported across scripts/normalize) so the
Docker scanner image stays self-contained.

SCHEMA-VERSION GATE (fail-safe): only surface_data.schema_version in
SUPPORTED_SCHEMA_VERSIONS is parsed. Anything else returns None -> the caller
skips exposure planning entirely and the existing http scan runs unchanged. This
is a deliberate mirror of derive_asset_kind.SUPPORTED_SCHEMA_VERSIONS — bump BOTH
together when discovery's schema bumps. Drifting only-this-file toward "stop
parsing" is the safe direction (no false exposure, existing scan unaffected).
"""
from __future__ import annotations

# Mirror of scripts/normalize/derive_asset_kind.SUPPORTED_SCHEMA_VERSIONS.
# Duplicated (not imported) to keep the scanner image dependency-free; keep in
# lockstep with that module.
SUPPORTED_SCHEMA_VERSIONS = {"3.0"}


def pick_sub(surface_data, asset_name):
    """name-match, else is_root, else None.

    Faithful mirror of derive_asset_kind.pick_sub — NEVER guesses subdomains[0]
    (hole 5 in that module's review). Returns the sub dict or None.
    """
    subs = (surface_data or {}).get("subdomains") or []
    for s in subs:
        if isinstance(s, dict) and s.get("name") == asset_name:
            return s
    for s in subs:
        if isinstance(s, dict) and s.get("is_root"):
            return s
    return None


def extract_signals(surface_data, asset_name):
    """Return (open_ports, fingerprint_tokens, has_http) for the host, or None.

    None is the fail-safe outcome for: not-a-dict surface_data, unsupported /
    missing schema_version, or no matching subdomain. The caller treats None as
    "no usable discovery signals -> skip exposure planning" (never narrows the
    existing scan).

    Fields read (mirror of derive_asset_kind.derive lines that read `sub`):
      reachability.http_status  -> has_http contributor
      fingerprint.tech[].name   -> fingerprint_tokens (web-role selection)
      services[].port           -> open_ports (network-role match + exposure)
      services[].service        -> has_http contributor ('http'/'https')

    has_http also treats 80/443 in open_ports as http (so a bare 80/443 can never
    be mis-emitted as an unmatched-port exposure).
    """
    if not isinstance(surface_data, dict):
        return None
    if surface_data.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        return None
    sub = pick_sub(surface_data, asset_name)
    if sub is None:
        return None

    r = sub.get("reachability") or {}
    status = r.get("http_status")

    fp = sub.get("fingerprint") or {}
    tech = [
        (t.get("name") or "")
        for t in (fp.get("tech") or [])
        if isinstance(t, dict)
    ]
    fingerprint_tokens = [t for t in tech if t]

    svcs = sub.get("services") or []
    ports = sorted({
        s.get("port")
        for s in svcs
        if isinstance(s, dict) and isinstance(s.get("port"), int)
    })
    port_set = set(ports)

    has_http = (
        (status is not None)
        or any(
            (s.get("service") in ("http", "https"))
            for s in svcs
            if isinstance(s, dict)
        )
        or (80 in port_set)
        or (443 in port_set)
    )

    return ports, fingerprint_tokens, has_http
