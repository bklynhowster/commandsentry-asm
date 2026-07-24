#!/usr/bin/env python3
"""
cloud_ip_check.py — scan-time "is this IP a cloud/CDN edge?" check (4.7 N2 / M1-M2, 2026-07-24).

Purpose: the scanner (asm-discover.sh) must decide BEFORE running naabu whether an
asset sits behind a cloud/load-balancer edge, so it can probe a curated port set
instead of a top-1000 sweep (which produces phantom "open" ports against cloud
edges — see the littleleaffarms.prodexlabs.com / GCP investigation, 2026-07-24).

M1 (hybrid): this is the SCAN-TIME gate. The classifier (derive_cloud_endpoint.py)
remains the authoritative record written to assets.device_class / cloud_provider.
M2 (single source of truth): this reads the SAME registry the classifier uses —
scripts/asm/cloud_providers.yaml — so the two cannot drift.

Signal (mirrors the classifier's D6 priority, using what's cheaply available at
scan time): IP -> ASN via Team Cymru origin DNS (reliable, no whois-port dependency;
`dig` per the GH-runner lesson that dnsx is flaky), matched against each provider's
`asns`; plus the `ip_prefixes` string-prefix backstop. (CNAME suffix — the classifier's
top signal — is handled separately by the caller when it has the FQDN's CNAME.)

Usage:
    python3 cloud_ip_check.py <ip>
Prints the provider id (e.g. "gcp") and exits 0 if the IP is a cloud edge;
prints nothing and exits 1 if not; exits 2 on a hard error (caller should
fail OPEN — treat as non-cloud and do the normal sweep, so we never SKIP a real
origin's deep scan because a lookup broke).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REGISTRY = Path(__file__).resolve().parent / "cloud_providers.yaml"


def _cymru_asn(ip: str) -> str | None:
    """IP -> ASN (e.g. 'AS396982') via Team Cymru origin DNS TXT. None on failure."""
    parts = ip.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None  # IPv4 only; IPv6 handled by ip_prefixes backstop if listed
    rev = ".".join(reversed(parts))
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=2", f"{rev}.origin.asn.cymru.com", "TXT"],
            capture_output=True, text=True, timeout=12,
        ).stdout
    except Exception:
        return None
    # TXT looks like: "396982 | 35.227.0.0/16 | US | arin | 2017-09-29"
    for line in out.splitlines():
        field = line.strip().strip('"').split("|")[0].strip()
        # first token may be a space-separated list of ASNs; take the first
        asn = field.split()[0] if field.split() else ""
        if asn.isdigit():
            return f"AS{asn}"
    return None


def detect(ip: str) -> str | None:
    """Return provider id if `ip` is a known cloud edge, else None."""
    try:
        import yaml
    except Exception:
        sys.exit(2)  # PyYAML missing — caller fails open
    try:
        reg = yaml.safe_load(REGISTRY.read_text()) or {}
    except Exception:
        sys.exit(2)
    providers = reg.get("providers") or {}

    asn = _cymru_asn(ip)
    ip = ip.strip()
    for pid, p in providers.items():
        if asn and asn in (p.get("asns") or []):
            return pid
        for pfx in (p.get("ip_prefixes") or []):
            if ip.startswith(pfx):
                return pid
    return None


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: cloud_ip_check.py <ip>\n")
        return 2
    provider = detect(sys.argv[1])
    if provider:
        print(provider)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
