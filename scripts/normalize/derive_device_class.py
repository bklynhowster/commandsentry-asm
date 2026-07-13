#!/usr/bin/env python3
"""
derive_device_class.py — ASM device-class classifier (4.7 D2/D3, 2026-07-13).

Pure functions. Given the raw device-fingerprint OBSERVATIONS for one asset
(SSH banner, wafw00f vendor, HTTP headers, cert issuer, fwbbot_check hit, IPs,
Fortinet CVE-template hit), decide the asset's TOPOLOGY ROLE — origin_host /
edge_firewall / waf / adc_lb / cdn / cloud_endpoint / unknown — and how
confident we are, using:
  * scripts/asm/device_fingerprints.yaml       — observation -> (class, vendor) rows
  * scripts/scanner/classifier_thresholds.yaml — signal weights + the D3 bar

Returns {device_class, confidence, evidence, vendor_product}:
  * device_class default 'unknown' (4.7 D2 — never presume origin on no evidence)
  * confidence in {confirmed, suspected, unknown} per the D3 multi-signal bar,
    computed over the DISTINCT signal names supporting the winning class:
      confirmed = >=2 high  OR  (>=1 high AND >=2 medium)
      suspected = 1 high    OR  >=2 medium
      unknown   = otherwise
  * evidence = the matched signals (jsonb-ready) so the write is auditable and
    the D3 freshness / class-transition guards have something to diff.

FRESHNESS (D3): the >30-day drop is the RUNNER's job — it only feeds observations
from scans within evidence_freshness_days. This pure scorer trusts its inputs.

ROUTING (D4): only a 'confirmed' class may change scan routing. That gate lives
in the routing layer, not here — this function only reports class + confidence.

Self-test: python3 scripts/normalize/derive_device_class.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_HERE = Path(__file__).resolve().parent.parent
FINGERPRINTS_PATH = _HERE / "asm" / "device_fingerprints.yaml"
THRESHOLDS_PATH = _HERE / "scanner" / "classifier_thresholds.yaml"

DEFAULT_CLASS = "unknown"


def load_fingerprints(path: Path = FINGERPRINTS_PATH) -> list[dict]:
    if yaml is None:
        raise RuntimeError("PyYAML required to read device_fingerprints.yaml")
    data = yaml.safe_load(path.read_text()) or {}
    return list(data.get("fingerprints") or [])


def load_thresholds(path: Path = THRESHOLDS_PATH) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML required to read classifier_thresholds.yaml")
    data = yaml.safe_load(path.read_text()) or {}
    sig = data.get("signals") or {}
    weight: dict[str, str] = {}
    for w in ("high", "medium", "low"):
        for name in (sig.get(w) or []):
            weight[name] = w
    return {
        "weight": weight,
        "routing_requires": data.get("routing_requires", "confirmed"),
        "evidence_freshness_days": int(data.get("evidence_freshness_days", 30)),
    }


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [v] if isinstance(v, str) else [str(x) for x in v]


def _fp_matches(fp: dict, observations: dict):
    """Return the matched evidence string if this fingerprint matches, else None."""
    obs = observations.get(fp.get("observation"))
    if obs is None:
        return None

    # boolean observations (fwbbot_check, nuclei_fortinet_hit)
    if "match_bool" in fp:
        return "hit" if (bool(obs) and bool(fp["match_bool"])) else None

    # ip-prefix observation (ips: list)
    if "ip_prefixes" in fp:
        pfx = tuple(fp["ip_prefixes"])
        for ip in _as_list(obs):
            if ip.startswith(pfx):
                return ip
        return None

    # text observations (ssh_banner, waf_vendor, http_headers, cert_issuer)
    hay = " ".join(_as_list(obs)).lower()
    for sub in (fp.get("match_substrings") or []):
        if sub.lower() in hay:
            return sub
    rx = fp.get("match_regex")
    if rx:
        m = re.search(rx, hay, re.I)
        if m:
            return m.group(0)
    return None


def match_signals(observations: dict, fingerprints: list[dict], thresholds: dict) -> list[dict]:
    """Every fingerprint that matches -> one evidence record."""
    weight = thresholds["weight"]
    out = []
    for fp in fingerprints:
        ev = _fp_matches(fp, observations)
        if ev is None:
            continue
        sig = fp.get("signal")
        out.append({
            "signal": sig,
            "weight": weight.get(sig, "low"),
            "device_class": fp.get("device_class"),
            "vendor_product": fp.get("vendor_product") or {},
            "matched": ev,
            "observation": fp.get("observation"),
        })
    return out


def _confidence(high: int, medium: int) -> str:
    if high >= 2 or (high >= 1 and medium >= 2):
        return "confirmed"
    if high >= 1 or medium >= 2:
        return "suspected"
    return "unknown"


def classify(observations: dict,
             fingerprints: list[dict] | None = None,
             thresholds: dict | None = None) -> dict:
    """Pure classifier. observations keys: ssh_banner, waf_vendor, http_headers,
    cert_issuer, fwbbot_check, ips, nuclei_fortinet_hit. Returns
    {device_class, confidence, evidence, vendor_product}."""
    fingerprints = fingerprints if fingerprints is not None else load_fingerprints()
    thresholds = thresholds if thresholds is not None else load_thresholds()

    matched = match_signals(observations, fingerprints, thresholds)
    if not matched:
        return {"device_class": DEFAULT_CLASS, "confidence": "unknown",
                "evidence": [], "vendor_product": {}}

    # Winning class = the device_class with the strongest support: most distinct
    # high-weight signal NAMES, then medium, then low. Distinct names so two
    # fingerprint rows for the same signal can't double-count the bar.
    by_class: dict[str, dict] = {}
    for m in matched:
        slot = by_class.setdefault(m["device_class"],
                                   {"high": set(), "medium": set(), "low": set(), "vendor": {}})
        slot[m["weight"]].add(m["signal"])
        slot["vendor"].update(m["vendor_product"])

    win_class, win = max(
        by_class.items(),
        key=lambda kv: (len(kv[1]["high"]), len(kv[1]["medium"]), len(kv[1]["low"])),
    )
    conf = _confidence(len(win["high"]), len(win["medium"]))

    # If even the strongest class can't clear 'suspected' (only low-weight or
    # nothing decisive), stay unknown — 4.7 D2/D3.
    if conf == "unknown":
        return {"device_class": DEFAULT_CLASS, "confidence": "unknown",
                "evidence": matched, "vendor_product": {}}

    return {
        "device_class": win_class,
        "confidence": conf,
        "evidence": matched,           # all matched signals — audit + transition diff
        "vendor_product": win["vendor"],
    }


def _selftest() -> int:
    fps, th = load_fingerprints(), load_thresholds()

    # 1) The pilot: ftp.sciimage.com / 24.157.51.76. SSH banner (high) + GoDaddy
    #    cert (medium). Expect edge_firewall / SUSPECTED — matches our human read
    #    (SCI edge appliance, but the banner never literally names Fortinet).
    ftp = {
        "ssh_banner": "SSH-2.0-8.1.0.0_openssh SCI",
        "cert_issuer": "Go Daddy Secure Certificate Authority - G2",
        "ips": ["24.157.51.76"],
    }
    # 2) A FortiWeb-fronted asset: bot challenge (high) + wafw00f (high) + range
    #    (medium). Expect waf / CONFIRMED (2 high) — would be routing-eligible.
    waf = {"fwbbot_check": True, "waf_vendor": "FortiWeb", "ips": ["52.119.65.5"]}
    # 3) A plain host, stock OpenSSH, nothing distinctive. Expect UNKNOWN — never
    #    presume origin on absence of evidence (D2).
    bare = {"ssh_banner": "SSH-2.0-OpenSSH_9.3"}
    # 4) A NON-Fortinet edge — Pressable/Automattic (Unimac). Cert CN + IP range,
    #    two mediums. Expect cdn / SUSPECTED. Proves the classifier isn't Forti-only.
    pressable = {"cert_subject": "tls.automattic.com", "ips": ["199.16.172.68"]}

    expected = {
        "ftp": ("edge_firewall", "suspected"),
        "waf": ("waf", "confirmed"),
        "bare": ("unknown", "unknown"),
        "pressable": ("cdn", "suspected"),
    }
    results = {"ftp": classify(ftp, fps, th), "waf": classify(waf, fps, th),
               "bare": classify(bare, fps, th),
               "pressable": classify(pressable, fps, th)}
    ok = True
    for k, r in results.items():
        got = (r["device_class"], r["confidence"])
        flag = "OK " if got == expected[k] else "XX "
        ok &= got == expected[k]
        print(f"  {flag}{k:5s} -> class={r['device_class']:<13s} conf={r['confidence']:<9s} "
              f"vendor={r['vendor_product']}  (want {expected[k]})")
    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_selftest())
