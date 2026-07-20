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

Returns {device_class, confidence, device_class_confidence,
vendor_product_confidence, evidence, vendor_product}:
  * device_class default 'unknown' (4.7 D2 — never presume origin on no evidence)
  * confidence in {confirmed, suspected, unknown} per the D3 multi-signal bar,
    == device_class_confidence (kept as 'confidence' for the routing path).
  * vendor_product_confidence (R5, Obsidian 146): same scale, scored over
    vendor_identifying signals ONLY — presence_only confirms the CLASS but never
    earns the right to name a vendor. P2 gates CVE attribution on this == confirmed.
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
COOKIE_SIGNATURES_PATH = _HERE / "asm" / "cookie_signatures.yaml"

DEFAULT_CLASS = "unknown"

# ── 4.7 R6 machine enforcement (2026-07-18) ─────────────────────────────────
# Topology roles a fingerprint row may assert (D2 enum minus the runtime-only
# 'unknown' default — a row must commit to a real role).
ROW_DEVICE_CLASSES = {
    "edge_firewall", "waf", "adc_lb", "cdn", "cloud_endpoint", "origin_host",
}
# The two-bar test, made machine-checkable. Every row MUST declare which one it
# clears, and the declaration MUST match its vendor_product (see validate_*).
EVIDENCE_CLASSES = {"vendor_identifying", "presence_only"}


class RegistryValidationError(ValueError):
    """A device_fingerprints.yaml row violates the R6 evidence-class schema.
    Raised at classifier startup so a bad row makes the classifier REFUSE to
    start rather than silently mislabel an asset (4.7 R6, risk #2)."""


def validate_fingerprints(fingerprints: list[dict], weight_map: dict | None = None) -> list[str]:
    """Return a list of human-readable errors (empty == valid). This is the
    guard that stops an inferred brand (the family:fortinet_suspected class of
    bug) ever going back in by hand.

    Rules (4.7 R6):
      1. evidence_class present and in EVIDENCE_CLASSES
      2. presence_only  -> vendor_product carries NO 'vendor'/'product'
                           (operator metadata like managed_by IS allowed)
      3. vendor_identifying -> vendor_product carries a non-empty 'vendor'
      4. device_class in ROW_DEVICE_CLASSES
      5. signal present; observation present
      6. (only when weight_map given) signal is a ratified weight — i.e. it
         appears in classifier_thresholds.yaml, not silently defaulted to 'low'
    """
    errs: list[str] = []
    for i, fp in enumerate(fingerprints):
        sig = fp.get("signal")
        tag = f"row[{i}] signal={sig!r}"
        if not sig:
            errs.append(f"{tag}: missing 'signal'")
        if not fp.get("observation"):
            errs.append(f"{tag}: missing 'observation'")
        dc = fp.get("device_class")
        if dc not in ROW_DEVICE_CLASSES:
            errs.append(f"{tag}: device_class {dc!r} not in {sorted(ROW_DEVICE_CLASSES)}")
        vp = fp.get("vendor_product") or {}
        has_vendor = bool(vp.get("vendor"))
        has_product = bool(vp.get("product"))
        ec = fp.get("evidence_class")
        if ec not in EVIDENCE_CLASSES:
            errs.append(f"{tag}: evidence_class {ec!r} must be one of {sorted(EVIDENCE_CLASSES)}")
        elif ec == "presence_only" and (has_vendor or has_product):
            errs.append(f"{tag}: presence_only forbids vendor/product in vendor_product "
                        f"(got {vp}); operator metadata like managed_by is fine")
        elif ec == "vendor_identifying" and not has_vendor:
            errs.append(f"{tag}: vendor_identifying requires a non-empty 'vendor' "
                        f"in vendor_product (got {vp})")
        if weight_map is not None and sig and sig not in weight_map:
            errs.append(f"{tag}: signal not a ratified weight in classifier_thresholds.yaml")
    return errs


def load_cookie_signatures(path: Path = COOKIE_SIGNATURES_PATH) -> dict:
    """cookie_name (lowercased) -> corpus entry. The R4 provenance store for
    cookie->vendor attribution (4.7 Q2/Q8b). A missing file yields {} — a cookie
    vendor row will then fail validate_cookie_citations, which is the intent."""
    if yaml is None or not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    out: dict = {}
    for e in (data.get("cookie_signatures") or []):
        name = e.get("cookie_name")
        if name:
            out[str(name).lower()] = e
    return out


def validate_cookie_citations(fingerprints: list[dict],
                              cookie_sigs: dict | None = None) -> list[str]:
    """4.7 R4 ship-blocker: every vendor_identifying row that matches on
    `set_cookie_names` must map each cookie value to a cookie_signatures.yaml entry
    carrying a citation (url + quote) whose vendor matches the row. This is the
    machine guard that stops a cookie->vendor mapping shipping on our say-so — the
    exact failure the 'cookiesession1 = wafw00f signature' correction caught."""
    sigs = load_cookie_signatures() if cookie_sigs is None else cookie_sigs
    errs: list[str] = []
    for i, fp in enumerate(fingerprints):
        if fp.get("observation") != "set_cookie_names" or fp.get("evidence_class") != "vendor_identifying":
            continue
        vp = fp.get("vendor_product") or {}
        row_vendor = str(vp.get("vendor") or "").lower()
        tag = f"row[{i}] signal={fp.get('signal')!r}"
        for v in (fp.get("match_values") or fp.get("match_substrings") or []):
            entry = sigs.get(str(v).lower())
            if not entry:
                errs.append(f"{tag}: cookie {v!r} has no cookie_signatures.yaml entry (R4 citation required)")
                continue
            cit = entry.get("citation") or {}
            if not (cit.get("url") and cit.get("quote")):
                errs.append(f"{tag}: cookie {v!r} citation missing url/quote (R4)")
            if row_vendor and str(entry.get("vendor") or "").lower() != row_vendor:
                errs.append(f"{tag}: cookie {v!r} corpus vendor {entry.get('vendor')!r} != row vendor {vp.get('vendor')!r}")
    return errs


def load_fingerprints(path: Path = FINGERPRINTS_PATH) -> list[dict]:
    if yaml is None:
        raise RuntimeError("PyYAML required to read device_fingerprints.yaml")
    data = yaml.safe_load(path.read_text()) or {}
    fps = list(data.get("fingerprints") or [])
    # Load-time enforcement (4.7 R6): structural rules 1-5 need no thresholds, so
    # they fire on EVERY load path — runner, CLI, selftest, tests. Rule 6 (weight
    # membership) runs where thresholds are loaded (validate_registry / runner).
    # R4 (4.7 Q2/Q8b): cookie->vendor rows must carry a cited source, enforced here
    # so every load path (runner, CLI, tests) refuses a say-so cookie attribution.
    errs = validate_fingerprints(fps) + validate_cookie_citations(fps)
    if errs:
        raise RegistryValidationError(
            f"{path.name} failed evidence-class validation — classifier refuses to start:\n  - "
            + "\n  - ".join(errs))
    return fps


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


def validate_registry(fp_path: Path = FINGERPRINTS_PATH,
                      th_path: Path = THRESHOLDS_PATH) -> list[str]:
    """Full check for CI + classifier startup: structural rules (via
    load_fingerprints, which RAISES RegistryValidationError) plus rule 6
    weight-membership (needs thresholds). Returns the residual weight errors;
    structural violations raise before we get here."""
    fps = load_fingerprints(fp_path)          # raises on rules 1-5
    th = load_thresholds(th_path)
    return validate_fingerprints(fps, th["weight"])   # + rule 6


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

    # exact / prefix token matching (4.7 Q8e, Obsidian 146) — for LIST observations
    # of discrete tokens like set_cookie_names, where substring would false-match
    # (cookiesession1 must NOT match cookiesession1234). Element-wise, case-insensitive.
    ms = fp.get("match_semantic")
    if ms in ("exact", "prefix"):
        items = [str(x).lower() for x in _as_list(obs)]
        for v in (fp.get("match_values") or []):
            vl = str(v).lower()
            for it in items:
                if (it == vl) if ms == "exact" else it.startswith(vl):
                    return str(v)
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


# ── SIGNAL INDEPENDENCE (4.7 R4-revised, Obsidian 146) ───────────────────────
# The bar tallies DISTINCT signal NAMES, so signal naming IS the independence
# decision. The test is "different ARTIFACT", NOT "same vendor conclusion":
#   INDEPENDENT (separate names, count separately) — different tools reading
#     different artifacts, or one tool reading different artifacts across probes.
#     e.g. cookiesession1 (passive Set-Cookie, Fortinet-doc-cited) vs a wafw00f
#     kind=fortiweb verdict (wafw00f keys on FORTIWAFSID + block page, NEVER
#     cookiesession1) -> two independent FortiWeb tells -> together 'confirmed'.
#   DEPENDENT (share one signal NAME so they count once) — signals reading the
#     SAME underlying artifact via different paths. e.g. a direct FORTIWAFSID
#     observation and wafw00f's verdict (which itself matches ^FORTIWAFSID=); or
#     wafw00f detected==true and wafw00f kind (one wafw00f run) — which is why
#     gather_observations emits `waf_present` ONLY when wafw00f names no vendor.
# Two signals both concluding "FortiWeb" are NOT automatically dependent —
# corroboration by independent artifacts IS the confirmation pathway. Dedupe only
# on shared artifact, never on shared conclusion.
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
            # R5 (Obsidian 146): carry evidence_class onto each record so classify()
            # can score vendor_product_confidence from vendor_identifying signals ONLY.
            "evidence_class": fp.get("evidence_class"),
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
    {device_class, confidence, device_class_confidence,
    vendor_product_confidence, evidence, vendor_product}."""
    fingerprints = fingerprints if fingerprints is not None else load_fingerprints()
    thresholds = thresholds if thresholds is not None else load_thresholds()

    matched = match_signals(observations, fingerprints, thresholds)
    if not matched:
        return {"device_class": DEFAULT_CLASS, "confidence": "unknown",
                "device_class_confidence": "unknown",
                "vendor_product_confidence": "unknown",
                "evidence": [], "vendor_product": {}}

    # Winning class = the device_class with the strongest support: most distinct
    # high-weight signal NAMES, then medium, then low. Distinct names so two
    # fingerprint rows for the same signal can't double-count the bar.
    #
    # R5 (Obsidian 146) two-bar split: the SAME per-class buckets also track the
    # vendor_identifying-only signal names (vi_high/vi_medium). device_class_confidence
    # scores over ALL signals — presence_only can confirm "a WAF is present"; but
    # vendor_product_confidence scores over vendor_identifying signals ONLY, so a
    # presence-only-confirmed asset never earns the right to NAME a vendor. This is
    # the load-bearing gate P2 reads before firing any CVE-attribution finding.
    by_class: dict[str, dict] = {}
    for m in matched:
        slot = by_class.setdefault(
            m["device_class"],
            {"high": set(), "medium": set(), "low": set(),
             "vi_high": set(), "vi_medium": set(), "vendor": {}})
        slot[m["weight"]].add(m["signal"])
        if m.get("evidence_class") == "vendor_identifying" and m["weight"] in ("high", "medium"):
            slot["vi_" + m["weight"]].add(m["signal"])
        slot["vendor"].update(m["vendor_product"])

    win_class, win = max(
        by_class.items(),
        key=lambda kv: (len(kv[1]["high"]), len(kv[1]["medium"]), len(kv[1]["low"])),
    )
    conf = _confidence(len(win["high"]), len(win["medium"]))
    vp_conf = _confidence(len(win["vi_high"]), len(win["vi_medium"]))

    # If even the strongest class can't clear 'suspected' (only low-weight or
    # nothing decisive), stay unknown — 4.7 D2/D3.
    if conf == "unknown":
        return {"device_class": DEFAULT_CLASS, "confidence": "unknown",
                "device_class_confidence": "unknown",
                "vendor_product_confidence": "unknown",
                "evidence": matched, "vendor_product": {}}

    return {
        "device_class": win_class,
        # 'confidence' unchanged (== device_class_confidence): the routing/write
        # path (device_class_runner) reads this key — keeping it identical means no
        # asset's routing changes, so this is additive with NO soak reset (146 §110).
        "confidence": conf,
        "device_class_confidence": conf,
        "vendor_product_confidence": vp_conf,
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
    # 2) A FortiWeb-fronted asset: bot challenge (high) + wafw00f (high). Expect
    #    waf / CONFIRMED (2 high) — would be routing-eligible. (Neither observation
    #    is gathered in prod yet — E1 — but the pure SCORER is what's under test.)
    waf = {"fwbbot_check": True, "waf_vendor": "FortiWeb"}
    # 3) A plain host, stock OpenSSH, nothing distinctive. Expect UNKNOWN — never
    #    presume origin on absence of evidence (D2).
    bare = {"ssh_banner": "SSH-2.0-OpenSSH_9.3"}
    # 4) A NON-Fortinet edge — Automattic (Unimac/CMI). In PRODUCTION only the cert
    #    CN is gathered (there is no `ips` observation), so this is a SINGLE medium
    #    -> below the >=2-medium bar -> unknown. The old fixture faked a 2nd medium
    #    with an ip-range row (deleted 4.7 R1) to force 'suspected'; that was never
    #    the real production outcome. Honest expectation: unknown. (Promote the
    #    cert CN to a vendor-identifying HIGH signal to lift Automattic to the bar.)
    pressable = {"cert_subject": "tls.automattic.com"}

    expected = {
        "ftp": ("edge_firewall", "suspected"),
        "waf": ("waf", "confirmed"),
        "bare": ("unknown", "unknown"),
        "pressable": ("unknown", "unknown"),
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

    # 4.7 R6 — the live registry must satisfy the evidence-class schema, and the
    # validator must REJECT violations (both directions, or it isn't a guard).
    reg_errs = validate_fingerprints(fps, th["weight"])
    bad_rows = [
        {"signal": "a", "observation": "o", "device_class": "waf",            # presence_only w/ vendor
         "evidence_class": "presence_only", "vendor_product": {"vendor": "Fortinet"}},
        {"signal": "b", "observation": "o", "device_class": "waf",            # vendor_identifying, no vendor
         "evidence_class": "vendor_identifying", "vendor_product": {}},
        {"signal": "c", "observation": "o", "device_class": "waf"},           # missing evidence_class
    ]
    rejects = validate_fingerprints(bad_rows)
    ok &= (reg_errs == [])
    ok &= (len(rejects) >= 3)
    print(f"  {'OK ' if reg_errs == [] else 'XX '}registry evidence_class valid "
          f"({len(reg_errs)} error(s))")
    print(f"  {'OK ' if len(rejects) >= 3 else 'XX '}validator rejects bad rows "
          f"({len(rejects)} caught, want >=3)")

    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    # `--validate` = the CI entrypoint (4.7 R6): exits non-zero on any bad row so
    # a PR that reintroduces an inferred brand fails to merge. Bare = selftest.
    if "--validate" in sys.argv:
        try:
            errs = validate_registry()
        except RegistryValidationError as e:
            print(str(e))
            sys.exit(1)
        if errs:
            print("REGISTRY INVALID (weight rule):\n  - " + "\n  - ".join(errs))
            sys.exit(1)
        print("device_fingerprints.yaml: evidence-class schema valid")
        sys.exit(0)
    sys.exit(_selftest())
