#!/usr/bin/env python3
"""
device_class_runner.py — device-class classifier RUNNER (4.7 D2/D3/D4 + E1-E6).

Dry-run-first. For every asset (4.7 F1-F4 corrected ordering, 2026-07-13):
  1. FINGERPRINT FIRST (F3): gather FRESH (< evidence_freshness_days, D3) signals
     from the DB — SSH banner (fingerprintx), cert issuer/subject (testssl),
     nuclei-Fortinet hit (E5 template-id PREFIX allowlist) — and run
     derive_device_class.classify(). ANY non-unknown result (confirmed OR suspected
     appliance/waf/edge/adc_lb/cdn) WINS. "A WAF hosted on GCP is still a WAF"; a
     suspected fingerprint is real appliance evidence and BLOCKS the cloud fallback
     (F3) — never silently overwritten by a cloud class.
  2. CLOUD FALLBACK (F1/F2/F4) — only when fingerprints say unknown: re-derive the
     cloud classification from the asset's surface_data (E2 re-derive-every-run, no
     caching, no schema change). Topology keys on cloud_provider, NOT is_cloud_endpoint
     (that flag is a rotating-pool churn signal — D6-F5, not a topology signal).
     cloud_provider present -> is_cloud_endpoint True = rotating edge -> 'cdn';
     False = static compute -> 'cloud_endpoint'. Confidence by classifier tier (F4):
     cname/asn = confirmed, ip-only = suspected; surface older than the freshness
     window caps at suspected.
  3. Decide the event vs the current row: STAMP / CHANGE / TRANSITION_UPGRADE /
     TRANSITION_DOWNGRADE (E6c). A DOWNGRADE (incl. -> unknown) is a red flag that
     resets the soak clock.
  4. On any actionable event, write a row to public.device_class_dryrun (4.7 E3 —
     the persistent soak audit trail; "structured logs, not text") EVERY pass,
     dry-run AND --write. --write ALSO stamps assets.device_class + confidence +
     evidence + vendor_product — CLASSIFY-ONLY, changes NO routing (D4 Phase A).

Everything keys on asset_id (the hostname PK scan_run/findings reference).
Fingerprint signals: SSH banner + cert + nuclei-Fortinet + (P1, Obsidian 146) the
two persisted stack-id artifacts — stack_id_wafw00f -> waf_vendor and
stack_id_passive -> http_headers — which light up the ratified-but-dormant
wafw00f_high_confidence and product_http_header rows. The IP-range signal is GONE
(4.7 R1: a netblock names an owner, never an appliance brand). P1 also persists the
R5 vendor_product_confidence bar (vendor_identifying signals only) alongside the
existing device_class_confidence; routing still gates ONLY on device_class_confidence.
The set_cookie_names artifact field (e.g. FortiWeb 'cookiesession1') is collected but
NOT yet a signal — a new vendor-identifying row for it is a 4.7 fast-follow.

TODO (post-Phase-B, 4.7 E4): replace regex-over-artifact extraction with structured
parsing (more robust to testssl/fingerprintx version bumps).

    export SUPABASE_DSN=...
    python3 scripts/db/device_class_runner.py                    # dry-run (writes audit rows only)
    python3 scripts/db/device_class_runner.py --write            # + stamp device_class (classify-only)
    python3 scripts/db/device_class_runner.py --soak-generation 2  # after a soak-clock reset
    python3 scripts/db/device_class_runner.py --selftest         # pure logic, no DB
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from derive_device_class import (  # noqa: E402
    FINGERPRINTS_PATH, classify, load_fingerprints, load_thresholds,
    validate_fingerprints, RegistryValidationError,  # noqa: F401  (R6 startup guard)
)
try:  # cloud fallback re-derives from surface_data (4.7 F1/F4; E2 re-derive-every-run)
    from derive_cloud_endpoint import (  # noqa: E402
        classify as classify_cloud, load_registry as load_cloud_registry,
    )
except Exception:  # pragma: no cover
    classify_cloud = None
    load_cloud_registry = None

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover
    psycopg = None
try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_CONF_RANK = {"unknown": 0, "suspected": 1, "confirmed": 2}


# ── pure signal extractors (unit-tested, no DB) ──────────────────────────
_SSH_RE = re.compile(r"SSH-\d[\w.\-]*[^\"\\\r\n]*")


def extract_ssh_banner(fpx_raw: str | None) -> str | None:
    if not fpx_raw:
        return None
    m = _SSH_RE.search(fpx_raw)
    return m.group(0).strip() if m else None


def _testssl_field(raw: str, cert_id: str) -> str | None:
    obj = re.search(r'\{[^{}]*"id"\s*:\s*"' + re.escape(cert_id) + r'"[^{}]*\}', raw or "")
    if not obj:
        return None
    f = re.search(r'"finding"\s*:\s*"([^"]+)"', obj.group(0))
    return f.group(1) if f else None


def extract_cert(testssl_raw: str | None) -> dict:
    if not testssl_raw:
        return {}
    out: dict = {}
    issuer = _testssl_field(testssl_raw, "cert_caIssuers")
    subject = (_testssl_field(testssl_raw, "cert_commonName")
               or _testssl_field(testssl_raw, "cert_subjectAltName"))
    if issuer:
        out["cert_issuer"] = issuer
    if subject:
        out["cert_subject"] = subject
    return out


# ── P1 (Obsidian 146): the two persisted stack-id artifacts -> observations ───
# These light up rows that were RATIFIED-BUT-DORMANT in device_fingerprints.yaml
# (wafw00f_high_confidence on waf_vendor; product_http_header on http_headers) —
# no new signal, no weight change. The runner stays "dumb": it emits the raw
# observation and lets the registry decide what (if anything) it names. A generic
# wafw00f verdict emits 'generic', which matches no vendor row -> no false brand.
def waf_vendor_from_wafw00f(verdict: dict | None) -> str | None:
    """E1's stack_id_wafw00f artifact {wafw00f_detected, wafw00f_kind} -> the
    waf_vendor observation string, or None. Only when wafw00f actually detected a
    WAF and named a kind; the registry's vendor_identifying rows decide if that
    kind (fortiweb/cloudflare/...) names a vendor."""
    if not isinstance(verdict, dict) or not verdict.get("wafw00f_detected"):
        return None
    kind = verdict.get("wafw00f_kind")
    return kind if isinstance(kind, str) and kind else None


def http_headers_from_passive(passive: dict | None) -> str | None:
    """P0's stack_id_passive artifact -> a 'name: value' header blob for the
    http_headers observation (product_http_header regex scans it, e.g.
    'server:\\s*forti'). passive['headers'] is the vendor-header SUBSET dict P0
    already filtered; serialize it so values (not just keys) are scannable."""
    if not isinstance(passive, dict):
        return None
    hdrs = passive.get("headers")
    if not isinstance(hdrs, dict) or not hdrs:
        return None
    lines = []
    for k, v in hdrs.items():
        val = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        lines.append(f"{k}: {val}")
    return "\n".join(lines) if lines else None


# ── E5: nuclei Fortinet template-id prefix allowlist ─────────────────────
def load_nuclei_fortinet_regex(path=FINGERPRINTS_PATH) -> str:
    """A precise template-id-prefix regex (NOT substring 'forti'). Never fortify-*."""
    prefixes = ["fortinet-", "fortios-", "fortiweb-", "fortiadc-", "fortisiem-", "fortimail-"]
    if yaml is not None:
        try:
            cfg = (yaml.safe_load(Path(path).read_text()) or {}).get("nuclei_fortinet_templates") or {}
            if cfg.get("prefixes"):
                prefixes = list(cfg["prefixes"])
        except Exception:
            pass
    alt = "|".join(re.escape(p.rstrip("-")) for p in prefixes)
    return f":({alt})-"


# ── E6c: transition event taxonomy ───────────────────────────────────────
def event_for(prior_class, prior_conf, new_class, new_conf) -> str | None:
    """None = nochange. STAMP first-classification; CHANGE lateral; UPGRADE/DOWNGRADE
    on confidence moves. A move TO unknown, or a confidence drop, is a DOWNGRADE
    (red flag — resets the soak clock)."""
    if (new_class, new_conf) == (prior_class, prior_conf):
        return None
    if prior_class == "unknown":
        return "STAMP"
    if new_class == "unknown":
        return "TRANSITION_DOWNGRADE"
    pr, nr = _CONF_RANK.get(prior_conf, 0), _CONF_RANK.get(new_conf, 0)
    if nr > pr:
        return "TRANSITION_UPGRADE"
    if nr < pr:
        return "TRANSITION_DOWNGRADE"
    return "CHANGE"


# ── fwbbot_check corroboration gate (4.7 Q5; pure, hardcoded, anchor-tested) ──
def _fwbbot_corroborated(probe: dict | None) -> bool:
    """The ONLY path that may enable the fwbbot_check signal. Fires TRUE only when the
    probe artifact recorded a CORROBORATED challenge (a redirect whose Location IS
    /fwbbot_check). Everything else — observed-without-corroboration (path-mention),
    banned, no-challenge, dry-run (corroborated null) — returns False. This is the
    honeypot/coincidence guard (4.7 Q7) and the empirical no-fabrication bar (4.7 Q4):
    no "close enough" fallback, no caching. `is True` is deliberate — a truthy non-bool
    must not slip the gate."""
    return isinstance(probe, dict) and probe.get("corroborated") is True


# ── Discovery-tier wafw00f (157, 4.7 Q1/Q2) ──────────────────────────────
def _discovery_waf(cur, asset_id: str):
    """The LIGHT/discovery-scan wafw00f verdict — persisted in
    asset_surface.surface_data.subdomains[].waf {detected, vendor} by the ASM import
    (import_asm_to_surface.py), the same blob the cloud fallback already reads. Returns
    (detected, vendor) for THIS asset's own subdomain entry, else (False, None). This is
    the SAME wafw00f detection as the heavy stack_id_wafw00f artifact but at a lower
    operating envelope (reduced rate/depth, unauth), so the registry dedupes the two
    (dedupe_key wafw00f_detection) and caps a discovery-only WAF at 'suspected'."""
    cur.execute("select surface_data from public.asset_surface where asset_id=%s", (asset_id,))
    row = cur.fetchone()
    if not row or not row.get("surface_data"):
        return (False, None)
    sd = row["surface_data"]
    if isinstance(sd, str):
        try:
            sd = json.loads(sd)
        except Exception:
            return (False, None)
    subs = sd.get("subdomains") if isinstance(sd, dict) else None
    if not isinstance(subs, list) or not subs:
        return (False, None)
    aid = str(asset_id).lower()
    entry = next((s for s in subs
                  if isinstance(s, dict) and str(s.get("name", "")).lower() == aid), None)
    # sliced single-host surface (a per-subdomain asset) -> the lone entry is this asset
    if entry is None and len(subs) == 1 and isinstance(subs[0], dict):
        entry = subs[0]
    if not isinstance(entry, dict):
        return (False, None)
    waf = entry.get("waf")
    if not isinstance(waf, dict) or not waf.get("detected"):
        return (False, None)
    return (True, waf.get("vendor"))


# ── DB signal gather (fresh signals for one asset) ───────────────────────
def gather_observations(cur, asset_id: str, freshness_days: int, nuclei_re: str) -> dict:
    obs: dict = {}
    fresh = f"now() - interval '{int(freshness_days)} days'"
    cur.execute(
        f"""select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw
              from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
             where r.asset_id = %s and a.tool_name ilike 'fingerprint%%'
               and r.completed_at > {fresh}
             order by r.completed_at desc limit 1""", (asset_id,))
    row = cur.fetchone()
    banner = extract_ssh_banner(row["raw"] if row else None)
    if banner:
        obs["ssh_banner"] = banner
    cur.execute(
        f"""select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw
              from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
             where r.asset_id = %s and a.tool_name ilike 'testssl%%'
               and r.completed_at > {fresh}
             order by r.completed_at desc limit 1""", (asset_id,))
    row = cur.fetchone()
    obs.update(extract_cert(row["raw"] if row else None))
    cur.execute(
        f"""select 1 from findings
             where asset_id = %s and source::text = 'nuclei' and finding_id ~ %s
               and last_observed_at > {fresh} limit 1""", (asset_id, nuclei_re))
    if cur.fetchone():
        obs["nuclei_fortinet_hit"] = True

    # P1 (Obsidian 146): the two persisted stack-id artifacts. Both are json-typed
    # scan_run_artifacts (content_jsonb holds the parsed object); read the freshest
    # per asset and feed the ratified dormant rows.
    def _fresh_json(tool_like: str) -> dict | None:
        cur.execute(
            f"""select a.content_jsonb::text as blob
                  from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
                 where r.asset_id = %s and a.tool_name ilike %s
                   and r.completed_at > {fresh}
                 order by r.completed_at desc limit 1""", (asset_id, tool_like))
        row = cur.fetchone()
        if not row or not row.get("blob"):
            return None
        try:
            obj = json.loads(row["blob"])
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    verdict = _fresh_json("stack_id_wafw00f")
    kind = waf_vendor_from_wafw00f(verdict)      # kind string if detected & named, else None
    if kind and kind != "generic":
        obs["waf_vendor"] = kind                 # named vendor -> wafw00f_high_confidence
    elif verdict and verdict.get("wafw00f_detected"):
        # detected but named no vendor -> presence-only signal. Emitted ONLY here
        # (not alongside waf_vendor) so it never double-counts the same wafw00f run
        # against a vendor row (4.7 same-artifact test, Obsidian 146).
        obs["waf_present"] = True                # -> waf_present_wafw00f
    passive = _fresh_json("stack_id_passive")
    http_headers = http_headers_from_passive(passive)
    if http_headers:
        obs["http_headers"] = http_headers       # -> product_http_header row
    cookie_names = passive.get("set_cookie_names") if isinstance(passive, dict) else None
    if isinstance(cookie_names, list) and cookie_names:
        obs["set_cookie_names"] = cookie_names   # -> fortiweb_cookiesession1 (exact match)

    # Phase D (4.7 Q5): the active-probe /fwbbot_check challenge. Freshest artifact per
    # asset, gated through _fwbbot_corroborated — emits ONLY on a corroborated challenge
    # (redirect-to-/fwbbot_check). observed-not-corroborated / banned / no-challenge /
    # dry-run all leave it dormant. -> fortiweb_challenge_endpoint_fwbbot_check.
    probe = _fresh_json("stack_id_fwbbot_check")
    if _fwbbot_corroborated(probe):
        obs["fwbbot_check"] = True

    # 157 (4.7 Q1/Q2): discovery-tier wafw00f from asset_surface (light scan), distinct
    # from the heavy stack_id_wafw00f above. Registry dedupes the two (dedupe_key) so heavy
    # wins when both fire and discovery-only caps at 'suspected'. This is what lifts the
    # FortiWeb estate (test/testapi/www/geisinger.commandcommcentral.com) off 'unknown'
    # without a per-host heavy scan. vendor 'None'/'Generic' -> presence-only; else named.
    d_detected, d_vendor = _discovery_waf(cur, asset_id)
    if d_detected:
        dv = str(d_vendor or "").strip().lower()
        # NAMED vendor ONLY. A generic/None discovery verdict fires NOTHING (157 dry-run,
        # 4.7 2026-07-23): discovery generic wafw00f false-positived 19 assets and (via F3)
        # downgraded 9 CONFIRMED cloud classes, so we never publish a generic discovery WAF —
        # discovery wafw00f names a vendor or stays silent. Heavy generic presence is separate.
        if dv and dv not in ("none", "generic"):
            obs["waf_vendor_discovery"] = d_vendor       # -> wafw00f_discovery_confidence
    return obs


def _latest_scan_run(cur, asset_id: str):
    cur.execute("select scan_run_id from scan_run where asset_id=%s "
                "order by completed_at desc nulls last limit 1", (asset_id,))
    r = cur.fetchone()
    return r["scan_run_id"] if r else None


# ── F2/F4 cloud-fallback mapping (pure; unit-tested, no DB) ──────────────
def _cloud_class_and_conf(cloud_result: dict, stale: bool) -> tuple[str, str]:
    """(classify_cloud() result, stale) -> (device_class, confidence).
    F2: rotating edge (is_cloud_endpoint=true) -> 'cdn'; static compute -> 'cloud_endpoint'.
    F4: cname/asn tier -> confirmed, ip-only -> suspected; stale surface caps at suspected."""
    device_class = "cdn" if cloud_result.get("is_cloud_endpoint") else "cloud_endpoint"
    confidence = "confirmed" if cloud_result.get("match_tier") in ("cname", "asn") else "suspected"
    if stale and confidence == "confirmed":
        confidence = "suspected"
    return device_class, confidence


# ── F3 ordering (pure; unit-tested, no DB) ───────────────────────────────
def _resolve(fp_result: dict, cloud_result: dict | None) -> tuple[dict, bool]:
    """Fingerprint-first (F3): ANY non-unknown fingerprint (confirmed OR suspected)
    WINS and BLOCKS cloud — a suspected WAF on GCP stays a suspected WAF, never a
    silent cloud_endpoint. Cloud is fallback ONLY when fingerprint == unknown.
    Returns (result, from_cloud)."""
    if fp_result["device_class"] != "unknown":
        return (fp_result, False)
    if cloud_result is not None:
        return (cloud_result, True)
    return (fp_result, False)


def _is_stale(last_seen, fresh_days: int) -> bool:
    """F4 freshness gate: surface with no/old last_seen can't hold 'confirmed'."""
    if last_seen is None:
        return True
    return last_seen < datetime.now(timezone.utc) - timedelta(days=int(fresh_days))


def _cloud_fallback(cur, asset_id: str, cloud_reg, fresh_days: int) -> dict | None:
    """F1/F2/F4: re-derive cloud classification from the persisted surface_data
    (E2 re-derive-every-run; no schema change). Topology keys on cloud_provider,
    NOT is_cloud_endpoint (rotating-pool churn flag, D6-F5). Returns a
    classify()-shaped result dict, or None (no cloud_provider / unavailable)."""
    if classify_cloud is None or cloud_reg is None:
        return None
    cur.execute("select surface_data, last_seen from public.asset_surface where asset_id=%s", (asset_id,))
    row = cur.fetchone()
    if not row or not row.get("surface_data"):
        return None
    surface = row["surface_data"]
    if isinstance(surface, str):
        try:
            surface = json.loads(surface)
        except Exception:
            return None
    cr = None
    for sub in (surface.get("subdomains") if isinstance(surface, dict) else None) or []:
        cr = classify_cloud(sub, cloud_reg)
        if cr:
            break
    if not cr:
        return None
    stale = _is_stale(row.get("last_seen"), fresh_days)
    device_class, confidence = _cloud_class_and_conf(cr, stale)
    ev = {"signals": [], "inherited_from": "cloud_provider",
          "cloud_provider": cr.get("cloud_provider"),
          "cloud_match_tier": cr.get("match_tier"),
          "is_cloud_endpoint": bool(cr.get("is_cloud_endpoint")),
          "surface_stale": stale,
          "inherited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return {"device_class": device_class, "confidence": confidence,
            "evidence": ev, "vendor_product": {"cloud_provider": cr.get("cloud_provider")}}


def _merge_cloud_provider(fp: dict, cloud: dict | None) -> None:
    """4.7 cloud-edge Q3: fold the hosting cloud_provider into a WINNING fingerprint's
    vendor_product so the display can COMPOSE 'Fronted by <edge> · on <cloud>'. Hosting is
    a persistent attribute, NOT a fallback — a named edge must not erase where the asset
    runs. device_class + the two-bar confidences are untouched: cloud_provider is derived
    from ASN/CNAME (inferred), never a vendor-identifying signal, so it never enters the
    tally — it rides the existing vendor_product JSON (no schema change)."""
    if not cloud:
        return
    cp = (cloud.get("vendor_product") or {}).get("cloud_provider")
    vp = fp.get("vendor_product")
    if cp and isinstance(vp, dict) and not vp.get("cloud_provider"):
        vp["cloud_provider"] = cp


def classify_asset(cur, a: dict, fps, th, fresh_days, nuclei_re, cloud_reg) -> tuple[dict, bool]:
    """(result, from_cloud). F3: fingerprint FIRST — any non-unknown result (confirmed OR
    suspected) wins the CLASS and blocks the cloud fallback from BECOMING the class. But
    cloud_provider (hosting) is now derived ALWAYS and composed onto a winning fingerprint
    (4.7 cloud-edge Q3): edge and hosting are different, often co-true facts — 'Fronted by
    Google Cloud CDN · on Google Cloud'. The cloud fallback still BECOMES the result only
    when fingerprints are unknown. NOTE: assets.is_cloud_endpoint is a rotating-pool churn
    flag (D6-F5), NOT a topology signal — cloud topology keys on cloud_provider (F1)."""
    fp = classify(gather_observations(cur, a["asset_id"], fresh_days, nuclei_re), fps, th)
    cloud = _cloud_fallback(cur, a["asset_id"], cloud_reg, fresh_days)
    if fp["device_class"] != "unknown":
        _merge_cloud_provider(fp, cloud)
        return (fp, False)
    return _resolve(fp, cloud)


def _has_wafw00f(evidence) -> bool:
    # any wafw00f-sourced signal — named vendor OR the generic presence signal —
    # for the conf_full vs conf_subset soak tally.
    return isinstance(evidence, list) and any(
        s.get("signal") in ("wafw00f_high_confidence", "waf_present_wafw00f") for s in evidence)


def run(dsn: str, write: bool, soak_generation: int) -> int:
    # R6 startup guard: load_fingerprints() already RAISES on structural rules
    # (evidence_class present/consistent, device_class enum). Here we also enforce
    # rule 6 (every signal is a ratified weight) now that thresholds are loaded —
    # a registry edited directly on a runner, bypassing CI, still can't run bad.
    fps, th = load_fingerprints(), load_thresholds()
    _werrs = validate_fingerprints(fps, th["weight"])
    if _werrs:
        raise RegistryValidationError(
            "device_fingerprints.yaml weight-rule violation — classifier refuses to run:\n  - "
            + "\n  - ".join(_werrs))
    fresh_days = th["evidence_freshness_days"]
    nuclei_re = load_nuclei_fortinet_regex()
    cloud_reg = None
    if load_cloud_registry is not None:
        try:
            cloud_reg = load_cloud_registry()
        except Exception as e:  # pragma: no cover
            print(f"  ! cloud registry unavailable ({e}) — cloud fallback disabled", file=sys.stderr)
    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=15)
    conn.autocommit = False

    tally = {"STAMP": 0, "CHANGE": 0, "TRANSITION_UPGRADE": 0, "TRANSITION_DOWNGRADE": 0}
    unknown = cloud_endpoint_ct = cdn_ct = conf_subset = conf_full = 0
    with conn.cursor() as cur:
        # F1/F3: classification no longer reads assets.is_cloud_endpoint/cloud_provider
        # (is_cloud_endpoint was the wrong topology key — see classify_asset). The cloud
        # fallback RE-DERIVES from surface_data every run (E2 re-derive, no caching), so
        # we only need each asset's CURRENT class to compute the transition event.
        cur.execute("select asset_id, device_class, device_class_confidence "
                    "from public.assets order by asset_id")
        assets = cur.fetchall()
        print(f"{'ASSET':38.38s} {'FROM':18s} {'-> TO':18s} EVENT")
        for a in assets:
            res, from_cloud = classify_asset(cur, a, fps, th, fresh_days, nuclei_re, cloud_reg)
            nc, ncf = res["device_class"], res["confidence"]
            # R5 vendor bar (P1). Cloud-fallback results have no vendor_product_confidence
            # (cloud_provider is not a security-stack vendor) -> default 'unknown'.
            vpc = res.get("vendor_product_confidence", "unknown")
            # 157 (4.7 Q1): audit-log the suspected cap when a WAF class rests on the
            # discovery wafw00f alone (no heavy wafw00f corroboration) — so an operator
            # asking "why not confirmed?" has the answer in the run log.
            if nc == "waf" and ncf == "suspected":
                _sigs = {e.get("signal") for e in res["evidence"]}
                if "wafw00f_discovery_confidence" in _sigs \
                        and "wafw00f_high_confidence" not in _sigs:
                    print(f"  · {a['asset_id']}: capped at suspected: "
                          f"source=discovery_wafw00f, heavy_wafw00f_absent=true")
            if nc == "unknown":
                unknown += 1
            if from_cloud:
                if nc == "cdn":
                    cdn_ct += 1
                else:
                    cloud_endpoint_ct += 1
            elif ncf == "confirmed":
                if _has_wafw00f(res["evidence"]):
                    conf_full += 1
                else:
                    conf_subset += 1

            ev = event_for(a["device_class"], a["device_class_confidence"], nc, ncf)
            if ev is None:
                continue
            tally[ev] += 1
            would_reroute = ncf == "confirmed"
            flag = "  !! red flag (resets soak)" if ev == "TRANSITION_DOWNGRADE" else (
                   "  [would reroute]" if would_reroute else "")
            print(f"{a['asset_id']:38.38s} "
                  f"{a['device_class']+'/'+a['device_class_confidence']:18.18s} "
                  f"{nc+'/'+ncf:18.18s} {ev}{flag}")

            # 4.7 E3 — persistent audit row, EVERY pass (dry-run and write)
            cur.execute(
                "insert into public.device_class_dryrun (asset_id, event_type, device_class, "
                "confidence, vendor_product_confidence, evidence, vendor_product, prior_state, "
                "would_reroute, scan_run_id, soak_generation) "
                "values (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,%s,%s,%s)",
                (a["asset_id"], ev, nc, ncf, vpc, json.dumps(res["evidence"]),
                 json.dumps(res["vendor_product"]),
                 json.dumps({"device_class": a["device_class"], "confidence": a["device_class_confidence"]}),
                 would_reroute, _latest_scan_run(cur, a["asset_id"]), soak_generation))

            if write:
                cur.execute(
                    "update public.assets set device_class=%s, device_class_confidence=%s, "
                    "vendor_product_confidence=%s, device_class_evidence=%s::jsonb, "
                    "vendor_product=%s::jsonb where asset_id=%s",
                    (nc, ncf, vpc, json.dumps(res["evidence"]),
                     json.dumps(res["vendor_product"]), a["asset_id"]))
    conn.commit()
    conn.close()

    total = len(assets)
    unk_pct = round(100 * unknown / total) if total else 0
    print(f"\n{'WROTE' if write else 'DRY-RUN'} (soak_generation={soak_generation}, audit rows committed):")
    print(f"  events: STAMP={tally['STAMP']} CHANGE={tally['CHANGE']} "
          f"UPGRADE={tally['TRANSITION_UPGRADE']} DOWNGRADE={tally['TRANSITION_DOWNGRADE']}")
    print(f"  cloud fallback (F1/F2, re-derived from surface_data): "
          f"cloud_endpoint={cloud_endpoint_ct} cdn={cdn_ct}")
    print(f"  fingerprint confirmed: via_subset={conf_subset} via_full_signals={conf_full}")
    print(f"  unknown={unknown}/{total} ({unk_pct}%)  "
          + ("<-- investigate coverage (E4 >70%)" if unk_pct > 70 else ""))
    print("  NOTE: wafw00f (HIGH) + IP-range signals not wired in v1 — WAF/edge assets "
          "under-confirm until waf_kind persistence lands (E1). 'via_full_signals' stays 0 until then.")
    return 0


def _selftest() -> int:
    ok = True
    # extractors
    fpx = ('{"host":"ftp.sciimage.com","ip":"24.157.51.76","port":22,"transport":"tcp",'
           '"protocol":"ssh","version":"SSH-2.0-8.1.0.0_openssh SCI\\r\\n"}')
    ts = ('[{"id":"cert_commonName","port":"443","finding":"*.sciimage.com"},'
          '{"id":"cert_caIssuers","port":"443","finding":"Go Daddy Secure Certificate Authority - G2"}]')
    ok &= extract_ssh_banner(fpx) == "SSH-2.0-8.1.0.0_openssh SCI"
    c = extract_cert(ts)
    ok &= c.get("cert_subject") == "*.sciimage.com" and "go daddy" in (c.get("cert_issuer") or "").lower()
    # E5 allowlist regex: matches fortinet-*, excludes fortify-*
    rx = load_nuclei_fortinet_regex()
    ok &= re.search(rx, "sciimage.com:nuclei:fortios-version-detect:abc123") is not None
    ok &= re.search(rx, "app.example.com:nuclei:fortify-sca-leak:def456") is None
    # E6c transition taxonomy
    checks = [
        (("unknown", "unknown", "edge_firewall", "suspected"), "STAMP"),
        (("edge_firewall", "suspected", "edge_firewall", "confirmed"), "TRANSITION_UPGRADE"),
        (("waf", "confirmed", "waf", "suspected"), "TRANSITION_DOWNGRADE"),
        (("waf", "confirmed", "unknown", "unknown"), "TRANSITION_DOWNGRADE"),
        (("edge_firewall", "confirmed", "waf", "confirmed"), "CHANGE"),
        (("waf", "confirmed", "waf", "confirmed"), None),
    ]
    for args, want in checks:
        got = event_for(*args)
        ok &= got == want
        print(f"  event_for{args[:2]}->{args[2:]} = {got} (want {want})")
    # F2/F4 cloud-fallback mapping (pure): class by rotating flag, confidence by tier + freshness
    cloud_cases = [
        ({"cloud_provider": "gcp",    "is_cloud_endpoint": False, "match_tier": "asn"},   False, ("cloud_endpoint", "confirmed")),
        ({"cloud_provider": "gcp",    "is_cloud_endpoint": False, "match_tier": "asn"},   True,  ("cloud_endpoint", "suspected")),  # F4 freshness cap
        ({"cloud_provider": "aws",    "is_cloud_endpoint": False, "match_tier": "cname"}, False, ("cloud_endpoint", "confirmed")),
        ({"cloud_provider": "azure",  "is_cloud_endpoint": True,  "match_tier": "cname"}, False, ("cdn",            "confirmed")),  # Azure Front Door
        ({"cloud_provider": "akamai", "is_cloud_endpoint": True,  "match_tier": "asn"},   False, ("cdn",            "confirmed")),  # Akamai edge
        ({"cloud_provider": "gcp",    "is_cloud_endpoint": False, "match_tier": "ip"},    False, ("cloud_endpoint", "suspected")), # F4 ip-only = suspected
    ]
    for cr, stale, want in cloud_cases:
        got = _cloud_class_and_conf(cr, stale)
        ok &= got == want
        print(f"  cloud {cr['cloud_provider']}/{cr['match_tier']}/stale={stale} = {got} (want {want})")
    # F3 ordering: fingerprint-first; suspected fingerprint BLOCKS cloud fallback
    waf_conf = {"device_class": "waf", "confidence": "confirmed", "evidence": [], "vendor_product": {}}
    waf_susp = {"device_class": "waf", "confidence": "suspected", "evidence": [], "vendor_product": {}}
    unk = {"device_class": "unknown", "confidence": "unknown", "evidence": [], "vendor_product": {}}
    cloud_ce = {"device_class": "cloud_endpoint", "confidence": "confirmed", "evidence": {}, "vendor_product": {}}
    f3 = [
        (_resolve(waf_conf, cloud_ce), (waf_conf, False)),   # confirmed fingerprint wins over cloud
        (_resolve(waf_susp, cloud_ce), (waf_susp, False)),   # suspected fingerprint BLOCKS cloud (F3)
        (_resolve(unk, cloud_ce),      (cloud_ce, True)),    # unknown fingerprint -> cloud fallback
        (_resolve(unk, None),          (unk, False)),        # nothing -> unknown
    ]
    for got, want in f3:
        ok &= got == want
    print(f"  F3 ordering (conf-wins / susp-blocks-cloud / unk->cloud / none->unknown): "
          f"{'ok' if all(g == w for g, w in f3) else 'FAIL'}")
    print(f"  ssh={extract_ssh_banner(fpx)!r}  cert={c}  nuclei_re={rx!r}")
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="stamp device_class (classify-only); default dry-run")
    ap.add_argument("--soak-generation", type=int, default=1, help="bump after a soak-clock reset")
    ap.add_argument("--selftest", action="store_true", help="pure-logic self-test (no DB)")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if psycopg is None:
        sys.exit("psycopg required (run in the scanner env).")
    dsn = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN") or os.environ.get("DSN")
    if not dsn:
        sys.exit("set SUPABASE_DSN (or COMMAND_SUPABASE_DSN / DSN)")
    return run(dsn, args.write, args.soak_generation)


if __name__ == "__main__":
    sys.exit(main())
