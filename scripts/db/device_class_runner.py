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
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from derive_device_class import (  # noqa: E402
    FINGERPRINTS_PATH, classify, load_fingerprints, load_thresholds,
    validate_fingerprints, RegistryValidationError,  # noqa: F401  (R6 startup guard)
)

# N2 cloud port-gate SSOT (4.7 P1/P5). would_reroute is scored against the SAME
# class set the gate actually routes on. IMPORTED, never re-declared: a local
# copy drifts silently and the audit metric stops matching reality, which is
# precisely the defect this replaced. Deliberately NOT wrapped in try/except --
# this is a first-party module in the same repo, and a routing metric that
# quietly falls back to a guess is the fail-open shape being eliminated fleet-wide.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "asm"))
from cloud_ip_check import CLOUD_CLASSES  # noqa: E402
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

# The device classes that are POSITIVE topology verdicts (not unknown/unreadable).
_POSITIVE_CLASSES = frozenset(CLOUD_CLASSES | {"origin_host", "edge_firewall", "adc_lb"})


# ── UNREADABLE phase 2 detection primitives (4.7 175, PURE + selftested) ──
# These are the runner-layer discriminator between "evidence collection failed /
# was absent" (-> unreadable) and "evidence gathered, nothing matched" (-> unknown).
# The pure classify() cannot make this call (it only sees the observations dict);
# the runner can, because it ran the reads. See Obsidian 175, 4.7 Q1/Q2.
#
# PHASE 2a (this increment) uses these to LOG the would-be verdict only. No write
# behaviour changes and no new event rows are written until phase 2b — deliberately,
# per 4.7 Q6 (measure the flip-rate in dry-run for 7+ days before enabling any write).

# The two producers of passive posture artifacts, newest-first-by-signal.
# ⚠ STRINGLY-TYPED BOUNDARY: "light_stack_passive" is also defined as
# LIGHT_PASSIVE_TOOL in scripts/scanner/stack_passive.py. scripts/db/ cannot
# import from scripts/scanner/ (different sys.path root), so the literal is
# duplicated and PINNED BY TEST rather than trusted — same treatment as
# DEEP_SWEEP_QUEUE_MARKER. If you rename one, the pin fails.
_PASSIVE_TOOL_NAMES = ("stack_id_passive", "light_stack_passive")

# ── EVIDENCE-COLLECTION CAPABILITY — ONE SOURCE OF TRUTH (4.7 ruling 201/1) ──
# Every artifact name/pattern gather_observations actually reads, in ONE place,
# consumed by BOTH gather_observations and _evidence_capable_scan_runs.
#
# ⛔ WHY THIS EXISTS. _fresh_scan_exists used to ask "did ANY scan_run complete
# in the window" — no tier filter, no artifact filter. Measured on Command
# 2026-09-16: a LIGHT scan emits common_paths / csp_nonce_check / dns_posture /
# headers_check / httpx_tech / naabu / tls_check and NOT ONE name below. Its
# empty evidence is absence of COLLECTION, not absence of the thing (169's
# principle). 27 of 51 fresh-scanned assets (53%) were light-only, so a
# tier-blind downgrade streak would have stripped real labels at fleet scale
# the moment --write flipped.
#
# ⚠ ARTIFACT-BASED, NOT TIER-BASED, AND THAT IS DELIBERATE. `intensity != 'light'`
# would be wrong in fact as well as in principle: 2 of 225 light runs in the 30d
# window DID emit light_stack_passive. Capability is a property of what a RUN
# produced, never of what its tier is usually able to produce.
#
# ⚠ nuclei is the one indirection: the classifier reads the nuclei SIGNAL from
# `findings`, not from an artifact. The nuclei artifact is therefore the
# CAPABILITY MARKER for that run ("this run was able to look"), while the
# finding is the evidence. Both halves are needed and they live in different
# tables; conflating them is what this comment exists to prevent.
_ART_FINGERPRINT = "fingerprint%"      # -> extract_ssh_banner
_ART_TESTSSL     = "testssl%"          # -> extract_cert
_ART_WAFW00F     = "stack_id_wafw00f"  # -> waf_vendor_from_wafw00f
_ART_NUCLEI      = "nuclei%"           # capability marker only (see above)

EVIDENCE_ARTIFACT_PATTERNS = (
    _ART_FINGERPRINT, _ART_TESTSSL, _ART_WAFW00F, _ART_NUCLEI,
) + _PASSIVE_TOOL_NAMES

_STATUS_READS_OK = "reads_ok"                        # got observations -> classify normally
_STATUS_GENUINE_EMPTY = "genuine_empty"              # fresh scan existed, nothing matched -> unknown (streak candidate, Q4)
_STATUS_NO_FRESH_COLLECTION = "no_fresh_collection"  # nothing fresh to read at all -> unreadable (Q2 Layer A)


def _read_with_retry(query_fn, attempts: int = 3, backoff_ms: int = 100, _sleep=time.sleep):
    """Layer C (4.7 Q3): re-read a SUCCESSFUL-BUT-EMPTY result a bounded number of times
    before treating empty as real. Targets the H2 concurrency window — the ASM importer
    rewrites asset_surface, and a classify read landing mid-rewrite sees no row for a few
    ms; a short backoff crosses it.

    query_fn() must return a falsy value (None/[]/{}) on empty and RAISE on a transport
    error. This helper NEVER swallows exceptions — 4.7 G1 keeps transport failures on the
    exception path (they are NOT relabelled to empty). It only retries genuine empties.
    `_sleep` is injected so the selftest runs at zero wall-time (and so this cannot be
    defeated by the def-time-default sleep-binding trap that bit gate_retry)."""
    result = None
    for attempt in range(attempts):
        result = query_fn()          # raises propagate — deliberately not caught
        if result:
            return result
        if attempt < attempts - 1:
            _sleep(backoff_ms / 1000.0)
    return result


def _collection_status(has_observations: bool, fresh_scan_exists: bool) -> str:
    """Layer A (4.7 Q2): classify an empty read, AFTER Layer C retries have settled.
    Pure decision over two booleans the runner computes from its own queries.

      has_observations  — did we end up with ANY usable evidence this pass?
      fresh_scan_exists — is there a fresh scan_run for this asset within the window?

    has evidence            -> reads_ok        (classify normally)
    empty + fresh scan      -> genuine_empty   (scan ran, nothing matched -> unknown; Q4 streak)
    empty + no fresh scan   -> no_fresh_collection (nothing to read -> unreadable; preserve prior)"""
    if has_observations:
        return _STATUS_READS_OK
    if fresh_scan_exists:
        return _STATUS_GENUINE_EMPTY
    return _STATUS_NO_FRESH_COLLECTION


_DOWNGRADE_STREAK_REQUIRED = 3

_DECISION_WRITE = "write"          # let the unknown verdict through to assets
_DECISION_PRESERVE = "preserve"    # keep the positive prior; audit + log, no assets write
_DECISION_NO_WRITE = "no_write"    # prior already unknown; nothing to preserve or lose


def apply_2b_matrix(prior_class: str, status: str, streak_met: bool) -> str:
    """THE 2b WRITE MATRIX (4.7 ruling, relay 153; replaces 175 Q5). Pure.

    Called only when the computed class is `unknown` — a computed POSITIVE class always
    writes and never reaches here.

      prior POSITIVE + no_fresh_collection  -> PRESERVE  (nothing could have been seen)
      prior POSITIVE + genuine_empty        -> PRESERVE, unless the downgrade streak is
                                               met (3 distinct EVIDENCE-CAPABLE runs)
      prior UNKNOWN  + no_fresh_collection  -> no write  (Q5b DROPPED: measured 2026-09-16,
      prior UNKNOWN  + genuine_empty        -> no write   that branch would have stamped
                                               `unreadable` on ~365 of 416 assets — 88%)

    `unreadable` stays in the taxonomy and nothing here writes it."""
    if prior_class not in _POSITIVE_CLASSES:
        return _DECISION_NO_WRITE
    if status == _STATUS_NO_FRESH_COLLECTION:
        return _DECISION_PRESERVE
    if status == _STATUS_GENUINE_EMPTY:
        return _DECISION_WRITE if streak_met else _DECISION_PRESERVE
    return _DECISION_NO_WRITE


def _downgrade_streak_met(cur, asset_id: str, capable_runs: list,
                          required: int = _DOWNGRADE_STREAK_REQUIRED) -> bool:
    """Q4 streak, DERIVED from rows we already write — no migration (4.7 201/2+3).

    Counts device_class_dryrun rows that are ALL of:
      * event_type = 'TRANSITION_DOWNGRADE'   (4.7 ruling 3: the event type IS the test.
        A STAMP from unknown->unknown is not a downgrade candidate and must not count.)
      * prior_state.device_class was POSITIVE  (what preserve-prior is protecting)
      * device_class = 'unknown'               (the computed verdict)
      * scan_run_id is one of THIS asset's EVIDENCE-CAPABLE runs, each counted ONCE
        (one scan re-read by four passes a day is ONE observation, not four)

    Requires `required` DISTINCT such runs. Rows accumulate because preserve keeps the
    prior POSITIVE, so every pass re-emits TRANSITION_DOWNGRADE — measured 291 rows over
    11 assets in 7 days, 0 with a NULL scan_run_id."""
    capable = set(capable_runs or ())
    if len(capable) < required:
        return False
    cur.execute(
        """select scan_run_id::text as scan_run_id, prior_state, device_class
             from public.device_class_dryrun
            where asset_id = %s and event_type = 'TRANSITION_DOWNGRADE'
            order by evaluated_at desc limit 500""", (asset_id,))
    seen = []
    for r in (cur.fetchall() or []):
        # ⚠ event_type is filtered in SQL AND re-checked here on purpose. By
        # construction of event_for() a row with a POSITIVE prior and a computed
        # `unknown` can only be a TRANSITION_DOWNGRADE, so the two checks are
        # redundant TODAY — which is exactly why the SQL filter alone was
        # unobservable: every test that tried to exercise it was actually being
        # caught by the prior/class checks. Re-checking here makes the rule the
        # test can see, and keeps the derivation honest if event_for ever changes.
        if r.get("event_type") not in (None, "TRANSITION_DOWNGRADE"):
            continue
        if r.get("device_class") != "unknown":
            continue
        prior = (r.get("prior_state") or {}).get("device_class")
        if prior not in _POSITIVE_CLASSES:
            continue
        sid = r.get("scan_run_id")
        if sid and sid in capable and sid not in seen:
            seen.append(sid)
            if len(seen) >= required:
                return True
    return False


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


# ── N2 routing buckets — what the cloud port-gate ACTUALLY does ──────────
def _routing_bucket(device_class: str | None) -> str:
    """Which N2 cloud-port-gate outcome a device_class lands in.

    cloud_ip_check.decide() reads device_class ONLY -- it never consults
    confidence -- and resolves to exactly three outcomes:

      shallow   dc in CLOUD_CLASSES {cloud_endpoint, cdn, waf}
                -> curated probe, decided at tier 1
      deep      dc == 'origin_host'
                -> full sweep, decided at tier 1
      backstop  anything else, including unknown/unreadable/adc_lb/edge_firewall
                -> falls through to the cloud_ip_ranges.json CIDR table, so the
                   outcome depends on the asset's IP rather than on its class

    A transition reroutes iff it moves the asset between these buckets. Moves
    WITHIN a bucket (e.g. waf/suspected -> waf/confirmed, or cdn -> cloud_endpoint)
    change no routing decision at all.
    """
    if device_class in CLOUD_CLASSES:
        return "shallow"
    if device_class == "origin_host":
        return "deep"
    return "backstop"


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


# ══ R12 — CAPABILITY IS CONTENT-BEARING, PER OBSERVATION (4.7 ruling 12) ════
#
# ⛔ WHY THE ARTIFACT'S NAME IS NOT ENOUGH. commandcommcentral.com's 2026-09-03
# heavy DID write a `stack_id_passive` artifact. Its contents were
# {schema, collected_at, hostname} — nikto had earned the FortiGate ban 35 seconds
# earlier and the collector ran on a dead egress (relay 231/233). A capability test
# keyed on the artifact NAME calls that run "able to see cookies", so the absent
# `cookiesession1` reads as evidence of absence and the FortiWeb confirmation is
# downgraded on the strength of a collection that never happened. The
# same-name/different-content pair is pinned in
# scripts/scanner/test_passive_collector_runs_first.py.
#
#     name-keyed:    artifact `stack_id_passive` exists  -> capable   ❌
#     content-keyed: does it CARRY set_cookie_names?     -> not capable ✅
#
# ⚠ KEYED ON THE OBSERVATION, NOT THE SIGNAL, AND THAT IS DELIBERATE.
# device_fingerprints.yaml ALREADY owns signal -> observation (19 rows over 11
# observations). A second signal->artifact table here would be a SECOND HOME for
# that mapping: add a registry row, forget this constant, and the new signal is
# silently either always-capable (writes downgrades it should not) or never-capable
# (preserves forever) — with no test failing either way. Keying on the observation
# leaves the registry as the only place the mapping lives, and
# validate_capability_coverage() below turns "forgot one" into a refuse-to-run —
# the same treatment validate_fingerprints() already gives weights (R6).
#
# ⚠ READ DEPTH MUST MATCH gather_observations. If capability looked deeper than the
# gather does, a 4th-newest artifact could make a signal "capable" that the gather
# never read — a capable-but-unseen downgrade, which is fail-open wearing the new
# rule's clothes. `depth` carries the alignment and a test pins it.
_PASSIVE_MERGE_DEPTH = 3          # == _fresh_json_many(limit=) in gather_observations

_CAP_ARTIFACT_PRESENT = "artifact_present"   # the row existing IS the capability
_CAP_JSON_KEY_PRESENT = "json_key_present"   # key present, ANY value (false is a verdict)
_CAP_JSON_NONEMPTY    = "json_nonempty"      # key present AND truthy ({} [] "" null = absence)
_CAP_TEXT_EXTRACT     = "text_extract"       # a pure extractor must return truthy
_CAP_ASSET_SURFACE    = "asset_surface"      # not an artifact at all


class _Cap(NamedTuple):
    mode: str
    sources: tuple = ()
    field: str | None = None
    extract: object = None
    depth: int = 1


OBSERVATION_CAPABILITY: dict[str, _Cap] = {
    "ssh_banner":   _Cap(_CAP_TEXT_EXTRACT, (_ART_FINGERPRINT,), extract=extract_ssh_banner),
    "cert_issuer":  _Cap(_CAP_TEXT_EXTRACT, (_ART_TESTSSL,),
                         extract=lambda raw: extract_cert(raw).get("cert_issuer")),
    "cert_subject": _Cap(_CAP_TEXT_EXTRACT, (_ART_TESTSSL,),
                         extract=lambda raw: extract_cert(raw).get("cert_subject")),
    # ⚠ KEY-PRESENT, NOT NON-EMPTY, AND THE DIFFERENCE IS LOAD-BEARING.
    # `wafw00f_detected: false` is a REAL verdict — wafw00f ran, probed five ways,
    # and found no WAF. Testing it for truthiness would call every genuine negative
    # "not capable" and make a WAF class UNFALSIFIABLE: once confirmed, no wafw00f
    # run could ever lower it again. Both wafw00f observations share one artifact
    # and one dedupe_key, so they share one capability spec.
    "waf_vendor":   _Cap(_CAP_JSON_KEY_PRESENT, (_ART_WAFW00F,), field="wafw00f_detected"),
    "waf_present":  _Cap(_CAP_JSON_KEY_PRESENT, (_ART_WAFW00F,), field="wafw00f_detected"),
    # ⚠ NON-EMPTY, and THIS is the 09-03 case. {} / [] / "" / null are absence of
    # COLLECTION, not evidence of absence — the same rule _passive_signal applies
    # when merging the two producers, applied here to capability. Either producer
    # satisfies it, exactly as either can supply the signal.
    "http_headers":     _Cap(_CAP_JSON_NONEMPTY, _PASSIVE_TOOL_NAMES, field="headers",
                             depth=_PASSIVE_MERGE_DEPTH),
    "set_cookie_names": _Cap(_CAP_JSON_NONEMPTY, _PASSIVE_TOOL_NAMES, field="set_cookie_names",
                             depth=_PASSIVE_MERGE_DEPTH),
    # nuclei: the ARTIFACT is the capability marker, the FINDING is the evidence, and
    # they live in different tables — see EVIDENCE_ARTIFACT_PATTERNS for why both
    # halves are needed.
    "nuclei_fortinet_hit": _Cap(_CAP_ARTIFACT_PRESENT, (_ART_NUCLEI,)),
    # the probe records its OWN outcome (banned / no-challenge / corroborated), so the
    # artifact existing is the capability; _fwbbot_corroborated reads the verdict.
    "fwbbot_check": _Cap(_CAP_ARTIFACT_PRESENT, ("stack_id_fwbbot_check",)),
    # not an artifact at all — the ASM import writes this into asset_surface.
    "waf_vendor_discovery": _Cap(_CAP_ASSET_SURFACE),
}

# Registry observations with NO producer in gather_observations. DECLARED, not
# discovered: the coverage guard would otherwise refuse to start, and a silent
# `else: assume capable` is precisely the fail-open shape being removed fleet-wide.
# waf_present_differential is a ratified-but-dormant row — nothing emits it yet.
DORMANT_OBSERVATIONS = frozenset({"waf_present_differential"})


def signal_observation_map(fps) -> dict:
    """signal -> frozenset(observations), READ FROM THE REGISTRY, never restated.

    Multi-valued on purpose: `cert_issuer_subject_pattern` fires from cert_issuer OR
    cert_subject, and three separate signals read http_headers. A signal is capable
    if ANY of its observations is — the question being asked is "could this signal
    have fired again this pass", not "was every input present"."""
    out: dict[str, set] = {}
    for row in fps or ():
        if not isinstance(row, dict):
            continue
        sig, obs = row.get("signal"), row.get("observation")
        if sig and obs:
            out.setdefault(sig, set()).add(obs)
    return {k: frozenset(v) for k, v in out.items()}


def validate_capability_coverage(fps) -> list:
    """R6-shaped startup guard for R12. Every observation the registry names must have
    a capability spec or be declared dormant. Returns a list of errors (empty = ok).

    ⛔ THE FAILURE THIS PREVENTS is not a crash, it is a silent behaviour change: an
    unmapped observation has no capability answer, and whichever way the code defaults
    is wrong for half the fleet with nothing failing. Refusing to start is the only
    honest response, and it is what the weight rule already does."""
    errs = []
    known = set(OBSERVATION_CAPABILITY) | set(DORMANT_OBSERVATIONS)
    for obs in sorted({r.get("observation") for r in (fps or ())
                       if isinstance(r, dict) and r.get("observation")} - known):
        errs.append(f"observation {obs!r} has no OBSERVATION_CAPABILITY entry and is not "
                    f"declared in DORMANT_OBSERVATIONS — capability for it is undefined")
    return errs


def _cap_satisfied(cap: _Cap, row) -> bool:
    """Does ONE artifact row actually CARRY the observation? Pure."""
    if not row:
        return False
    if cap.mode == _CAP_ARTIFACT_PRESENT:
        return True
    raw = row.get("raw")
    if raw is None:
        return False
    if cap.mode == _CAP_TEXT_EXTRACT:
        try:
            return bool(cap.extract(raw))
        except Exception:
            return False
    try:
        obj = json.loads(raw)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    if cap.mode == _CAP_JSON_KEY_PRESENT:
        return cap.field in obj          # ANY value — `false` is a real verdict
    return bool(obj.get(cap.field))      # NONEMPTY: {} [] "" null all fall through


def _surface_carries_waf(cur, asset_id: str) -> bool:
    """Capability for the discovery-tier observation: did the ASM import record a
    `waf` block for this asset at all? Distinct from _discovery_waf, which returns
    (False, None) both for 'no surface' and for 'waf.detected is false' — capability
    must tell those apart, because only the first is a collection failure."""
    cur.execute("select surface_data from public.asset_surface where asset_id=%s", (asset_id,))
    row = cur.fetchone()
    if not row or not row.get("surface_data"):
        return False
    sd = row["surface_data"]
    if isinstance(sd, str):
        try:
            sd = json.loads(sd)
        except Exception:
            return False
    subs = sd.get("subdomains") if isinstance(sd, dict) else None
    if not isinstance(subs, list) or not subs:
        return False
    aid = str(asset_id).lower()
    entry = next((s for s in subs
                  if isinstance(s, dict) and str(s.get("name", "")).lower() == aid), None)
    if entry is None and len(subs) == 1 and isinstance(subs[0], dict):
        entry = subs[0]
    return isinstance(entry, dict) and isinstance(entry.get("waf"), dict)


def _capability_rows(cur, asset_id: str, cap: _Cap, freshness_days: int | None):
    """Newest `cap.depth` rows per source, with completed_at. freshness_days=None
    drops the window (used for evidence_age_days, which asks 'when did we last
    actually see it', not 'is it fresh')."""
    out = []
    for src in cap.sources:
        op = "ilike" if "%" in src else "="
        window = (f"and r.completed_at > now() - interval '{int(freshness_days)} days'"
                  if freshness_days is not None else "")
        limit = cap.depth if freshness_days is not None else 50
        cur.execute(
            f"""select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw,
                       r.completed_at
                  from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
                 where r.asset_id = %s and a.tool_name {op} %s {window}
                 order by r.completed_at desc limit {int(limit)}""", (asset_id, src))
        out.extend(cur.fetchall() or [])
    return out


def observation_capable(cur, asset_id: str, observation: str, freshness_days: int) -> bool:
    """Could this observation have been COLLECTED for this asset, in-window?

    ⛔ FAILS CLOSED on an unmapped observation. Reaching that branch means the startup
    guard was bypassed; 'not capable' preserves the prior, which is the recoverable
    error. 'Capable' would strip a real label on absent evidence — the whole defect
    family this rule exists to close."""
    cap = OBSERVATION_CAPABILITY.get(observation)
    if cap is None:
        return False
    if cap.mode == _CAP_ASSET_SURFACE:
        return _surface_carries_waf(cur, asset_id)
    return any(_cap_satisfied(cap, r)
               for r in _capability_rows(cur, asset_id, cap, freshness_days))


def signal_capable(cur, asset_id: str, signal: str, sig2obs: dict, freshness_days: int) -> bool:
    """A signal is capable if ANY observation it can fire from was collectible."""
    return any(observation_capable(cur, asset_id, o, freshness_days)
               for o in (sig2obs.get(signal) or ()))


def observation_age_days(cur, asset_id: str, observation: str) -> int | None:
    """Days since the newest collection that actually CARRIED this observation, at any
    age. None = we have never collected it. This is the number an operator wants when
    a verdict is being preserved: 'the cookie evidence is 14 days old'."""
    cap = OBSERVATION_CAPABILITY.get(observation)
    if cap is None or cap.mode == _CAP_ASSET_SURFACE:
        return None
    now = datetime.now(timezone.utc)
    best = None
    for r in _capability_rows(cur, asset_id, cap, None):
        if not _cap_satisfied(cap, r):
            continue
        when = r.get("completed_at")
        if when is None:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        age = (now - when).days
        if best is None or age < best:
            best = age
    return best


# ══ R5 — THE CLASS RULE, APPLIED TO CONFIDENCE (4.7 ruling 5, relay 236) ════
_DECISION_PRESERVE_AGED = "preserve_aged"   # same-class confidence drop on uncollected evidence
_R5_REASON = "EVIDENCE_AGED"


def apply_r5_confidence_rule(prior_class, prior_conf, new_class, new_conf,
                             prior_signals, incapable_signals) -> str:
    """PURE. 2b gave the CLASS a preserve rule; R5 gives CONFIDENCE the same one.

    A same-class confidence drop writes ONLY when a CAPABLE observation saw weaker
    evidence. Otherwise the drop is an artifact of what we failed to collect, and the
    prior confidence is preserved with reason EVIDENCE_AGED.

    This is the 09-03 shape exactly: wafw00f still named FortiWeb (waf survives), but
    the passive collector ran on a banned egress, so `cookiesession1` and the cert
    were absent — waf/confirmed -> waf/suspected on two signals that were never
    collected. Nothing about the host got weaker.

      class changed              -> WRITE   (not this rule's business; 2b owns unknown)
      confidence same or higher  -> WRITE   (nothing to protect)
      no recorded prior basis    -> WRITE   (see below)
      any prior signal INCAPABLE -> PRESERVE_AGED
      every prior signal capable -> WRITE   (a real observation of weaker evidence)

    ⚠ NO STREAK, unlike 2b, and deliberately. 2b counts repeat observations because
    it cannot tell whether a genuine-empty run looked hard enough. R5 does not need a
    counter because capability answers that question directly, per signal, for THIS
    pass.

    ⚠ EMPTY PRIOR BASIS -> WRITE, NOT PRESERVE. An asset whose stored class carries no
    evidence rows did not get there through this runner, so there is nothing to call
    aged. Preserving on an empty basis would build a RATCHET: a confidence that can
    rise and never fall. The blast radius is bounded — _routing_bucket pins that a
    same-class confidence move changes no routing decision at all."""
    if new_class != prior_class:
        return _DECISION_WRITE
    if _CONF_RANK.get(new_conf, 0) >= _CONF_RANK.get(prior_conf, 0):
        return _DECISION_WRITE
    if not prior_signals:
        return _DECISION_WRITE
    if set(prior_signals) & set(incapable_signals):
        return _DECISION_PRESERVE_AGED
    return _DECISION_WRITE


def prior_signals_of(prior_evidence) -> list:
    """The signal names the asset's CURRENT stored class rests on, from
    assets.device_class_evidence — the blob every --write pass already stores. No
    migration, no new column; the runner simply starts reading what it writes."""
    rows = prior_evidence
    if isinstance(rows, str):
        try:
            rows = json.loads(rows)
        except Exception:
            return []
    out = []
    for r in rows or ():
        if isinstance(r, dict) and r.get("signal") and r["signal"] not in out:
            out.append(r["signal"])
    return out


# ── DB signal gather (fresh signals for one asset) ───────────────────────
def _evidence_capable_scan_runs(cur, asset_id: str, freshness_days: int) -> list:
    """scan_run_ids for this asset, inside the freshness window, that produced AT LEAST
    ONE artifact the classifier actually reads (EVIDENCE_ARTIFACT_PATTERNS — the single
    source; do NOT restate the names here). Newest first. Read-only.

    This is the unit of "an observation that could have seen something". A run absent
    from this list did not fail to find evidence; it was never able to collect it."""
    cur.execute(
        f"""select distinct on (r.completed_at, r.scan_run_id)
                   r.scan_run_id::text as scan_run_id, r.completed_at
              from scan_run r
              join scan_run_artifacts a on a.scan_run_id = r.scan_run_id
             where r.asset_id = %s
               and r.completed_at > now() - interval '{int(freshness_days)} days'
               and a.tool_name ilike any(%s)
             order by r.completed_at desc, r.scan_run_id""",
        (asset_id, list(EVIDENCE_ARTIFACT_PATTERNS)))
    return [r["scan_run_id"] for r in (cur.fetchall() or [])]


def _fresh_scan_exists(cur, asset_id: str, freshness_days: int) -> bool:
    """Layer A absence probe (4.7 Q2, Obsidian 175; CAPABILITY-AWARE per 4.7 201/1):
    did any EVIDENCE-CAPABLE scan_run complete within the window? Distinguishes 'no
    collection happened' (-> preserve prior) from 'collection happened, nothing matched'
    (-> genuine_empty, the only downgrade candidate). Read-only.

    ⚠ Was "did ANY scan_run complete". That counted light scans, which emit nothing the
    classifier reads — see EVIDENCE_ARTIFACT_PATTERNS for the measurement."""
    return bool(_evidence_capable_scan_runs(cur, asset_id, freshness_days))


def gather_observations(cur, asset_id: str, freshness_days: int, nuclei_re: str) -> dict:
    obs: dict = {}
    fresh = f"now() - interval '{int(freshness_days)} days'"
    cur.execute(
        f"""select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw
              from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
             where r.asset_id = %s and a.tool_name ilike %s
               and r.completed_at > {fresh}
             order by r.completed_at desc limit 1""", (asset_id, _ART_FINGERPRINT))
    row = cur.fetchone()
    banner = extract_ssh_banner(row["raw"] if row else None)
    if banner:
        obs["ssh_banner"] = banner
    cur.execute(
        f"""select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text) as raw
              from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
             where r.asset_id = %s and a.tool_name ilike %s
               and r.completed_at > {fresh}
             order by r.completed_at desc limit 1""", (asset_id, _ART_TESTSSL))
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

    def _fresh_json_many(tool_names: tuple, limit: int = _PASSIVE_MERGE_DEPTH) -> list:
        """Newest `limit` json artifacts per tool name, merged newest-first.

        Explicit NAME LIST, never a prefix — `ilike 'stack_id_passive%'` is the
        predicate shape that made seed-device-class.yml fragile, and the light
        artifact is deliberately named outside that namespace.
        Bounded (4.7): an unbounded read inside a per-asset loop is a cost trap.
        """
        rows: list = []
        for tool in tool_names:
            cur.execute(
                f"""select a.content_jsonb::text as blob, r.completed_at
                      from scan_run_artifacts a join scan_run r on r.scan_run_id = a.scan_run_id
                     where r.asset_id = %s and a.tool_name = %s
                       and r.completed_at > {fresh}
                     order by r.completed_at desc limit {int(limit)}""", (asset_id, tool))
            for row in cur.fetchall() or []:
                if not row or not row.get("blob"):
                    continue
                try:
                    obj = json.loads(row["blob"])
                except Exception:
                    continue
                if isinstance(obj, dict):
                    rows.append((row["completed_at"], obj))
        rows.sort(key=lambda t: t[0], reverse=True)
        return [o for _, o in rows]

    verdict = _fresh_json(_ART_WAFW00F)
    kind = waf_vendor_from_wafw00f(verdict)      # kind string if detected & named, else None
    if kind and kind != "generic":
        obs["waf_vendor"] = kind                 # named vendor -> wafw00f_high_confidence
    elif verdict and verdict.get("wafw00f_detected"):
        # detected but named no vendor -> presence-only signal. Emitted ONLY here
        # (not alongside waf_vendor) so it never double-counts the same wafw00f run
        # against a vendor row (4.7 same-artifact test, Obsidian 146).
        obs["waf_present"] = True                # -> waf_present_wafw00f
    # ── PER-SIGNAL MERGE across the two passive producers (4.7 ruling, 2026-09-14) ──
    # heavy's `stack_id_passive`  = cert + headers + cookies, RARE
    # light's `light_stack_passive` = headers + cookies, FREQUENT (no cert by design)
    #
    # ⛔ A single newest-wins pick CANNOT EXPRESS "this artifact does not carry
    # that signal" — the same inexpressibility that made `lastDeepAt:
    # Map<id, Date>` unable to say "this scan doesn't count" in #060. Newest-wins
    # here would let light's fresher artifact shadow heavy's, and if light lacked
    # cookies it would silently kill the fortiweb_cookiesession1 tell — fixing
    # Pressable posture and going blind on FortiGate posture in one commit, with
    # no test failing.
    # ⇒ each signal takes the newest candidate that actually CONTAINS it, where
    #   "contains" is PRESENT AND NON-EMPTY: {} / [] / "" / null all fall through.
    #   An empty map is ABSENCE, not evidence of absence.
    passive_candidates = _fresh_json_many(_PASSIVE_TOOL_NAMES, limit=_PASSIVE_MERGE_DEPTH)

    def _passive_signal(key):
        for cand in passive_candidates:
            val = cand.get(key)
            if val:
                return val
        return None

    http_headers = http_headers_from_passive({"headers": _passive_signal("headers")})
    if http_headers:
        obs["http_headers"] = http_headers       # -> product_http_header row
    cookie_names = _passive_signal("set_cookie_names")
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

    EXCEPTION (157 Fix 4, 4.7 Q5): origin_host is the absence-of-fronting role and must YIELD
    to the cloud fallback — a cloud-hosted origin is 'cloud_endpoint', not a bare 'origin_host'.
    Without this, origin_host would steal every cloud asset that merely shows its own Server
    header (the exact F3-vs-cloud regression Fix 1 hit). origin_host stands only when cloud is
    ALSO empty. Returns (result, from_cloud)."""
    dc = fp_result["device_class"]
    if _fp_blocks_cloud(dc):
        return (fp_result, False)               # real edge/waf/cdn fingerprint blocks cloud (F3)
    if cloud_result is not None:
        return (cloud_result, True)             # cloud beats origin_host AND unknown
    return (fp_result, False)                   # no cloud -> origin_host (or unknown) stands


def _fp_blocks_cloud(device_class: str) -> bool:
    """Which fingerprint classes BLOCK the cloud fallback (F3). A real edge/waf/cdn does; but
    origin_host (157 Fix 4 — the WEAKEST role) and unknown do NOT — they must fall through to the
    cloud fallback so a cloud-hosted origin stays cloud_endpoint instead of being downgraded to
    origin_host. PURE + selftested: classify_asset applies the same predicate but needs a DB cursor,
    so this is the seam the selftest pins (the 2026-07-24 dry-run caught uoltest.unimacgraphics.com
    cloud_endpoint->origin_host precisely because this decision was inlined in classify_asset, which
    returned the origin_host fingerprint BEFORE _resolve ever ran)."""
    return device_class not in ("unknown", "origin_host")


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
    # 157 Fix 4: a real edge/waf/cdn fingerprint blocks cloud AND composes hosting; but origin_host
    # (weakest role) does NOT block here — it falls through to _resolve, which yields to the cloud
    # fallback so a cloud-hosted origin (uoltest.unimacgraphics.com) stays cloud_endpoint.
    if _fp_blocks_cloud(fp["device_class"]):
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
    # R12 startup guard, same shape and same reason as the weight rule above: an
    # observation with no capability spec has no capability ANSWER, and whichever way
    # the code defaults is silently wrong for part of the fleet with nothing failing.
    _cerrs = validate_capability_coverage(fps)
    if _cerrs:
        raise RegistryValidationError(
            "OBSERVATION_CAPABILITY does not cover the registry — classifier refuses to run:\n  - "
            + "\n  - ".join(_cerrs))
    sig2obs = signal_observation_map(fps)
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
    # per-matrix-row counters for the heartbeat (169's third condition)
    m2b = {"preserve_no_collection": 0, "preserve_genuine_empty": 0,
           "downgrade_streak_met": 0, "no_write_unknown_prior": 0}
    # R5 counters — the fires/doesn't-fire pair, both counted, so a rule that only
    # ever preserves is visible in the heartbeat instead of looking like it works.
    m5 = {"preserve_evidence_aged": 0, "downgrade_capable_saw_weaker": 0}
    _pass_started = datetime.now(timezone.utc)
    unknown = cloud_endpoint_ct = cdn_ct = conf_subset = conf_full = 0
    with conn.cursor() as cur:
        # F1/F3: classification no longer reads assets.is_cloud_endpoint/cloud_provider
        # (is_cloud_endpoint was the wrong topology key — see classify_asset). The cloud
        # fallback RE-DERIVES from surface_data every run (E2 re-derive, no caching), so
        # we only need each asset's CURRENT class to compute the transition event.
        # device_class_evidence is READ here for the first time (R5). It is the blob
        # every --write pass already stores on this same table — the prior verdict's
        # own basis. No migration, no new column: the runner starts reading what it
        # has been writing since D4.
        cur.execute("select asset_id, device_class, device_class_confidence, "
                    "device_class_evidence from public.assets order by asset_id")
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
            # PHASE 2b (4.7 ruling, relay 201). A computed POSITIVE class always
            # writes — row 5 of the matrix — so the decision starts as write and is
            # narrowed only when the verdict is `unknown`.
            decision = _DECISION_WRITE
            r5_note = None
            if nc == "unknown":
                unknown += 1
                had_evidence = bool(res.get("evidence"))
                capable = _evidence_capable_scan_runs(cur, a["asset_id"], fresh_days)
                status2b = _collection_status(had_evidence, bool(capable))
                streak_met = (
                    status2b == _STATUS_GENUINE_EMPTY
                    and a["device_class"] in _POSITIVE_CLASSES
                    and _downgrade_streak_met(cur, a["asset_id"], capable))
                decision = apply_2b_matrix(a["device_class"], status2b, streak_met)
                prior_s = f"{a['device_class']}/{a['device_class_confidence']}"
                if decision == _DECISION_PRESERVE and status2b == _STATUS_NO_FRESH_COLLECTION:
                    m2b["preserve_no_collection"] += 1
                    print(f"  · {a['asset_id']}: [2b-preserve] kept {prior_s} "
                          f"(no evidence-capable collection in {fresh_days}d)")
                elif decision == _DECISION_PRESERVE:
                    m2b["preserve_genuine_empty"] += 1
                    print(f"  · {a['asset_id']}: [2b-preserve] kept {prior_s} "
                          f"(genuine-empty; streak {len(capable)}/{_DOWNGRADE_STREAK_REQUIRED} "
                          f"evidence-capable runs, not met)")
                elif decision == _DECISION_WRITE:
                    m2b["downgrade_streak_met"] += 1
                    print(f"  · {a['asset_id']}: [2b-downgrade] {prior_s} -> unknown "
                          f"({_DOWNGRADE_STREAK_REQUIRED} distinct evidence-capable runs, all genuine-empty)")
                else:
                    m2b["no_write_unknown_prior"] += 1
            else:
                # ── R5 (4.7 ruling 5, relay 236). MUTUALLY EXCLUSIVE WITH 2b BY
                # CONSTRUCTION: a computed `unknown` never reaches here, so the two
                # rules can never both narrow the same decision. Pinned by test.
                prior_sigs = prior_signals_of(a.get("device_class_evidence"))
                incapable = []
                # Only the signals that STOPPED firing are worth asking about — a
                # signal present in this pass's evidence was, self-evidently, capable.
                still_firing = {e.get("signal") for e in (res.get("evidence") or [])}
                for sig in prior_sigs:
                    if sig in still_firing:
                        continue
                    if not signal_capable(cur, a["asset_id"], sig, sig2obs, fresh_days):
                        incapable.append(sig)
                decision = apply_r5_confidence_rule(
                    a["device_class"], a["device_class_confidence"], nc, ncf,
                    prior_sigs, incapable)
                if decision == _DECISION_PRESERVE_AGED:
                    m5["preserve_evidence_aged"] += 1
                    ages = {}
                    for sig in incapable:
                        for o in sorted(sig2obs.get(sig) or ()):
                            ages[o] = observation_age_days(cur, a["asset_id"], o)
                    _seen = [v for v in ages.values() if v is not None]
                    r5_note = {"reason": _R5_REASON, "incapable_signals": incapable,
                               "evidence_age_days": ages,
                               "preserved": f"{a['device_class']}/{a['device_class_confidence']}",
                               "would_have_written": f"{nc}/{ncf}"}
                    print(f"  · {a['asset_id']}: [R5-preserve] kept "
                          f"{a['device_class']}/{a['device_class_confidence']} "
                          f"(would have been {ncf}; {_R5_REASON} on {','.join(incapable)}; "
                          f"newest such evidence "
                          f"{min(_seen) if _seen else 'never'}d old)")
                elif _CONF_RANK.get(ncf, 0) < _CONF_RANK.get(a["device_class_confidence"], 0) \
                        and nc == a["device_class"]:
                    m5["downgrade_capable_saw_weaker"] += 1
                    print(f"  · {a['asset_id']}: [R5-downgrade] "
                          f"{a['device_class']}/{a['device_class_confidence']} -> {nc}/{ncf} "
                          f"(every prior signal was collectible this pass)")
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
            # Was: `ncf == "confirmed"`. That measured whether the NEW class was
            # confirmed -- a dimension the N2 gate never reads -- so it was wrong
            # in BOTH directions: false on cloud_endpoint/confirmed -> unknown
            # (a real reroute, 30 assets in the 07-24..08-06 soak), and true on
            # waf/suspected -> waf/confirmed (no routing change whatsoever).
            # Obsidian 169/170, corrected 2026-08-06.
            would_reroute = _routing_bucket(a["device_class"]) != _routing_bucket(nc)
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
                 # ⚠ THE R5 REASON RIDES prior_state, NOT A NEW COLUMN. A dedicated
                 # column on device_class_dryrun is a MIGRATION, and a migration push
                 # halts scanning. prior_state is a jsonb this runner constructs and
                 # owns, and the note is about the prior being preserved — the right
                 # home for it as well as the available one. 2b's audit shape is
                 # untouched: this key appears only on an R5 preserve.
                 json.dumps({"device_class": a["device_class"],
                             "confidence": a["device_class_confidence"],
                             **({"preserve": r5_note} if r5_note else {})}),
                 would_reroute, _latest_scan_run(cur, a["asset_id"]), soak_generation))

            # ⛔ THE PRESERVE GATE. A preserved row keeps its POSITIVE prior, so the
            # next pass re-emits TRANSITION_DOWNGRADE and the audit row lands again —
            # which is exactly what lets the streak accumulate without a migration.
            if write and decision == _DECISION_WRITE:
                cur.execute(
                    "update public.assets set device_class=%s, device_class_confidence=%s, "
                    "vendor_product_confidence=%s, device_class_evidence=%s::jsonb, "
                    "vendor_product=%s::jsonb where asset_id=%s",
                    (nc, ncf, vpc, json.dumps(res["evidence"]),
                     json.dumps(res["vendor_product"]), a["asset_id"]))
        # ── HEARTBEAT (169's third condition, relay 153/201 item 3) ──────────
        # "A soak with no heartbeat is indistinguishable from a soak that never ran."
        # ONE row per pass, ALWAYS — dry-run included, and before any early return.
        #
        # ⚠ HOSTED IN meta_alerter_runs, WHICH IS NAMED FOR THE ALERTER. Deliberate,
        # and flagged rather than done quietly: device_class_dryrun.asset_id is an FK
        # to assets, so a synthetic `_heartbeat` asset_id cannot be inserted there, and
        # a purpose-built device_class_runs table is a MIGRATION — which halts scanning
        # and which 4.7 told me not to default to. meta_alerter_runs is the existing
        # per-run heartbeat shape in this schema (alerter_name / window / status /
        # notes). If the name grates, renaming it is a migration and a separate call.
        cur.execute(
            "insert into public.meta_alerter_runs "
            "(alerter_name, window_start, window_end, status, notes) "
            "values (%s,%s,%s,%s,%s)",
            ("device_class_runner", _pass_started, datetime.now(timezone.utc),
             "complete",
             json.dumps({"mode": "write" if write else "dry-run",
                         "soak_generation": soak_generation,
                         "assets_evaluated": len(assets),
                         "unknown": unknown,
                         "events": tally,
                         "matrix_2b": m2b,
                         "matrix_r5": m5,
                         "streak_required": _DOWNGRADE_STREAK_REQUIRED,
                         "evidence_artifact_patterns": list(EVIDENCE_ARTIFACT_PATTERNS),
                         "capability_observations": sorted(OBSERVATION_CAPABILITY)})))
    conn.commit()
    conn.close()

    total = len(assets)
    unk_pct = round(100 * unknown / total) if total else 0
    print(f"\n{'WROTE' if write else 'DRY-RUN'} (soak_generation={soak_generation}, audit rows committed):")
    print(f"  events: STAMP={tally['STAMP']} CHANGE={tally['CHANGE']} "
          f"UPGRADE={tally['TRANSITION_UPGRADE']} DOWNGRADE={tally['TRANSITION_DOWNGRADE']}")
    print(f"  2b matrix: preserve(no-collection)={m2b['preserve_no_collection']} "
          f"preserve(genuine-empty)={m2b['preserve_genuine_empty']} "
          f"downgrade(streak met)={m2b['downgrade_streak_met']} "
          f"no-write(unknown prior)={m2b['no_write_unknown_prior']}")
    print(f"  R5 confidence: preserve(evidence-aged)={m5['preserve_evidence_aged']} "
          f"downgrade(capable saw weaker)={m5['downgrade_capable_saw_weaker']}")
    print("  heartbeat: 1 row -> meta_alerter_runs(alerter_name='device_class_runner')")
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
    # N2 would_reroute — must track the gate's BUCKETS, never confidence.
    # The first two rows are the 2026-08-06 defect (Obsidian 169): the old
    # `ncf == "confirmed"` scored these False while the gate really does lose
    # its tier-1 SHALLOW answer and fall through to the CIDR backstop.
    # The waf->waf row is the same bug in reverse: a pure confidence move that
    # the old rule scored True despite changing no routing decision at all.
    reroute_cases = [
        ("cloud_endpoint", "unknown",        True),   # shallow -> backstop  (the defect)
        ("cdn",            "unknown",        True),   # shallow -> backstop
        ("cloud_endpoint", "origin_host",    True),   # shallow -> deep
        ("origin_host",    "cloud_endpoint", True),   # deep    -> shallow
        ("unknown",        "cloud_endpoint", True),   # backstop-> shallow
        ("waf",            "waf",            False),  # confidence-only: NO reroute
        ("cdn",            "cloud_endpoint", False),  # within CLOUD_CLASSES: NO reroute
        ("waf",            "cdn",            False),  # within CLOUD_CLASSES: NO reroute
        ("unknown",        "adc_lb",         False),  # both backstop: NO reroute
        ("unknown",        "unreadable",     False),  # both backstop (phase 2 forward-compat)
    ]
    for prior_c, new_c, want in reroute_cases:
        got = _routing_bucket(prior_c) != _routing_bucket(new_c)
        ok &= got == want
        print(f"  reroute {prior_c} -> {new_c} = {got} (want {want})")
    # UNREADABLE phase 2a detection primitives (4.7 175).
    # Layer C: retries a successful-empty read, stops on first hit, exhausts the bound,
    # and NEVER swallows an exception. _sleep injected so this runs at zero wall-time.
    _c = {"n": 0}
    def _empty_then_full():
        _c["n"] += 1
        return [] if _c["n"] < 2 else ["row"]
    ok &= _read_with_retry(_empty_then_full, _sleep=lambda _s: None) == ["row"]
    ok &= _c["n"] == 2                                  # stopped as soon as data arrived
    _c2 = {"n": 0}
    def _always_empty():
        _c2["n"] += 1
        return []
    ok &= _read_with_retry(_always_empty, attempts=3, _sleep=lambda _s: None) == []
    ok &= _c2["n"] == 3                                 # exhausted the bound, no more
    _raised = False
    try:
        _read_with_retry(lambda: (_ for _ in ()).throw(RuntimeError("boom")), _sleep=lambda _s: None)
    except RuntimeError:
        _raised = True
    ok &= _raised                                      # G1: transport error propagates, not relabelled
    # Layer A: the empty-read discriminator (Q2)
    ok &= _collection_status(True,  True)  == _STATUS_READS_OK
    ok &= _collection_status(True,  False) == _STATUS_READS_OK
    ok &= _collection_status(False, True)  == _STATUS_GENUINE_EMPTY
    ok &= _collection_status(False, False) == _STATUS_NO_FRESH_COLLECTION
    print(f"  layer C retry (2/3-attempt + raise-propagates) + layer A status: 4 cases ok")
    # 2b write matrix (4.7 relay 201). Pure; the DB-shaped cases live in
    # test_device_class_2b.py. Q5b's absence is asserted, not assumed.
    _m = apply_2b_matrix
    _matrix = [
        (("waf", _STATUS_NO_FRESH_COLLECTION, False), _DECISION_PRESERVE),
        (("waf", _STATUS_GENUINE_EMPTY,       False), _DECISION_PRESERVE),
        (("waf", _STATUS_GENUINE_EMPTY,       True),  _DECISION_WRITE),
        (("unknown", _STATUS_NO_FRESH_COLLECTION, False), _DECISION_NO_WRITE),
        (("unknown", _STATUS_GENUINE_EMPTY,       True),  _DECISION_NO_WRITE),
    ]
    for args, want in _matrix:
        ok &= _m(*args) == want
    print(f"  2b matrix: {len(_matrix)} cases "
          f"{'ok' if all(_m(*a) == w for a, w in _matrix) else 'FAIL'} "
          f"(Q5b dropped: unknown prior never writes)")
    # R5 confidence rule (4.7 ruling 5, relay 236). Pure; the DB-shaped branches live
    # in test_device_class_2c.py. BOTH halves are here — a rule that only ever
    # preserves is indistinguishable from a rule that works.
    _r5 = apply_r5_confidence_rule
    _r5_cases = [
        # same class, confidence DROPS, a prior signal could not be collected -> preserve
        (("waf", "confirmed", "waf", "suspected",
          ["wafw00f_high_confidence", "fortiweb_cookiesession1"],
          ["fortiweb_cookiesession1"]),                          _DECISION_PRESERVE_AGED),
        # ⭐ the doesn't-fire half: same drop, EVERY prior signal was collectible
        (("waf", "confirmed", "waf", "suspected",
          ["wafw00f_high_confidence", "fortiweb_cookiesession1"], []), _DECISION_WRITE),
        # a class change is 2b's business (or a real CHANGE), never R5's
        (("waf", "confirmed", "cdn", "suspected",
          ["wafw00f_high_confidence"], ["wafw00f_high_confidence"]), _DECISION_WRITE),
        # confidence rises / holds -> nothing to protect
        (("waf", "suspected", "waf", "confirmed", ["x"], ["x"]),  _DECISION_WRITE),
        (("waf", "confirmed", "waf", "confirmed", ["x"], ["x"]),  _DECISION_WRITE),
        # no recorded basis -> WRITE, not preserve (no ratchet)
        (("waf", "confirmed", "waf", "suspected", [], ["anything"]), _DECISION_WRITE),
        # an incapable signal NOT in the prior basis is irrelevant
        (("waf", "confirmed", "waf", "suspected", ["a"], ["b"]),  _DECISION_WRITE),
    ]
    for args, want in _r5_cases:
        got = _r5(*args)
        ok &= got == want
    print(f"  R5 confidence rule: {len(_r5_cases)} cases "
          f"{'ok' if all(_r5(*a) == w for a, w in _r5_cases) else 'FAIL'} "
          f"(preserve on incapable, WRITE when every prior signal was collectible)")
    # R12 content-bearing capability (4.7 ruling 12). The two that matter: an empty
    # passive envelope is NOT capable for cookies (the 09-03 shape), and a wafw00f
    # NEGATIVE verdict IS capable (false is a verdict, not a failure to look).
    _empty_envelope = {"raw": json.dumps(
        {"schema": 1, "collected_at": "2026-09-03T20:14:56Z", "hostname": "commandcommcentral.com"})}
    _full_envelope = {"raw": json.dumps(
        {"schema": 1, "hostname": "commandcommcentral.com",
         "set_cookie_names": ["cookiesession1", "ASP.NET_SessionId"],
         "headers": {"server": "nginx"}, "cert": "CN=*.commandcommcentral.com"})}
    _cap_cases = [
        (OBSERVATION_CAPABILITY["set_cookie_names"], _empty_envelope, False),  # ⭐ 09-03
        (OBSERVATION_CAPABILITY["set_cookie_names"], _full_envelope,  True),
        (OBSERVATION_CAPABILITY["http_headers"],     _empty_envelope, False),
        (OBSERVATION_CAPABILITY["http_headers"],     _full_envelope,  True),
        (OBSERVATION_CAPABILITY["set_cookie_names"],
         {"raw": json.dumps({"set_cookie_names": []})}, False),               # [] is absence
        # ⭐ the key-present/non-empty split: a genuine negative stays CAPABLE
        (OBSERVATION_CAPABILITY["waf_vendor"],
         {"raw": json.dumps({"schema": 1, "wafw00f_detected": False, "wafw00f_kind": None})}, True),
        (OBSERVATION_CAPABILITY["waf_vendor"], {"raw": json.dumps({"schema": 1})}, False),
        (OBSERVATION_CAPABILITY["ssh_banner"], {"raw": fpx}, True),
        (OBSERVATION_CAPABILITY["ssh_banner"], {"raw": "no banner here"}, False),
        (OBSERVATION_CAPABILITY["cert_issuer"], {"raw": ts}, True),
        (OBSERVATION_CAPABILITY["nuclei_fortinet_hit"], {"raw": None}, True),  # presence only
        (OBSERVATION_CAPABILITY["set_cookie_names"], None, False),
    ]
    for cap, row, want in _cap_cases:
        got = _cap_satisfied(cap, row)
        ok &= got == want
    print(f"  R12 capability (content-bearing): {len(_cap_cases)} cases "
          f"{'ok' if all(_cap_satisfied(c, r) == w for c, r, w in _cap_cases) else 'FAIL'} "
          f"(empty envelope != capable; wafw00f False IS capable)")
    # R12 coverage guard over the REAL registry — the startup condition run() enforces.
    _fps = load_fingerprints()
    _cov = validate_capability_coverage(_fps)
    ok &= not _cov
    print(f"  R12 coverage over device_fingerprints.yaml: "
          f"{'ok' if not _cov else 'FAIL — ' + '; '.join(_cov)}")
    # …and its doesn't-fire half: an unmapped observation MUST be reported.
    _bogus = validate_capability_coverage([{"signal": "x", "observation": "not_a_real_observation"}])
    ok &= len(_bogus) == 1
    print(f"  R12 guard catches an unmapped observation: {'ok' if len(_bogus) == 1 else 'FAIL'}")
    # Tripwire, not a correctness check: _routing_bucket imports CLOUD_CLASSES so
    # it cannot drift behaviourally. This fires when someone CHANGES the gate's
    # routing semantics, which is a signal to re-review what would_reroute means.
    ok &= CLOUD_CLASSES == {"cloud_endpoint", "cdn", "waf"}
    print(f"  CLOUD_CLASSES tripwire = {sorted(CLOUD_CLASSES)}")
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
    origin = {"device_class": "origin_host", "confidence": "suspected", "evidence": [], "vendor_product": {}}
    cloud_ce = {"device_class": "cloud_endpoint", "confidence": "confirmed", "evidence": {}, "vendor_product": {}}
    f3 = [
        (_resolve(waf_conf, cloud_ce), (waf_conf, False)),   # confirmed fingerprint wins over cloud
        (_resolve(waf_susp, cloud_ce), (waf_susp, False)),   # suspected fingerprint BLOCKS cloud (F3)
        (_resolve(unk, cloud_ce),      (cloud_ce, True)),    # unknown fingerprint -> cloud fallback
        (_resolve(unk, None),          (unk, False)),        # nothing -> unknown
        (_resolve(origin, cloud_ce),   (cloud_ce, True)),    # 157 Fix 4: origin_host YIELDS to cloud fallback
        (_resolve(origin, None),       (origin, False)),     # 157 Fix 4: origin_host stands when cloud empty
    ]
    for got, want in f3:
        ok &= got == want
    print(f"  F3 ordering (conf-wins / susp-blocks-cloud / unk->cloud / none->unknown): "
          f"{'ok' if all(g == w for g, w in f3) else 'FAIL'}")
    # 157 Fix 4 — the block-cloud predicate. origin_host must NOT block cloud (else the 2026-07-24
    # dry-run's uoltest.unimacgraphics.com cloud_endpoint->origin_host downgrade recurs).
    blocks_ok = (all(_fp_blocks_cloud(c) for c in ("waf", "cdn", "edge_firewall"))
                 and not _fp_blocks_cloud("origin_host") and not _fp_blocks_cloud("unknown"))
    ok &= blocks_ok
    print(f"  {'ok' if blocks_ok else 'FAIL'} _fp_blocks_cloud: edge/waf/cdn block cloud; "
          f"origin_host+unknown fall through to _resolve")
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
