#!/usr/bin/env python3
"""
device_class_runner.py — device-class classifier RUNNER (4.7 D2/D3/D4 + E1-E6).

Dry-run-first. For every asset:
  1. is_cloud_endpoint=true -> INHERIT device_class='cloud_endpoint' with PROVENANCE
     recorded in evidence (4.7 E2). Re-derived every run (no caching), so a
     cloud->non-cloud flip propagates. The cloud classifier owns AWS/GCP/Azure/CF-CDN.
  2. else gather FRESH (< evidence_freshness_days, D3) fingerprint signals from the
     DB — SSH banner (fingerprintx artifact), cert issuer/subject (testssl artifact),
     nuclei-Fortinet hit (E5: template-id PREFIX allowlist, not substring 'forti') —
     and run derive_device_class.classify().
  3. Decide the event vs the current row: STAMP / CHANGE / TRANSITION_UPGRADE /
     TRANSITION_DOWNGRADE (E6c). A DOWNGRADE (incl. -> unknown) is a red flag that
     resets the soak clock.
  4. On any actionable event, write a row to public.device_class_dryrun (4.7 E3 —
     the persistent soak audit trail; "structured logs, not text") EVERY pass,
     dry-run AND --write. --write ALSO stamps assets.device_class + confidence +
     evidence + vendor_product — CLASSIFY-ONLY, changes NO routing (D4 Phase A).

Everything keys on asset_id (the hostname PK scan_run/findings reference).
v1 signals: SSH banner + cert + nuclei-Fortinet. DEFERRED to v1.1: wafw00f vendor
(run_medium computes ctx.waf_kind but nothing persists it) and the IP-range signal
(needs a clean asset_id-keyed IP source). Until wafw00f lands, WAF/edge assets top
out at 'suspected' (below the routing bar) — E1: fine for the soak; each
wafw00f-confirmed WAF then gets its own 7-day mini-soak.

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
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from derive_device_class import (  # noqa: E402
    FINGERPRINTS_PATH, classify, load_fingerprints, load_thresholds,
)

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
    return obs


def _latest_scan_run(cur, asset_id: str):
    cur.execute("select scan_run_id from scan_run where asset_id=%s "
                "order by completed_at desc nulls last limit 1", (asset_id,))
    r = cur.fetchone()
    return r["scan_run_id"] if r else None


def classify_asset(cur, a: dict, fps, th, fresh_days, nuclei_re) -> tuple[dict, bool]:
    """(result, inherited). E2: cloud inheritance carries provenance in evidence."""
    if a["is_cloud_endpoint"]:
        ev = {"signals": [], "inherited_from": "is_cloud_endpoint",
              "inherited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "cloud_classifier_confidence": "confirmed",
              "cloud_provider_at_inheritance": a.get("cloud_provider")}
        return ({"device_class": "cloud_endpoint", "confidence": "confirmed",
                 "evidence": ev, "vendor_product": {"cloud_provider": a.get("cloud_provider")}}, True)
    return (classify(gather_observations(cur, a["asset_id"], fresh_days, nuclei_re), fps, th), False)


def _has_wafw00f(evidence) -> bool:
    return isinstance(evidence, list) and any(
        s.get("signal") == "wafw00f_high_confidence" for s in evidence)


def run(dsn: str, write: bool, soak_generation: int) -> int:
    fps, th = load_fingerprints(), load_thresholds()
    fresh_days = th["evidence_freshness_days"]
    nuclei_re = load_nuclei_fortinet_regex()
    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=15)
    conn.autocommit = False

    tally = {"STAMP": 0, "CHANGE": 0, "TRANSITION_UPGRADE": 0, "TRANSITION_DOWNGRADE": 0}
    unknown = cloud = conf_subset = conf_full = 0
    with conn.cursor() as cur:
        # Resilience guard (instance divergence): the cloud classifier's
        # `cloud_provider` (20260707b) is Command-only; `is_cloud_endpoint`
        # (20260712b) is on both. Build the SELECT from whichever cloud columns
        # actually exist so the runner works on either schema — a missing column
        # reads as false/null (same lesson as demotion_writer's Prodex no-op).
        cur.execute("select column_name from information_schema.columns "
                    "where table_name='assets' "
                    "and column_name in ('is_cloud_endpoint','cloud_provider')")
        have = {r["column_name"] for r in cur.fetchall()}
        cols = [
            "asset_id",
            "is_cloud_endpoint" if "is_cloud_endpoint" in have else "false as is_cloud_endpoint",
            "cloud_provider" if "cloud_provider" in have else "null::text as cloud_provider",
            "device_class", "device_class_confidence",
        ]
        cur.execute(f"select {', '.join(cols)} from public.assets order by asset_id")
        assets = cur.fetchall()
        print(f"{'ASSET':38.38s} {'FROM':18s} {'-> TO':18s} EVENT")
        for a in assets:
            res, inherited = classify_asset(cur, a, fps, th, fresh_days, nuclei_re)
            nc, ncf = res["device_class"], res["confidence"]
            if nc == "unknown":
                unknown += 1
            if inherited:
                cloud += 1
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
                "confidence, evidence, vendor_product, prior_state, would_reroute, "
                "scan_run_id, soak_generation) values (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,%s,%s,%s)",
                (a["asset_id"], ev, nc, ncf, json.dumps(res["evidence"]),
                 json.dumps(res["vendor_product"]),
                 json.dumps({"device_class": a["device_class"], "confidence": a["device_class_confidence"]}),
                 would_reroute, _latest_scan_run(cur, a["asset_id"]), soak_generation))

            if write:
                cur.execute(
                    "update public.assets set device_class=%s, device_class_confidence=%s, "
                    "device_class_evidence=%s::jsonb, vendor_product=%s::jsonb where asset_id=%s",
                    (nc, ncf, json.dumps(res["evidence"]), json.dumps(res["vendor_product"]), a["asset_id"]))
    conn.commit()
    conn.close()

    total = len(assets)
    unk_pct = round(100 * unknown / total) if total else 0
    print(f"\n{'WROTE' if write else 'DRY-RUN'} (soak_generation={soak_generation}, audit rows committed):")
    print(f"  events: STAMP={tally['STAMP']} CHANGE={tally['CHANGE']} "
          f"UPGRADE={tally['TRANSITION_UPGRADE']} DOWNGRADE={tally['TRANSITION_DOWNGRADE']}")
    print(f"  confirmed: cloud_inherited={cloud} via_subset={conf_subset} via_full_signals={conf_full}")
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
