#!/usr/bin/env python3
"""
derive_asset_kind.py — Host Characterization, Phase A derivation

Derives each asset's functional `kind` (+ scan_url, confidence, is_staging,
drift, evidence) from data the daily discovery scan ALREADY captured in
asset_surface.surface_data.subdomains[]. Writes assets.kind + kind_* columns.

Phase A of the Host Characterization redesign (HOST_CHARACTERIZATION_SPEC.md,
ruled by 4.7 2026-07-05; code-reviewed by 4.7 2026-07-05). Phase A is
SCAN-BEHAVIOR-NEUTRAL — run_medium.py does NOT read these columns yet (Phase B).

Derives the 8 observable kinds (first match wins, spec §5):
    dead, portal, api, web, mail, ftp, infra, unknown   (+ is_staging modifier)

`redirect` is DEFERRED (D1): discovery's httpx FOLLOWS redirects and stores only
reachability={live,http_status,title} with no chain, so a root-redirect is not
observable from surface_data. Enum value exists but is never assigned here.
TODO(Phase-C, engine-3.1): capture reachability.redirect_chain[] at discovery,
then plumb `redirect` derivation + the scan_url ownership guard (ruling ④).

4.7 CODE-REVIEW fixes folded in (2026-07-05):
  * dead-counter idempotency (D2 / hole 1): the consecutive-dead streak advances
    ONLY on a genuinely newer discovery observation (asset_surface.updated_at) —
    re-running --apply on the same observation can no longer manufacture
    dead@high. Streak + last-counted stamp live in kind_evidence.
  * server-fingerprints vs platform hints (hole 2): only real server
    fingerprints (nginx/apache/...) cast a `web` vote; platform/CDN markers
    (Vercel/Cloudflare/GCP) go into evidence but never vote — a Vercel-hosted
    API stays `api`.
  * pick_sub no longer guesses (hole 5): name-match or is_root, else None ->
    outer "no-surface-data" path.
  * explicit no-reachability branch (hole 7) for triage clarity.

Usage:
  SUPABASE_DSN=... python scripts/normalize/derive_asset_kind.py --dry-run
  SUPABASE_DSN=... python scripts/normalize/derive_asset_kind.py --apply
  SUPABASE_DSN=... python scripts/normalize/derive_asset_kind.py --apply --asset <hostname>

Environment:
  SUPABASE_DSN — Postgres DSN (same var the scanner uses). Required.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import psycopg

# ---- constants (spec §5, 4.7 rulings + code-review) ------------------------
# Mirror of scripts/scanner/surface_read.SUPPORTED_SCHEMA_VERSIONS. Duplicated
# (not imported) — the scanner Docker image doesn't ship scripts/normalize/. If
# you bump this, grep the other file and bump there too. Drift = safe direction
# (unsupported version → skip parsing → existing behavior unaffected). [4.7 R7]
SUPPORTED_SCHEMA_VERSIONS = {"3.0"}                       # ruling (9)
DEAD_5XX = {500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527}  # hole §5.1
DEAD_CONSECUTIVE_HIGH = 3                                 # ruling (2)
STAGING_TOKENS = {"staging", "stg", "uat", "sandbox", "preview", "dev",
                  "test", "qa", "demo", "nonprod"}

# 4.7 code-review hole 2 — only SERVER fingerprints cast a `web` classification
# vote. Platform / CDN hints (Vercel, Cloudflare, GCP, ...) are recorded in
# evidence but never vote, so a Vercel-hosted API cannot slide into `web`.
SERVER_FINGERPRINTS = {"nginx", "apache", "iis", "kestrel", "openresty",
                       "litespeed", "caddy", "express", "gunicorn", "tomcat",
                       "php", "wordpress", "drupal", "joomla"}
PLATFORM_HINTS = {"vercel", "cloudflare", "google cloud", "google cloud cdn",
                  "akamai", "fastly", "netlify", "azure", "azure front door"}

MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
LOGIN_TITLE_MARKERS = ("sign in", "signin", "log in", "login", "sso",
                       "authenticate", "single sign")


def _parse_ts(x):
    """Normalize a timestamp (datetime or ISO string) to tz-aware UTC, or None."""
    if x is None:
        return None
    dt = x if isinstance(x, datetime) else None
    if dt is None:
        try:
            dt = datetime.fromisoformat(str(x))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def meaningful_title(t: str | None) -> bool:
    if not t:
        return False
    s = t.strip().lower()
    return s not in {"", "loading", "loading...", "loading…", "untitled"}


def web_server_fingerprint(tech_names: list[str]) -> bool:
    """True iff a real server/CMS fingerprint is present (casts a web vote)."""
    return any(any(w in (n or "").lower() for w in SERVER_FINGERPRINTS) for n in tech_names)


def platform_hints(tech_names: list[str]) -> list[str]:
    """Platform/CDN markers — recorded in evidence, do NOT vote (hole 2)."""
    return sorted({p for n in tech_names for p in PLATFORM_HINTS if p in (n or "").lower()})


def looks_like_login(title: str | None, auth_gated: bool) -> bool:
    if auth_gated:
        return True
    t = (title or "").lower()
    return any(m in t for m in LOGIN_TITLE_MARKERS)


def is_staging_name(name: str) -> bool:
    toks = set(name.replace("-", ".").split("."))
    return bool(toks & STAGING_TOKENS)


def compute_drift(is_manual: bool, new_kind: str, cur_kind: str | None, conf: str) -> bool:
    """Ruling 5: a manual label DRIFTS only when a HIGH-confidence derivation
    disagrees. Never on low/medium — not trustworthy enough to flag a human
    override."""
    return bool(is_manual and (new_kind != cur_kind) and (conf == "high"))


def schema_supported(version) -> bool:
    """Ruling 9: refuse to derive on an unknown surface_data.schema_version."""
    return version in SUPPORTED_SCHEMA_VERSIONS


def pick_sub(surface_data: dict | None, asset_name: str) -> dict | None:
    """name-match, else is_root, else None (hole 5: never guess subs[0])."""
    subs = (surface_data or {}).get("subdomains") or []
    for s in subs:
        if s.get("name") == asset_name:
            return s
    for s in subs:
        if s.get("is_root"):
            return s
    return None


def derive(sub: dict, prior_evidence: dict | None, auth_gated: bool,
           surface_updated_at=None):
    """Return (kind, confidence, scan_url, evidence).

    scan_url is always None here (redirect deferred — D1); kept in the signature
    for Phase-B parity. surface_updated_at gates the dead streak counter so a
    re-run on the same observation cannot advance it (D2 idempotency fix).
    """
    r = sub.get("reachability") or {}
    live, status, title = r.get("live"), r.get("http_status"), r.get("title")
    fp = sub.get("fingerprint") or {}
    tech = [(t.get("name") or "") for t in (fp.get("tech") or [])]
    waf = sub.get("waf") or {}
    waf_det = bool(waf.get("detected")) and (waf.get("vendor") not in (None, "None"))
    svcs = sub.get("services") or []
    ports = {s.get("port") for s in svcs}
    http_live = (status is not None) or any(s.get("service") in ("http", "https") for s in svcs)

    ev = {"status": status, "title": title or None, "waf": waf.get("vendor"),
          "tech": tech[:6], "platform_hints": platform_hints(tech),
          "live": live, "http_live": http_live}

    # Rule 0.5 — no reachability AND no services (hole 7): explicit, for triage.
    if not r and not svcs:
        ev.update(rule="no-reachability")
        return "unknown", "low", None, ev

    # Rule 1 — dead (hole §5.1: live=false OR 5xx-class; NO title match).
    # Streak counter (ruling 2 + D2): advance ONLY on a newer discovery
    # observation (asset_surface.updated_at) so operator re-runs of --apply on
    # the same observation cannot manufacture dead@high.
    if live is False or (status in DEAD_5XX):
        pe = prior_evidence or {}
        prior_n = int(pe.get("consecutive_dead", 0) or 0)
        prior_ts = _parse_ts(pe.get("dead_last_counted_at"))
        cur_ts = _parse_ts(surface_updated_at)
        new_obs = (prior_ts is None) or (cur_ts is not None and cur_ts > prior_ts)
        n = (prior_n + 1) if new_obs else max(prior_n, 1)
        ev.update(rule="dead", consecutive_dead=n,
                  dead_last_counted_at=(cur_ts.isoformat() if cur_ts
                                        else pe.get("dead_last_counted_at")))
        return "dead", ("high" if n >= DEAD_CONSECUTIVE_HIGH else "low"), None, ev

    # Rule 2 — live HTTP -> HTTP-kind branch (before mail/ftp, hole §5-order)
    if http_live:
        if waf_det and status == 403:                       # hole §5.4: WAF 403 != api
            ev.update(rule="waf-403-web")
            return "web", "low", None, ev
        if status == 401 or looks_like_login(title, auth_gated):  # hole §5.6: portal before web
            ev.update(rule="portal")
            return "portal", ("high" if status == 401 else "medium"), None, ev
        if status == 403 or (status == 404 and not meaningful_title(title)
                             and not web_server_fingerprint(tech)):   # hole §5.4
            ev.update(rule="api")
            return "api", "medium", None, ev
        # web: meaningful title OR a real SERVER fingerprint. Platform/CDN hints
        # (Vercel/GCP) do NOT vote (hole 2) — an API on Vercel stays api above.
        if isinstance(status, int) and 200 <= status < 400 \
           and (meaningful_title(title) or web_server_fingerprint(tech)):
            ev.update(rule="web")
            return "web", "high", None, ev
        ev.update(rule="web-default")                       # live HTTP, unclear -> scan (ruling 3)
        return "web", "low", None, ev

    # Rule 3 — no live HTTP
    if ports & MAIL_PORTS:
        ev.update(rule="mail")
        return "mail", "medium", None, ev
    if 21 in ports:
        ev.update(rule="ftp")
        return "ftp", "medium", None, ev
    if svcs:
        ev.update(rule="infra")
        return "infra", "low", None, ev
    ev.update(rule="unknown")
    return "unknown", "low", None, ev


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true", help="print proposed changes, write nothing")
    g.add_argument("--apply", action="store_true", help="write derived kind + columns")
    ap.add_argument("--asset", help="single asset name (default: all)")
    args = ap.parse_args()

    dsn = os.environ.get("SUPABASE_DSN")
    if not dsn:
        sys.exit("SUPABASE_DSN not set")

    conn = psycopg.connect(dsn, connect_timeout=20)
    cur = conn.cursor()
    # ownership is pulled for the Phase-B/redirect scan_url ownership guard
    # (ruling 4); unused today. s.updated_at gates the dead streak counter (D2).
    q = """select a.asset_id, a.name, a.kind::text, a.kind_source, a.kind_evidence,
                  a.ownership::text, s.surface_data, s.auth_gated,
                  s.surface_data->>'schema_version', s.updated_at
             from public.assets a
             left join public.asset_surface s using(asset_id)
            {where}
            order by a.name"""
    if args.asset:
        cur.execute(q.format(where="where a.name = %s"), (args.asset,))
    else:
        cur.execute(q.format(where=""))
    rows = cur.fetchall()

    skipped, drift, changed, planned = [], [], [], []
    print(f"{'ASSET':<32} {'CUR':<9}-> {'DERIVED':<9} {'CONF':<7} {'STG':<4} RULE")
    print("-" * 88)

    for (asset_id, name, cur_kind, kind_source, prior_ev, ownership,
         surface_data, auth_gated, schema_version, surface_updated_at) in rows:

        # Rule 0 — version-gate (ruling 9)
        if not schema_supported(schema_version):
            skipped.append((name, f"schema_version={schema_version!r}"))
            print(f"{name:<32} {cur_kind or '-':<9}   {'SKIP':<9} {'-':<7} {'-':<4} unsupported schema_version={schema_version!r}")
            continue

        sub = pick_sub(surface_data, name)
        if sub is None:
            new_kind, conf, scan_url, ev = "unknown", "low", None, {"rule": "no-surface-data"}
        else:
            new_kind, conf, scan_url, ev = derive(sub, prior_ev, bool(auth_gated), surface_updated_at)
        ev["surface_schema_version"] = schema_version         # ruling 7 stamp
        is_stg = is_staging_name(name)

        is_manual = (kind_source == "manual")
        is_drift = compute_drift(is_manual, new_kind, cur_kind, conf)

        flag = ""
        if is_manual:
            flag = " [MANUAL:keep]" + (" DRIFT!" if is_drift else "")
        elif new_kind != cur_kind:
            flag = " *"

        print(f"{name:<32} {cur_kind or '-':<9}-> {new_kind:<9} {conf:<7} "
              f"{'yes' if is_stg else '-':<4} {ev.get('rule','')}{flag}")

        if is_manual:
            if is_drift:
                drift.append(name)
            if args.apply:
                # manual kind/confidence/scan_url are NEVER overwritten (ruling 5).
                # is_staging IS refreshed — it's a hostname-derived modifier, not
                # part of the human's kind decision.
                cur.execute("""update public.assets
                    set kind_drift=%s, is_staging=%s, kind_evidence=%s::jsonb, kind_updated_at=now()
                    where asset_id=%s""", (is_drift, is_stg, json.dumps(ev), asset_id))
        else:
            if new_kind != cur_kind:
                changed.append((name, cur_kind, new_kind))
            planned.append(name)
            if args.apply:
                cur.execute("""update public.assets set
                        kind=%s::public.asset_kind_t,
                        kind_confidence=%s::public.kind_conf_t,
                        scan_url=%s,
                        kind_evidence=%s::jsonb,
                        kind_updated_at=now(),
                        is_staging=%s,
                        kind_source='derived',
                        kind_drift=false
                    where asset_id=%s""",
                    (new_kind, conf, scan_url, json.dumps(ev), is_stg, asset_id))

    if args.apply:
        conn.commit()

    print("-" * 88)
    print(f"total={len(rows)}  changed_kind={len(changed)}  manual_drift={len(drift)}  "
          f"skipped_schema={len(skipped)}  mode={'APPLIED' if args.apply else 'DRY-RUN'}")
    if changed:
        print("\nkind changes:")
        for nm, a, b in changed:
            print(f"  {nm}: {a} -> {b}")
    if drift:
        print("\nMANUAL DRIFT (label kept, kind_drift flagged):", ", ".join(drift))
    if skipped:
        print("\nSKIPPED (unsupported schema):", ", ".join(f"{n} ({r})" for n, r in skipped))
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
