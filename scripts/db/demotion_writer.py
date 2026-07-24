#!/usr/bin/env python3
"""demotion_writer.py — P2 went-dark demotion writer (DRY-RUN-FIRST).

Flips confirmed_live assets that have stopped responding to discovery_status='went_dark'
after a per-reason dwell, with a strengthened sweep-health gate, a multi-probe active
confirmation, and an optimistic-concurrency flip that can't lose a race with the importer.

Runs as a step in asm-discover.yml AFTER import_asm_to_surface.py, every 6h.

SAFETY: default is --write-enable OFF. With writes off this process changes NO asset
state; it only inserts observation rows into public.p2_demotion_dryrun (would_demote +
hold_reason + gate_state) so the ~2026-07-25 review can validate the guards against real
fleet behaviour before anything tombstones a live asset.

Spec: P2_DEMOTION_WRITER_BUILD_SPEC.md v2 (4.7 Q1-Q8 applied). Grounded on the real repo:
  - staleness-by-age (no per-sweep counter exists); multi-probe re-verify == the K the
    architecture can't count (4.7 Q1).
  - sweep-health gate: >=50% of NON-CLOUD confirmed_live bumped this sweep AND 2
    consecutive healthy sweeps AND min-fleet 100% AND near-threshold->human review (Q2).
  - 72h show threshold reused from detect_dark_assets (Q3).
  - MULTI-PROBE: 3x30s, all-fail-same-reason to demote, any success aborts, mixed=HOLD (Q4).
  - ambiguous timeout-vs-RST -> service_gone + audited (Q5); Python sockets actually
    distinguish RST (ECONNREFUSED) from timeout, so we classify precisely most of the time.
  - rate-limit 5/run + eligibility >=7d-live + oldest-first (Q6).
  - optimistic flip: WHERE last_alive_at = <value read at eval> (importer race fix).

Env: SUPABASE_DSN (same as the importer) or --dsn. psycopg3.

COMPANION CHANGES (do at write-enable, with the importer in front of us — NOT edited blind
here because import_asm_to_surface.py's UPSERT diverges Command-cloud vs Prodex-characterization):
  1. importer resurrection hook: when a went_dark asset is re-observed confirmed_live, in the
     SAME upsert UPDATE bump resurrection_count, clear went_dark_at/fade_detected_at/dark_reason,
     stamp last_transition_at (single SET; four-gate-valid + >=1 service only).
  2. asm-discover.yml: add a step after the importer that runs this script (write-enable off).
  3. Q7 audit: confirm no non-observation writer mutates a went_dark asset's asset_surface.
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    raise

# ── Constants (4.7-ratified). DWELL_DAYS MUST match asset_dark_debounce_state() in
#    migration 20260712a — the regression test test_flip_at_matches_sql_constants guards drift. ──
SHOW_THRESHOLD_HOURS = 72          # Q3 reuse detect_dark_assets DARK_THRESHOLD_HOURS
DWELL_DAYS = {"dns_gone": 7, "service_gone": 14, "unreachable": None}  # None = HOLD
PROBE_COUNT = 3                    # Q4 multi-probe
PROBE_INTERVAL_S = 30
PROBE_TIMEOUT_S = 4
DEFAULT_PORTS = (443, 80, 22)      # fallback when asset_surface has no known ports
RATE_LIMIT = 5                     # Q6 demotions per run
MIN_LIVE_DAYS = 7                  # Q6 eligibility
SWEEP_WINDOW_HOURS = 2             # "bumped this sweep" window (inside the 6h cadence)
FRACTION_MIN = 0.50               # Q2 gate floor
NEAR_THRESHOLD_HI = 0.60          # Q2 50-60% => human review
MIN_FLEET = 10                     # Q2 below this, require 100% observation
PREV_SWEEP_MAX_AGE_H = 12         # consecutive-healthy: prior sweep must be this recent
SWEEP_MARKER = "__sweep__"        # asset_id sentinel for the per-run gate row

UTC = timezone.utc


def now() -> datetime:
    return datetime.now(UTC)


# ────────────────────────────────────────────────────────────────────────────
# PURE cores (unit-tested without a DB) — the load-bearing logic lives here.
# ────────────────────────────────────────────────────────────────────────────

# classify_ports now lives in asset_liveness.py (Obsidian 161, 4.7 Q3) as the CANONICAL
# classify_ports_for_state_flip — ONE source of truth shared with the dark-digest suppression
# path, so the two liveness semantics (state-flip vs alert-suppression) can never drift
# (4.7 risk #1). Re-exported under the original name so every existing caller + test is unchanged.
from asset_liveness import classify_ports_for_state_flip as classify_ports  # noqa: E402


def aggregate_probes(reasons: list[str], last_alive_moved: bool) -> dict:
    """Combine PROBE_COUNT single-probe reasons into a demotion decision (4.7 Q4).
    reasons[i] in {'alive','dns_gone','service_gone','unreachable','inconclusive'}.
    Any 'alive' -> alive (abort). Importer bumped last_alive_at mid-probe -> alive/race.
    All identical & concrete -> that reason. Anything else -> mixed (HOLD).
    This is the anti-single-probe guard: one flaky probe can never demote on its own.
    """
    if last_alive_moved:
        return {"decision": "alive", "reason": None, "note": "last_alive_moved"}
    if any(r == "alive" for r in reasons):
        return {"decision": "alive", "reason": None, "note": "probe_alive"}
    concrete = {"dns_gone", "service_gone", "unreachable"}
    uniq = set(reasons)
    if len(uniq) == 1 and next(iter(uniq)) in concrete:
        return {"decision": "demote_candidate", "reason": next(iter(uniq)), "note": "unanimous"}
    return {"decision": "mixed", "reason": None, "note": "mixed:" + ",".join(sorted(uniq))}


def evaluate_gate(bumped: int, denom: int, prev_healthy: bool | None,
                  prev_age_hours: float | None) -> dict:
    """Strengthened sweep-health gate (4.7 Q2). Returns dict(ok, coverage_ok, reason, state).

    Two separate signals so the gate can BOOTSTRAP (else it deadlocks):
      - coverage_ok  = THIS sweep's coverage is good: >=50% non-cloud fleet bumped,
                       min-fleet 100% when denom<10, and not in the 50-60% review band.
                       This is what gets recorded in the __sweep__ marker's sweep_healthy,
                       so the NEXT run has a meaningful prior to compare against.
      - ok (may demote) = coverage_ok AND the PREVIOUS sweep was coverage-healthy AND recent
                       (the "2 consecutive healthy sweeps" rule). prev_healthy is the prior
                       row's coverage_ok. On the first-ever run prev is None -> not consecutive
                       -> ok False (demote nothing) but coverage_ok True (marker records healthy),
                       so run 2 can pass. Without this split, sweep_healthy would echo ok and
                       nothing would ever go healthy.
    """
    frac = (bumped / denom) if denom else 0.0
    state = {
        "bumped": bumped, "denom": denom, "fraction": round(frac, 4),
        "prev_healthy": prev_healthy, "prev_age_hours": prev_age_hours,
        "window_hours": SWEEP_WINDOW_HOURS,
    }
    # ── per-sweep coverage (independent of history) ──
    coverage_ok, reason = True, "healthy"
    if denom == 0:
        coverage_ok, reason = False, "sweep_unhealthy_no_fleet"
    elif denom < MIN_FLEET:
        state["min_fleet_100_required"] = True
        if frac < 1.0:
            coverage_ok, reason = False, "sweep_unhealthy_min_fleet"
    if coverage_ok and frac < FRACTION_MIN:
        coverage_ok, reason = False, "sweep_unhealthy_low_fraction"
    if coverage_ok and FRACTION_MIN <= frac < NEAR_THRESHOLD_HI:
        state["near_threshold"] = True
        coverage_ok, reason = False, "near_threshold_human_review"
    state["coverage_ok"] = coverage_ok
    # ── consecutive-healthy (this coverage AND a recent healthy prior) ──
    consecutive = (coverage_ok and bool(prev_healthy)
                   and prev_age_hours is not None and prev_age_hours <= PREV_SWEEP_MAX_AGE_H)
    state["consecutive_healthy"] = consecutive
    if not coverage_ok:
        return {"ok": False, "coverage_ok": False, "reason": reason, "state": state}
    if not consecutive:
        return {"ok": False, "coverage_ok": True, "reason": "no_consecutive_healthy_sweep", "state": state}
    return {"ok": True, "coverage_ok": True, "reason": "healthy", "state": state}


def flip_at(last_alive: datetime, reason: str, override_days: int | None) -> datetime | None:
    """When the writer becomes eligible to flip. None => HOLD (unreachable).
    MUST match asset_dark_debounce_state() SQL; parity asserted by the regression test.
    """
    d = override_days if override_days is not None else DWELL_DAYS.get(reason)
    if d is None:
        return None
    return last_alive + timedelta(days=d)


# ────────────────────────────────────────────────────────────────────────────
# Active probe (LIGHT, pure-Python — no external tool, no VPN slots; 4.7 s5.4).
# ────────────────────────────────────────────────────────────────────────────

def resolve_host(host: str) -> tuple[str | None, str]:
    """Return (ip_or_None, status). status: 'ok' | 'nxdomain' | 'inconclusive'."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return (infos[0][4][0], "ok") if infos else (None, "nxdomain")
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)):
            return None, "nxdomain"
        return None, "inconclusive"   # EAI_AGAIN etc. — resolver hiccup, don't call it dns_gone
    except OSError:
        return None, "inconclusive"


def probe_port(ip: str, port: int, timeout: float = PROBE_TIMEOUT_S) -> str:
    """'open' | 'refused' (RST) | 'noresponse' (timeout/unreachable). Distinguishing
    refused from timeout is what lets us split service_gone from unreachable cleanly."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
        if rc == 0:
            return "open"
        if rc in (errno.ECONNREFUSED,):
            return "refused"
        return "noresponse"     # ETIMEDOUT/EHOSTUNREACH/ENETUNREACH/EAGAIN
    except socket.timeout:
        return "noresponse"
    except OSError:
        return "noresponse"
    finally:
        try:
            s.close()
        except OSError:
            pass


def single_probe(host: str, ports: list[int]) -> str:
    """One full re-probe -> one reason: 'alive'|'dns_gone'|'service_gone'|'unreachable'|'inconclusive'."""
    ip, status = resolve_host(host)
    if status == "nxdomain":
        return "dns_gone"
    if status == "inconclusive" or ip is None:
        return "inconclusive"
    results = [probe_port(ip, p) for p in (ports or list(DEFAULT_PORTS))]
    reason = classify_ports(results)
    return reason  # 'alive' | 'service_gone' | 'unreachable'


# ────────────────────────────────────────────────────────────────────────────
# SQL
# ────────────────────────────────────────────────────────────────────────────
Q_FRACTION = """
SELECT count(*) FILTER (WHERE last_alive_at >= now() - %(win)s::interval) AS bumped,
       count(*) AS denom
FROM public.assets
WHERE discovery_status = 'confirmed_live' AND NOT is_cloud_endpoint
"""
Q_PREV_SWEEP = """
SELECT sweep_healthy, extract(epoch FROM (now() - observed_at)) / 3600.0 AS age_h
FROM public.p2_demotion_dryrun
WHERE asset_id = %(m)s
ORDER BY observed_at DESC
LIMIT 1
"""
Q_CANDIDATES = """
SELECT asset_id, last_alive_at, first_observed, dark_patience_override_days
FROM public.assets
WHERE discovery_status = 'confirmed_live'
  AND last_alive_at IS NOT NULL
  AND last_alive_at < now() - %(show)s::interval
ORDER BY last_alive_at ASC
"""
Q_SURFACE_PORTS = "SELECT surface_data FROM public.asset_surface WHERE asset_id = %(a)s"
Q_LAST_ALIVE = "SELECT last_alive_at FROM public.assets WHERE asset_id = %(a)s"
Q_INSERT_DRYRUN = """
INSERT INTO public.p2_demotion_dryrun
  (run_tag, sweep_healthy, asset_id, discovery_status, last_alive_at, age_hours,
   dark_reason, days_remaining, writer_will_flip_at, would_demote, hold_reason,
   gate_state, write_enabled)
VALUES
  (%(run_tag)s, %(sweep_healthy)s, %(asset_id)s, %(discovery_status)s, %(last_alive_at)s,
   %(age_hours)s, %(dark_reason)s, %(days_remaining)s, %(writer_will_flip_at)s,
   %(would_demote)s, %(hold_reason)s, %(gate_state)s, %(write_enabled)s)
"""
Q_SET_FADE = """
UPDATE public.assets
SET fade_detected_at = COALESCE(fade_detected_at, now()), dark_reason = %(reason)s
WHERE asset_id = %(a)s AND discovery_status = 'confirmed_live'
"""
Q_BUMP_ALIVE = """
UPDATE public.assets
SET last_alive_at = now(), fade_detected_at = NULL, dark_reason = NULL
WHERE asset_id = %(a)s
"""
Q_FLIP = """
UPDATE public.assets
SET discovery_status = 'went_dark', went_dark_at = now(), last_transition_at = now(),
    fade_detected_at = COALESCE(fade_detected_at, now()), dark_reason = %(reason)s
WHERE asset_id = %(a)s AND discovery_status = 'confirmed_live'
  AND last_alive_at = %(eval)s
"""
Q_AUDIT = """
INSERT INTO public.admin_audit_log (actor_user_id, action, target_user_id, target_email,
                                    before_state, after_state, details)
VALUES (NULL, 'auto_went_dark', NULL, NULL,
        %(before)s, %(after)s, %(details)s)
"""


def known_ports(conn, asset_id: str) -> list[int]:
    """Last-known ports from asset_surface.surface_data.subdomains[].services[]."""
    with conn.cursor() as cur:
        cur.execute(Q_SURFACE_PORTS, {"a": asset_id})
        row = cur.fetchone()
    if not row or not row[0]:
        return list(DEFAULT_PORTS)
    blob = row[0]
    ports: set[int] = set()
    for sub in (blob.get("subdomains") or []):
        svcs = list(sub.get("services") or [])
        for h in (sub.get("hosts") or []):
            svcs.extend(h.get("services") or [])
        for svc in svcs:
            p = svc.get("port")
            if isinstance(p, int):
                ports.add(p)
    return sorted(ports) if ports else list(DEFAULT_PORTS)


def current_last_alive(conn, asset_id: str) -> datetime | None:
    with conn.cursor() as cur:
        cur.execute(Q_LAST_ALIVE, {"a": asset_id})
        row = cur.fetchone()
    return row[0] if row else None


def multi_probe(conn, asset_id: str, eval_last_alive: datetime, ports: list[int]) -> dict:
    """PROBE_COUNT probes at PROBE_INTERVAL_S; re-read last_alive_at between them (Q4)."""
    reasons: list[str] = []
    for i in range(PROBE_COUNT):
        if i > 0:
            time.sleep(PROBE_INTERVAL_S)
            if current_last_alive(conn, asset_id) != eval_last_alive:
                return aggregate_probes(reasons, last_alive_moved=True)
        reasons.append(single_probe(asset_id, ports))
        if reasons[-1] == "alive":            # short-circuit: any success aborts
            return aggregate_probes(reasons, last_alive_moved=False)
    return aggregate_probes(reasons, last_alive_moved=False)


def sweep_health(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute(Q_FRACTION, {"win": f"{SWEEP_WINDOW_HOURS} hours"})
        bumped, denom = cur.fetchone()
        cur.execute(Q_PREV_SWEEP, {"m": SWEEP_MARKER})
        prev = cur.fetchone()
    prev_healthy = prev[0] if prev else None
    prev_age_h = float(prev[1]) if prev else None
    return evaluate_gate(bumped, denom, prev_healthy, prev_age_h)


def log_dryrun(conn, run_tag, sweep_healthy, asset_id, disc, last_alive, reason,
               days_remaining, flip, would, hold, gate_state, write_enabled):
    age_h = None
    if last_alive is not None:
        age_h = round((now() - last_alive).total_seconds() / 3600.0, 1)
    with conn.cursor() as cur:
        cur.execute(Q_INSERT_DRYRUN, {
            "run_tag": run_tag, "sweep_healthy": sweep_healthy, "asset_id": asset_id,
            "discovery_status": disc, "last_alive_at": last_alive, "age_hours": age_h,
            "dark_reason": reason, "days_remaining": days_remaining,
            "writer_will_flip_at": flip, "would_demote": would, "hold_reason": hold,
            "gate_state": Json(gate_state), "write_enabled": write_enabled,
        })


def run(conn, write_enabled: bool, run_tag: str) -> int:
    gate = sweep_health(conn)
    # Per-run gate marker row. Record THIS sweep's coverage_ok (not the final gate
    # decision) so the next run's consecutive-healthy check has a real prior to read —
    # recording gate["ok"] here would deadlock the gate (it can never bootstrap).
    log_dryrun(conn, run_tag, gate["coverage_ok"], SWEEP_MARKER, None, None, None, None,
               None, False, gate["reason"], gate["state"], write_enabled)
    conn.commit()
    if not gate["ok"]:
        print(f"  sweep gate: {gate['reason']} {gate['state']} — demoting nothing")
        return 0

    with conn.cursor() as cur:
        cur.execute(Q_CANDIDATES, {"show": f"{SHOW_THRESHOLD_HOURS} hours"})
        cands = cur.fetchall()
    print(f"  sweep healthy ({gate['state']}); {len(cands)} fade candidate(s)")

    demoted = 0
    for asset_id, last_alive, first_observed, override_days in cands:
        ports = known_ports(conn, asset_id)
        probe = multi_probe(conn, asset_id, last_alive, ports)

        def emit(reason, days_rem, flip, would, hold):
            log_dryrun(conn, run_tag, True, asset_id, "confirmed_live", last_alive,
                       reason, days_rem, flip, would, hold, gate["state"], write_enabled)
            conn.commit()

        if probe["decision"] == "alive":
            if write_enabled:
                with conn.cursor() as cur:
                    cur.execute(Q_BUMP_ALIVE, {"a": asset_id})
            emit(None, None, None, False, "reprobe_alive")
            continue
        if probe["decision"] == "mixed":
            emit(None, None, None, False, "reprobe_mixed_reason")
            continue

        reason = probe["reason"]
        fa = flip_at(last_alive, reason, override_days)
        if write_enabled and reason in ("dns_gone", "service_gone", "unreachable"):
            with conn.cursor() as cur:
                cur.execute(Q_SET_FADE, {"a": asset_id, "reason": reason})

        if reason == "unreachable":
            emit(reason, None, None, False, "unreachable_hold")
            continue

        days_rem = max(0, (fa - now()).days) if fa else None
        if fa is not None and now() < fa:
            emit(reason, days_rem, fa, False, "within_dwell")
            continue
        # first_observed is NULL for a freshly-discovered asset (e.g. the new
        # perimeter-IP assets 24-38-70-x / 52-119-65-x). Unknown age = we cannot
        # prove it has lived >= MIN_LIVE_DAYS, so it is NOT demotion-eligible —
        # same bucket as the <7d guard, and the conservative choice (never demote
        # on unknown age). This None-guard also prevents `now() - None`, the
        # TypeError that failed ASM Discover #369/#370 (2026-07-19).
        if first_observed is None or (now() - first_observed).days < MIN_LIVE_DAYS:
            emit(reason, days_rem, fa, False, "not_eligible_7d")
            continue
        if demoted >= RATE_LIMIT:
            emit(reason, days_rem, fa, False, "rate_limited")
            continue

        # ── would demote ──
        if write_enabled:
            with conn.cursor() as cur:
                cur.execute(Q_FLIP, {"a": asset_id, "reason": reason, "eval": last_alive})
                n = cur.rowcount
            if n == 0:  # importer bumped last_alive_at during the probe window — it won
                emit(reason, 0, fa, True, "race_importer_won")
                continue
            ambiguous = probe.get("note", "").startswith("mixed")
            with conn.cursor() as cur:
                cur.execute(Q_AUDIT, {
                    "before": Json({"discovery_status": "confirmed_live"}),
                    "after": Json({"discovery_status": "went_dark"}),
                    "details": Json({
                        "asset_id": asset_id, "dark_reason": reason,
                        "last_alive_at": last_alive.isoformat() if last_alive else None,
                        "rule": "demotion_writer_v1", "ambiguous_reason": ambiguous,
                    }),
                })
        emit(reason, 0, fa, True, None)
        demoted += 1

    print(f"  done: {demoted} demotion(s) {'WRITTEN' if write_enabled else '(dry-run)'}")
    return demoted


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"),
                    help="Postgres DSN (or set SUPABASE_DSN)")
    ap.add_argument("--write-enable", action="store_true",
                    help="ACTUALLY flip assets to went_dark. Default OFF (dry-run: logs only).")
    ap.add_argument("--run-tag", default=os.environ.get("GITHUB_RUN_ID", "manual"),
                    help="Groups this run's dry-run rows.")
    args = ap.parse_args()
    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 1
    mode = "WRITE-ENABLED" if args.write_enable else "dry-run (no asset writes)"
    print(f"demotion_writer: {mode}  run_tag={args.run_tag}")
    conn = psycopg.connect(args.dsn, autocommit=False)
    try:
        run(conn, args.write_enable, args.run_tag)
        conn.commit()
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn,
            psycopg.errors.UndefinedFunction) as e:
        # Foundation (migration 20260712a) not applied yet — degrade to a clean no-op
        # instead of red-failing the discovery job. Same spirit as the importer's
        # SUPABASE_DSN guard. Makes push order-independent of migrate-approval.
        conn.rollback()
        msg = e.diag.message_primary if getattr(e, "diag", None) else str(e)
        print(f"::warning::demotion_writer: foundation missing ({msg}); "
              f"apply migration 20260712a_asset_dark_debounce_p2.sql. No-op this run.",
              file=sys.stderr)
        return 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
