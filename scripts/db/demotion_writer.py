#!/usr/bin/env python3
"""demotion_writer.py — P2 went-dark demotion writer (DRY-RUN-FIRST).

Flips confirmed_live assets that have stopped responding to discovery_status='went_dark'
after a per-reason dwell, with a strengthened sweep-health gate, a multi-probe active
confirmation, and an optimistic-concurrency flip that can't lose a race with the importer.

Runs as a step in asm-discover.yml AFTER import_asm_to_surface.py, every 6h.

SAFETY: default is --write-enable OFF. With writes off this process changes no asset's
discovery_status, clock or reason; it inserts observation rows into public.p2_demotion_dryrun
(would_demote + hold_reason + gate_state) and — since job 3t — stamps or clears ONE display
field, assets.fade_detected_at (when the "not responding" notice began). Nothing leaves the
portal, comes back, or has its clock bumped without --write-enable.

⛔ JOB 3t (2026-10-26) — "NOT RESPONDING", THEN IT LEAVES THE PORTAL. Howie, 07:00: "initially we
let people know that it's not responding and then after a certain amount of time we say that it's
going off-line and out of the portal". Ruled 07:16 (D1-D7) and 08:39 (D8-D10); plan v1.2, reviewed
by Qwen3.8 Max (MF1-MF10). What changed here:
  - ONE SOURCE. Candidates, the notice and the leave date come from public.v_asset_reachability
    (migration 20261026a), the same view the portal and the daily read. Its clock is the newest
    liveness ANSWER from any route; assets.last_alive_at is the scan/import clock (MF1).
  - THE NOTICE. Every run (dry-run too: it is display state) stamps fade_detected_at on each host
    the view says is not responding, and clears it when the host answers again or is put on hold.
    The banner (portal push P) lands before this push, so the stamp can never predate the banner
    (D8).
  - THE FLIP needs a notice that is 7 days old, AND 7 days since the last answer (D2, the view's
    leaves_on), fresh checks, no hold, no answer in 72 h, plus the July gates. A NULL notice is a
    HOLD ('no_notice_yet'), never "floor satisfied" (MF3). DWELL is 7 days for every reason; the
    July 'unreachable' hold is gone (D2).
  - TWO CLOCKS, KEPT APART (MF7). Selection uses the view's clock; multi_probe's re-read and
    Q_FLIP's optimistic lock keep the raw last_alive_at, so a fresh verdict can't fake a race.
  - THE WRITER'S PROBE uses asset_liveness.select_probe_ports (the worker's set; it reaches the
    port-53-only nameservers) — defence in depth with the 72 h answer skip.
  - COMING BACK (MF5): a went_dark host with an answer in the last 24 h is brought back through
    asset_liveness.resurrect_if_dark (write mode; dry-run logs 'would_resurrect'). The liveness
    worker probes went_dark hosts so an answer can be seen.
  - STALE CHECKS (alternative 3): if the instance's newest verdict is older than 12 h, nothing is
    stamped, cleared, brought back or demoted this run.
  - HELD hosts (assets.dark_hold_reason, D7) are logged 'policy_hold' and never touched.
  - A REFUSAL IS AN ANSWER (Howie 2026-10-25 10:00: "a host with any port that answers is UP").
    The writer's own re-probe removes only on dns_gone or unreachable (REMOVABLE_REASONS); a
    refused re-probe (July's service_gone, Q5 below) is a hold, 'reprobe_refused_is_an_answer'.

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

# ── Constants. NOTICE_DAYS / DWELL_DAYS MUST match v_asset_reachability's leaves_on in
#    migration 20261026a (7 days, or a per-host dark_patience_override_days) — pinned by
#    test_demotion_writer.py::test_dwell_matches_sql_migration. (The July comment named a test,
#    test_flip_at_matches_sql_constants, that never existed; MF2.) ──
SHOW_THRESHOLD_HOURS = 72          # no answer for this long before the writer probes (= dark-event gate)
NOTICE_DAYS = 7                    # job 3t D2: 7 days, whatever the reason
DWELL_DAYS = {"dns_gone": NOTICE_DAYS, "service_gone": NOTICE_DAYS, "unreachable": NOTICE_DAYS}
# Job 3t: what the writer's own re-probe may remove on. A refusal (service_gone) is an answer.
REMOVABLE_REASONS = ("dns_gone", "unreachable")
VERDICT_FRESH_HOURS = 12           # job 3t: the instance's newest check must be this recent (= asset_liveness)
COME_BACK_HOURS = 24               # job 3t MF5: an answer this recent brings a went_dark host back
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
from asset_liveness import resurrect_if_dark, select_probe_ports  # noqa: E402  (job 3t)


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
    """July helper, kept for its callers: last_alive + the dwell for `reason`. Since job 3t every
    reason is NOTICE_DAYS, and the decision reads the view's leaves_on instead (flip_decision)."""
    d = override_days if override_days is not None else DWELL_DAYS.get(reason)
    if d is None:
        return None
    return last_alive + timedelta(days=d)


def flip_decision(*, notice_since: datetime | None, leaves_on: datetime | None,
                  first_observed: datetime | None, demoted_so_far: int,
                  at: datetime) -> str | None:
    """PURE (job 3t). After the probes agree the host is gone: why it is held, or None = flip.

    Order matters and every branch is a HOLD except the last:
      no_notice_yet   — the notice was never stamped. NULL never satisfies the floor (MF3): a host
                        nobody was warned about is never removed.
      within_dwell    — leaves_on (the view: greatest(notice, last answer) + 7 days, D2) not yet
                        reached. A missing leaves_on with a notice present is also a hold.
      not_eligible_7d — first_observed unknown or under MIN_LIVE_DAYS (July Q6; #369/#370 guard).
      rate_limited    — RATE_LIMIT flips already this run (July Q6).
    """
    if notice_since is None:
        return "no_notice_yet"
    if leaves_on is None or at < leaves_on:
        return "within_dwell"
    if first_observed is None or (at - first_observed).days < MIN_LIVE_DAYS:
        return "not_eligible_7d"
    if demoted_so_far >= RATE_LIMIT:
        return "rate_limited"
    return None


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
# Job 3t: candidates come from the view (its clock = the newest liveness answer, any route). The
# RAW assets.last_alive_at rides along for multi_probe's re-read and Q_FLIP's lock (MF7). The view's
# not_responding already means: owned, confirmed_live, not held, fresh checks, no answer for 24 h.
Q_CANDIDATES = """
SELECT a.asset_id, a.last_alive_at, a.first_observed, r.last_answer_at, r.notice_since, r.leaves_on
FROM public.assets a
JOIN public.v_asset_reachability r ON r.asset_id = a.asset_id
WHERE a.discovery_status = 'confirmed_live'
  AND r.not_responding
  AND (r.last_answer_at IS NULL OR r.last_answer_at < now() - %(show)s::interval)
ORDER BY r.last_answer_at ASC NULLS FIRST, a.asset_id
"""
Q_CHECKS_NEWEST = "SELECT max(probed_at) FROM public.asset_liveness_verdict"
# The notice (job 3t D2/D8): stamped on every host the view says is not responding, in BOTH modes
# (display state). Cleared when the host answered after its notice began, or was put on hold.
Q_STAMP_NOTICE = """
UPDATE public.assets a
   SET fade_detected_at = now()
  FROM public.v_asset_reachability r
 WHERE r.asset_id = a.asset_id
   AND r.not_responding
   AND a.fade_detected_at IS NULL
RETURNING a.asset_id
"""
Q_CLEAR_NOTICE = """
UPDATE public.assets a
   SET fade_detected_at = NULL
  FROM public.v_asset_reachability r
 WHERE r.asset_id = a.asset_id
   AND a.discovery_status = 'confirmed_live'
   AND a.fade_detected_at IS NOT NULL
   AND (a.dark_hold_reason IS NOT NULL
        OR (r.last_answer_at IS NOT NULL AND r.last_answer_at > a.fade_detected_at))
RETURNING a.asset_id
"""
Q_HELD_QUIET = """
SELECT r.asset_id, r.last_answer_at
  FROM public.v_asset_reachability r
 WHERE r.discovery_status = 'confirmed_live'
   AND r.held_reason IS NOT NULL
   AND (r.last_answer_at IS NULL OR r.last_answer_at < now() - interval '24 hours')
 ORDER BY r.asset_id
"""
Q_COME_BACK = """
SELECT r.asset_id, r.last_answer_at
  FROM public.v_asset_reachability r
 WHERE r.discovery_status = 'went_dark'
   AND r.last_answer_at > now() - %(win)s::interval
 ORDER BY r.asset_id
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
Q_AUDIT_BACK = """
INSERT INTO public.admin_audit_log (actor_user_id, action, target_user_id, target_email,
                                    before_state, after_state, details)
VALUES (NULL, 'auto_came_back', NULL, NULL,
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
    # Job 3t (Qwen code review minor 2) — what p2_demotion_dryrun.last_alive_at holds depends on
    # the row: for a candidate (hold_reason NULL/'WOULD', within_dwell, no_notice_yet,
    # reprobe_*, race_importer_won, rate_limited, not_eligible_7d) it is the RAW scan clock
    # assets.last_alive_at (MF7); for 'policy_hold', 'came_back' and 'would_resurrect' it is the
    # view's last_answer_at (the newest liveness answer). Read it per hold_reason for D9.
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


def checks_are_fresh(newest, at=None) -> bool:
    """PURE (job 3t): the instance's newest liveness verdict is under VERDICT_FRESH_HOURS old."""
    if newest is None:
        return False
    at = at or now()
    if getattr(newest, "tzinfo", None) is None:
        newest = newest.replace(tzinfo=UTC)
    return (at - newest) <= timedelta(hours=VERDICT_FRESH_HOURS)


def notices_and_come_backs(conn, run_tag: str, write_enabled: bool, gate_state: dict) -> dict:
    """Job 3t: stamp / clear the notice (both modes), log the held hosts, and bring back a
    went_dark host that answered in the last COME_BACK_HOURS (write mode; dry-run logs it).
    Called only when the checks are fresh."""
    with conn.cursor() as cur:
        cur.execute(Q_STAMP_NOTICE)
        stamped = [r[0] for r in cur.fetchall()]
        cur.execute(Q_CLEAR_NOTICE)
        cleared = [r[0] for r in cur.fetchall()]
        cur.execute(Q_HELD_QUIET)
        held = cur.fetchall()
        cur.execute(Q_COME_BACK, {"win": f"{COME_BACK_HOURS} hours"})
        back = cur.fetchall()
    conn.commit()
    for asset_id, last_answer in held:
        log_dryrun(conn, run_tag, True, asset_id, "confirmed_live", last_answer, None, None,
                   None, False, "policy_hold", gate_state, write_enabled)
    came_back = 0
    for asset_id, last_answer in back:
        if write_enabled:
            with conn.cursor() as cur:
                n = resurrect_if_dark(cur, asset_id, logfn=print)
                if n is not None:
                    cur.execute(Q_AUDIT_BACK, {
                        "before": Json({"discovery_status": "went_dark"}),
                        "after": Json({"discovery_status": "confirmed_live"}),
                        "details": Json({"asset_id": asset_id, "rule": "demotion_writer_3t",
                                         "last_answer_at": last_answer.isoformat() if last_answer else None,
                                         "resurrection_count": n}),
                    })
                    came_back += 1
        log_dryrun(conn, run_tag, True, asset_id, "went_dark", last_answer, None, None, None,
                   False, "came_back" if write_enabled else "would_resurrect", gate_state, write_enabled)
    conn.commit()
    print(f"  notice: stamped {len(stamped)} {stamped}; cleared {len(cleared)} {cleared}; "
          f"held {len(held)}; back {len(back)}{'' if write_enabled else ' (dry-run)'}")
    return {"stamped": stamped, "cleared": cleared, "held": len(held), "back": len(back),
            "came_back": came_back}


def run(conn, write_enabled: bool, run_tag: str) -> int:
    gate = sweep_health(conn)
    with conn.cursor() as cur:
        cur.execute(Q_CHECKS_NEWEST)
        newest = cur.fetchone()[0]
    fresh = checks_are_fresh(newest)
    gate["state"]["checks_newest"] = newest.isoformat() if newest else None
    gate["state"]["checks_fresh"] = fresh
    # Per-run gate marker row. Record THIS sweep's coverage_ok (not the final gate
    # decision) so the next run's consecutive-healthy check has a real prior to read —
    # recording gate["ok"] here would deadlock the gate (it can never bootstrap).
    log_dryrun(conn, run_tag, gate["coverage_ok"], SWEEP_MARKER, None, None, None, None,
               None, False, gate["reason"] if fresh else "checks_stale", gate["state"], write_enabled)
    conn.commit()
    if not fresh:
        # Job 3t (alternative 3): the liveness worker stopped or is behind. Stamp nothing, clear
        # nothing, bring nothing back, demote nothing — and say so (note 161:90's precedent).
        print(f"::warning::demotion_writer: newest liveness check is {newest} — older than "
              f"{VERDICT_FRESH_HOURS} h; doing nothing this run")
        return 0
    notices_and_come_backs(conn, run_tag, write_enabled, gate["state"])
    if not gate["ok"]:
        print(f"  sweep gate: {gate['reason']} {gate['state']} — demoting nothing")
        return 0

    with conn.cursor() as cur:
        cur.execute(Q_CANDIDATES, {"show": f"{SHOW_THRESHOLD_HOURS} hours"})
        cands = cur.fetchall()
    print(f"  sweep healthy ({gate['state']}); {len(cands)} fade candidate(s)")

    demoted = 0
    for asset_id, last_alive, first_observed, last_answer, notice_since, leaves_on in cands:
        # The worker's port set (job 3t): reaches the port-53-only nameservers.
        ports = select_probe_ports(asset_id, known_ports(conn, asset_id))
        # MF7: the RAW scan clock for the race re-read, never the view's answer clock.
        probe = multi_probe(conn, asset_id, last_alive, ports)
        days_rem = max(0, (leaves_on - now()).days) if leaves_on else None

        def emit(reason, would, hold):
            log_dryrun(conn, run_tag, True, asset_id, "confirmed_live", last_alive,
                       reason, days_rem, leaves_on, would, hold, gate["state"], write_enabled)
            conn.commit()

        if probe["decision"] == "alive":
            if write_enabled:
                with conn.cursor() as cur:
                    cur.execute(Q_BUMP_ALIVE, {"a": asset_id})
            emit(None, False, "reprobe_alive")
            continue
        if probe["decision"] == "mixed":
            emit(None, False, "reprobe_mixed_reason")
            continue

        reason = probe["reason"]
        if reason not in REMOVABLE_REASONS:
            # Job 3t: Howie 2026-10-25 10:00, "a host with any port that answers is UP". A refused
            # connection is an answer: the view never flags one, so the writer never removes one
            # (July's service_gone, "host up, service gone", is a hold now, not a removal).
            emit(reason, False, "reprobe_refused_is_an_answer")
            continue
        if write_enabled:
            with conn.cursor() as cur:
                cur.execute(Q_SET_FADE, {"a": asset_id, "reason": reason})

        hold = flip_decision(notice_since=notice_since, leaves_on=leaves_on,
                             first_observed=first_observed, demoted_so_far=demoted, at=now())
        if hold is not None:
            emit(reason, False, hold)
            continue

        # ── would demote ──
        if write_enabled:
            with conn.cursor() as cur:
                cur.execute(Q_FLIP, {"a": asset_id, "reason": reason, "eval": last_alive})
                n = cur.rowcount
            if n == 0:  # a scan bumped last_alive_at during the probe window — it won
                emit(reason, True, "race_importer_won")
                continue
            ambiguous = probe.get("note", "").startswith("mixed")
            with conn.cursor() as cur:
                cur.execute(Q_AUDIT, {
                    "before": Json({"discovery_status": "confirmed_live"}),
                    "after": Json({"discovery_status": "went_dark"}),
                    "details": Json({
                        "asset_id": asset_id, "dark_reason": reason,
                        "last_alive_at": last_alive.isoformat() if last_alive else None,
                        "last_answer_at": last_answer.isoformat() if last_answer else None,
                        "notice_since": notice_since.isoformat() if notice_since else None,
                        "rule": "demotion_writer_3t", "ambiguous_reason": ambiguous,
                    }),
                })
        emit(reason, True, None)
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
    mode = "WRITE-ENABLED" if args.write_enable else "dry-run (notice stamps only; no flips)"
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
              f"apply migrations 20260712a_asset_dark_debounce_p2.sql and 20261026a_reachability.sql. "
              f"No-op this run.",
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
