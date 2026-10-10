#!/usr/bin/env python3
"""asset_liveness_probe.py — per-sweep liveness probe worker (Obsidian 161 step 2, 4.7 Q2/Q4/Q7).

Probes EVERY confirmed_live asset once per sweep and writes ONE public.asset_liveness_verdict row
per asset — the shared verdict later read by the dark-digest suppression AND the went_dark demotion
writer (via asset_liveness.get_fresh_verdict). PURE observation: writes only to
asset_liveness_verdict, NEVER mutates asset state. Runs as a step in asm-discover.yml BEFORE
demotion_writer, every 6h (4.7 Q4 cadence). Verdict-writing is LIVE from ship (that's how data
accumulates); the DRY-RUN in this program (--dry-run) only skips the write for a manual first look —
the consumer-side dry-run (digest logs-not-acts) is a separate, later push.

Ports (4.7 Q2): asset_surface known-open ∪ asset-type fallback ∪ safe defaults, via
asset_liveness.select_probe_ports. Verdict booleans (4.7 Q3): asset_liveness.verdict_booleans
(any_port_responded = open OR refused; any_port_open = open only). Probe primitives reused from
demotion_writer (resolve_host / probe_port / known_ports) so probe behaviour is identical fleet-wide.

Sweep-health (4.7 Q7 fail-safe): if a non-trivial fleet comes back almost entirely non-responding,
that's OUR egress breaking, not the fleet dying — abort the sweep and write NOTHING rather than
stamp a fleet of false-dead verdicts. A resolver hiccup on a single asset skips that asset (no row)
rather than recording a wrong verdict.

Env: SUPABASE_DSN or --dsn. psycopg3.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print("error: psycopg (psycopg3) required. pip install --user --break-system-packages 'psycopg[binary]'",
          file=sys.stderr)
    raise

from asset_liveness import select_probe_ports, verdict_booleans
from demotion_writer import resolve_host, probe_port, known_ports

UTC = timezone.utc

MAX_WORKERS = 24                 # bounded concurrency (4.7 Q7 pacing — light TCP connects, not scans)
SWEEP_RESPONDED_FLOOR = 0.10     # <10% of a non-trivial fleet responding => egress broken => abort
MIN_FLEET_FOR_FLOOR = 10         # below this, no floor (a tiny fleet legitimately can be mostly quiet)

Q_CONFIRMED_LIVE = "SELECT asset_id FROM public.assets WHERE discovery_status = 'confirmed_live'"
Q_UPSERT_VERDICT = """
INSERT INTO public.asset_liveness_verdict
  (asset_id, sweep_id, probed_at, any_port_responded, any_port_open, per_port_results, probe_source)
VALUES (%(asset_id)s, %(sweep_id)s, now(), %(responded)s, %(open)s, %(ppr)s, %(src)s)
ON CONFLICT (asset_id, sweep_id) DO UPDATE SET
  probed_at          = EXCLUDED.probed_at,
  any_port_responded = EXCLUDED.any_port_responded,
  any_port_open      = EXCLUDED.any_port_open,
  per_port_results   = EXCLUDED.per_port_results,
  probe_source       = EXCLUDED.probe_source
"""


def log(m: str) -> None:
    print(f"[liveness_probe] {m}", flush=True)


# ── PURE cores (unit-tested; probe primitives patched in tests) ─────────────────────────────────
def probe_asset(asset_id: str, ports: list[int]) -> dict | None:
    """Probe one asset (PURE network — no DB, thread-safe). Returns the verdict dict, or None to
    SKIP this asset (resolver hiccup: don't record a wrong verdict). asset_id doubles as the host
    (resolvable), matching demotion_writer.single_probe."""
    ip, status = resolve_host(asset_id)
    if status == "nxdomain":
        # DNS truly gone => nothing answered => not responded (a genuinely-dark asset stays dark).
        return {"any_port_responded": False, "any_port_open": False,
                "per_port_results": {"_dns": "nxdomain"}}
    if status != "ok" or not ip:
        return None                                    # EAI_AGAIN etc. — resolver hiccup, skip
    per: dict = {}
    for p in ports:
        per[str(p)] = {"result": probe_port(ip, p)}
    results = [per[str(p)]["result"] for p in ports]
    responded, is_open = verdict_booleans(results)
    return {"any_port_responded": responded, "any_port_open": is_open, "per_port_results": per}


def sweep_ok(verdicts: list, fleet_size: int) -> tuple[bool, str]:
    """Egress fail-safe (4.7 Q7). A non-trivial fleet coming back almost entirely non-responding
    is our egress, not the fleet — abort. Small fleets get no floor (they can legitimately be
    mostly quiet). None verdicts (skipped) don't count as responded."""
    if fleet_size < MIN_FLEET_FOR_FLOOR:
        return True, f"small_fleet({fleet_size})_no_floor"
    responded = sum(1 for v in verdicts if v and v.get("any_port_responded"))
    frac = responded / fleet_size if fleet_size else 0.0
    if frac < SWEEP_RESPONDED_FLOOR:
        return False, (f"only {responded}/{fleet_size} responded ({frac:.0%}) < floor "
                       f"{SWEEP_RESPONDED_FLOOR:.0%} — likely egress outage, not the fleet")
    return True, f"{responded}/{fleet_size} responded ({frac:.0%})"


# ── DB glue ─────────────────────────────────────────────────────────────────────────────────────
def confirmed_live_targets(conn) -> list[tuple[str, list[int]]]:
    """(asset_id, probe_ports) for every confirmed_live asset. Ports = known-open (asset_surface)
    ∪ asset-type fallback ∪ safe defaults."""
    with conn.cursor() as cur:
        cur.execute(Q_CONFIRMED_LIVE)
        asset_ids = [r[0] for r in cur.fetchall()]
    targets = []
    for a in asset_ids:
        ko = known_ports(conn, a)                      # reuse demotion_writer (surface services -> ports)
        targets.append((a, select_probe_ports(a, ko)))
    return targets


def write_verdict(conn, asset_id: str, sweep_id: str, v: dict, source: str) -> None:
    with conn.cursor() as cur:
        cur.execute(Q_UPSERT_VERDICT, {
            "asset_id": asset_id, "sweep_id": sweep_id,
            "responded": bool(v["any_port_responded"]), "open": bool(v["any_port_open"]),
            "ppr": Json(v["per_port_results"]), "src": source,
        })


def run(conn, dry_run: bool, sweep_id: str, source: str) -> int:
    targets = confirmed_live_targets(conn)
    fleet = len(targets)
    log(f"sweep {sweep_id[:8]} — {fleet} confirmed_live asset(s); dry_run={dry_run}")
    if not targets:
        log("no confirmed_live assets — nothing to probe")
        return 0

    results: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(probe_asset, a, ports): a for a, ports in targets}
        for f in as_completed(futs):
            a = futs[f]
            try:
                results[a] = f.result()
            except Exception as e:                     # a single probe blowing up must not kill the sweep
                log(f"  probe error {a}: {e!r} — skipping")
                results[a] = None

    ok, reason = sweep_ok(list(results.values()), fleet)
    log(f"sweep-health: {reason}")
    if not ok:
        log("ABORT (fail-safe): writing NO verdicts this sweep")
        return 0

    responded = sum(1 for v in results.values() if v and v.get("any_port_responded"))
    open_svc = sum(1 for v in results.values() if v and v.get("any_port_open"))
    skipped = sum(1 for v in results.values() if v is None)
    log(f"verdicts: responded={responded} open={open_svc} skipped(resolver)={skipped}")

    written = 0
    for a, v in results.items():
        if v is None:
            continue
        if dry_run:
            log(f"  DRY-RUN {a}: responded={v['any_port_responded']} open={v['any_port_open']} "
                f"ports={list(v['per_port_results'])}")
        else:
            write_verdict(conn, a, sweep_id, v, source)
        written += 1
    if not dry_run:
        conn.commit()
    log(f"{'would-write' if dry_run else 'wrote'} {written} verdict(s)")
    return written


# ── VPN RE-CHECK of the hosts the direct sweep could not reach (note 307, 2026-10-10) ───────────
#
# ⛔ WHY. The 6-hourly sweep runs from GitHub's servers. Three of Command's hosts —
# ftp.unimacgraphics.com, pm.unimacgraphics.com, ftp.commandmi.com — sit behind a firewall that
# turns most of those addresses away: from 2026-07-20 to 2026-10-10 they answered about 1 sweep in
# 5, all three at the same sweep, while the deep scanner reached them every time through the VPN.
# The dark alarm called them dark every week. Howie chose (2026-10-10) to check them the way the
# deep scanner reaches them: through the VPN.
#
# ⇒ HOW. scanner.yml runs this mode right after any scan that brought the tunnel up, BEFORE the
#   tunnel is torn down — so it rides a tunnel and a VPN slot that already exist (no new slot
#   claim; the pools are small — Command has one slot, Prodex two). It re-probes only the confirmed_live hosts whose
#   LATEST verdict, from any route, did not answer, and writes one verdict each under its own
#   sweep_id with probe_source 'liveness_vpn'. The dark gate counts an answer from either route
#   (asset_liveness.get_dark_gate_verdict).
#
# ⚠ THE ROUTE IS PROVED BEFORE ANYTHING IS PROBED (independent review, 2026-10-10). A medium scan
#   can rotate its exit mid-run; vpn_rotate.sh tears the old tunnel down BEFORE bringing the new
#   one up, so a failed rotation leaves the job on the runner's own address while the bring-up
#   step still reads 'success'. Probing from there is exactly the route the firewall turns away,
#   and the result would be written as a VPN check. So, first: the job's egress address, asked of
#   the same three echo services vpn_bringup.sh uses, must differ from the pre-VPN baseline the
#   bring-up recorded. Unknown on either side => refuse. AND, without asking anyone outside: the
#   kernel's route for a public address must leave by a device other than the runner's original
#   default device (independent re-review: the runner's public address seen by an echo service is
#   not guaranteed to stay the same for 90 minutes; the local routing table is the direct fact).
#
# ⚠ AND THE TUNNEL IS PROVED TO CARRY TRAFFIC. Up to RECHECK_CONTROLS hosts that DID answer their
#   latest check are probed through it. If none answer, the tunnel (not the fleet) is broken:
#   write NOTHING. A broken tunnel's silence written as 'liveness_vpn' verdicts would read as
#   "the VPN route also failed" — a second, false witness against a live host.
#
# ⚠ SAME PROBE, SAME TARGET SET. TCP connects to the same ports the direct sweep uses, on the same
#   confirmed_live set. The route changes; nothing about what is sent does (D-056).
RECHECK_CONTROLS = 3             # hosts that answered last time, probed first to prove the tunnel
RECHECK_MAX = 25                 # bound the step; more quiet hosts than this means something else broke

# Third column: the host's most recent ANSWER from any route (NULL if it never answered). It orders
# the quiet list so the cap drops long-dead hosts, never the intermittent ones this exists for.
# Aggregated ONCE per asset in its own CTE (independent re-review: a correlated subquery here ran
# per verdict row, before DISTINCT ON — 8s at a year of history and growing with its square).
Q_LATEST_VERDICT_PER_LIVE_ASSET = """
WITH answered AS (
  SELECT asset_id, max(probed_at) AS last_answered_at
    FROM public.asset_liveness_verdict
   WHERE any_port_responded
   GROUP BY asset_id
)
SELECT DISTINCT ON (v.asset_id) v.asset_id, v.any_port_responded, an.last_answered_at
  FROM public.asset_liveness_verdict v
  JOIN public.assets a ON a.asset_id = v.asset_id
  LEFT JOIN answered an ON an.asset_id = v.asset_id
 WHERE a.discovery_status = 'confirmed_live'
 ORDER BY v.asset_id, v.probed_at DESC
"""


def split_recheck_targets(latest: list[tuple], max_targets: int = RECHECK_MAX,
                          n_controls: int = RECHECK_CONTROLS) -> tuple[list[str], list[str], int]:
    """PURE. From (asset_id, latest_answered[, last_answered_at]) rows: (quiet hosts to re-check,
    control hosts that answered, how many quiet hosts were dropped by the cap).

    ⚠ ORDER IS THE CAP'S POLICY (independent review, 2026-10-10). Quiet hosts are taken most-
    recently-answered first, never-answered last, then by name. Alphabetical alone let 25 long-
    dead hosts that sort early (the demotion writer is still dry-run, so dead hosts stay
    confirmed_live) push pm.unimacgraphics.com out of the re-check for good."""
    def last(r):
        return r[2] if len(r) > 2 else None
    quiet_rows = [r for r in latest if not r[1]]
    answered_ever = sorted((r for r in quiet_rows if last(r) is not None),
                           key=lambda r: (-last(r).timestamp(), r[0]))
    never = sorted((r for r in quiet_rows if last(r) is None), key=lambda r: r[0])
    quiet = [r[0] for r in answered_ever + never]
    controls = sorted(r[0] for r in latest if r[1])[:n_controls]
    dropped = max(0, len(quiet) - max_targets)
    return quiet[:max_targets], controls, dropped


# ── Route proof: the job's egress must not be the runner's own address ─────────────────────────
EGRESS_ECHO = ("https://api.ipify.org", "https://ifconfig.me", "https://icanhazip.com")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def current_egress_ip(fetch=None) -> str:
    """The address this job's traffic leaves from, asked of the same echo services the bring-up
    uses. '' if none answer with an IPv4."""
    def _get(url):
        with urllib.request.urlopen(url, timeout=8) as r:   # noqa: S310 — fixed https URLs
            return r.read(64).decode("ascii", "replace")
    fetch = fetch or _get
    for url in EGRESS_ECHO:
        try:
            ip = fetch(url).strip().splitlines()[0].strip()
        except Exception:                                   # noqa: BLE001 — try the next one
            continue
        if _IPV4.match(ip):
            return ip
    return ""


def _ip_dev(args: list[str], run=None) -> str:
    """The `dev` named by an `ip` command's first output line, or '' if it can't be read."""
    run = run or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=5).stdout)
    try:
        toks = run(["ip", *args]).splitlines()[0].split()
    except Exception:                                       # noqa: BLE001 — unreadable = unknown
        return ""
    return toks[toks.index("dev") + 1] if "dev" in toks and toks.index("dev") + 1 < len(toks) else ""


def route_device_ok(run=None) -> tuple[bool, str]:
    """Local fact, no outside service: the route to a public address must NOT leave by the
    runner's original default device (the one the carve-out step reads the same way)."""
    orig = _ip_dev(["route", "show", "default", "table", "main"], run)
    now = _ip_dev(["route", "get", "1.1.1.1"], run)
    if not orig or not now:
        return False, "could not read the routing table — refusing"
    if now == orig:
        return False, f"public traffic leaves by {now}, the runner's own device — no tunnel — refusing"
    return True, f"public traffic leaves by {now}, not the runner's own {orig}"


def route_ok(baseline_ip: str, egress_ip: str) -> tuple[bool, str]:
    """PURE. The route is tunnelled iff both addresses are known and they differ."""
    if not baseline_ip:
        return False, "no pre-VPN baseline address to compare with — refusing"
    if not egress_ip:
        return False, "could not read this job's egress address — refusing"
    if egress_ip == baseline_ip:
        return False, (f"egress {egress_ip} IS the runner's own address — the tunnel is gone "
                       f"(failed rotation?) — refusing")
    return True, f"egress {egress_ip} differs from the runner's own {baseline_ip}"


def tunnel_ok(control_verdicts: list) -> tuple[bool, str]:
    """PURE. The tunnel is proved iff at least one control host answered through it. No controls
    at all (every live host was quiet last time) cannot prove anything either way — refuse."""
    if not control_verdicts:
        return False, "no control hosts to prove the tunnel with — refusing to write"
    answered = sum(1 for v in control_verdicts if v and v.get("any_port_responded"))
    if answered == 0:
        return False, (f"0/{len(control_verdicts)} control hosts answered through the tunnel — "
                       f"tunnel broken, not the fleet")
    return True, f"{answered}/{len(control_verdicts)} control hosts answered through the tunnel"


def _probe_many(targets: list[tuple[str, list[int]]]) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(probe_asset, a, ports): a for a, ports in targets}
        for f in as_completed(futs):
            a = futs[f]
            try:
                out[a] = f.result()
            except Exception as e:                     # one probe blowing up must not kill the step
                log(f"  probe error {a}: {e!r} — skipping")
                out[a] = None
    return out


def run_recheck(conn, dry_run: bool, sweep_id: str, source: str, baseline_ip: str = "",
                egress_ip=None, route_run=None) -> int:
    ok_dev, why_dev = route_device_ok(route_run)
    log(f"route check (device): {why_dev}")
    ok, reason = route_ok(baseline_ip, current_egress_ip() if egress_ip is None else egress_ip)
    log(f"route check (egress): {reason}")
    if not (ok_dev and ok):
        log("::warning::liveness re-check ABORTED — not proved to be inside the tunnel; "
            "nothing probed, nothing written")
        return 0
    with conn.cursor() as cur:
        cur.execute(Q_LATEST_VERDICT_PER_LIVE_ASSET)
        latest = [(r[0], bool(r[1]), r[2]) for r in cur.fetchall()]
    quiet, controls, dropped = split_recheck_targets(latest)
    log(f"re-check {sweep_id[:8]} via {source}: {len(quiet)} quiet host(s), "
        f"{len(controls)} control(s); dry_run={dry_run}")
    if dropped:
        log(f"::warning::{dropped} more quiet host(s) than the cap ({RECHECK_MAX}) — not re-checked")
    if not quiet:
        log("every confirmed_live host answered its latest check — nothing to re-check")
        return 0

    ok, reason = tunnel_ok(list(_probe_many(
        [(a, select_probe_ports(a, known_ports(conn, a))) for a in controls]).values()))
    log(f"tunnel check: {reason}")
    if not ok:
        log("::warning::liveness re-check ABORTED — writing NO verdicts (tunnel not proved)")
        return 0

    # Each verdict is written and COMMITTED as its probe finishes (independent re-review): the step
    # has a hard 2-minute limit, and a timeout must not throw away the hosts already re-checked —
    # quiet hosts are probed most-recently-answered first, so the ones this exists for land first.
    targets = [(a, select_probe_ports(a, known_ports(conn, a))) for a in quiet]
    written = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(probe_asset, a, ports): a for a, ports in targets}
        for f in as_completed(futs):
            a = futs[f]
            try:
                v = f.result()
            except Exception as e:                     # one probe blowing up must not kill the step
                log(f"  probe error {a}: {e!r} — skipping")
                continue
            if v is None:
                continue
            log(f"  {a}: answered={v['any_port_responded']} open={v['any_port_open']}")
            if not dry_run:
                write_verdict(conn, a, sweep_id, v, source)
                conn.commit()
            written += 1
    log(f"{'would-write' if dry_run else 'wrote'} {written} re-check verdict(s)")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-sweep liveness probe worker (Obsidian 161).")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--dry-run", action="store_true", help="probe + log, write NO verdicts")
    ap.add_argument("--run-tag", default="", help="correlation tag (e.g. GITHUB_RUN_ID); informational")
    ap.add_argument("--recheck-unresponsive", action="store_true",
                    help="re-probe only hosts whose latest verdict did not answer (run inside the "
                         "VPN tunnel; see note 307)")
    ap.add_argument("--baseline-ip", default=os.environ.get("VPN_BASELINE_IP", ""),
                    help="the runner's pre-VPN address (vpn_bringup.sh output vpn_baseline_ip); "
                         "the re-check refuses unless the job's egress differs from it")
    ap.add_argument("--source", default=None,
                    help="probe_source label (default liveness_sweep, or liveness_vpn with "
                         "--recheck-unresponsive)")
    args = ap.parse_args()
    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 2
    source = args.source or ("liveness_vpn" if args.recheck_unresponsive else "liveness_sweep")
    sweep_id = str(uuid.uuid4())
    if args.run_tag:
        log(f"run-tag={args.run_tag}")
    with psycopg.connect(args.dsn, autocommit=False, connect_timeout=15) as conn:
        if args.recheck_unresponsive:
            run_recheck(conn, dry_run=args.dry_run, sweep_id=sweep_id, source=source,
                        baseline_ip=args.baseline_ip)
        else:
            run(conn, dry_run=args.dry_run, sweep_id=sweep_id, source=source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
