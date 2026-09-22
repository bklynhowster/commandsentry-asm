"""relay 444 — FRESH EGRESS PER FIRE, so a fleet fwbbot sweep can't poison itself.

⛔ THE DEFECT THIS CLOSES (relay 435). The active-probe egress is PINNED: every
active_probe_audit row back to 2026-09-06 carries the same 87.249.134.7, because
vpn_bringup.sh falls back to the FIRST /etc/wireguard/*.conf when VPN_REGION is
unset and heavy never rotates. FortiWeb's ban is temporary but real, so a
back-to-back sweep of the 14 Fortinet hosts through ONE exit reads:

    host #1  -> ban lands on the exit      -> enforcement_corroborated = TRUE
    host #2..14 -> exit already banned     -> reachable_earlier = FALSE
                                           -> enforcement_corroborated = FALSE

Twelve hosts would confirm NOTHING, and the corroboration gate is right to
refuse — but the sweep would have burned 90 minutes of heavy scans to learn one
fact. Worse, "claims nothing" is visually close to "not enforcing", which is the
exact false negative 405/430 exist to stop.

⭐ ORCHESTRATION, NOT MID-RUN ROTATION — and the reason is the corroboration
itself. run_heavy captures the egress ONCE per run (ctx.egress_ip_initial), and
network_reset is corroborated by SAME-RUN reachability (relay 430:
passive_stack_answered). Rotating mid-run would measure reachability on one exit
and fire the probe from another, so `reachable_earlier` would describe a
different vantage than the reset — silently inverting the one gate that makes a
ban readable. One host per run, one fresh tunnel per run, keeps
egress_ip_initial truthful and the corroboration honest. 4.7 leaned this way in
444; this is the same conclusion reached from the corroboration side.

⚠ PURE. No I/O, no DB, no subprocess. This module PLANS; the plan is executed by
an operator dispatch that brings up the chosen region (vpn_rotate.sh already
does the tunnel work) and fires ONE host. Nothing here can send a packet.

⛔ WHAT THIS MODULE DELIBERATELY DOES NOT DO: decide to fire. The two gates are
untouched — per-asset assets.active_probe_authorized (opt-in AND kill switch)
and ACTIVE_PROBE_LIVE (dry-run default). A plan is a description; arming and
firing stay Howie's.
"""
from __future__ import annotations

# FortiGate/FortiWeb bans are temporary. run_medium already encodes the patient
# tier's wait as PATIENT_BAN_COOLDOWN_S = 1800; an exit is treated as burned for
# at least that long, which is the conservative direction — waiting longer than
# necessary costs time, reusing too early costs a false negative.
DEFAULT_BURN_COOLDOWN_S = 1800

# The classifier outcome that means "this exit got cut off" (relay 430).
NETWORK_RESET = "network_reset"


def resolve_cooldown_s(env=None, default=DEFAULT_BURN_COOLDOWN_S):
    """The ONE cooldown, resolved from the same env var run_medium reads.

    ⛔ (relay 446 nit) run_medium's PATIENT_BAN_COOLDOWN_S is env-OVERRIDABLE
    (L448: `int(os.environ.get("PATIENT_BAN_COOLDOWN_S") or "1800")`). If this
    module kept a hard 1800 while an operator raised that, the burned-window and
    the rotation-wait would silently disagree: the sweep would consider an exit
    clean while the scanner was still waiting out its ban. One source, resolved
    once, passed through.

    ⚠ Takes a MAPPING rather than reading os.environ, so this stays pure and the
    module keeps its no-I/O property (pinned by AST in the test). The I/O layer
    passes os.environ in.

    Mirrors run_medium's guarded parse exactly — `or default` catches the
    set-but-EMPTY case, which is the trap relay 202 swept fleet-wide.
    """
    raw = (env or {}).get("PATIENT_BAN_COOLDOWN_S")
    try:
        return int(raw or default)
    except (TypeError, ValueError):
        # A malformed override must not silently become 0 (every exit clean) —
        # fall back to the conservative default.
        return default


class SweepPlanError(ValueError):
    """The sweep cannot be planned safely. Raised rather than degraded.

    ⛔ REFUSING IS THE FEATURE. The failure mode this module exists to prevent is
    a sweep that LOOKS like it ran and silently produced false negatives. A plan
    that cannot give every host its own clean exit must not quietly fall back to
    reusing one — that IS the bug.
    """


def burned_egress_ips(audit_rows, *, now_epoch, cooldown_s=DEFAULT_BURN_COOLDOWN_S):
    """Which egress IPs are known-burned right now? PURE.

    ⭐ THE LEDGER ALREADY EXISTS — no new state. active_probe_audit records
    egress_ip per evaluation, and relay 430 made a cut-off readable as
    details.result == "network_reset". An exit that produced a reset within the
    cooldown is burned: the edge stopped answering it, and pointing the next
    host at it would measure the ban, not the host.

    `audit_rows`: dicts with egress_ip, created_at_epoch, and details.result.
    Rows missing any of those are ignored — a row we cannot read is not evidence
    that an exit is clean, but it is also not evidence that it is burned, and
    guessing either way is worse than skipping it.
    """
    burned = set()
    for row in audit_rows or []:
        if not isinstance(row, dict):
            continue
        ip = row.get("egress_ip")
        ts = row.get("created_at_epoch")
        if not ip or ts is None:
            continue
        details = row.get("details") or {}
        if not isinstance(details, dict):
            continue
        if details.get("result") != NETWORK_RESET:
            continue
        try:
            age = float(now_epoch) - float(ts)
        except (TypeError, ValueError):
            continue
        # ⚠ A FUTURE timestamp (negative age, i.e. clock skew) is already
        # covered: it is trivially < cooldown_s, so it burns. This was written
        # as a separate `if age < 0` branch, which a mutation proved to be
        # EQUIVALENT — removing it changed nothing, because the comparison below
        # already handles it. Dead defensive code reads as a guard and isn't
        # one; the comment carries the intent instead.
        if age < cooldown_s:
            burned.add(ip)
    return burned


def plan_sweep(hosts, regions, *, region_to_ip=None, burned_ips=frozenset()):
    """Assign each host its OWN fresh exit. PURE. Returns [{host, region}].

    Contract (relay 444):
      (1) every host gets a DISTINCT region — no exit is reused within a sweep;
      (4) a burned exit is excluded from the pool, never reassigned.

    ⛔ REFUSES rather than degrades when the clean pool is smaller than the host
    list. Silently truncating, or wrapping around and reusing an exit, would
    reproduce exactly the self-contamination this module exists to prevent —
    and it would do so invisibly, which is worse than not running.

    `region_to_ip` maps a region name to its known egress IP so a region whose
    IP is burned can be excluded. A region with no known IP is treated as
    USABLE: we have no evidence it is burned, and the live pre-fire check
    (contract 2, an I/O step outside this module) is the backstop.

    Deterministic: hosts keep their given order, regions are consumed in sorted
    order, so the same inputs always produce the same plan and a dry-run preview
    matches what the operator will actually run.
    """
    hosts = [h for h in (hosts or []) if h]
    if not hosts:
        raise SweepPlanError("no hosts to sweep")

    region_to_ip = region_to_ip or {}
    # ONE filter, not two. This was written as two passes that both excluded
    # burned regions — the second was dead, and a mutation neutering it survived
    # every test, which is how dead logic hides. A region whose IP is UNKNOWN
    # stays in (no evidence it is burned); one whose known IP is burned is out.
    def _usable(r):
        ip = region_to_ip.get(r)
        return ip is None or ip not in burned_ips

    clean = [r for r in sorted(set(regions or [])) if _usable(r)]

    if len(clean) < len(hosts):
        raise SweepPlanError(
            f"pool too small: {len(hosts)} host(s) need {len(hosts)} distinct clean "
            f"exits, only {len(clean)} available "
            f"({len(set(regions or []))} configured, "
            f"{len(set(regions or [])) - len(clean)} burned). "
            f"Add Mullvad configs or wait out the {DEFAULT_BURN_COOLDOWN_S}s cooldown — "
            f"reusing an exit would produce false negatives on the reused hosts.")

    # zip is safe precisely BECAUSE of the refusal above: len(clean) >= len(hosts)
    # is guaranteed here, so zip consumes a distinct region per host and cannot
    # truncate. (A modulo/wrap form is an equivalent mutant for the same reason —
    # it can only differ when the pool is short, which is exactly what we refuse.)
    return [{"host": h, "region": r} for h, r in zip(hosts, clean)]


def build_sweep_preview(hosts, regions, *, region_to_ip=None, burned_ips=frozenset()):
    """The DRY-RUN description an operator reads BEFORE arming anything.

    ⛔ Returns a description, never a request — the same shape relay 382 used for
    the enforcement sweep. `fired` is hard-coded False because nothing in this
    module can fire; it is present so a reader never has to infer it.
    """
    plan = plan_sweep(hosts, regions,
                      region_to_ip=region_to_ip, burned_ips=burned_ips)
    return {
        "dry_run": True,
        "fired": False,
        "one_host_per_run": True,      # ⭐ see the module docstring: why not mid-run
        "count": len(plan),
        "burned_excluded": sorted(burned_ips),
        "plan": plan,
    }
