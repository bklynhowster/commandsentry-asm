"""relay 446 — THE PRE-FIRE CHECK. Step 2 of 2; a sweep must not fire without it.

⛔ WHY 445 ALONE IS NOT ENOUGH (4.7's ruling). egress_pool.plan_sweep treats a
region with an UNKNOWN IP as usable — correctly, since absence of evidence is
not evidence of a burn. That makes the PLAN optimistic by design, and the live
check is the backstop that keeps it honest. Contract (2) of relay 444 —
"verified live AND not-already-banned BEFORE the fire" — lives here.

⭐ THE 435 PIN HAS A SIGNATURE, AND THIS IS WHAT CATCHES IT. vpn_bringup.sh
falls back to the FIRST /etc/wireguard/*.conf when VPN_REGION is unset or its
conf is missing. That fallback is SILENT: the sweep would believe it rotated
while every host went out the same exit — exactly the state relay 435 measured
(87.249.134.7 on every row for weeks). The tell is not an error code; it is that
the actual egress IP is the SAME ONE the previous host already used. So
`used_ips` is not bookkeeping, it is the detector for the original defect.

⚠ SPLIT ON PURPOSE: `verify_egress` is PURE and holds every refusal decision;
`observe_and_verify` is the thin I/O shell that gathers the facts and delegates.
Same shape as _classify_fwbbot_response (pure) + _fire_fwbbot_check_probe
(shell) in run_heavy — it is what makes the refusals unit-testable without a
tunnel.

⛔ REFUSE, NEVER DEGRADE. Every failure raises. A pre-fire check that "warns and
continues" is worse than none: it produces exactly the confident-looking false
negative the whole 405/430/444 arc exists to prevent, and it does so with a
green check mark next to it.
"""
from __future__ import annotations

from egress_pool import NETWORK_RESET, SweepPlanError


class EgressVerifyError(SweepPlanError):
    """The fire must NOT happen. Subclasses SweepPlanError so one `except`
    covers plan-time and fire-time refusals — a caller cannot accidentally
    handle one and let the other through."""


def verify_egress(*, region, actual_ip, expected_ip=None,
                  used_ips=frozenset(), burned_ips=frozenset(),
                  exit_live=None):
    """Decide whether this host's fwbbot fire may proceed. PURE. Raises or returns.

    Refusals, in the order a failure is most likely to be a silent one:

    1. NO ACTUAL IP — we could not observe where we are going out from. Firing
       blind means the resulting verdict cannot be attributed to an egress, so
       the row would be unusable even if the probe worked.
    2. THE TUNNEL IS NOT THE PLANNED ONE (expected_ip known and mismatched) —
       either the rotation failed or vpn_bringup fell back to conf #1.
    3. THIS EXIT WAS ALREADY USED IN THIS SWEEP — the fallback signature above,
       and the one that fires even when expected_ip is UNKNOWN. This is the
       check that actually closes relay 435.
    4. THE LEDGER SAYS BURNED — a recent network_reset on this IP (445's
       burned_egress_ips), so a reset now would measure the old ban.
    5. THE EXIT IS NOT LIVE — `exit_live is False` means the reachability probe
       failed. ⚠ `None` means NOT CHECKED and is REFUSED too: "we didn't look"
       must never pass as "it's fine".

    Returns the verified egress IP on success, so a caller cannot use this as a
    bare assertion and then read the IP from somewhere else.
    """
    if not actual_ip:
        raise EgressVerifyError(
            f"{region}: no egress IP observed — cannot attribute a verdict to an "
            f"exit we cannot name; refusing to fire blind")

    if expected_ip and actual_ip != expected_ip:
        raise EgressVerifyError(
            f"{region}: egress is {actual_ip}, expected {expected_ip} — the "
            f"rotation did not take, or vpn_bringup fell back to the first "
            f"config (the relay 435 pin). Refusing to fire through an exit we "
            f"did not plan.")

    if actual_ip in used_ips:
        raise EgressVerifyError(
            f"{region}: egress {actual_ip} was ALREADY USED earlier in this "
            f"sweep. That is the silent-fallback signature — the tunnel did not "
            f"actually move, so this host and the previous one would share a "
            f"ban. Refusing; fix the rotation before continuing.")

    if actual_ip in burned_ips:
        raise EgressVerifyError(
            f"{region}: egress {actual_ip} is BURNED (a recent network_reset). "
            f"A reset from here would measure the old ban, not this host. "
            f"Refusing; wait out the cooldown or use another region.")

    if exit_live is not True:
        why = ("was not checked" if exit_live is None else "failed its liveness probe")
        raise EgressVerifyError(
            f"{region}: egress {actual_ip} {why}. A dead or pre-banned exit "
            f"produces a no-response that is indistinguishable from enforcement. "
            f"Refusing.")

    return actual_ip


def fold_fire_outcome(burned_ips, *, egress_ip, result):
    """Keep the burned ledger current WITHIN the sweep (contract 5). PURE.

    ⛔ WHY IN-SWEEP AND NOT JUST THE DB. active_probe_audit is written by the
    scan, but the NEXT host in the sweep is planned before that row is queried
    back. Without folding the outcome forward, host N+1 could be handed the exit
    host N just got banned on — the self-contamination this whole relay exists
    to remove, reintroduced in the gap between write and read.

    Returns a NEW frozenset; the caller threads it into the next verify call.
    Only a reset burns, matching burned_egress_ips — a challenge or a clean pass
    leaves the exit usable.
    """
    if result == NETWORK_RESET and egress_ip:
        return frozenset(burned_ips) | {egress_ip}
    return frozenset(burned_ips)


def observe_and_verify(*, region, expected_ip, used_ips, burned_ips,
                       observe_ip, probe_exit_live):
    """The thin I/O shell: gather the two live facts, then delegate every
    decision to verify_egress.

    ⚠ The callables are INJECTED rather than imported so this layer carries no
    subprocess/HTTP of its own — the operator dispatch supplies them (one reads
    the post-rotation egress IP, e.g. from vpn_rotate.sh's `post_ip`; the other
    probes that the exit answers). That keeps the whole module unit-testable
    with fakes and keeps the firing machinery in the dispatch where it belongs.

    ⛔ An exception from either callable is NOT swallowed into a soft failure —
    it is re-raised as a refusal, because "the check itself broke" is not
    evidence that the exit is fine.
    """
    try:
        actual_ip = observe_ip(region)
    except Exception as e:  # noqa: BLE001 — any failure is a refusal
        raise EgressVerifyError(
            f"{region}: could not observe the egress IP ({e}). Refusing to fire "
            f"on an unverified exit.") from e

    try:
        live = probe_exit_live(actual_ip)
    except Exception as e:  # noqa: BLE001
        raise EgressVerifyError(
            f"{region}: liveness probe errored for {actual_ip} ({e}). Refusing — "
            f"a broken check is not a passing check.") from e

    return verify_egress(region=region, actual_ip=actual_ip,
                         expected_ip=expected_ip, used_ips=used_ips,
                         burned_ips=burned_ips, exit_live=live)
