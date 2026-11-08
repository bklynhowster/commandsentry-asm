"""wildcard_www.py — KB 12 job 4 step 5 (plan v4.1 C2, 2026-11-08): a www name that only the
zone's wildcard DNS answers is never made a live asset.

WHY. www.firewall., www.portal. and www.zoetislabs.unimacgraphics.com came in from discovery on
2026-10-23 as `confirmed_live` because the unimacgraphics.com zone has a wildcard record
(*.unimacgraphics.com → 199.16.172.68, 199.16.173.113, Pressable's shared host) that answers any
name, and that host answers on its ports. They are not websites: a stock certificate, no page,
and their plain names (firewall., portal., zoetislabs.) live elsewhere. site_members.py measured
exactly that ("the two names resolve to different addresses", zone.wildcard true). The job 4
cleanup retires the three; this keeps discovery from making a new one live.

THE RULE (pure, `wildcard_only`). A name www.<rest> (not www.<apex>: that one is routed into the
apex's own bucket and is never its own asset) is wildcard-only when ALL hold:
  1. a made-up name next to it (site_members.control_name: sentry-site-check-<token>.<rest>)
     resolves — the zone answers names that do not exist;
  2. www.<rest>'s addresses (from discovery's own reading) are EXACTLY the made-up name's;
  3. <rest> itself does not resolve to those same addresses (it is elsewhere, or gone).
Rule 3 is what keeps a real www name on a wildcard zone: www.unimacgraphics.com sits on the
wildcard's addresses too, but so does unimacgraphics.com (one site, one host), so it is never
caught. A failed lookup ('error') is not evidence: the rule answers False and nothing changes.

WHAT HAPPENS (importer_status, called once per non-apex bucket). The importer writes 'retired'
instead of the status discovery would have given the name, and prints why. Its upsert CASE only
ever promotes ct_ghost/unverified/dns_only to confirmed_live, so:
  - a NEW wildcard-only name is inserted retired (the new-asset email only counts confirmed_live,
    so nobody is told about it, and no scan is queued for it);
  - an EXISTING ct_ghost/unverified/dns_only one is never promoted by discovery;
  - an existing confirmed_live one keeps its status: this never demotes. The job 4 cleanup
    (migration B) retires the three that exist. Its alive clock is still bumped as before (the
    host DID answer; the demotion writer's sweep-health count, 37 of 53 bumped on Command at
    13:05 UTC Nov 8, is unchanged by this), but it is never brought back from dark by discovery.
  - an existing retired one stays retired (the CASE never touches it).

WHAT IT CAN GET WRONG. A real website reached ONLY through the wildcard, on the wildcard's host,
whose plain name lives somewhere else, would be recorded retired and not scanned. The log line
names it; un-retiring is one UPDATE. None exists today (Command: three www.<sub> names, all
three ghosts; Prodex: none), checked 2026-11-08.

Network: at most two DNS lookups per www.<sub> bucket per discovery run (none for any other name), the
same lookups site_members.py already makes in the same workflow. `RESOLVE` is a module attribute
so tests inject a fake and never touch the network.
"""
from __future__ import annotations

import uuid

import site_members

STATUS = "retired"
RESOLVE = site_members.resolve          # (name) -> ('ok'|'nxdomain'|'v6only'|'error', [ipv4...])


def is_candidate(bucket_id: str, apex_asset_id: str) -> bool:
    """www.<rest> where <rest> is not the apex itself. PURE."""
    b = (bucket_id or "").lower().strip()
    return b.startswith("www.") and len(b) > 4 and b != f"www.{(apex_asset_id or '').lower().strip()}"


def bucket_addrs(sub_list: list) -> list[str]:
    """The IPv4 addresses discovery read for this bucket's names (hosts[].ip). PURE."""
    out = set()
    for sub in sub_list or []:
        if not isinstance(sub, dict):
            continue
        for h in sub.get("hosts") or []:
            ip = h.get("ip") if isinstance(h, dict) else None
            if isinstance(ip, str) and ip.count(".") == 3:
                out.add(ip.strip())
    return sorted(out)


def wildcard_only(www_addrs: list[str], plain: tuple[str, list[str]], zone: tuple[str, list[str]]) -> bool:
    """The rule in the module docstring. PURE."""
    if not www_addrs:
        return False
    z_status, z_addrs = zone
    if z_status != "ok" or not z_addrs:
        return False                                   # no wildcard (or the lookup failed)
    if set(www_addrs) != set(z_addrs):
        return False                                   # the www name has records of its own
    p_status, p_addrs = plain
    if p_status == "error":
        return False                                   # can't tell: change nothing
    if p_status == "ok" and set(p_addrs) == set(www_addrs):
        return False                                   # the plain name is on the same host
    return True


def check(bucket_id: str, sub_list: list, token: str | None = None) -> tuple[bool, dict]:
    """(wildcard_only?, the readings). At most two lookups; none if discovery read no address."""
    www_addrs = bucket_addrs(sub_list)
    reading: dict = {"www": www_addrs}
    if not www_addrs:
        return False, reading
    zone = RESOLVE(site_members.control_name(bucket_id, token or uuid.uuid4().hex[:12]))
    reading["zone"] = list(zone)
    if zone[0] != "ok" or set(zone[1]) != set(www_addrs):
        return False, reading                          # no wildcard, or records of its own
    rest = bucket_id[4:]
    plain = RESOLVE(rest)
    reading["plain"] = list(plain)
    return wildcard_only(www_addrs, plain, zone), reading


def importer_status(bucket_id: str, apex_asset_id: str, sub_list: list, disc: str, logfn=print) -> str:
    """The importer's one call: the status to write for this bucket. STATUS when the name is
    wildcard-only, otherwise `disc` unchanged. Never raises: a failed check changes nothing."""
    if not is_candidate(bucket_id, apex_asset_id):
        return disc
    try:
        wild, reading = check(bucket_id, sub_list)
    except Exception as e:  # noqa: BLE001 — a DNS hiccup must never stop the import
        logfn(f"  ! wildcard check for {bucket_id} failed (non-fatal; status left as "
              f"discovery read it, {disc}): {type(e).__name__}: {e}")
        return disc
    if not wild:
        return disc
    www = ", ".join(reading.get("www") or [])
    plain = reading.get("plain") or ["?", []]
    elsewhere = ", ".join(plain[1]) if plain[1] else plain[0]
    logfn(f"  wildcard-only: {bucket_id} answers only through the zone's wildcard DNS (it and a "
          f"made-up name next to it both resolve to {www}; {bucket_id[4:]} is at {elsewhere}). "
          f"Discovery will not make it live: a new name is recorded as {STATUS}, an existing "
          f"one keeps its status (discovery read it as {disc}).")
    return STATUS
