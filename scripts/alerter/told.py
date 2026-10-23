"""told.py — say it once, then remind on a timer (KB 12 job 3s, 2026-10-23).

Howie, 2026-10-22 19:59–20:01, on the same firewall items arriving again and again: "us
constantly reminding Sean or Kianu or the people over at Unimac or Command might get sick of
hearing it"; "they just need a quick glance"; "We leave them alone, and after a certain amount
of time, we remind them again." Ruled ("Agreed"): a problem gets a FULL card when it is NEW,
WORSE or CAME BACK; after that it is one QUIET line in the weekly, and a full REMINDER on a
timer. 2026-10-23 07:25: Overdue (job 3r) the same, every 30 days. 13:50 (D1): "it's all the
same companies … their main marketing website is hosted, I think, by Pressable, which has
their own WAF" — the company is the whole fleet. D2: other serious problems every 30 days.

PURE. No database, no network. The record of what was told (`public.digest_told`, migration
20261023c) is read and written by run_alerter.py; here it is a dict {finding_id: row} where
a row has first_told_at, last_full_at, last_full_severity and closed_seen_at.

THE UNIT is the item digest_daily.group_problems builds (one problem, its sites, its
finding_ids). An item is FULL when any member is NEW (no row), WORSE (now more severe than
when last told in full), CAME BACK (seen closed after it was last told, open again now) or
DUE (its cadence has passed since it was last told in full); otherwise QUIET.
"""
from __future__ import annotations

from datetime import timedelta

SEV_RANK = {"CRITICAL": 1, "HIGH": 2, "MODERATE-HIGH": 3, "MODERATE": 4, "LOW": 5, "INFO": 6}
OPEN_STATUSES = ("detected", "confirmed", "open", "regressed")

# Cadence in days — starting numbers (Howie, 2026-10-22 20:02 and 2026-10-23 07:25, 13:50).
CADENCE = {"firewall-1": 30, "firewall-2": 90, "overdue": 30, "serious": 30}

FIREWALL_FAMILIES = ("waf-absent", "waf-not-blocking", "waf-partial")
# a firewall is there by definition: the case cannot flip when another gap closes
PRESENT_FIREWALL_FAMILIES = ("waf-not-blocking", "waf-partial")
FIREWALL_ID_MARK = ":commandsentry_heavy:waf-"
# the same two by identity (run_heavy's check ids), for a title the words table does not know
PRESENT_FIREWALL_IDS = (":commandsentry_heavy:waf-present-not-enforcing", ":commandsentry_heavy:waf-partial-coverage")


def is_firewall(item: dict) -> bool:
    if item.get("family") in FIREWALL_FAMILIES:
        return True
    return any(FIREWALL_ID_MARK in (f or "") for f in item.get("finding_ids", []))


def firewall_case(item: dict, fleet_has_waf: bool) -> int:
    """1 = the company has an enforcing web firewall somewhere (a CONFIRMED waf asset in the
    fleet, or this finding is itself about a firewall that is there): a gap in something they
    pay for, to IT, every 30 days. 2 = none anywhere: a budget decision, every 90 days. With D1
    (one company per fleet) both fleets are case 1 today; case 2 fires only for a fleet with
    no firewall at all."""
    if fleet_has_waf or item.get("family") in PRESENT_FIREWALL_FAMILIES:
        return 1
    if any(m in (f or "") for f in item.get("finding_ids", []) for m in PRESENT_FIREWALL_IDS):
        return 1
    return 2


def kind_of(item: dict, overdue_ids=frozenset(), fleet_has_waf: bool = True) -> str:
    """'overdue' (a member is an out-of-date finding 30+ days old: plan v3 Design 5, "an item
    with an out-of-date member 30+ days old is presented as Overdue"), 'firewall-1' /
    'firewall-2', or 'serious' — which cadence applies."""
    ids = item.get("finding_ids") or []
    if any(f in overdue_ids for f in ids):
        return "overdue"
    if is_firewall(item):
        return f"firewall-{firewall_case(item, fleet_has_waf)}"
    return "serious"


def decide(item: dict, told: dict, now, member_sev: dict, kind: str = "serious"):
    """('full', reason) with reason in back / worse / new / due, or ('quiet', None).
    `member_sev` {finding_id: severity now}."""
    ids = item.get("finding_ids") or []
    rows = [told.get(f) for f in ids]
    back = worse = new = False
    for f, r in zip(ids, rows):
        if not r:
            new = True
            continue
        cs, lf = r.get("closed_seen_at"), r.get("last_full_at")
        if cs is not None and lf is not None and cs > lf:
            back = True
        was = SEV_RANK.get((r.get("last_full_severity") or "").upper(), 9)
        if SEV_RANK.get((member_sev.get(f) or item.get("severity") or "").upper(), 9) < was:
            worse = True
    if back:
        return "full", "back"
    if worse:
        return "full", "worse"
    if new:
        return "full", "new"
    lasts = [r.get("last_full_at") for r in rows if r and r.get("last_full_at") is not None]
    if lasts and now >= max(lasts) + timedelta(days=CADENCE.get(kind, 30)):
        return "full", "due"
    return "quiet", None


def first_told(item: dict, told: dict):
    ts = [told[f]["first_told_at"] for f in item.get("finding_ids", [])
          if told.get(f) and told[f].get("first_told_at") is not None]
    return min(ts) if ts else None


def tag_for(reason: str, item: dict, told: dict, kind: str, day) -> str:
    """The line under a full card's title saying why it is here again (nothing for NEW)."""
    ft = first_told(item, told)
    d = day(ft) if ft is not None else ""
    if reason == "back":
        return "Came back after it was fixed" + (f" (first told {d})" if d else "")
    if reason == "worse":
        return "Got worse since we told you" + (f" on {d}" if d else "")
    if reason == "due":
        every = CADENCE.get(kind, 30)
        return f"Reminder, every {every} days" + (f" — first told {d}" if d else "") + "; nothing has changed"
    return ""


def records(items: list, member_sev: dict, where: str) -> list:
    """(finding_id, severity, where) for every member of every item rendered in full."""
    out, seen = [], set()
    for it in items:
        for f in it.get("finding_ids", []):
            if f in seen:
                continue
            seen.add(f)
            out.append((f, (member_sev.get(f) or it.get("severity") or "").upper(), where))
    return out
