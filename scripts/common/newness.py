#!/usr/bin/env python3
"""newness.py — ONE definition of "this asset is genuinely new to the inventory".

⛔ WHY THIS MODULE EXISTS (audit 248 finding A6, relay 172/178).

`asset_surface_event.asset_first_seen` does NOT mean "new asset". It means "this
PRODUCER has never written surface for this asset before" — `surface_diff.py`
emits it whenever `existing_blob is None`, which is correct for surface diffing
and correct to keep. The claim built on top of it is what was wrong.

Two consumers turn that event into a human-facing statement:

    DIGEST     scripts/alerter/run_alerter.py  SQL_NEW_ASSETS_IN_WINDOW
               guarded: first_observed window · NOT EXISTS earlier first_seen
               · ownership='owned' · discovery_status='confirmed_live'
    REAL-TIME  import_asm_to_surface.dispatch_event_notifications()
               guarded: NOTHING. It fired on the bare existence of the event.

⚠ THE COUNT IS THE POINT. There was ONE copy of the predicate, not two — the
real-time path had none. So writing the guard inline in the importer would have
created the SECOND copy, and two is exactly the count that drifted in the digest
(where the newness fix had to be applied twice before it was right). Hence a
shared module rather than a local fix.

MEASURED ON LIVE DATA, 2026-09-16, Command — 42 `asm_cron` first-seen events,
the only ones that reach the fan-out:

    OLD rule (event exists)             fires on all 42
    NEW rule (row INSERTED by this run) ALERT 37 · SUPPRESS 5

    suppressed   commandmarketinginnovations.com     9d after its row was created
                 ftp.unimacgraphics.com             31d
                 app3.commandmarketinginnovations   15d
                 insite.sciimage.com                50d
                 testapi.commandcommcentral.com     50d
    alerted      bcbsma.commandcommcentral.com       0s — the one genuinely new asset

⛔ WHY NOT A CLOCK COMPARISON — 4.7 nearly ruled `first_observed >= run_start`
and measurement killed it. `assets.first_observed` comes from the ASM DOC's own
scan timestamp; `created_at` comes from the INSERT. On bcbsma they are 20 minutes
apart (04:54:43 vs 05:14:14), so `first_observed >= run_start` would have
suppressed the ONE real new asset while still passing the false-positive tests.
The digest gets away with `first_observed` only because its window is hours wide.

⇒ NEWNESS, REAL-TIME = THE UPSERT **INSERTED** THE ROW RATHER THAN UPDATING IT.
  No clock, no window, no tolerance to tune. `UPSERT_ASSET` already returns it:
  `RETURNING asset_id, (xmax = 0) AS inserted`.

⚠ WHAT IS DELIBERATELY NOT HERE. The digest's SQL rendering of the same rule is
NOT in this module yet, even though it would look tidy. Shipping a constant no
caller reads is producer-without-consumer — the defect family that cost us the
enrich worker, the bare "httpx" in _HTTP_PROBE_TOOLS, and a day of review. The
digest migrates onto this module in its own reviewed push: GATES.md DEFERRED
row 2, due 2026-09-23. The window in which two renderings exist is bounded and
dated, not open and forgotten.
"""

from __future__ import annotations

from typing import Iterable

# Events whose HUMAN-FACING claim is "this asset is new to the inventory".
# Only these are gated here. port_opened / port_closed / asset_went_dark make no
# newness claim and are not touched — port_closed has its own streak gate.
NEWNESS_CLAIMING_EVENT_TYPES = ("asset_first_seen",)


def asset_is_new_to_inventory(asset_id: str, inserted_asset_ids: Iterable[str]) -> bool:
    """True iff THIS run's UPSERT inserted the asset row rather than updating it.

    `inserted_asset_ids` is built from `UPSERT_ASSET`'s own
    `RETURNING asset_id, (xmax = 0) AS inserted` — so it is the database's
    answer, not a reconstruction from timestamps.
    """
    if not asset_id:
        return False
    return asset_id in set(inserted_asset_ids or ())


def filter_newsworthy(events: list[dict], *, inserted_asset_ids: Iterable[str]) -> list[dict]:
    """Drop newness-CLAIMING events for assets this run did not insert.

    Everything else passes through untouched, in order. A port that opened on a
    six-month-old asset is still news; "we discovered a new asset" about that
    same host is not.

    ⚠ FAIL-CLOSED ON AN ABSENT SET. If `inserted_asset_ids` is empty, every
    first-seen event is suppressed. That is deliberate: an empty set means either
    the run inserted nothing (so there is genuinely nothing new to announce) or
    the caller failed to plumb it through — and the failure mode of a silent
    caller must be "say nothing", never "announce everything". The four measured
    false positives are what "announce everything" looks like.
    """
    keep = set(inserted_asset_ids or ())
    return [
        ev for ev in events
        if ev.get("event_type") not in NEWNESS_CLAIMING_EVENT_TYPES
        or (ev.get("asset_id") in keep)
    ]
