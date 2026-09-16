#!/usr/bin/env python3
"""A6 — the newness rule, tested in BOTH directions (relay 172/178).

⛔ 4.7's acceptance condition, verbatim: "the four measured false positives must
be SUPPRESSED, and bcbsma must ALERT. A rule that passes only the first four is
a rule that silences the feature."

The fixtures below are the REAL assets and the REAL gaps, measured against the
live Command database on 2026-09-16 — 42 `asm_cron` first-seen events, the only
ones that reach the fan-out:

    commandmarketinginnovations.com      event  9d after its row was created
    app3.commandmarketinginnovations     event 15d after
    ftp.unimacgraphics.com               event 31d after
    insite.sciimage.com                  event 50d after
    testapi.commandcommcentral.com       event 50d after
    bcbsma.commandcommcentral.com        event  0s after — INSERTED by that run

⚠ FIVE, NOT FOUR. 4.7's audit named four; measuring every asm_cron first-seen
event against `assets.created_at` found `ftp.unimacgraphics.com` as well. The
ages also differ from the audit's (50d vs "103d") because the audit measured
from `assets.first_observed` — the ASM doc's clock — and this measures from
`created_at`, the insert's clock. Same assets, different clock, and which clock
you use is exactly what this whole finding turned on.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import newness  # noqa: E402


# The five assets whose first-seen event fired long after their row existed.
STALE_FALSE_POSITIVES = [
    "commandmarketinginnovations.com",
    "app3.commandmarketinginnovations.com",
    "ftp.unimacgraphics.com",
    "insite.sciimage.com",
    "testapi.commandcommcentral.com",
]
# The one genuinely new asset in the same window.
GENUINELY_NEW = "bcbsma.commandcommcentral.com"


def _first_seen(asset_id: str) -> dict:
    return {"asset_id": asset_id, "event_type": "asset_first_seen",
            "host": None, "port": None, "proto": None}


def _port_opened(asset_id: str, port: int = 443) -> dict:
    return {"asset_id": asset_id, "event_type": "port_opened",
            "host": asset_id, "port": port, "proto": "tcp"}


# ---------------------------------------------------------------------------
# Direction 1 — the false positives must go
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("asset_id", STALE_FALSE_POSITIVES)
def test_a_first_seen_on_an_asset_this_run_did_not_insert_is_suppressed(asset_id):
    """Each of these produced a real "new asset discovered" email about an asset
    the fleet had already held for weeks. The event itself was correct — a
    producer genuinely had no prior surface for it — but the claim was not."""
    events = [_first_seen(asset_id)]
    kept = newness.filter_newsworthy(events, inserted_asset_ids={GENUINELY_NEW})
    assert kept == [], f"{asset_id} would still send a false 'new asset' email"


# ---------------------------------------------------------------------------
# Direction 2 — ⛔ THE ONE THAT STOPS THIS BEING A MUTE BUTTON
# ---------------------------------------------------------------------------

def test_the_genuinely_new_asset_still_alerts():
    """⛔ A rule that suppresses all six is not a fix, it is an off switch.

    bcbsma is why the clock comparison was rejected: its `first_observed` is
    04:54:43 (the ASM doc's own scan time) and its row was created at 05:14:14,
    twenty minutes later. `first_observed >= run_start` would have passed all
    five suppression tests above and silently killed the only true alert.
    """
    events = [_first_seen(GENUINELY_NEW)]
    kept = newness.filter_newsworthy(events, inserted_asset_ids={GENUINELY_NEW})
    assert kept == events, "the one genuinely new asset was silenced"


def test_the_real_mixed_run_gives_exactly_one_alert():
    """The measured run shape: many first-seen events, one real insert."""
    events = [_first_seen(a) for a in STALE_FALSE_POSITIVES] + [_first_seen(GENUINELY_NEW)]
    kept = newness.filter_newsworthy(events, inserted_asset_ids={GENUINELY_NEW})
    assert [e["asset_id"] for e in kept] == [GENUINELY_NEW]


# ---------------------------------------------------------------------------
# Scope — only the newness CLAIM is gated
# ---------------------------------------------------------------------------

def test_other_event_types_are_untouched_on_old_assets():
    """A port opening on a six-month-old asset is real news and must survive.
    Gating it would trade a false-positive bug for a false-negative one, which is
    strictly worse — nobody notices the email that never arrives."""
    events = [_port_opened("insite.sciimage.com"),
              _first_seen("insite.sciimage.com")]
    kept = newness.filter_newsworthy(events, inserted_asset_ids=set())
    assert [e["event_type"] for e in kept] == ["port_opened"]


def test_order_is_preserved_and_nothing_is_duplicated():
    events = [_port_opened("a.example"), _first_seen("new.example"),
              _port_opened("b.example")]
    kept = newness.filter_newsworthy(events, inserted_asset_ids={"new.example"})
    assert kept == events


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------

def test_an_empty_inserted_set_suppresses_rather_than_announces():
    """⚠ THE PLUMBING FAILURE MODE, PINNED. The set is accumulated in main() and
    threaded through two call sites. If a future edit drops that plumbing, the
    set arrives empty — and this asserts the result is silence, not a flood.
    An omission must never re-enable the bug it was added to fix."""
    events = [_first_seen(GENUINELY_NEW)]
    assert newness.filter_newsworthy(events, inserted_asset_ids=set()) == []
    assert newness.filter_newsworthy(events, inserted_asset_ids=None) == []


def test_a_missing_asset_id_does_not_crash_the_fan_out():
    assert newness.filter_newsworthy(
        [{"event_type": "asset_first_seen"}], inserted_asset_ids={"x"}) == []


def test_asset_is_new_to_inventory_is_the_same_rule():
    assert newness.asset_is_new_to_inventory(GENUINELY_NEW, {GENUINELY_NEW}) is True
    assert newness.asset_is_new_to_inventory("insite.sciimage.com", {GENUINELY_NEW}) is False
    assert newness.asset_is_new_to_inventory("", {""}) is False
    assert newness.asset_is_new_to_inventory("x", None) is False


# ---------------------------------------------------------------------------
# The wiring, executed — not grepped
# ---------------------------------------------------------------------------

def test_the_importer_actually_applies_the_filter_and_threads_the_set():
    """⚠ Every other test here exercises the helper in isolation, which proves
    the RULE and not the WIRING. The logfn outage shipped through three green
    structural tests for exactly that reason. This drives the real
    dispatch_event_notifications with no SENDGRID_API_KEY, so it returns before
    sending — but only AFTER the filter has run, which is what we assert.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(here, "..", "db"))
    import import_asm_to_surface as imp

    saved = os.environ.pop("SENDGRID_API_KEY", None)
    try:
        # Every event suppressed -> returns on the empty-list guard, never
        # reaching the api-key check, so skipped_no_key stays 0.
        st = imp.dispatch_event_notifications(
            None, [_first_seen("insite.sciimage.com")], "asm_cron",
            inserted_asset_ids=set())
        assert st["skipped_no_key"] == 0 and st["emails_sent"] == 0, (
            "a suppressed-only run must return BEFORE the send path, proving the "
            "filter ran ahead of the grouping")

        # One survivor -> gets past the filter, then stops on the missing key.
        st = imp.dispatch_event_notifications(
            None, [_first_seen(GENUINELY_NEW)], "asm_cron",
            inserted_asset_ids={GENUINELY_NEW})
        assert st["skipped_no_key"] == 1, (
            "the genuinely-new event did not survive the filter inside the "
            "importer — the helper is right but the wiring is not")
    finally:
        if saved is not None:
            os.environ["SENDGRID_API_KEY"] = saved

def test_every_dispatch_call_threads_the_inserted_set():
    """⚠ THE PLUMBING, PINNED SEPARATELY — because the executable tests above
    cannot see it. They call dispatch_event_notifications directly with an
    explicit set, so a future edit that drops `run_inserted_asset_ids` from
    main() leaves all of them green while the fan-out silently receives an empty
    set. Fail-closed turns that into silence rather than a flood, but silence is
    still a broken feature and nothing would have said so.

    Reads ast.keyword nodes, not text: the same trap that made a regex guard
    match `logfn=log` inside a comment applies to any grep for `inserted_asset_ids=`.
    """
    import ast
    import glob

    here = os.path.dirname(os.path.abspath(__file__))
    problems = []
    for path in glob.glob(os.path.join(here, "..", "db", "*.py")) + \
                glob.glob(os.path.join(here, "*.py")):
        if os.path.basename(path).startswith("test_"):
            continue
        try:
            tree = ast.parse(open(path).read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "dispatch_event_notifications":
                continue
            if not any(k.arg == "inserted_asset_ids" for k in node.keywords):
                problems.append(
                    f"{os.path.basename(path)}:{node.lineno} calls "
                    f"dispatch_event_notifications WITHOUT inserted_asset_ids= "
                    f"— the fan-out would gate on an empty set and announce nothing")
    assert not problems, "newness set not threaded:\n  " + "\n  ".join(problems)

def test_no_production_caller_passes_to_override():
    """⛔ THE OPERATOR OVERRIDE MUST STAY OPERATOR-ONLY (4.7, relay 179).

    `to_override` replaces the entire subscriber list with one address. That is
    correct for preview_fire_notification.py — whose whole job is to show ONE
    human ONE email, and which now requires --to unless --dry-run — and it would
    be a redirect of production mail anywhere else.

    A parameter that can silently reroute every alert deserves a pin, not a
    comment. AST again, not grep: the string "to_override" appears in the
    explanatory comments beside the code, and a text search would match those.
    """
    import ast
    import glob

    here = os.path.dirname(os.path.abspath(__file__))
    allowed = {"preview_fire_notification.py"}
    problems = []
    for path in glob.glob(os.path.join(here, "..", "db", "*.py")) + \
                glob.glob(os.path.join(here, "*.py")) + \
                glob.glob(os.path.join(here, "..", "alerter", "*.py")):
        base = os.path.basename(path)
        if base.startswith("test_") or base in allowed:
            continue
        try:
            tree = ast.parse(open(path).read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "dispatch_event_notifications":
                continue
            if any(k.arg == "to_override" for k in node.keywords):
                problems.append(
                    f"{base}:{node.lineno} passes to_override= — that replaces the "
                    f"whole subscriber list with one address. Only the preview tool "
                    f"may do that, and only because it requires --to.")
    assert not problems, "operator override leaked into production:\n  " + "\n  ".join(problems)


def test_the_preview_tool_refuses_to_send_without_an_explicit_recipient():
    """⛔ Before this, the tool had two modes: --dry-run, or mail EVERY real-time
    subscriber. With A6's declare-as-new that made it the single sanctioned
    bypass of the newness gate — a synthetic "New asset discovered" about a real
    months-old host, delivered to the whole admin list, with a comment saying it
    was deliberate. Reads the source because the guard is an early return in
    main(), which cannot be exercised without a live DSN.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "..", "db", "preview_fire_notification.py")).read()
    tree_ok = "--to" in src and "args.to" in src
    assert tree_ok, "the preview tool has no --to flag"
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "if not args.dry_run and not args.to:" in code, (
        "--to is not REQUIRED outside --dry-run — the tool can still mail the "
        "whole subscriber list a synthetic new-asset alert")
    assert "to_override=args.to" in code, (
        "the tool computes --to but does not route the send through it")

class _DispatchCur:
    """Answers the three queries dispatch_event_notifications makes."""
    def __init__(self, subscribers):
        self._subs = subscribers
        self._last = ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._last = " ".join(str(sql).split())

    def fetchall(self):
        u = self._last
        if "user_notification_prefs" in u:
            return self._subs
        if "discovery_status, ownership" in u:
            return [("bcbsma.commandcommcentral.com", "confirmed_live", "owned")]
        return []

    def fetchone(self):
        return (99,)          # port_closed streak, unused by first_seen


class _DispatchConn:
    def __init__(self, subscribers):
        self._subs = subscribers

    def cursor(self):
        return _DispatchCur(self._subs)


def test_to_override_really_replaces_the_subscriber_list(monkeypatch):
    """⛔ THIS TEST EXISTS BECAUSE ITS ABSENCE SURVIVED A MUTATION.

    With the `if to_override:` branch disabled, every other test in this file
    still passed — 16/16 green while the preview tool quietly mailed the entire
    admin list again. A guard nothing is ever observed to enforce is not a guard;
    that is the lesson this whole bundle is built on, and it nearly shipped
    inside the fix for it.

    Drives the real dispatch_event_notifications with a fake connection that
    returns SIX real subscribers, and asserts the override sends to exactly one.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(here, "..", "db"))
    import import_asm_to_surface as imp

    real_subscribers = [
        (f"u{i}", f"admin{i}@commandcompanies.com",
         {"new_asset_discovered": {"cadence": "real_time"}})
        for i in range(6)
    ]
    sent_to = []
    monkeypatch.setattr(imp, "_send_notification_email",
                        lambda **kw: (sent_to.append(kw["to_email"]) or True))
    monkeypatch.setenv("SENDGRID_API_KEY", "test-key-not-real")
    # ⭐ The per-instance identity guard (2026-07-29) returns BEFORE the
    # subscriber fetch when these are unset, so that Prodex can never mail as
    # Command. Discovered by this test failing with 0 sent on the baseline —
    # which is the guard doing its job, and worth the two extra lines to keep it
    # doing it.
    monkeypatch.setenv("ALERTER_FROM", "test@example.invalid")
    monkeypatch.setenv("ALERTER_FROM_NAME", "TESTsentry")
    monkeypatch.setenv("PORTAL_BASE_URL", "https://portal.example.invalid")
    for _n, _v in (("SENDGRID_FROM_EMAIL", "test@example.invalid"),
                   ("SENDGRID_FROM_NAME", "TESTsentry"),
                   ("PORTAL_BASE_URL", "https://portal.example.invalid")):
        monkeypatch.setattr(imp, _n, _v, raising=False)

    ev = [_first_seen(GENUINELY_NEW)]

    # WITHOUT the override: the real fan-out reaches every subscriber.
    imp.dispatch_event_notifications(
        _DispatchConn(real_subscribers), list(ev), "manual_test_fire",
        inserted_asset_ids={GENUINELY_NEW})
    assert len(sent_to) == 6, (
        f"baseline wrong: expected the fan-out to reach all 6 subscribers, got {sent_to}")

    # WITH it: exactly one address, and it is the operator's.
    sent_to.clear()
    imp.dispatch_event_notifications(
        _DispatchConn(real_subscribers), list(ev), "manual_test_fire",
        inserted_asset_ids={GENUINELY_NEW},
        to_override="howie@example.com")
    assert sent_to == ["howie@example.com"], (
        f"to_override did not replace the subscriber list — sent to {sent_to}. "
        f"The preview tool would mail a synthetic 'new asset' alert to everyone.")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
