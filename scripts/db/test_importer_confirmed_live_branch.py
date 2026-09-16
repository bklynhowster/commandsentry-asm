#!/usr/bin/env python3
"""⛔ EXECUTABLE coverage of import_one's confirmed_live write path — relay 164.

4.7 (relay 163): "A module we run every 6 hours in production has zero executable
tests on its main write path — that is a bigger gap than the bug."

THE BUG THAT MADE THIS NECESSARY. The shipped U6 hook read
`resurrect_if_dark(cur, bucket_id, logfn=log)`. This module has no `log` — it
prints (23 call sites). Python resolves `log` AT THE CALL, for the first
confirmed_live asset of every run, so the whole importer exited 1; and because
the later steps in asm-discover.yml are `if: success()`, the liveness probe
worker AND the demotion writer were SKIPPED. The dark gate shipped hours earlier
silently stopped running. 1375 tests passed the whole time.

⚠ WHY EVERY EXISTING TEST MISSED IT. test_alive_clock_and_resurrection.py greps
the SQL and the constants. Structural tests read the source; they never RUN it,
and a NameError only exists at runtime. Three structural tests agreeing with
each other is not coverage.

⚠ WHAT THIS FILE IS AND IS NOT. It drives the real `import_one` through a fake
cursor, so every name on the confirmed_live path must actually resolve. It is
the companion to `test_every_logfn_argument_resolves_in_its_own_module`, which
is static and covers EVERY module; this one is dynamic and covers ONE path.
Neither subsumes the other: static proves names exist everywhere, dynamic proves
this path runs at all.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import import_asm_to_surface as m  # noqa: E402


# ---------------------------------------------------------------------------
# A fake cursor that answers by statement, so the real code path is exercised.
# ---------------------------------------------------------------------------

class _FakeCur:
    def __init__(self, conn, *, resurrect_row):
        self._conn = conn
        self._last = ""
        self._resurrect_row = resurrect_row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._last = " ".join(str(sql).split())
        self._conn.calls.append((self._last, params))

    def fetchone(self):
        u = self._last
        if u.startswith("SELECT aliases"):
            return ([],)
        if "SELECT surface_data" in u:
            return (None,)
        if "cloud_source" in u:
            return ("derived", False, None)
        # U6's resurrect RETURNS resurrection_count — a 1-tuple, or None when
        # the WHERE matched nothing (the no-op case for a non-dark asset).
        if "resurrection_count" in u:
            return self._resurrect_row
        if "RETURNING" in u:
            return ("example.com", True, False)
        return None

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self, *, resurrect_row=None):
        self.calls: list[tuple[str, object]] = []
        self._resurrect_row = resurrect_row

    def cursor(self):
        return _FakeCur(self, resurrect_row=self._resurrect_row)

    def commit(self):
        pass

    def rollback(self):
        pass


def _sub(name: str, *, services: list | None = None, hosts: list | None = None) -> dict:
    return {
        "name": name, "alive": True, "is_root": True, "discovered_via": "manual",
        "first_discovered": "2026-09-15T18:13:22Z", "last_seen": "2026-09-15T18:13:22Z",
        "tags": [], "reachability": {"live": True, "http_status": 200, "title": "t"},
        "probe_status": {},
        "hosts": [{"ip": "1.2.3.4", "asn": "AS1", "asn_org": "X", "country": "US",
                   "region": "NY", "city": "NYC", "reverse_dns": None,
                   "is_private": False}] if hosts is None else hosts,
        "services": [{"port": 443, "protocol": "tcp", "service": "https"}]
        if services is None else services,
        "dns": {"a": ["1.2.3.4"], "aaaa": [], "cname": None, "mx": [], "ns": [],
                "txt": [], "spf": None, "dnssec": False},
        "fingerprint": {"server": None, "platform_label": None, "tech": []},
        "waf": {"detected": False, "vendor": None, "confidence": "unknown"},
    }


def _doc(sub: dict, *, service_count: int) -> dict:
    return {
        "schema_version": 1,
        "asset": {"value": "example.com", "type": "domain", "organization": "Test"},
        "scan": {"started_at": "2026-09-15T18:00:00Z",
                 "finished_at": "2026-09-15T18:13:22Z"},
        "registration": {},
        "summary": {"subdomain_count": 1, "live_subdomain_count": 1, "host_count": 1,
                    "service_count": service_count, "newest_cert_expiry_days": None,
                    "top_hosting_org": "X", "platforms": []},
        "subdomains": [sub], "phantom_subdomains": [], "deltas": {}, "history": [],
    }


def _run(conn, doc):
    return m.import_one(conn, doc, "test", dry_run=False, skip_events=True)


def _stmts(conn) -> list[str]:
    return [s for s, _ in conn.calls]


# ---------------------------------------------------------------------------
# The load-bearing case: the branch RUNS.
# ---------------------------------------------------------------------------

def test_confirmed_live_branch_executes_clock_then_resurrect():
    """⛔ THIS IS THE TEST THAT WOULD HAVE CAUGHT THE OUTAGE.

    It calls the real import_one, so `resurrect_if_dark(cur, bucket_id, logfn=...)`
    is really evaluated. With the shipped `logfn=log` this raises NameError here,
    in under a second, instead of in production six hours later.
    """
    conn = _FakeConn(resurrect_row=None)      # asset was not dark -> no-op
    res = _run(conn, _doc(_sub("example.com"), service_count=1))
    assert res["status"] == "ok"

    stmts = _stmts(conn)
    clock = [i for i, s in enumerate(stmts) if "SET last_alive_at = GREATEST" in s]
    resur = [i for i, s in enumerate(stmts) if "resurrection_count" in s]
    assert clock, "the confirmed_live clock bump never ran — branch not reached"
    assert resur, "the U6 resurrection hook never ran — branch not reached"
    assert clock[0] < resur[0], (
        "the clock must be stamped BEFORE the status flips, so a resurrected "
        "asset already has a fresh last_alive_at"
    )


def test_resurrection_of_a_genuinely_dark_asset_returns_the_count(capsys):
    """The other side of the same branch: the WHERE matched, so a count comes
    back and the line is LOGGED — through logfn, the argument that broke."""
    conn = _FakeConn(resurrect_row=(3,))
    _run(conn, _doc(_sub("example.com"), service_count=1))
    out = capsys.readouterr().out
    assert "resurrection" in out.lower(), (
        "a real resurrection must be logged — this is the only place logfn is "
        "actually invoked, and an unexercised logfn is how the NameError shipped"
    )


def test_a_non_dark_asset_logs_nothing_and_does_not_crash(capsys):
    conn = _FakeConn(resurrect_row=None)
    _run(conn, _doc(_sub("example.com"), service_count=1))
    assert "resurrection" not in capsys.readouterr().out.lower()


def test_a_zero_service_asset_takes_NEITHER_branch():
    """dns_only never had a live service, so it cannot go dark and must not be
    clock-stamped. If this ever starts issuing those statements, the gate that
    decides 'alive' has drifted from the gate that decides 'confirmed_live'."""
    conn = _FakeConn(resurrect_row=None)
    _run(conn, _doc(_sub("example.com", services=[]), service_count=0))
    stmts = _stmts(conn)
    assert not [s for s in stmts if "SET last_alive_at = GREATEST" in s]
    assert not [s for s in stmts if "resurrection_count" in s]


def test_the_importer_still_has_no_log_of_its_own():
    """Pins the fact that made `logfn=log` a crash. If someone later adds a
    module-level `log` shim, this fails LOUDLY and on purpose: the module would
    then have two logging conventions, and the next port would pick the wrong
    one — which is how the first one got here."""
    assert not hasattr(m, "log"), (
        "import_asm_to_surface prints (23 sites) and must keep exactly one "
        "logging convention — pass logfn=print, do not add a `log` shim"
    )

def _phantom_calls(conn) -> list:
    """⚠ DO NOT discriminate by looking for the ct_ghost token in the SQL. The
    first version of this filter did, and matched UPSERT_ASSET — whose
    no-downgrade CASE merely MENTIONS that status — so the test read the apex
    asset's timestamps and failed on the FIXED tree.

    That is the third time in one day that prose containing a token satisfied a
    check looking for the token (the regex guard matched a comment; a grep of the
    fixed file counted 2; this). ⚠ And the fourth was the assertion written to
    prevent it: `assert 'ct_' + 'ghost' not in source` tripped on THIS docstring,
    which is why the word above is not spelled as a quoted literal.

    Discriminate on the phantom call's exact parameter set instead. Nothing else
    in this module passes that set, and a parameter dict cannot be mentioned in
    passing.
    """
    want = {"asset_id", "organization", "apex_domain",
            "first_observed", "last_observed"}
    return [(s, p) for s, p in conn.calls
            if isinstance(p, dict) and set(p) == want]


# ---------------------------------------------------------------------------
# The phantom / ct_ghost path — the SECOND undefined name, found by pyflakes.
# ---------------------------------------------------------------------------

def test_phantom_path_runs_when_the_scan_doc_has_no_completed_at():
    """⛔ THE utc_now BUG. `first_seen = ... .get("completed_at") or utc_now()`
    named a function this module never defined and never imported — there is no
    datetime import in the file at all. It fires only when a target yields
    phantom subdomains AND the doc has no scan.completed_at, which is why three
    months of production runs never hit it and 1358 tests never saw it.

    This drives exactly that combination. Before the fix it raises NameError.
    """
    doc = _doc(_sub("example.com"), service_count=1)
    doc["scan"].pop("completed_at", None)
    doc["phantom_subdomains"] = ["ghost.example.com"]

    conn = _FakeConn(resurrect_row=None)
    res = _run(conn, doc)
    assert res["phantoms_seen"] == 1

    phantom = _phantom_calls(conn)
    assert phantom, "the phantom UPSERT never ran"
    sql, params = phantom[0]
    assert params["first_observed"] is None and params["last_observed"] is None, (
        "with no completed_at the call site must pass None and let SQL default it"
    )


def test_the_phantom_upsert_defaults_its_own_timestamps():
    """⚠ WHY DELETING `or utc_now()` ALONE WOULD HAVE BEEN WORSE THAN THE CRASH.

    first_seen feeds BOTH first_observed and last_observed. A NULL last_observed
    is read by the dark/staleness logic; a NULL first_observed is what the
    alerter's new-asset predicate deliberately excludes — so the rows would have
    gone silently missing instead of loudly failing. The default belongs in the
    statement, where a caller cannot forget it, exactly as UPSERT_ASSET already
    does it in this same module.
    """
    sql = m.UPSERT_PHANTOM_SUBDOMAIN
    assert "COALESCE(%(first_observed)s, now())" in sql
    assert "COALESCE(%(last_observed)s, now())" in sql


def test_phantom_path_still_uses_completed_at_when_it_is_there():
    doc = _doc(_sub("example.com"), service_count=1)
    doc["scan"]["completed_at"] = "2026-09-15T18:13:22Z"
    doc["phantom_subdomains"] = ["ghost.example.com"]
    conn = _FakeConn(resurrect_row=None)
    _run(conn, doc)
    params = _phantom_calls(conn)[0][1]
    assert params["first_observed"] == "2026-09-15T18:13:22Z"

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
