#!/usr/bin/env python3
"""U7 alive clock + U6 resurrection hook — relay 155/158, 2026-09-15.

⛔ THE TWO DEFECTS.

U7 — `assets.last_alive_at` was written in exactly two places, both DISCOVERY: the ASM
importer's UPSERTs, and run_light's promote branch, which is gated
`WHERE discovery_status IN ('ct_ghost','unverified','dns_only')`. Once an asset is
confirmed_live it stops matching, so light stops bumping it; medium and heavy never wrote to
`assets` at all. www.prodexlabs.com had six completed scans and forty liveness verdicts since
2026-09-05 and still read "last observed Sep 5" on its own page — and asm_cron declared the
company website DARK three days after a heavy scan of it.

U6 — UPSERT_ASSET's no-downgrade CASE promotes only from ('ct_ghost','unverified','dns_only').
A dark asset is not in that list, so re-observing it live never brings it back. The importer
had no path to undo a demotion, which is why demotion_writer's --write-enable gate has been
OVERDUE since 2026-07-26: its own docstring names this hook as a required companion.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asset_liveness as al  # noqa: E402


# ---------------------------------------------------------------------------
# U7 — what counts as "this observation got an answer"
# ---------------------------------------------------------------------------

def test_naabu_ports_prove_alive():
    """light + heavy: svc_count is the SAME signal discovery_status_from_service_count
    uses to promote, so the clock and the promote agree by construction."""
    assert al.observation_proves_alive(svc_count=1) is True
    assert al.observation_proves_alive(svc_count=7) is True


def test_zero_ports_do_not_prove_alive():
    """A naabu-firewalled rescan seeing 0 ports must not move the clock. An unbumped
    clock is recoverable; a falsely-bumped one hides a dead host."""
    assert al.observation_proves_alive(svc_count=0) is False


def test_medium_uses_httpx_because_it_has_no_naabu():
    """⛔ Medium runs NO naabu, so relay 155's "svc_count > 0, the same signal the
    promote uses" cannot apply. httpx IS an HTTP prober: a clean httpx run is positive
    evidence the host answered on 80/443."""
    assert al.observation_proves_alive(tool_status={"httpx": "ok"}) is True
    assert al.observation_proves_alive(tool_status={"httpx_tech": {"status": "ok"}}) is True


def test_a_degraded_http_probe_does_not_prove_alive():
    assert al.observation_proves_alive(tool_status={"httpx": "degraded"}) is False
    assert al.observation_proves_alive(tool_status={"httpx": "skipped"}) is False


def test_no_evidence_means_no_bump():
    """⛔ THE LOAD-BEARING CASE. Bumping because close_out was *reached* would infer
    liveness from the absence of a crash — the exact error class this lane exists to
    kill (the digest's '0 findings', the enrich worker's 'No findings match')."""
    assert al.observation_proves_alive() is False
    assert al.observation_proves_alive(tool_status={}) is False
    assert al.observation_proves_alive(tool_status={"nikto": "ok"}) is False, \
        "a non-probe tool completing says nothing about whether the HOST answered"


def test_garbage_svc_count_does_not_crash_or_bump():
    assert al.observation_proves_alive(svc_count="two") is False
    assert al.observation_proves_alive(svc_count=None) is False


# ---------------------------------------------------------------------------
# U7 — the SQL itself
# ---------------------------------------------------------------------------

def test_alive_clock_sql_never_regresses_the_clock():
    """GREATEST, not assignment: a late-arriving slow scan must not rewind a newer stamp."""
    assert "GREATEST(last_alive_at, now())" in al.ALIVE_CLOCK_SQL


def test_alive_clock_sql_has_NO_discovery_status_filter():
    """⛔ THE WHOLE POINT. The promote-only filter is what stopped light refreshing the
    clock on confirmed_live assets. The clock records an observation, not a transition."""
    assert "discovery_status" not in al.ALIVE_CLOCK_SQL


def test_alive_clock_does_not_touch_last_probe_alive_at():
    """161 Q6 keeps the probe clock separate — it is a RESCUE record (written only when
    the dark gate saves a stale asset), not a freshness record. 155 ②: do not fold them."""
    assert "last_probe_alive_at" not in al.ALIVE_CLOCK_SQL


class _Cur:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


def test_bump_runs_the_update_only_when_alive_is_proven():
    c = _Cur()
    assert al.bump_alive_clock(c, "a.example", svc_count=2) is True
    assert len(c.calls) == 1 and c.calls[0][1] == ("a.example",)

    c2 = _Cur()
    assert al.bump_alive_clock(c2, "a.example", svc_count=0) is False
    assert c2.calls == [], "no evidence must mean no statement, not a no-op UPDATE"


# ---------------------------------------------------------------------------
# U6 — resurrection
# ---------------------------------------------------------------------------

def _importer_src() -> str:
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "import_asm_to_surface.py")
    src = open(p).read()
    return "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))


def test_resurrection_handles_BOTH_dark_vocabularies():
    """⛔ CHECK constraint 20260711a:52 admits 'confirmed_dark' AND 'went_dark'.
    demotion_writer writes 'went_dark'; the one dark row on Command today is
    'confirmed_dark'. A hook matching only one strands the other permanently."""
    src = _importer_src()
    assert "confirmed_dark" in src and "went_dark" in src
    m = re.search(r"_DARK_STATUSES\s*=\s*\(([^)]*)\)", src)
    assert m, "the dark set must be a named constant, not inlined at the call site"
    assert "confirmed_dark" in m.group(1) and "went_dark" in m.group(1)


def test_resurrection_clears_every_dark_field_in_one_statement():
    """Atomic: a half-resurrected asset (status live, went_dark_at still set) would make
    the demotion writer's own staleness read inconsistent."""
    src = _importer_src()
    i = src.index("RESURRECT_ASSET_SQL")
    sql = src[i:src.index('"""', src.index('"""', i) + 3)]
    for field in ("went_dark_at", "fade_detected_at", "dark_reason"):
        assert f"{field}       = NULL" in sql or f"{field}   = NULL" in sql \
            or re.search(rf"{field}\s*=\s*NULL", sql), f"{field} not cleared"
    assert re.search(r"resurrection_count\s*=\s*COALESCE\(resurrection_count, 0\) \+ 1", sql)
    assert re.search(r"last_transition_at\s*=\s*now\(\)", sql)
    assert sql.count("UPDATE public.assets") == 1, "must be ONE statement"


def test_resurrection_only_matches_dark_assets():
    """It runs on every confirmed_live observation, so for the overwhelming majority of
    assets the WHERE must match nothing and the call must be a no-op."""
    src = _importer_src()
    i = src.index("RESURRECT_ASSET_SQL")
    sql = src[i:src.index('"""', src.index('"""', i) + 3)]
    assert "discovery_status = ANY(" in sql


def test_upsert_still_cannot_resurrect_on_its_own():
    """The no-downgrade CASE must stay as it is — resurrection is an explicit, logged,
    countable transition, not a silent side effect of a routine UPSERT."""
    src = _importer_src()
    i = src.index("UPSERT_ASSET =")
    upsert = src[i:src.index('"""', src.index('"""', i) + 3)]
    assert "'ct_ghost', 'unverified', 'dns_only'" in upsert
    assert "went_dark" not in upsert and "confirmed_dark" not in upsert


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
