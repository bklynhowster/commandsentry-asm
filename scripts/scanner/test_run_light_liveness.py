"""
test_run_light_liveness.py — regression guards for run_light's light-scan
liveness write-back (Obsidian 224, 2026-09-05).

THE BUG: a portal MANUAL-add inserts an asset as discovery_status='unverified'
and queues a LIGHT scan, but nothing ran the ASM ingestion that promotes
discovery_status, so the asset stayed 'unverified' and the portal — which
surfaces ONLY confirmed_live assets — filtered it out forever
(www.prodexlabs.com; verified live both instances).

THE FIX: run_light.close_out promotes discovery_status to 'confirmed_live'
when naabu saw >0 open ports (the SAME service-count signal the ASM ingestion
uses), reusing asset_liveness.discovery_status_from_service_count. PROMOTE-ONLY:
only from {ct_ghost,unverified,dns_only}, never touching confirmed_live or
went_dark (mirrors the UPSERT_ASSET no-downgrade CASE).

These tests CALL the shipped close_out with a fake cursor (the scanner suite
has no DB harness) so they exercise the real branch logic — the svc>0 gate and
the promote-only WHERE — not a mirror of it. tool_status={} makes the scan
delta-INeligible, which skips the finding-history writer (needs no DB).
"""
import inspect

import run_light


class _FakeCursor:
    def __init__(self, rowcount=1):
        self.executed = []          # list of (sql, params)
        self.rowcount = rowcount
        self._last = ""
        self.resurrect_row = None   # None = asset was not dark (the common case)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._last = " ".join(str(sql).split())
        self.executed.append((sql, params))

    def fetchone(self):
        """⛔ ADDED 2026-09-15 (relay 169) AND THE OMISSION WAS THE POINT.

        close_out now calls resurrect_if_dark after bump_alive_clock (Q7 audit,
        relay 167), and that statement RETURNs resurrection_count — so the write
        path performs a READ for the first time. This double had no fetchone, so
        all three tests here raised AttributeError the moment the call landed.

        ⭐ That is the double working as intended: a stand-in that cannot simulate
        the new behaviour must FAIL, not silently absorb it. Compare the defect
        this same bundle fixes — a guard that could not observe the failure and
        reported success anyway.

        Returns None by default, which is the honest common case: these fixtures
        use live/promoting assets, and for any asset that was not dark the
        resurrection WHERE matches nothing. Set .resurrect_row to exercise the
        dark branch.
        """
        if "resurrection_count" in getattr(self, "_last", ""):
            return getattr(self, "resurrect_row", None)
        return None


class _FakeConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


class _Ctx:
    """Minimal ScanContext stand-in for close_out."""
    def __init__(self, open_ports, asset_id="www.prodexlabs.com"):
        self.tools_run = []
        self.tool_status = {}        # empty -> delta_close_eligible False -> skip history writer
        self.scan_run_id = "sr-test"
        self.queue_id = "q-test"
        self.asset_id = asset_id
        self.open_ports = open_ports


def _run_close_out(open_ports, *, resurrect_row=None):
    cur = _FakeCursor()
    cur.resurrect_row = resurrect_row
    conn = _FakeConn(cur)
    run_light.close_out(conn, _Ctx(open_ports), 0, 0, Json=lambda x: x)
    return cur


def _liveness_updates(cur):
    return [sql for sql, _ in cur.executed
            if "discovery_status = 'confirmed_live'" in sql and "UPDATE public.assets" in sql]


# ── the gate: svc>0 promotes, svc=0 does NOT ─────────────────────────────────────
def test_open_ports_promote_to_confirmed_live():
    cur = _run_close_out({443, 80})
    ups = _liveness_updates(cur)
    assert len(ups) == 1, "svc>0 must fire exactly one discovery_status promotion UPDATE"
    # bound to the asset being scanned
    sql, params = next((s, p) for s, p in cur.executed if s in ups)
    assert params == ("www.prodexlabs.com",), "promotion must be scoped to ctx.asset_id"


def test_no_open_ports_does_not_promote():
    # naabu saw nothing (firewalled or genuinely no service) — MUST NOT write
    # discovery_status at all (can't distinguish dns_only from ct_ghost, and must
    # never demote). This is the svc>0 gate.
    cur = _run_close_out(set())
    assert _liveness_updates(cur) == [], "svc=0 must not touch discovery_status"


# ── promote-only / no-downgrade — mirrors UPSERT_ASSET's CASE ────────────────────
def test_promotion_is_promote_only_never_downgrades():
    cur = _run_close_out({443})
    sql = _liveness_updates(cur)[0]
    # only the three low states are eligible to be promoted...
    assert "discovery_status IN ('ct_ghost', 'unverified', 'dns_only')" in sql, (
        "promotion WHERE must restrict to the low states (mirror UPSERT_ASSET CASE)"
    )
    # ...and an already-live or a deliberately-dark asset is never overwritten here.
    assert "went_dark" not in sql, "must never re-promote went_dark from a light scan"


def test_last_alive_at_never_regresses():
    cur = _run_close_out({443})
    sql = _liveness_updates(cur)[0]
    assert "last_alive_at = GREATEST(last_alive_at, now())" in sql, (
        "last_alive_at must move forward only (GREATEST), never regress"
    )


# ── wiring: run_light imports and USES the shared verdict (no re-inlined ladder) ──
def test_run_light_uses_shared_verdict():
    assert hasattr(run_light, "discovery_status_from_service_count"), (
        "run_light must import the shared verdict from asset_liveness"
    )
    src = inspect.getsource(run_light.close_out)
    assert "discovery_status_from_service_count" in src, (
        "close_out must call the shared verdict, not re-inline svc>0"
    )

def test_close_out_resurrects_a_dark_asset_that_answered():
    """⛔ THE Q7 REGRESSION, AT THE LIGHT-SCAN CALL SITE (4.7, relay 167).

    Before this, run_light bumped the clock and could NOT resurrect — the hook
    lived in import_asm_to_surface.py, which a scanner cannot import. A dark asset
    scanned here that ANSWERED came out `went_dark` carrying a fresh last_alive_at,
    and never self-corrected, because the only resurrection path was ASM discovery
    — which never enumerates manually-added assets at all.

    Drives the REAL close_out and asserts both statements are issued, in order.
    """
    cur = _run_close_out({443}, resurrect_row=(1,))
    stmts = [" ".join(str(x).split()) for x, _ in cur.executed]
    clock = [i for i, x in enumerate(stmts) if "last_alive_at = GREATEST" in x]
    res = [i for i, x in enumerate(stmts) if "resurrection_count" in x]
    assert clock, "the alive clock was not bumped"
    assert res, "resurrect_if_dark was NOT called — a dark asset would stay dark forever"
    assert clock[0] < res[0], "the clock must be stamped before the status flips"


def test_close_out_with_no_open_ports_neither_bumps_nor_resurrects():
    """The resurrection is gated on the clock bump's return value, so a scan that
    proved nothing issues neither statement — no revival on absent evidence."""
    cur = _run_close_out(set())
    stmts = [" ".join(str(x).split()) for x, _ in cur.executed]
    assert not [x for x in stmts if "last_alive_at = GREATEST" in x]
    assert not [x for x in stmts if "resurrection_count" in x]
