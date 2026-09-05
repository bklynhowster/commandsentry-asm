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

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))


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


def _run_close_out(open_ports):
    cur = _FakeCursor()
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
