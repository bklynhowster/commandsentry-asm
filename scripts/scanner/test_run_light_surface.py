"""
test_run_light_surface.py — regression guards for run_light's ASM-surface write-back
(Obsidian 225, 4.7 Option B).

Calls the SHIPPED run_light.close_out with a fake cursor (no DB harness in the scanner suite)
so it exercises the real path: per-tier baseline read → compute_events → event insert → surface
upsert. The load-bearing assertion is test_first_write_no_false_port_closed — the fleet-wide
guard (4.7 Q6): the scanner's first surface write (baseline None) must emit asset_first_seen and
ZERO port_closed, even with open ports, so B's first run over the 28 already-discovered assets
can't storm the port-event timeline with false closes.
"""
import inspect

import run_light


class _Cur:
    def __init__(self, prior=None, rowcount=1):
        self.executed = []            # (sql, params)
        self.executemany_calls = []   # (sql, rows)
        self._prior = prior
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def executemany(self, sql, rows):
        self.executemany_calls.append((sql, list(rows)))

    def fetchone(self):
        # Only the surface-baseline SELECT calls fetchone in close_out.
        return {"prior": self._prior}


class _Txn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur

    def transaction(self):
        return _Txn()


class _Ctx:
    def __init__(self, open_ports, asset_id="www.prodexlabs.com", naabu_ok=True):
        self.tools_run = []
        self.tool_status = {"naabu": {"ok": naabu_ok}}  # empty of other tools → history skipped
        self.scan_run_id = "sr-test"
        self.queue_id = "q-test"
        self.asset_id = asset_id
        self.hostname = asset_id
        self.open_ports = open_ports


def _run(open_ports, prior=None, naabu_ok=True):
    cur = _Cur(prior=prior)
    conn = _Conn(cur)
    run_light.close_out(conn, _Ctx(open_ports, naabu_ok=naabu_ok), 0, 0, Json=lambda x: x)
    return cur


def _events(cur):
    ev = []
    for _sql, rows in cur.executemany_calls:
        ev.extend(rows)
    return ev


def _surface_upserts(cur):
    return [sql for sql, _ in cur.executed
            if "INSERT INTO public.asset_surface" in sql and "_scanner" in sql]


# ── the fleet-wide guard: first write emits NO false port_closed ─────────────────────────────────
def test_first_write_no_false_port_closed():
    cur = _run({80, 443}, prior=None)          # baseline None = scanner never wrote this asset
    ev = _events(cur)
    types = [e["event_type"] for e in ev]
    assert types == ["asset_first_seen"], f"first write must be first_seen only, got {types}"
    assert not any(e["event_type"] == "port_closed" for e in ev), "NO false port_closed on first write"


def test_surface_upsert_fires_isolated_and_no_downgrade():
    cur = _run({80, 443}, prior=None)
    ups = _surface_upserts(cur)
    assert len(ups) == 1, "exactly one asset_surface upsert"
    sql = ups[0]
    # isolation: writes ONLY under surface_data->_scanner->tier, never top-level (asm's axis)
    assert "ARRAY['_scanner'" in sql, "surface write must be isolated under _scanner"
    # no-downgrade: a thin light scan can't shrink a fuller discover's service_count
    assert "GREATEST(public.asset_surface.service_count" in sql, "service_count must be no-downgrade"


def test_second_write_same_coverage_no_events():
    # scanner's own prior with identical ports → no opens, no closes
    prior = run_light.build_scanner_surface_blob(
        "www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    cur = _run({80, 443}, prior=prior)
    assert _events(cur) == [], f"identical re-scan must emit no events, got {_events(cur)}"


def test_naabu_failed_suppresses_close():
    prior = run_light.build_scanner_surface_blob(
        "www.prodexlabs.com", [80, 443], True, "partial", "scanner_light")
    cur = _run({80}, prior=prior, naabu_ok=False)   # 443 "gone" but naabu failed → no close
    assert not any(e["event_type"] == "port_closed" for e in _events(cur)), "fail-closed on naabu failure"


# ── SQL type-cast pin (caught LIVE 2026-09-05) ───────────────────────────────────────────────────
def test_upsert_casts_blob_to_jsonb():
    # psycopg's Json adapts a dict to type `json`, but jsonb_set() has no `json` overload — so
    # WITHOUT an explicit ::jsonb cast the whole UPSERT fails to PLAN (UndefinedFunction), even on
    # the plain-INSERT path (Postgres resolves the ON CONFLICT branch at plan time). The fake-cursor
    # tests can't see this (no real Postgres), so pin the cast here.
    sql = run_light.SCANNER_SURFACE_UPSERT
    assert "%(blob)s::jsonb" in sql, "blob param must be cast ::jsonb (json has no jsonb_set overload)"
    assert "jsonb_set(" in sql
    # AmbiguousParameter guard: jsonb_build_object is VARIADIC "any", so an untyped param key
    # can't have its type inferred — the tier param must be cast ::text (caught live 2026-09-05).
    assert "%(tier)s::text" in sql, "tier param must be cast ::text inside jsonb_build_object"
    # No bare %(blob)s / %(tier)s feeding a jsonb builder (every such param must carry a ::cast).
    assert "jsonb_build_object(%(tier)s," not in sql and "jsonb_build_object(%(tier)s)" not in sql


# ── wiring: close_out actually calls the surface write-back ───────────────────────────────────────
def test_close_out_calls_surface_writeback():
    src = inspect.getsource(run_light.close_out)
    assert "write_scanner_surface" in src, "close_out must call write_scanner_surface"
    assert "conn.transaction()" in src, "surface write must be savepoint-isolated (best-effort)"
    assert hasattr(run_light, "build_scanner_surface_blob"), "shared blob builder must be imported"
