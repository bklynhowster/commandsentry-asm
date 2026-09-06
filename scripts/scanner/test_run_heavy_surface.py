"""
test_run_heavy_surface.py — regression guards for run_heavy's ASM-surface write-back
(Obsidian 226; spec 225 Option B; 4.7 ruling 2026-09-05).

Calls the SHIPPED run_heavy.close_out_heavy with a fake cursor (no DB harness in the
scanner suite) so it exercises the real path: fail-closed gate → per-tier baseline read →
compute_events → event insert → surface upsert.

Load-bearing assertions:
  - test_naabu_failed_is_a_true_noop        (4.7 Q4)  — a failed naabu writes NOTHING at all
  - test_first_write_no_false_port_closed   (4.7 Q6)  — fleet-wide false-close guard
  - test_upsert_identical_to_light          (drift)   — heavy/light SQL can never diverge
  - test_upsert_is_no_downgrade_on_service_count (D3) — the invariant D3 actually protects
"""
import inspect

import run_heavy
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
        # close_out_heavy's own SQL (CLOSE_SCAN_*) doesn't fetchone; only the baseline does.
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
    """Mirrors the HeavyScanContext fields close_out_heavy + write_scanner_surface read."""

    def __init__(self, open_ports, naabu_ok=True, fpx_services=None,
                 asset_id="www.prodexlabs.com"):
        self.tools_run = []
        self.tool_status = {}
        self.scan_run_id = "sr-test"
        self.queue_id = "q-test"
        self.asset_id = asset_id
        self.hostname = asset_id
        self.open_ports = open_ports        # list[dict] — heavy's naabu shape
        self.naabu_ok = naabu_ok
        self.fpx_services = fpx_services or {}
        self.egress_ip_initial = None
        self.vpn_config_used = None
        # build_rotation_log() reads these five
        self.rotation_count = 0
        self.egress_ips_seen = []
        self.ban_events = []
        self.healthcheck_failures = []
        self.rotation_storm = False


def _ports(*nums):
    return [{"host": "h", "ip": "1.2.3.4", "port": n, "protocol": "tcp"} for n in nums]


def _run(open_ports, prior=None, naabu_ok=True, fpx_services=None):
    cur = _Cur(prior=prior)
    conn = _Conn(cur)
    ctx = _Ctx(open_ports, naabu_ok=naabu_ok, fpx_services=fpx_services)
    run_heavy.close_out_heavy(conn, ctx, 0, 0, Json=lambda x: x)
    return cur


def _events(cur):
    ev = []
    for _sql, rows in cur.executemany_calls:
        ev.extend(rows)
    return ev


def _surface_upserts(cur):
    return [(sql, params) for sql, params in cur.executed
            if "INSERT INTO public.asset_surface" in sql and "_scanner" in sql]


# ── 4.7 Q4: a failed naabu is a TRUE no-op, not a value-preserving write ────────────────
def test_naabu_failed_is_a_true_noop():
    cur = _run(_ports(80, 443), prior=None, naabu_ok=False)
    assert _surface_upserts(cur) == [], "naabu-fail must not touch asset_surface AT ALL"
    assert _events(cur) == [], "naabu-fail must emit no surface events"
    # and it must not even read a baseline (nothing to diff — we observed nothing)
    assert not any("_scanner" in sql for sql, _ in cur.executed if "SELECT" in sql.upper()), \
        "naabu-fail must not establish or read a per-tier baseline"


def test_naabu_failed_does_not_block_scan_closeout():
    # the close-out itself MUST still run — the surface skip is not a scan failure
    cur = _run(_ports(80), prior=None, naabu_ok=False)
    assert any("scan_run" in sql.lower() for sql, _ in cur.executed), \
        "close_out_heavy must still close the scan_run when the surface write is skipped"


# ── 4.7 Q6: the fleet-wide guard — first write emits NO false port_closed ───────────────
def test_first_write_no_false_port_closed():
    cur = _run(_ports(80, 443), prior=None)     # baseline None = heavy never wrote this asset
    ev = _events(cur)
    types = [e["event_type"] for e in ev]
    assert types == ["asset_first_seen"], f"first write must be first_seen only, got {types}"
    assert not any(e["event_type"] == "port_closed" for e in ev), "NO false port_closed on first write"


def test_second_write_same_ports_no_events():
    prior = run_heavy.build_scanner_surface_blob(
        "www.prodexlabs.com", [80, 443], True, "full_ports", "scanner_heavy")
    cur = _run(_ports(80, 443), prior=prior)
    assert _events(cur) == [], f"identical re-scan must emit no events, got {_events(cur)}"


# ── D3's actual invariant: monotonic-up service_count + isolation ───────────────────────
def test_upsert_is_no_downgrade_on_service_count():
    cur = _run(_ports(80, 443), prior=None)
    sql, _params = _surface_upserts(cur)[0]
    assert "GREATEST(public.asset_surface.service_count" in sql, \
        "service_count MUST be no-downgrade — a plain assignment reopens D3's false-zero"


def test_write_is_isolated_under_scanner_key():
    cur = _run(_ports(80, 443), prior=None)
    sql, params = _surface_upserts(cur)[0]
    # P2's went-dark reader walks surface_data['subdomains'] (TOP level). We must only ever
    # write surface_data['_scanner'][tier], which that reader cannot see.
    assert "ARRAY['_scanner'" in sql, "surface write must be isolated under _scanner"
    assert params["tier"] == "heavy"
    assert params["updated_by"] == "scanner_heavy"


# ── 4.7 Q2: params + fingerprintx service names ────────────────────────────────────────
def test_coverage_is_axis_scoped_not_blanket_full():
    cur = _run(_ports(80), prior=None)
    _sql, params = _surface_upserts(cur)[0]
    blob = params["blob"]
    assert blob["coverage"] == "full_ports", \
        "heavy is full-on-PORTS but probes no web tech — blanket 'full' overstates coverage"
    assert blob["source"] == "scanner_heavy"


def test_fingerprintx_service_names_populate_blob():
    cur = _run(_ports(22, 8080), prior=None,
               fpx_services={(22, "tcp"): "ssh", (8080, "tcp"): "http"})
    _sql, params = _surface_upserts(cur)[0]
    svcs = {s["port"]: s["service"] for s in params["blob"]["subdomains"][0]["services"]}
    assert svcs == {22: "ssh", 8080: "http"}, f"fingerprintx names must enrich the blob, got {svcs}"


def test_missing_fingerprintx_degrades_label_not_ports():
    # fingerprintx miss → service null, but the naabu port inventory is intact
    cur = _run(_ports(22, 8080), prior=None, fpx_services={})
    _sql, params = _surface_upserts(cur)[0]
    svcs = params["blob"]["subdomains"][0]["services"]
    assert {s["port"] for s in svcs} == {22, 8080}, "ports must survive a fingerprintx miss"
    assert all(s["service"] is None for s in svcs)
    assert params["svc_count"] == 2


# ── drift + SQL type-cast pins ──────────────────────────────────────────────────────────
def test_upsert_identical_to_light():
    """The two tiers write the SAME row shape through the SAME SQL. If someone fixes a cast
    in one and not the other, this fails before it reaches Postgres."""
    assert run_heavy.SCANNER_SURFACE_UPSERT == run_light.SCANNER_SURFACE_UPSERT, \
        "heavy/light surface UPSERT drifted — they must stay byte-identical"
    assert run_heavy.SCANNER_SURFACE_BASELINE_SQL == run_light.SCANNER_SURFACE_BASELINE_SQL


def test_upsert_casts_blob_to_jsonb():
    # psycopg's Json adapts a dict to `json`, but jsonb_set() has no `json` overload — so
    # WITHOUT an explicit ::jsonb cast the whole UPSERT fails to PLAN (UndefinedFunction).
    # Fake-cursor tests can't see this (no real Postgres), so pin the casts here.
    sql = run_heavy.SCANNER_SURFACE_UPSERT
    assert "%(blob)s::jsonb" in sql, "blob param must be cast ::jsonb"
    assert "jsonb_set(" in sql
    # AmbiguousParameter guard: jsonb_build_object is VARIADIC "any" — an untyped param key
    # can't have its type inferred, so the tier param must be cast ::text.
    assert "%(tier)s::text" in sql, "tier param must be cast ::text inside jsonb_build_object"
    assert "jsonb_build_object(%(tier)s," not in sql


# ── wiring: close_out_heavy actually calls the surface write-back ───────────────────────
def test_close_out_heavy_calls_surface_writeback():
    src = inspect.getsource(run_heavy.close_out_heavy)
    assert "write_scanner_surface" in src, "close_out_heavy must call write_scanner_surface"
    assert "conn.transaction()" in src, "surface write must be savepoint-isolated (best-effort)"
    assert '"full_ports"' in src, "heavy must write axis-scoped coverage, not blanket 'full'"


def test_fail_closed_gate_reads_ctx_naabu_ok():
    """The gate must key off the naabu SUCCESS signal, not merely 'are there ports'.
    0 ports with naabu_ok=True is a legitimate 'nothing open'; naabu_ok=False is 'couldn't look'."""
    src = inspect.getsource(run_heavy.write_scanner_surface)
    body = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "if not ctx.naabu_ok" in body, "fail-closed gate must test ctx.naabu_ok"
