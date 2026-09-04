"""Spec 221 ruling ① — crawl-empty is DEGRADED, never a path-enum fall-back.

THE DEFECT this pins (pre-fix run_katana_crawl):
    On rc!=0, an empty crawl, or an unreadable output file, run_katana_crawl
    returned None. The caller then ran nuclei with `-u target`, re-introducing
    the exact /.env, /wp-login, /phpinfo.php path probes that crawl-first exists
    to avoid — the 6 content-signature paths run #4 proved trip Command's
    FortiGate. So a blocked crawl on a FortiGate asset didn't just lose the
    crawl; it actively fired the ban-tripping traffic, silently.

Ruling ①: the crawl must produce a real URL surface (>= CRAWL_MIN_URLS) or the
run DEGRADES (evidence-mandatory, same family as Spec 220). There is NO None
return and NO path-enum fall-back. A crawl-empty ON a FortiGate asset is itself
the signal that the FortiGate blocked the crawl (Trap B) — surfaced as DEGRADED,
not hidden behind a false ok.

Run: python -m pytest scripts/scanner/test_crawl_first_evidence.py -q
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import run_medium as M                                    # noqa: E402
from run_medium import ScanContext, run_katana_crawl      # noqa: E402
from degradation import DegradedRunError                  # noqa: E402


def _ctx(scan_run_id: str) -> ScanContext:
    ctx = ScanContext.__new__(ScanContext)
    ctx.hostname = "commandcommcentral.com"
    ctx.scan_run_id = scan_run_id
    ctx.tools_run = []
    ctx.artifacts = []
    ctx.tool_status = {}
    ctx.tool_diag = {}
    ctx.dsn = None
    ctx.egress_ips_seen = []
    return ctx


def _drive(monkeypatch, ctx, *, rc: int, urls: list[str] | None):
    """Run the SHIPPED run_katana_crawl with a canned katana result.

    run_cmd is stubbed (katana never really runs), so we write the output file
    ourselves to model what katana would have produced. urls=None models 'katana
    never wrote the file' (unreadable-output path).
    """
    out_file = f"/tmp/katana_urls_{ctx.scan_run_id}.txt"
    p = pathlib.Path(out_file)
    if urls is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text("\n".join(urls))
    monkeypatch.setattr(M, "run_cmd", lambda *a, **k: (rc, "", ""))
    monkeypatch.setattr(M, "is_tool_output_degraded", lambda **k: None)
    monkeypatch.setattr(M, "is_effective_patient_mode", lambda ctx: False)
    monkeypatch.setattr(M, "pick_ua", lambda: "UA")
    monkeypatch.setattr(M, "log", lambda *a, **k: None)
    monkeypatch.setattr(M, "flush_progress", lambda *a, **k: None, raising=False)
    return run_katana_crawl(ctx, f"https://{ctx.hostname}")


# ── ruling ①: the three failure modes DEGRADE, they do not fall back ─────────


def test_crawl_empty_degrades_never_returns_none(monkeypatch):
    ctx = _ctx("empty")
    with pytest.raises(DegradedRunError) as ei:
        _drive(monkeypatch, ctx, rc=0, urls=[])
    assert ei.value.reason == "crawl_empty_no_surface"
    # stamped degraded, NOT ok — the record cannot read as a clean crawl
    assert ctx.tool_status["katana"] == {"degraded": "crawl_empty_no_surface"}


def test_crawl_failed_degrades(monkeypatch):
    ctx = _ctx("failed")
    with pytest.raises(DegradedRunError) as ei:
        _drive(monkeypatch, ctx, rc=1, urls=[])
    assert ei.value.reason == "crawl_failed"
    assert "ok" not in ctx.tool_status["katana"]


def test_unreadable_output_degrades(monkeypatch):
    ctx = _ctx("unreadable")
    with pytest.raises(DegradedRunError) as ei:
        _drive(monkeypatch, ctx, rc=0, urls=None)  # file never written
    assert ei.value.reason == "crawl_output_unreadable"


# ── the success path still works and stamps ok ───────────────────────────────


def test_healthy_crawl_returns_file_and_marks_ok(monkeypatch):
    ctx = _ctx("healthy")
    urls = ["https://commandcommcentral.com/",
            "https://commandcommcentral.com/Account/Login",
            "https://commandcommcentral.com/Home/About"]
    out = _drive(monkeypatch, ctx, rc=0, urls=urls)
    assert out == "/tmp/katana_urls_healthy.txt"
    assert ctx.tool_status["katana"] == {"ok": True}
    # evidence persisted for forensics
    assert any(a[0] == "katana" for a in ctx.artifacts)


# ── the floor is honoured (calibratable; default 1) ──────────────────────────


def test_below_floor_degrades(monkeypatch):
    monkeypatch.setattr(M, "CRAWL_MIN_URLS", 5)
    ctx = _ctx("thin")
    with pytest.raises(DegradedRunError) as ei:
        _drive(monkeypatch, ctx, rc=0, urls=["https://commandcommcentral.com/",
                                             "https://commandcommcentral.com/x"])
    assert ei.value.reason == "crawl_empty_no_surface"


def test_at_floor_passes(monkeypatch):
    monkeypatch.setattr(M, "CRAWL_MIN_URLS", 2)
    ctx = _ctx("atfloor")
    out = _drive(monkeypatch, ctx, rc=0, urls=["https://commandcommcentral.com/",
                                               "https://commandcommcentral.com/x"])
    assert out is not None
    assert ctx.tool_status["katana"] == {"ok": True}


# ── the load-bearing invariant: run_katana_crawl NEVER returns None ──────────
# If a future refactor re-introduces `return None` on any failure path, the
# caller path-enumerates and trips the ban. This pins that it always either
# returns a real file or raises.


@pytest.mark.parametrize("rc,urls", [(0, []), (1, []), (0, None)])
def test_never_returns_none_on_failure(monkeypatch, rc, urls):
    ctx = _ctx(f"noneguard_{rc}_{urls is None}")
    with pytest.raises(DegradedRunError):
        _drive(monkeypatch, ctx, rc=rc, urls=urls)
