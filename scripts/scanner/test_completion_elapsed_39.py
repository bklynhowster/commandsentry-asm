"""#39 — the nuclei COMPLETION path records elapsed_s + reason, mirroring the
cut path, so observed_rate is derivable from chunks that FINISHED. Record-only."""
import types, run_medium as rm
from tool_evidence import Evidence

def test_completion_records_elapsed_and_reason(monkeypatch):
    monkeypatch.setattr(rm, "flush_progress", lambda *a, **k: None)
    c = types.SimpleNamespace(tool_status={}, dsn=None)
    rm.mark_tool_ok_evidenced(
        c, "nuclei[critical,high]",
        Evidence.measured(requests=1460, total=4318, percent=33),
        elapsed_s=337.4)
    e = c.tool_status["nuclei[critical,high]"]
    assert e["ok"] is True and e["elapsed_s"] == 337.4 and e["reason"] == "completed"

def test_absent_elapsed_is_backward_compatible(monkeypatch):
    monkeypatch.setattr(rm, "flush_progress", lambda *a, **k: None)
    c = types.SimpleNamespace(tool_status={}, dsn=None)
    rm.mark_tool_ok_evidenced(
        c, "nuclei[medium:cve]",
        Evidence.measured(requests=10, total=10, percent=100))
    assert "elapsed_s" not in c.tool_status["nuclei[medium:cve]"]
