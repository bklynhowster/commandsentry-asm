"""4.7 J5b — SSOT guard for cross-scan confirmation thresholds.

Both alert paths MUST read the SAME CONFIRMATION_THRESHOLDS object, never a
hand-copied literal. Drift here silently desyncs the file-delta path
(scanner/post-email-alerts.py) from the DB-event path
(scripts/db/import_asm_to_surface.py) — someone bumps N in one place and the
other keeps the old value. The identity (`is`) check, not equality, is the point:
a local dict with the same values would pass `==` but reintroduce the drift.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

DB_DIR = Path(__file__).resolve().parent      # scripts/db
REPO = DB_DIR.parent.parent                    # repo root
sys.path.insert(0, str(DB_DIR))

from confirmation_thresholds import CONFIRMATION_THRESHOLDS as CANON  # noqa: E402
import import_asm_to_surface  # noqa: E402


def test_db_path_reads_the_shared_object():
    # identity, not equality — a local dict with the same values would pass ==
    assert import_asm_to_surface.CONFIRMATION_THRESHOLDS is CANON


def test_file_delta_path_imports_not_hardcodes():
    # post-email-alerts.py has a hyphen (not importable as a module), so assert
    # statically: it imports the shared constant and derives its named thresholds
    # from it — never as integer literals.
    src = (REPO / "scanner" / "post-email-alerts.py").read_text(encoding="utf-8")
    assert "from confirmation_thresholds import CONFIRMATION_THRESHOLDS" in src
    for name in ("HOST_REMOVED_ABSENCE_SCANS", "SERVICE_CLOSED_ABSENCE_SCANS",
                 "SUBDOMAIN_GONE_ABSENCE_SCANS"):
        assert re.search(rf'^{name}\s*=\s*CONFIRMATION_THRESHOLDS\[', src, re.M), \
            f"{name} not sourced from the shared dict"
        assert not re.search(rf'^{name}\s*=\s*\d+', src, re.M), f"{name} hardcoded"


def test_expected_values():
    assert CANON == {"host_removed": 3, "service_closed": 2,
                     "subdomain_gone": 3, "port_closed": 2}


if __name__ == "__main__":
    test_db_path_reads_the_shared_object()
    test_file_delta_path_imports_not_hardcodes()
    test_expected_values()
    print("all confirmation-threshold SSOT tests PASSED")
