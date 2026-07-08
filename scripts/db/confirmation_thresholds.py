"""4.7 G5/J5b — single source of truth for cross-scan absence-confirmation
thresholds: the number of CONSECUTIVE scans a surface element must be absent
before its REMOVAL is alerted. A degraded/egress-failed scan can't reach a live
element and mis-reports it gone; requiring N consecutive absences (different
runners/tunnels/windows) is the real confirmation.

Imported by BOTH alert paths so they can NEVER drift:
  * scanner/post-email-alerts.py         — file-delta path (host_removed, service_closed, subdomain_gone)
  * scripts/db/import_asm_to_surface.py  — DB-event path (port_closed email gate, 4.7 J5b(c))

Change a value HERE and every consumer updates. Do NOT hand-copy these numbers
into either path — test_confirmation_thresholds.py asserts each import site reads
THIS object (identity, not just value) and breaks on a local redefinition.
"""
from __future__ import annotations

CONFIRMATION_THRESHOLDS: dict[str, int] = {
    "host_removed":   3,   # match subdomain_gone discipline (4.7 G4)
    "service_closed": 2,   # services close more often; smaller blast radius
    "subdomain_gone": 3,   # centralised (was an inline ABSENCE_THRESHOLD)
    "port_closed":    2,   # 4.7 J5b — same tier as service_closed
}
