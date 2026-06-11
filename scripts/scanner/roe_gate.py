"""ROE / ownership gate — PULL-TIME side (the non-bypassable backstop).

Contract: no active scan (intensity ∈ {medium, heavy}) may execute against
an asset unless ownership is on ROE_OWNERSHIP_ALLOWLIST. Light is unaffected.

This is the asm-side gate. The portal has a matching INSERT-time helper
(src/lib/roe.ts::assertActiveScanAllowed) that catches user-session inserts
with a clearer error. But service-role inserts (portal admin client,
Cowork-driven, direct REST) and SQL-Editor inserts BYPASS the portal
helper entirely — this module is what catches those.

Site: called as the FIRST action in run_medium.py / run_heavy.py after
descriptor.json is parsed, BEFORE any target-bound network op (no DNS,
no curl, no tool invocation — nothing). The scan_run row already exists
(created by poll_queue.py). If we block, we UPDATE the scan_run to
failed + error_message='roe_block: ownership=<x>', UPDATE the scan_queue
row to failed (so the watchdog and dashboards see consistent state),
fire a best-effort SendGrid alert via the portal /api/roe-block-alert
endpoint, and return a result the caller branches on.

Caller exit-code policy (advisor 2026-06-11 QA — distinguish routine
refusals from broken-gate states at the GH Actions layer):

  - GateResult.reason == 'ownership_not_allowed' (the namesake / unknown /
    not-on-allowlist case) → routine refusal. The scanner did its job.
    DB stamp + SendGrid alert + GREEN workflow run. Caller EXITS 0.
  - GateResult.reason in {'asset_not_found', 'db_error'} or a thrown
    exception during gate import / execution (the fail-closed-on-
    uncertainty paths) → something is actually broken. The gate refused
    because it couldn't trust the input or the lookup. Caller EXITS 1
    so the run shows RED in GH Actions history.

This split is what makes "Scanner failed" a meaningful signal again.
Without it, routine blocks and real failures look identical, and we
train ourselves to ignore the failure email — which is how a real
failure slips by. Use `GateResult.is_routine_refusal()` to make the
decision in the caller.

Fails CLOSED on any uncertainty: DB error / missing asset / unknown
ownership string / NULL → BLOCK.

Alert is best-effort: the abort decision does NOT depend on whether the
POST to /api/roe-block-alert succeeds. The scan_run audit record is the
durable signal; the email is the visibility surface on top.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional


# ─── Allowlist — bound to LIVE assets.ownership data 2026-06-11 ──────────
# Any expansion needs a documented ROE decision and an update to the
# portal-side ROE_OWNERSHIP_ALLOWLIST in commandsentry-portal/src/lib/roe.ts.
ROE_OWNERSHIP_ALLOWLIST = frozenset({"owned", "test_target"})

# ─── Intensities that REQUIRE the gate ──────────────────────────────────
_ACTIVE_INTENSITIES = frozenset({"medium", "heavy"})

# ─── Portal alert endpoint (best-effort SendGrid delivery) ──────────────
_ROE_ALERT_URL = "https://commandsentry-portal.netlify.app/api/roe-block-alert"


@dataclass
class GateResult:
    """Return shape from check_ownership_or_block(). None = proceed; an
    instance = blocked. Pure data; the gate handles its own DB writes +
    alert dispatch before returning.

    Caller branches exit code on `is_routine_refusal()`:
      - True (ownership_not_allowed) → exit 0, scan was correctly refused.
      - False (asset_not_found, db_error) → exit 1, gate failed closed
        on uncertainty — something is actually broken.
    """

    asset_id: str
    intensity: str
    ownership: Optional[str]
    reason: str  # 'ownership_not_allowed' | 'asset_not_found' | 'db_error'
    message: str

    def is_routine_refusal(self) -> bool:
        """True for the policy-compliant refusal case (ownership_not_allowed).
        False for the fail-closed-on-uncertainty cases (asset_not_found,
        db_error) which indicate a broken gate state and should bubble up
        as a failed workflow run."""
        return self.reason == "ownership_not_allowed"


def check_ownership_or_block(
    conn,
    asset_id: str,
    intensity: str,
    scan_run_id: str,
    queue_id: str,
    github_run_url: Optional[str] = None,
    queue_source: Optional[str] = None,
) -> Optional[GateResult]:
    """Insert-time light scans short-circuit immediately (no DB hit).
    For medium/heavy, fetch assets.ownership and check the allowlist.

    Returns None if the scan is cleared to proceed.
    Returns a GateResult if the scan is blocked. On block:
      1. UPDATE scan_run.status='failed', error_message='roe_block: ...'
      2. UPDATE scan_queue.status='failed', error_message='roe_block: ...'
      3. Best-effort POST to /api/roe-block-alert (NOT load-bearing —
         alert failures do NOT change the abort decision).

    Caller exit-code policy (see module docstring):
      - GateResult.is_routine_refusal()=True → exit 0 (correct refusal).
      - GateResult.is_routine_refusal()=False → exit 1 (gate failed
        closed because something was broken — DB unreachable, asset row
        missing, etc.).

    queue_source: optional pass-through of scan_queue.source so the
    SendGrid alert can surface the actual ingress (e.g., 'manual',
    'workflow_dispatch') instead of a generic "Likely causes" list.
    Pass None when the caller can't read it; the alert template falls
    back gracefully.

    Fails CLOSED — any uncertainty blocks.
    """

    # Light never gates — passive HTTPS only.
    if intensity not in _ACTIVE_INTENSITIES:
        return None

    # ─── Ownership lookup (single SELECT, fails CLOSED on error) ────────
    ownership: Optional[str]
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ownership FROM public.assets WHERE asset_id = %s",
                (asset_id,),
            )
            row = cur.fetchone()
    except Exception as e:
        # DB error — fail closed. We can't even reach the assets table.
        result = GateResult(
            asset_id=asset_id,
            intensity=intensity,
            ownership=None,
            reason="db_error",
            message=f"roe_block: ownership lookup failed for {asset_id}: {e!r}",
        )
        _stamp_failed(conn, scan_run_id, queue_id, result.message)
        _send_alert(result, scan_run_id, queue_id, github_run_url, queue_source)
        return result

    if row is None:
        result = GateResult(
            asset_id=asset_id,
            intensity=intensity,
            ownership=None,
            reason="asset_not_found",
            message=f"roe_block: asset {asset_id} not found in inventory",
        )
        _stamp_failed(conn, scan_run_id, queue_id, result.message)
        _send_alert(result, scan_run_id, queue_id, github_run_url, queue_source)
        return result

    # psycopg row shape — dict_row or tuple-style, handle both
    ownership = row["ownership"] if isinstance(row, dict) else row[0]

    if ownership not in ROE_OWNERSHIP_ALLOWLIST:
        result = GateResult(
            asset_id=asset_id,
            intensity=intensity,
            ownership=ownership,
            reason="ownership_not_allowed",
            message=(
                f"roe_block: ownership={ownership!r} not on active-scan allowlist "
                f"(owned, test_target) for {asset_id}"
            ),
        )
        _stamp_failed(conn, scan_run_id, queue_id, result.message)
        _send_alert(result, scan_run_id, queue_id, github_run_url, queue_source)
        return result

    # Allowlisted — proceed. Light short-circuit happened above.
    return None


# ─── Internal helpers ───────────────────────────────────────────────────


def _stamp_failed(conn, scan_run_id: str, queue_id: str, message: str) -> None:
    """Mark BOTH scan_run and scan_queue rows failed with the roe_block
    message. Wrapped in try/except so the gate stays best-effort on the
    audit write too — the caller still exits non-zero either way."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.scan_run
                   SET status         = 'failed',
                       completed_at   = now(),
                       error_message  = %s
                 WHERE scan_run_id    = %s
                """,
                (message, scan_run_id),
            )
            cur.execute(
                """
                UPDATE public.scan_queue
                   SET status         = 'failed',
                       completed_at   = now(),
                       error_message  = %s
                 WHERE queue_id       = %s
                """,
                (message, queue_id),
            )
        conn.commit()
    except Exception as e:
        # Best-effort. If the audit write fails, the caller still exits
        # non-zero and the workflow will mark the run failed at that
        # level. The 20260531a sync trigger will not fire (no scan_run
        # terminal transition), but the queue row will be visible as
        # stale to the next watchdog cycle.
        print(f"[roe_gate] _stamp_failed write failed: {e!r}")
        try:
            conn.rollback()
        except Exception:
            pass


def _send_alert(
    result: GateResult,
    scan_run_id: str,
    queue_id: str,
    github_run_url: Optional[str],
    queue_source: Optional[str] = None,
) -> None:
    """Best-effort POST to portal /api/roe-block-alert. Always swallows
    exceptions. The abort decision NEVER depends on this succeeding."""
    from datetime import datetime, timezone

    token = os.environ.get("ROE_ALERT_TOKEN")
    if not token:
        print("[roe_gate] ROE_ALERT_TOKEN not set — skipping alert (gate still aborted)")
        return

    payload = {
        "asset_id": result.asset_id,
        "intensity": result.intensity,
        "ownership": result.ownership,
        "reason": result.reason,
        "scan_run_id": scan_run_id,
        "queue_id": queue_id,
        "github_run_id": github_run_url,
        "queue_source": queue_source,
        # UTC timestamp of the block — the alert template surfaces it so
        # operators know WHEN, not just what. Coverage-watchdog already
        # follows this pattern; ROE alerts mirror it.
        "blocked_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        import requests  # lazy import; scanner image bakes it in
    except Exception as e:
        print(f"[roe_gate] requests not available — skipping alert: {e!r}")
        return

    try:
        r = requests.post(
            _ROE_ALERT_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload),
            timeout=10,
        )
        if 200 <= r.status_code < 300:
            print(f"[roe_gate] alert delivered ({r.status_code})")
        else:
            print(
                f"[roe_gate] alert non-2xx: {r.status_code} — gate still aborted "
                f"(body: {r.text[:200]})"
            )
    except Exception as e:
        print(f"[roe_gate] alert POST failed: {e!r} — gate still aborted")
