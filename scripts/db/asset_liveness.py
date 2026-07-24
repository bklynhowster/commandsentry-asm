#!/usr/bin/env python3
"""asset_liveness.py — shared liveness-verdict layer (Obsidian 161, 4.7-ratified 2026-07-24).

ONE source of truth for "is this asset alive", read by BOTH the went_dark demotion writer
(state flip) AND the dark-digest alert suppression, via a single per-sweep verdict in
public.asset_liveness_verdict (4.7 Q4). TWO DISTINCT semantics live here as TWO NAMED
functions, so the subtle difference can never be collapsed into one (4.7 Q3 — the biggest-risk
item; conflating them either false-negatives dark on RST hosts or makes went_dark too permissive):

  * classify_ports_for_state_flip()   — went_dark STATE. A RST ('refused') => 'service_gone'
        (host up, but the service is gone). Bounded lifecycle semantics.
  * has_any_response_for_alive_check() — dark ALERT suppression. ANY TCP reply ('open' OR
        'refused'/RST) => alive, because the HOST answered. A responding box is not "dark"
        (Howie's rule: respond on any port = not dead).

Port outcomes use the demotion_writer vocabulary: 'open' | 'refused' | 'noresponse'. The
classifiers are PURE (no I/O, unit-tested). get_fresh_verdict() is the ONLY read path consumers
use (4.7 Q4 stale-guard): a verdict older than max_age_hours => None => the caller fails safe
(defers) instead of acting on stale liveness. Consumers MUST NOT query the table directly.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = timezone.utc

# ── Asset-type-aware fallback probe ports (4.7 Q2). VERSIONED so drift is visible; the naming
#    heuristic is ADVISORY (order/augment only) — the safe defaults are ALWAYS probed, so a wrong
#    guess can never blind the probe. ────────────────────────────────────────────────────────────
FALLBACK_PORTS_VERSION = "fallback_ports_v1"
FALLBACK_PORTS_REVIEWED = "2026-07-24"
SAFE_DEFAULT_PORTS = (22, 443, 80)                      # union'd into EVERY selection
PORTS_BY_TYPE = {
    "web":  (443, 80),
    "ftp":  (22, 443, 990, 21),                        # SFTP + FTPS + HTTPS + legacy FTP
    "mail": (25, 443, 465, 993, 995),                  # SMTP / SMTPS / IMAPS / POP3S
    "dns":  (53, 443),
}
# First-DNS-label base tokens per asset type (4.7 Q2). Match on the FIRST label with trailing
# digits stripped (mx01->mx, ns1->ns, web02->web) so real infra names hit but lookalikes
# ("mailchimp", "nsx") don't. Advisory only — safe defaults are probed regardless.
_TYPE_BY_BASE = {
    "ftp": "ftp", "sftp": "ftp", "files": "ftp", "transfer": "ftp",
    "mail": "mail", "mx": "mail", "smtp": "mail", "imap": "mail", "pop": "mail",
    "ns": "dns", "dns": "dns", "resolver": "dns",
}


def infer_asset_type(host: str) -> str:
    """Advisory host-type from the FIRST DNS label (4.7 Q2). A HEURISTIC, not empirical evidence —
    used only to order/augment the probe set; safe defaults are always included so a wrong guess
    never blinds the probe. First label, trailing digits stripped (mx01->mx, ns1->ns), looked up
    in _TYPE_BY_BASE. Returns a PORTS_BY_TYPE key, or 'web' (has host) / 'other' (empty)."""
    h = (host or "").strip().lower()
    if not h:
        return "other"
    base = h.split(".", 1)[0].rstrip("0123456789")
    return _TYPE_BY_BASE.get(base, "web")


def select_probe_ports(host: str, known_open_ports=None, asset_type: str | None = None) -> list[int]:
    """Ports to probe for an asset (4.7 Q2): known-open (accumulated empirical evidence) UNION the
    asset-type fallback UNION the safe defaults. De-duped, stable order (known first, then type,
    then defaults) so the most-likely-open ports are hit first."""
    t = asset_type or infer_asset_type(host)
    ordered: list[int] = []
    for group in (known_open_ports or [], PORTS_BY_TYPE.get(t, ()), SAFE_DEFAULT_PORTS):
        for p in group:
            ip = int(p)
            if ip not in ordered:
                ordered.append(ip)
    return ordered


# ── The two NAMED liveness semantics (4.7 Q3). Inputs = probe_port() outcomes. ──────────────────
_RESPONDED = ("open", "refused")           # host answered (ACK or RST)


def has_any_response_for_alive_check(port_results) -> bool:
    """Dark-ALERT suppression semantic (4.7 Q3): the HOST answered on some port => alive => NOT
    dark. ANY 'open' (serving) OR 'refused' (RST = host up, port closed) counts; only all-timeout
    ('noresponse') / empty is "not responding". DELIBERATELY more permissive than the state
    classifier below — a RST box is alive for alerting even though its service is gone for state."""
    return any(r in _RESPONDED for r in (port_results or []))


def classify_ports_for_state_flip(port_results) -> str:
    """went_dark STATE semantic (4.7 Q3) — the CANONICAL logic that demotion_writer.classify_ports
    re-exports (ONE source of truth; prevents the two semantics from drifting, 4.7 risk #1).
    Precedence: any 'open' -> 'alive'; all 'refused' -> 'service_gone' (host up, service gone);
    all 'noresponse' -> 'unreachable'; mixed / empty -> 'service_gone' (bounded beats indefinite)."""
    if not port_results:
        return "service_gone"
    if any(r == "open" for r in port_results):
        return "alive"
    if all(r == "refused" for r in port_results):
        return "service_gone"
    if all(r == "noresponse" for r in port_results):
        return "unreachable"
    return "service_gone"                                  # mixed refused + noresponse


def verdict_booleans(port_results) -> tuple[bool, bool]:
    """Compute the two verdict booleans stored per sweep (4.7 Q4, computed at WRITE time):
    (any_port_responded  -> dark-alert suppression,  open OR refused),
    (any_port_open       -> went_dark state,          open only)."""
    return (has_any_response_for_alive_check(port_results),
            any(r == "open" for r in (port_results or [])))


# ── Shared verdict read path (4.7 Q4 stale-guard) ───────────────────────────────────────────────
DEFAULT_VERDICT_MAX_AGE_H = 12


def is_verdict_fresh(probed_at, now=None, max_age_hours: int = DEFAULT_VERDICT_MAX_AGE_H) -> bool:
    """PURE freshness check (4.7 Q4). A verdict older than max_age_hours is stale => callers must
    NOT act on it (fail-safe defer) — guards against a probe-worker outage driving decisions on
    stale liveness. Naive datetimes are treated as UTC. None => not fresh."""
    if probed_at is None:
        return False
    n = now or datetime.now(UTC)
    if getattr(probed_at, "tzinfo", None) is None:
        probed_at = probed_at.replace(tzinfo=UTC)
    if getattr(n, "tzinfo", None) is None:
        n = n.replace(tzinfo=UTC)
    return (n - probed_at) <= timedelta(hours=max_age_hours)


def get_fresh_verdict(conn, asset_id: str, max_age_hours: int = DEFAULT_VERDICT_MAX_AGE_H,
                      now=None) -> dict | None:
    """THE single read path every consumer uses (4.7 Q4). Returns the latest asset_liveness_verdict
    row for asset_id IFF it is fresh, else None (=> caller defers; never acts on stale liveness).
    The age-guard lives HERE so it can't be forgotten on one code path — consumers must not query
    asset_liveness_verdict directly. Tolerates dict_row or tuple cursors."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT asset_id, sweep_id, probed_at, any_port_responded, any_port_open, "
            "       per_port_results, probe_source "
            "FROM public.asset_liveness_verdict WHERE asset_id = %s "
            "ORDER BY probed_at DESC LIMIT 1",
            (asset_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    if isinstance(row, dict):
        v = row
    else:
        v = {"asset_id": row[0], "sweep_id": row[1], "probed_at": row[2],
             "any_port_responded": row[3], "any_port_open": row[4],
             "per_port_results": row[5], "probe_source": row[6]}
    if not is_verdict_fresh(v["probed_at"], now=now, max_age_hours=max_age_hours):
        return None
    return v
