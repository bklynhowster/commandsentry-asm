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


# ── discovery_status verdict — ASM ingestion + light-scan write-back share ONE rule (Obsidian 224)
# The confirmed_live / dns_only / ct_ghost verdict, hoisted out of import_asm_to_surface.py so the
# light-scan completion write-back (run_light.close_out) can promote on the EXACT same rule the ASM
# ingestion uses — no drift between "discovery said live" and "a scan said live". This closes the
# manual-add invisibility bug: a portal manual-add inserts the asset as 'unverified' and queues a
# LIGHT scan, but nothing ran the ASM ingestion, so discovery_status was never promoted and the
# portal (which surfaces only confirmed_live) filtered the asset out forever.
def discovery_status_from_service_count(svc_count: int, host_count: int = 0,
                                        is_apex: bool = False) -> str:
    """PURE discovery_status verdict (mirrors import_asm_to_surface.py's Gate #1, note 93).
    SIGNAL = service_count (naabu open ports), NOT HTTP-reachability: DNS-only infra
    (ns01/ns02: svc=1, alive=False) must stay confirmed_live, so a service answering wins.
      * svc_count > 0                    -> 'confirmed_live'  (a service answered — wins outright)
      * else is_apex OR host_count > 0   -> 'dns_only'        (resolved to a host, no service)
      * else                             -> 'ct_ghost'        (never resolved — passive/CT phantom)
    Promote-only consumers (the light-scan write-back) check `== 'confirmed_live'` and act only
    then, so the dns_only/ct_ghost split is irrelevant to — and safe on — the promote-only path."""
    if int(svc_count or 0) > 0:
        return "confirmed_live"
    if is_apex or int(host_count or 0) > 0:
        return "dns_only"
    return "ct_ghost"


# ── U7: the ALIVE CLOCK (relay 155/158, 2026-09-15) ─────────────────────────────────────────────
#
# ⛔ THE DEFECT. `assets.last_alive_at` was bumped in exactly two places, and both are
# DISCOVERY: the ASM importer's UPSERTs, and run_light's promote branch — which is gated
# `WHERE discovery_status IN ('ct_ghost','unverified','dns_only')`. Once an asset is
# confirmed_live the row stops matching, so light stops bumping it; medium and heavy never
# wrote to `assets` at all (grep: zero `UPDATE public.assets` in either).
#
# Result, measured 2026-09-15: www.prodexlabs.com had six completed scans and forty
# liveness verdicts since 2026-09-05 and still read "last observed Sep 5" on its own page —
# and asm_cron declared the company website DARK on 09-12, three days after a heavy scan of
# it. Command: 6 of 53 confirmed_live assets carry last_observed > 7d, 4 of them scanned
# this week, 5 probe-alive in the last 24h.
#
# THE RULE (Howie's, via 155): the alive clock is bumped by EVERY observation that got an
# answer — regardless of discovery_status. The promote-only filter stays on the
# discovery_status CHANGE (the no-downgrade rule is untouched); it must not gate the clock.
#
# ⚠ DELIBERATELY SEPARATE FROM `last_probe_alive_at` (161 Q6). That one is the PROBE clock,
# written only when the dark gate rescues a stale asset — a rescue record, not a freshness
# record. 155 ② says do not fold them. The portal composes all three at read time.
ALIVE_CLOCK_SQL = (
    "UPDATE public.assets SET last_alive_at = GREATEST(last_alive_at, now()) "
    "WHERE asset_id = %s"
)

# Medium runs no naabu, so it has no svc_count — see observation_proves_alive().
# httpx IS an HTTP prober: a clean httpx run means the host answered on 80/443.
#
# ⛔ REACHABILITY = PRODUCED **AND** ROUTED. Two halves, and the first draft of this
# comment stated only the first one — wrongly. It said a bare "httpx" is marked by
# NO tier. 4.7 measured and corrected it (relay 166): **run_heavy DOES mark "httpx"**
# (run_heavy.py:953 `tool_name = "httpx"`, then mark_tool_ok/degraded via that
# variable). The drop was right; the stated reason was false, and a false reason in a
# comment is what the next person acts on.
#
# The real reason is the SECOND half — which runner passes `tool_status` to
# bump_alive_clock at all:
#
#     runner       marks                 passes to bump_alive_clock   reachable here
#     run_light    "httpx_tech"          svc_count  (:3109)           NO
#     run_medium   "httpx[-td]"          tool_status (:5027)          YES
#     run_heavy    "httpx"     (:953)    svc_count  (:2995)           NO
#
# ⇒ EXACTLY ONE NAME IS REACHABLE TODAY: "httpx[-td]". Calling the pair below "the
#   complete set" would be wrong. "httpx_tech" is retained as forward-compatibility,
#   not as a claim that it matches anything.
#
#   "httpx[-td]"   run_medium. Marked ok ONLY when httpx returned parseable content
#                  (run_medium.py:2516/2586/2599 degrade on no output / rc!=0 / no
#                  signal), so `ok` is an ANSWER, not the absence of a crash.
#   "httpx_tech"   run_light. Genuinely produced; unreachable because light routes
#                  svc_count. Correct in advance if light is ever routed here. If that
#                  has not happened by the time you read this, delete it rather than
#                  leave it decorative.
#
# ⛔ THE FAILURE MODE THIS TUPLE CREATES, and why a test guards it instead of a
# comment (4.7, relay 166). The plausible future change is HEAVY falling back to
# tool_status when naabu is blocked — a WAF blocking naabu while the host answers
# HTTP is not hypothetical on the FortiGate fleet. On that day heavy routes
# tool_status carrying "httpx", this tuple does not contain it,
# observation_proves_alive returns False, the clock is never bumped, and the host
# drifts toward looking DARK. Silent, and exactly the class we spent 2026-09-15
# fixing. test_a_runner_that_routes_tool_status_must_have_its_probe_names_here
# fails the build on that change instead of waiting for the asset to fade.
_HTTP_PROBE_TOOLS = ("httpx_tech", "httpx[-td]")
_TOOL_OK = ("ok", "success", "complete", "completed")


def observation_proves_alive(svc_count=None, tool_status=None) -> bool:
    """Did THIS completed scan actually get an answer from the host?

    PURE. The caller supplies whichever evidence its tier has:

      light / heavy  svc_count — naabu open ports, the SAME signal
                     discovery_status_from_service_count() uses to promote.
      medium         tool_status — ⛔ medium runs NO naabu and has no svc_count, so
                     relay 155's "svc_count > 0, the same signal the promote uses"
                     cannot be applied there. Its honest equivalent is a clean httpx
                     run: httpx is an HTTP prober, so httpx=ok means the host
                     responded on 80/443. Anything weaker (e.g. "close_out was
                     reached") would assert liveness from the absence of a crash,
                     which is the precise error class this whole lane exists to kill.

    Returns False on no evidence. A scan that cannot show an answer must not move the
    clock — an unbumped clock is recoverable, a falsely-bumped one hides a dead host.
    """
    if svc_count is not None:
        try:
            if int(svc_count) > 0:
                return True
        except (TypeError, ValueError):
            pass
    if tool_status:
        for tool in _HTTP_PROBE_TOOLS:
            st = tool_status.get(tool)
            if isinstance(st, str) and st.strip().lower() in _TOOL_OK:
                return True
            if isinstance(st, dict) and str(st.get("status", "")).strip().lower() in _TOOL_OK:
                return True
    return False


def bump_alive_clock(cur, asset_id: str, *, svc_count=None, tool_status=None, logfn=None) -> bool:
    """Run ALIVE_CLOCK_SQL iff this observation proves the host answered.

    Returns True if the UPDATE ran. Caller supplies an open cursor — this module stays
    psycopg-free so the scanners' lazy-psycopg pattern is preserved.
    """
    if not observation_proves_alive(svc_count=svc_count, tool_status=tool_status):
        return False
    cur.execute(ALIVE_CLOCK_SQL, (asset_id,))
    if logfn:
        logfn(f"alive-clock: bumped last_alive_at for {asset_id} "
              f"(svc_count={svc_count}, http_probe={'yes' if tool_status else 'n/a'})")
    return True


# ── Shared verdict read path (4.7 Q4 stale-guard) ───────────────────────────────────────────────
DEFAULT_VERDICT_MAX_AGE_H = 12



# ── U6: RESURRECTION HOOK (relay 147/158; MOVED HERE from import_asm_to_surface 167/169) ────
#
# ⛔ IT LIVES HERE, NOT IN THE IMPORTER, BECAUSE THAT WAS THE DEFECT. Q7 audit (4.7, relay 167):
# resurrect_if_dark was defined and called in import_asm_to_surface.py ONLY. All three scanners
# call bump_alive_clock (which has NO discovery_status filter, by design) and none of them could
# resurrect, because they cannot import the importer. So a dark asset that was scanned and
# answered stayed `went_dark` with a fresh `last_alive_at` — "dead" and "answered a minute ago"
# in the same row, permanently, since the only resurrection path was ASM discovery.
#
# ⚠ THE REACHABLE PATH WAS THE MOST HUMAN ONE. Automatic enqueueing filters to confirmed_live
# (enqueue-fleet.yml:140, seed-device-class.yml:89) — but that filter exists for AUTHORIZATION
# SCOPE and protected us only by coincidence. The per-asset RUN SCAN button has no status filter
# at all. The sequence is: someone distrusts a "dark" label, presses Run Scan to check, the scan
# succeeds, and the card still says dark. After 2026-09-15 that distrust is the correct instinct.
#
# ⇒ Placed immediately after bump_alive_clock ON PURPOSE. They are two halves of one observation
#   and the next person must not be able to take one without the other.
#
# ⛔ WHY IT MUST EXIST BEFORE demotion_writer --write-enable. UPSERT_ASSET's no-downgrade CASE
# promotes ONLY from ('ct_ghost','unverified','dns_only'). A dark asset is not in that list, so
# once anything marks an asset dark, re-observing it live NEVER brings it back — the importer
# has no path to undo a demotion. demotion_writer.py's own docstring lists this hook as a
# required companion change; it was never built, which is why that gate has sat OVERDUE since
# 2026-07-26.
#
# ⚠ BOTH DARK VOCABULARIES. The CHECK constraint (20260711a_asset_lifecycle_p1_columns.sql:52)
# admits 'confirmed_dark' AND 'went_dark'. demotion_writer writes 'went_dark'; the one dark row
# on Command today is 'confirmed_dark'. A hook matching only 'went_dark' would strand every
# 'confirmed_dark' asset permanently. Matching both is not defensive padding — it is the
# difference between a reversible and an irreversible state today.
#
# SINGLE SET, one statement, so the transition is atomic:
#   resurrection_count += 1      how many times this asset has come back
#   went_dark_at      -> NULL    it is not dark now
#   fade_detected_at  -> NULL    the countdown that led here is void
#   dark_reason       -> NULL    the reason no longer holds
#   last_transition_at -> now()  the lifecycle audit clock
#   discovery_status  -> 'confirmed_live'
#
# The caller gates on `disc == 'confirmed_live'`, which is itself derived from
# service_count > 0 — so "re-observed with at least one responding service" is already
# established before this runs. It does NOT fire on a dns_only/ct_ghost re-observation.
_DARK_STATUSES = ("confirmed_dark", "went_dark")

RESURRECT_ASSET_SQL = """
UPDATE public.assets
SET discovery_status   = 'confirmed_live',
    resurrection_count = COALESCE(resurrection_count, 0) + 1,
    went_dark_at       = NULL,
    fade_detected_at   = NULL,
    dark_reason        = NULL,
    last_transition_at = now()
WHERE asset_id = %(asset_id)s
  AND discovery_status = ANY(%(dark_statuses)s)
RETURNING resurrection_count;
"""


def resurrect_if_dark(cur, asset_id: str, logfn=None) -> int | None:
    """Bring a dark asset back on a live re-observation. Returns the new
    resurrection_count, or None if the asset was not dark (the overwhelmingly common
    case — the WHERE simply matches nothing and this is a no-op)."""
    cur.execute(RESURRECT_ASSET_SQL,
                {"asset_id": asset_id, "dark_statuses": list(_DARK_STATUSES)})
    row = cur.fetchone()
    if not row:
        return None
    n = row[0] if not isinstance(row, dict) else row.get("resurrection_count")
    if logfn:
        logfn(f"resurrection: {asset_id} was dark, re-observed live "
              f"(resurrection_count={n}) — went_dark_at/fade_detected_at/dark_reason cleared")
    return n

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


# ── Dark-signal gate (Obsidian 161 step 3, 4.7 Q1/Q4/Q6) ────────────────────────────────────────
def gate_dark_decision(verdict: dict | None) -> str:
    """PURE two-signal gate (4.7 Q1). Given the fresh liveness verdict for an already-STALE dark
    candidate, decide what the dark signal should do:
      * verdict is None (no fresh verdict) -> 'defer'   — don't alert on staleness alone (4.7 Q4
            fail-safe; a probe-worker gap must never manufacture a dark alert).
      * any_port_responded is True        -> 'suppress' — the HOST answered on some port; it is not
            dead (Howie's rule). Do not alert; heal the clock.
      * any_port_responded is False        -> 'emit'     — stale AND the probe confirms no response
            = genuinely dark.
    Staleness is assumed already true (only stale assets reach here); this adds the second signal."""
    if verdict is None:
        return "defer"
    return "suppress" if verdict.get("any_port_responded") else "emit"


def apply_liveness_gate(dark_events, live, get_verdict, heal=None, logfn=print):
    """Gate candidate dark events on the shared liveness verdict (4.7 Q1/Q4/Q6). PURE of DB: the
    caller injects `get_verdict(asset_id) -> verdict|None` and `heal(asset_id) -> None` (bump
    last_probe_alive_at). Each event needs an 'asset_id'.
      * DRY-RUN (live=False): LOG the would-decision for every candidate, return the events
        UNCHANGED (zero behaviour change, no heal) — this is the 7d soak (4.7 Q7).
      * LIVE: return only the 'emit' (genuinely-dark) events; suppress the rest; heal each
        probe-alive suppression (never a 'defer').
    Returns the list of events that should proceed to emission."""
    kept, counts = [], {"emit": 0, "suppress": 0, "defer": 0, "heal": 0}
    for ev in dark_events:
        a = ev.get("asset_id")
        v = get_verdict(a)
        d = gate_dark_decision(v)
        counts[d] += 1
        detail = (f"responded={v.get('any_port_responded')},open={v.get('any_port_open')}"
                  if v else "no fresh verdict")
        logfn(f"[liveness-gate] {a}: {d} ({detail})" + ("" if live else " [dry-run]"))
        if d == "emit":
            kept.append(ev)
        elif live and d == "suppress" and heal is not None:
            heal(a)
            counts["heal"] += 1
    mode = "LIVE" if live else "DRY-RUN"
    tail = "" if live else f" — returning all {len(dark_events)} unchanged"
    logfn(f"[liveness-gate] {mode}: emit={counts['emit']} suppress={counts['suppress']} "
          f"defer={counts['defer']} heal={counts['heal']}{tail}")
    return kept if live else list(dark_events)
