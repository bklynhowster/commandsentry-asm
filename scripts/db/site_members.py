#!/usr/bin/env python3
"""site_members.py — one site, not two: the plain name and its www (KB 12 job 4).

Howie, 2026-10-24 21:44: "it's the same damn box it's the same site. It's the same everything
this has to be fixed as well." Ruled 2026-10-25 08:46 (D1, "Yes"): two names are one site only
on evidence seen on both names, never because of what the names look like.

For every in-scope pair www.X / X (both owned and in the portal's scope; IP addresses and
ranges excluded), each discovery run (asm-discover.yml, every 6 h) looks at both names once:

  * DNS   the set of IPv4 addresses each name resolves to, plus ONE name that cannot exist at
          the www name's level (sentry-site-check-<random>.X). If that resolves, the zone
          answers every name (wildcard DNS) and "same addresses" proves nothing by itself.
  * TLS   the SHA-256 of the leaf certificate each name presents (any certificate; nothing is
          trusted or validated — this is a fingerprint, not a check of the certificate).
  * HTTP  one GET / per name with curl and no -L, so a redirect is read, never followed: the status,
          the Location host, the page title, and a hash of the page once scripts, styles,
          attribute values and long token-like strings are stripped (CSP nonces and anti-
          forgery tokens differ on every load; measured 2026-10-25 on commandcommcentral.com).

The rule (plan v3, Design; plan review M3 and M4, 2026-10-25 08:38, by the checker window, which
was running Claude Sonnet 5.5 although the note was signed GLM-5.3):

    same addresses AND either
      leg 1 'redirect'   one name answers 301/308 and its Location host is exactly the other
                         name (and canonical_host.redirect_target_authorized agrees), or
      leg 2 'same_page'  the same leaf certificate, both answer 2xx, the same title, and the
                         same stripped page (or 98% of its words in the same order)
    -> 'same_site'. Any other complete reading -> 'separate', with the reason.

    Anything that failed (a lookup, a connection, a handshake, a request) -> 'unknown', which
    NEVER changes a stored verdict, in a zone that answers every name too. A pair's first
    verdict is set, and a stored verdict flips, only after TWO definite runs in a row agree on
    it (an 'unknown' in between neither counts nor resets); both runs' readings are kept.

Code review fixes (2026-10-25: Claude Sonnet 5.5 at 10:37, then Qwen3.8 Max blind at 11:23, the
same main defect found by both): a failed request in a wildcard zone was 'separate' and is now
'unknown'; two identical pages with no title compared by title and are now compared by page; the
first verdict needed one run and now needs two; a name with only IPv6 addresses read as "does not
exist" and a permanent redirect to the same name read as evidence, and both are now 'unknown'.

Writes ONLY public.site_members (migration 20261025a). Nothing reads that table until
migration B and push B (plan v3, Design step 0): this push only gathers evidence, which is
read back first. Never changes an asset, a finding or a scan. Env: SUPABASE_DSN or --dsn.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import html as html_lib
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))
from canonical_host import redirect_target_authorized  # noqa: E402  (pure; no network)

UTC = timezone.utc

FLIP_AFTER = 2                    # contrary definite runs in a row before a verdict flips (M3)
SAME_PAGE_RATIO = 0.98            # leg 2 fallback when the stripped hashes differ
PERMANENT = (301, 308)
TIMEOUT_S = 15.0
MAX_BODY = 512 * 1024
FLIPS_KEPT = 10
USER_AGENT = "Mozilla/5.0 (compatible; Sentry-ASM site-check/1.0)"
CONTROL_PREFIX = "sentry-site-check-"


def log(m: str) -> None:
    print(f"[site_members] {m}", flush=True)


# ── PURE: the page ───────────────────────────────────────────────────────────────────────────
_SCRIPT = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.S | re.I)
_STYLE = re.compile(r"<style\b[^>]*>.*?</style\s*>", re.S | re.I)
_ATTR = re.compile(r"""(\s[\w:.-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""")
_TOKEN = re.compile(r"\b[A-Za-z0-9+/_=-]{24,}\b")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.S | re.I)


def strip_page(text: str) -> str:
    """The page with what changes on every load removed: scripts, styles, every attribute value
    (nonces, tokens, cache-busters live there) and long token-like strings. PURE."""
    t = _SCRIPT.sub(" ", text or "")
    t = _STYLE.sub(" ", t)
    t = _ATTR.sub(r"\1", t)
    t = _TOKEN.sub("", t)
    return re.sub(r"\s+", " ", t).strip()


def page_title(text: str) -> str | None:
    m = _TITLE.search(text or "")
    if not m:
        return None
    t = re.sub(r"\s+", " ", html_lib.unescape(m.group(1))).strip()
    return t or None


def page_signature(body: bytes) -> dict:
    """{'title', 'page' (sha256 of the stripped page, 16 hex), 'words' (the stripped words, kept in
    memory only for the 98% comparison; never stored)}. PURE."""
    text = (body or b"").decode("utf-8", errors="replace")
    stripped = strip_page(text)
    return {"title": page_title(text),
            "page": hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:16],
            "words": stripped.split()}


def location_host(location: str | None, own_host: str) -> str | None:
    """The host a Location header points at; a relative Location stays on the same host. PURE."""
    if not location:
        return None
    parts = urlsplit(location.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    return host or own_host.lower().rstrip(".")


def control_name(www_name: str, token: str) -> str:
    """A name that cannot exist at the www name's level: www.portal.x.com -> sentry-site-check-
    <token>.portal.x.com. PURE."""
    rest = www_name[4:] if www_name.lower().startswith("www.") else www_name
    return f"{CONTROL_PREFIX}{token}.{rest}"


# ── PURE: the decision ───────────────────────────────────────────────────────────────────────
def _answered(o: dict) -> bool:
    return o.get("http") == "ok" and isinstance(o.get("status"), int)


def decide(plain: dict, www: dict, zone: dict | None) -> tuple[str, str, str]:
    """(result, leg, reason). result: 'same_site' | 'separate' | 'unknown'. PURE.

    plain / www: one reading per name — {'name', 'dns': 'ok'|'nxdomain'|'error', 'addrs',
    'tls': 'ok'|'error', 'leaf', 'http': 'ok'|'error', 'status', 'location', 'title', 'page',
    'words'}. zone: {'wildcard': bool, 'addrs': [...]} or None when the control lookup failed.
    The zone reading is kept in the evidence (for job 4b) and is never a reason for a verdict:
    a request that failed is not evidence of anything, in a wildcard zone or not."""
    for o in (plain, www):
        if o.get("dns") == "error":
            return "unknown", "", f"the lookup of {o['name']} failed"
        if o.get("dns") == "v6only":
            return "unknown", "", f"{o['name']} has only IPv6 addresses, which this check doesn't read"
    for o in (plain, www):
        if o.get("dns") == "nxdomain":
            return "separate", "", f"{o['name']} does not exist"
    if sorted(plain.get("addrs") or []) != sorted(www.get("addrs") or []):
        return "separate", "", "the two names resolve to different addresses"

    # leg 1: a permanent redirect to exactly the other name. HTTP only; TLS not needed.
    for src, dst in ((www, plain), (plain, www)):
        if _answered(src) and src["status"] in PERMANENT:
            tgt = location_host(src.get("location"), src["name"])
            if tgt == dst["name"].lower():
                ok, why = redirect_target_authorized(src["name"], dst["name"], target_is_known_asset=True)
                if ok:
                    return "same_site", "redirect", f"{src['name']} redirects permanently to {dst['name']}"

    for o in (plain, www):
        if o.get("tls") != "ok":
            return "unknown", "", f"the secure connection to {o['name']} failed"
        if not _answered(o):
            return "unknown", "", f"{o['name']} did not answer"

    # Only a page (2xx) or a permanent redirect is a reading of the site itself. A 403 bot
    # challenge, a sign-in or temporary redirect, a 404 or a 5xx says we did not see the site:
    # 'unknown', never 'separate' (M3; on 2026-10-25 a bot shield answered 403 on all three
    # Pressable sites to one client and the real 200/301 to another).
    def _seen(o):
        return 200 <= o["status"] < 300 or o["status"] in PERMANENT
    for o in (plain, www):
        if not _seen(o):
            return "unknown", "", f"{o['name']} answered HTTP {o['status']}, not its page"
    if plain["status"] in PERMANENT and www["status"] in PERMANENT:
        return "unknown", "", "both names redirect elsewhere; neither shows a page"
    if not (200 <= plain["status"] < 300 and 200 <= www["status"] < 300):
        moved = www if www["status"] in PERMANENT else plain
        tgt = location_host(moved.get("location"), moved["name"])
        if not tgt or tgt == moved["name"].lower().rstrip("."):
            # no Location, or one on the same name (another path, a language page): not a reading
            # of where the site lives
            return "unknown", "", f"{moved['name']} redirects permanently to itself, not to a site"
        return "separate", "", f"{moved['name']} redirects permanently to {tgt}, not to the other name"
    if not plain.get("leaf") or plain.get("leaf") != www.get("leaf"):
        return "separate", "", "the two names present different certificates"
    pt, wt = plain.get("title"), www.get("title")
    if pt != wt:                        # two pages with no title fall through to the page itself
        if pt and wt:
            return "separate", "", "the two names serve different pages (different titles)"
        return "separate", "", "the two names serve different pages (one has a title, the other none)"
    if plain.get("page") == www.get("page"):
        return "same_site", "same_page", "same certificate, same page on both names"
    ratio = difflib.SequenceMatcher(None, plain.get("words") or [], www.get("words") or [],
                                    autojunk=False).ratio()
    if ratio >= SAME_PAGE_RATIO:
        return "same_site", "same_page", f"same certificate, same page on both names ({ratio:.0%} alike)"
    return "separate", "", f"the two names serve different pages ({ratio:.0%} alike)"


def stored_reading(o: dict) -> dict:
    """A reading as kept in the evidence: everything but the in-memory word list. PURE."""
    return {k: v for k, v in o.items() if k != "words"}


def advance(prev: dict | None, result: str, leg: str, reason: str, readings: dict,
            now: datetime) -> dict:
    """The stored row after one run (M3). PURE.

    prev: None, or {'verdict', 'contrary_runs', 'evidence', 'since'} as stored.
    Returns {'verdict', 'last_result', 'contrary_runs', 'evidence', 'since', 'flipped'}.
    contrary_runs counts definite runs in a row that agree with each other and not with the stored
    verdict (or toward a first verdict, when none is stored); at FLIP_AFTER it becomes the verdict."""
    at = now.astimezone(UTC).isoformat(timespec="seconds")
    reading = {"at": at, "result": result, "leg": leg, "reason": reason, "readings": readings}
    ev = dict((prev or {}).get("evidence") or {})
    flips = list(ev.get("flips") or [])
    verdict = (prev or {}).get("verdict")
    since = (prev or {}).get("since")
    contrary = int((prev or {}).get("contrary_runs") or 0)
    basis, pending = ev.get("basis"), ev.get("pending")
    flipped = False

    if result == "unknown":
        pass                                            # never changes the stored state
    elif result == verdict:                             # agrees: refresh the basis
        contrary, basis, pending = 0, reading, None
    else:                                               # no verdict yet, or disagrees with it
        contrary = contrary + 1 if (pending or {}).get("result") == result else 1
        if contrary >= FLIP_AFTER:
            runs = [pending, reading]
            if verdict is None:
                ev["first"] = {"at": at, "to": result, "runs": runs}
            else:
                flips.append({"at": at, "from": verdict, "to": result, "runs": runs})
                flipped = True
            verdict, since, contrary, basis, pending = result, at, 0, reading, None
        else:
            pending = reading

    ev.update({"basis": basis, "last": reading, "pending": pending, "flips": flips[-FLIPS_KEPT:]})
    return {"verdict": verdict, "last_result": result, "contrary_runs": contrary,
            "evidence": ev, "since": since, "flipped": flipped}


# ── NETWORK (thin; patched out in tests) ─────────────────────────────────────────────────────
def _has_ipv6(name: str) -> bool:
    try:
        return bool(socket.getaddrinfo(name, 443, family=socket.AF_INET6, type=socket.SOCK_STREAM))
    except OSError:
        return False


def resolve(name: str) -> tuple[str, list[str]]:
    """('ok', sorted IPv4 addresses) | ('nxdomain', []) | ('v6only', []) | ('error', []).
    A name with IPv6 addresses but no IPv4 one exists: 'v6only', never 'nxdomain' (code review)."""
    try:
        infos = socket.getaddrinfo(name, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME),
                       getattr(socket, "EAI_ADDRFAMILY", socket.EAI_NONAME)):
            return ("v6only", []) if _has_ipv6(name) else ("nxdomain", [])
        return "error", []
    except OSError:
        return "error", []
    addrs = sorted({i[4][0] for i in infos})
    if addrs:
        return "ok", addrs
    return ("v6only", []) if _has_ipv6(name) else ("nxdomain", [])


def _no_trust_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # a fingerprint, not a validation
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_NO_PAGE = {"http": "error", "status": None, "location": None, "title": None, "page": None,
            "words": []}


def leaf_fingerprint(name: str, addr: str) -> tuple[str, str | None]:
    """('ok', sha256 hex[:32]) | ('error', None). One TLS handshake to `addr`, SNI = name; no
    request is sent on it."""
    try:
        with socket.create_connection((addr, 443), timeout=TIMEOUT_S) as raw:
            with _no_trust_context().wrap_socket(raw, server_hostname=name) as s:
                der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return "error", None
    return ("ok", hashlib.sha256(der).hexdigest()[:32]) if der else ("error", None)


def parse_head(head: str) -> tuple[int | None, str | None]:
    """(status, Location) from curl's -D output (one response: redirects are not followed). PURE."""
    status, location = None, None
    for line in (head or "").splitlines():
        line = line.strip()
        if line.upper().startswith("HTTP/") and status is None:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif line.lower().startswith("location:") and location is None:
            location = line.split(":", 1)[1].strip()
    return status, location


def get_page(name: str, addr: str) -> dict:
    """One GET / with curl, pinned to `addr`, WITHOUT -L: a redirect is read, never followed
    (the same probe shape as run_medium._canonical_probe; review Q3 / m1). curl, not Python's
    http.client: on 2026-10-25 Pressable's bot shield answered http.client with a 403
    'Checking your browser...' page on every WordPress site, and curl with the real answer."""
    with tempfile.TemporaryDirectory() as d:
        body_path = os.path.join(d, "body")
        try:
            p = subprocess.run(
                ["curl", "-sS", "--max-time", str(int(TIMEOUT_S)), "-o", body_path, "-D", "-",
                 "-A", USER_AGENT, "--resolve", f"{name}:443:{addr}", f"https://{name}/"],
                capture_output=True, text=True, timeout=TIMEOUT_S + 5)
        except (OSError, subprocess.SubprocessError):
            return dict(_NO_PAGE)
        status, location = parse_head(p.stdout)
        if p.returncode != 0 or status is None:
            return dict(_NO_PAGE)
        try:
            with open(body_path, "rb") as f:
                body = f.read(MAX_BODY)
        except OSError:
            body = b""
    out = {"http": "ok", "status": status, "location": location}
    out.update(page_signature(body))
    return out


def read_name(name: str) -> dict:
    """One full reading of one name: its addresses, one handshake and one GET to the first."""
    o: dict = {"name": name}
    o["dns"], o["addrs"] = resolve(name)
    if o["dns"] != "ok":
        o.update({"tls": "skipped", "leaf": None, **_NO_PAGE, "http": "skipped"})
        return o
    o["tls"], o["leaf"] = leaf_fingerprint(name, o["addrs"][0])
    o.update(get_page(name, o["addrs"][0]))
    return o


def read_zone(www_name: str) -> dict | None:
    status, addrs = resolve(control_name(www_name, uuid.uuid4().hex[:12]))
    if status == "error":
        return None
    return {"wildcard": status == "ok", "addrs": addrs}


# ── DB glue ──────────────────────────────────────────────────────────────────────────────────
# The pairs: www.X and X, both in the portal's scope (the same rule as v_fleet_open_reps's scope
# CTE, migration 20261013a: owned; not ct_ghost / went_dark / retired; unverified only for IP
# and range markers), names only (no IP addresses or ranges). Review m2: www.sciimage.com
# (ct_ghost) gets no row.
Q_PAIRS = """
WITH scope AS (
  SELECT a.asset_id
    FROM public.assets a
   WHERE coalesce(a.ownership, 'unknown') = 'owned'
     AND coalesce(a.discovery_status, 'unverified') <> ALL (ARRAY['ct_ghost', 'went_dark', 'retired'])
     AND coalesce(a.discovery_status, 'unverified') <> 'unverified'
     AND a.asset_id !~ '^[0-9.]+$'
     AND a.asset_id NOT LIKE 'range:%%'
     AND a.asset_id NOT LIKE 'ip-range:%%'
     AND a.asset_id NOT LIKE 'ip:%%'
)
SELECT w.asset_id AS member, p.asset_id AS site
  FROM scope w
  JOIN scope p ON w.asset_id = 'www.' || p.asset_id
 ORDER BY p.asset_id
"""

Q_READ = """
SELECT member_asset_id, verdict, contrary_runs, evidence, since
  FROM public.site_members
"""

Q_UPSERT = """
INSERT INTO public.site_members
  (member_asset_id, site_asset_id, verdict, last_result, contrary_runs, evidence, checked_at, since)
VALUES (%(member)s, %(site)s, %(verdict)s, %(last_result)s, %(contrary)s, %(evidence)s, now(), %(since)s)
ON CONFLICT (member_asset_id) DO UPDATE SET
  site_asset_id = EXCLUDED.site_asset_id,
  verdict       = EXCLUDED.verdict,
  last_result   = EXCLUDED.last_result,
  contrary_runs = EXCLUDED.contrary_runs,
  evidence      = EXCLUDED.evidence,
  checked_at    = EXCLUDED.checked_at,
  since         = EXCLUDED.since
"""


def check_pair(member: str, site: str, prev: dict | None, now: datetime,
               reader=read_name, zone_reader=read_zone) -> dict:
    """Read both names, decide, advance the stored state. Network only through the readers."""
    plain, www = reader(site), reader(member)
    zone = zone_reader(member)
    result, leg, reason = decide(plain, www, zone)
    readings = {"plain": stored_reading(plain), "www": stored_reading(www), "zone": zone}
    row = advance(prev, result, leg, reason, readings, now)
    row.update({"member": member, "site": site})
    return row


def run(conn, dry_run: bool, now: datetime | None = None, reader=read_name,
        zone_reader=read_zone) -> list[dict]:
    from psycopg.types.json import Json
    now = now or datetime.now(UTC)
    with conn.cursor() as cur:
        cur.execute(Q_PAIRS)
        pairs = [(r[0], r[1]) for r in cur.fetchall()]
        cur.execute(Q_READ)
        stored = {r[0]: {"verdict": r[1], "contrary_runs": r[2], "evidence": r[3] or {},
                         "since": r[4].isoformat() if hasattr(r[4], "isoformat") else r[4]}
                  for r in cur.fetchall()}
    log(f"{len(pairs)} www/plain pair(s) in scope; dry_run={dry_run}")
    rows = []
    for member, site in pairs:
        row = check_pair(member, site, stored.get(member), now, reader, zone_reader)
        rows.append(row)
        log(f"{site} / {member}: {row['last_result']} — {row['evidence']['last']['reason']}"
            f" · stored verdict {row['verdict'] or 'none yet'}"
            + (" · FLIPPED" if row["flipped"] else "")
            + (f" · {row['contrary_runs']} contrary run(s)" if row["contrary_runs"] else ""))
    if dry_run:
        conn.rollback()
        return rows
    with conn.cursor() as cur:
        for row in rows:
            cur.execute(Q_UPSERT, {"member": row["member"], "site": row["site"],
                                   "verdict": row["verdict"], "last_result": row["last_result"],
                                   "contrary": row["contrary_runs"], "evidence": Json(row["evidence"]),
                                   "since": row["since"]})
    conn.commit()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="One site, not two: www/plain evidence (KB 12 job 4).")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN", ""))
    ap.add_argument("--dry-run", action="store_true", help="read and decide, write nothing")
    ap.add_argument("--run-tag", default="", help="correlation tag (e.g. GITHUB_RUN_ID); informational")
    args = ap.parse_args()
    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 2
    import psycopg
    if args.run_tag:
        log(f"run-tag={args.run_tag}")
    with psycopg.connect(args.dsn, autocommit=False, connect_timeout=15) as conn:
        run(conn, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
