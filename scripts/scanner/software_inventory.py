"""Per-asset software inventory from what the scan already saw (302 step 1).

httpx tech-detect names software with its version ("IIS:10.0",
"jQuery UI:1.12.1") on every light, medium and heavy run. This turns those into
rows in asset_tech_history, the table the portal's "Recent stack changes"
panel reads: one row the first time a product is seen on an asset, one when a
version not seen before appears, nothing when it is simply seen again.

It sends nothing to any target: it only reads httpx output the run already
holds. Only exact versions are kept (no guessing), and a block page is not
the target's software (tech_detect.is_tech_detection_valid).

The write runs inside a SAVEPOINT on the writer's own cursor, so a problem
here rolls back the inventory alone and never the findings written in the
same transaction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from tech_detect import is_tech_detection_valid, tech_rows_from_artifacts

CATEGORY = "web.technology"
SOURCE = "httpx"
CONFIDENCE = "medium"   # a banner or page fingerprint, not a login-side read

# Dotted numbers, a short first part (so a cache-buster timestamp is not a
# version), optionally one trailing letter (OpenSSL 1.1.1k).
VERSION_RE = re.compile(r"^\d{1,4}(?:\.\d{1,6}){0,5}[a-z]?$")


@dataclass(frozen=True)
class Observation:
    product: str
    version: str
    url: str

    @property
    def item_key(self) -> str:
        return self.product.lower()


def observations_from_httpx_rows(rows) -> list[Observation]:
    """Exact product/version pairs from VALID httpx rows. PURE."""
    found: dict[tuple[str, str], Observation] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        valid, _ = is_tech_detection_valid(row)
        if not valid:
            continue
        tech = row.get("tech")
        if not isinstance(tech, list):
            continue
        url = str(row.get("url") or row.get("input") or "")
        for entry in tech:
            if not isinstance(entry, str) or ":" not in entry:
                continue
            name, _, version = entry.rpartition(":")
            name = name.strip()
            if not name or not VERSION_RE.match(version):
                continue
            key = (name.lower(), version)
            if key not in found:
                found[key] = Observation(product=name, version=version, url=url)
    return sorted(found.values(), key=lambda o: (o.item_key, o.version))


def plan_history_rows(observations, recorded) -> list[dict]:
    """Rows to insert, given what asset_tech_history already holds for this
    asset and category as (item_key, version) pairs, oldest first. PURE."""
    seen = {(k, v) for k, v in recorded}
    latest: dict[str, str] = {}
    for k, v in recorded:
        latest[k] = v
    rows = []
    for o in observations:
        key = o.item_key
        if (key, o.version) in seen:
            continue
        prior = latest.get(key)
        rows.append({
            "item_key": key,
            "name": o.product,
            "version": o.version,
            "change_type": "version_changed" if prior is not None else "first_seen",
            "prior_value": {"version": prior} if prior is not None else None,
            "new_value": {"version": o.version, "url": o.url},
        })
        seen.add((key, o.version))
        latest[key] = o.version
    return rows


SELECT_RECORDED_SQL = """
SELECT item_key, version
  FROM public.asset_tech_history
 WHERE asset_id = %(asset_id)s AND category = %(category)s
 ORDER BY observed_at, history_id
"""

# scan_id is deliberately absent: it references the legacy scans table, which
# never holds a scan_run id. The scan_run id goes in notes.
INSERT_HISTORY_SQL = """
INSERT INTO public.asset_tech_history
    (asset_id, category, item_key, name, version, prior_value, new_value,
     change_type, confidence, source, notes)
VALUES (%(asset_id)s, %(category)s, %(item_key)s, %(name)s, %(version)s,
        %(prior_value)s, %(new_value)s, %(change_type)s, %(confidence)s,
        %(source)s, %(notes)s)
"""


def _pair(r):
    if isinstance(r, dict):
        return r["item_key"], r["version"]
    return r[0], r[1]


def record(cur, asset_id, scan_run_id, observations, Json, log=None) -> int:
    """Write the new history rows. Returns how many, or -1 if the inventory
    write failed (rolled back to its savepoint; the caller's transaction and
    its findings are untouched). Never raises."""
    if not observations:
        return 0
    cur.execute("SAVEPOINT software_inventory")
    try:
        cur.execute(SELECT_RECORDED_SQL, {"asset_id": asset_id, "category": CATEGORY})
        recorded = [_pair(r) for r in cur.fetchall()]
        rows = plan_history_rows(observations, recorded)
        for r in rows:
            cur.execute(INSERT_HISTORY_SQL, {
                "asset_id": asset_id,
                "category": CATEGORY,
                "item_key": r["item_key"],
                "name": r["name"],
                "version": r["version"],
                "prior_value": Json(r["prior_value"]) if r["prior_value"] is not None else None,
                "new_value": Json(r["new_value"]),
                "change_type": r["change_type"],
                "confidence": CONFIDENCE,
                "source": SOURCE,
                "notes": f"scan_run {scan_run_id}",
            })
        cur.execute("RELEASE SAVEPOINT software_inventory")
        if log and rows:
            log(f"  software inventory: {len(rows)} new version row(s) of {len(observations)} seen")
        return len(rows)
    except Exception as e:  # noqa: BLE001 — never let the inventory cost the findings
        try:
            cur.execute("ROLLBACK TO SAVEPOINT software_inventory")
        except Exception:
            pass
        if log:
            log(f"  ⚠ software inventory not saved: {type(e).__name__}: {str(e)[:200]}")
        return -1


def record_from_artifacts(cur, ctx, Json, log=None) -> int:
    """The one call each tier's writer makes: inventory from the httpx output
    this run banked in ctx.artifacts ('httpx_tech' / 'httpx')."""
    obs = observations_from_httpx_rows(tech_rows_from_artifacts(getattr(ctx, "artifacts", None)))
    return record(cur, ctx.asset_id, ctx.scan_run_id, obs, Json, log=log)
