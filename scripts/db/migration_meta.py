#!/usr/bin/env python3
"""
migration_meta.py — parse + validate the MIGRATION-META header (4.7 Q4, 2026-07-10).
See SCANNER_MIGRATION_LEDGER_SPEC.md.

Every NEW migration (one not yet in schema_migrations) must carry a machine-readable header so
the tooling can reason about it without guessing:

  -- MIGRATION-META:
  --   idempotent: true            # safe to re-run (IF NOT EXISTS / ON CONFLICT / guarded)
  --   transactional: true         # wrapped in BEGIN/COMMIT (false for standalone ALTER TYPE ADD VALUE)
  --   safe_auto_apply: false      # true => migrate.yml may auto-apply (requires idempotent + transactional)
  --   requires_backup: false      # true => pre-apply backup / manual approval
  --   estimated_duration_ms: 100
  --   notes: <one line>
  --   idempotent_reason: <text>   # REQUIRED when idempotent: false (e.g. one-time data backfill)
  -- END-META

Grandfathered migrations already in the ledger are never re-validated (Phase 1 backfill), so the
header requirement only bites on migrations added from here forward.
"""
import re

REQUIRED = ["idempotent", "transactional", "safe_auto_apply", "requires_backup",
            "estimated_duration_ms", "notes"]
BOOLS = ["idempotent", "transactional", "safe_auto_apply", "requires_backup"]


def parse_meta(sql_text):
    """Return a dict of the MIGRATION-META block, or None if no header is present."""
    m = re.search(r"--\s*MIGRATION-META:\s*(.*?)--\s*END-META", sql_text, re.S | re.I)
    if not m:
        return None
    meta = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line.startswith("--"):
            continue
        line = line[2:].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        # strip a trailing '# comment' on the value
        v = v.split("#", 1)[0].strip()
        meta[k.strip().lower()] = v
    return meta


def _as_bool(v):
    return str(v).strip().lower() in ("true", "yes", "1")


def validate_meta(meta, filename):
    """Return a list of error strings ([] means valid)."""
    if meta is None:
        return [f"{filename}: missing MIGRATION-META header (required on new migrations)"]
    errs = []
    for k in REQUIRED:
        if k not in meta or meta[k] == "":
            errs.append(f"{filename}: MIGRATION-META missing required key '{k}'")
    for k in BOOLS:
        if k in meta and str(meta[k]).strip().lower() not in ("true", "false", "yes", "no", "1", "0"):
            errs.append(f"{filename}: MIGRATION-META '{k}' must be true/false (got '{meta[k]}')")
    if "idempotent" in meta and not _as_bool(meta["idempotent"]) and not meta.get("idempotent_reason"):
        errs.append(f"{filename}: idempotent:false requires an idempotent_reason (justify the non-idempotent migration)")
    if _as_bool(meta.get("safe_auto_apply", "false")):
        if not _as_bool(meta.get("idempotent", "false")):
            errs.append(f"{filename}: safe_auto_apply:true requires idempotent:true")
        if not _as_bool(meta.get("transactional", "false")):
            errs.append(f"{filename}: safe_auto_apply:true requires transactional:true (else migrate.yml can't wrap it)")
    if meta.get("estimated_duration_ms"):
        try:
            int(str(meta["estimated_duration_ms"]).strip())
        except ValueError:
            errs.append(f"{filename}: estimated_duration_ms must be an integer (got '{meta['estimated_duration_ms']}')")
    return errs


def is_safe_auto_apply(meta):
    return bool(meta) and _as_bool(meta.get("safe_auto_apply", "false"))


def is_transactional(meta):
    return bool(meta) and _as_bool(meta.get("transactional", "true"))
