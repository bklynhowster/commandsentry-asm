"""(KB 12 job 3m, 2026-10-22) One rating rule: an asset's rating is its single worst open
finding. Howie: "Absolutely." (08:59); Decision 1: "Go with A." (12:36) — the one-time
recompute rides inside migration 20261022a.

Pins: refresh_asset_posture delegates to the trigger's recompute function with the same
signature; maintenance.sql carries the same body (it is the source-of-truth file); the
one-time pass recomputes every asset and clears only the old rule's INFO text under
UNKNOWN; it touches no finding; the meta auto-applies; posture_rollup and import_jsonl
follow the one rule.
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261022a_one_rating_rule.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "normalize"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

FUNC_RE = re.compile(r"CREATE OR REPLACE FUNCTION public\.refresh_asset_posture\(p_asset_id text\).*?';", re.S)


def _stmts():
    return runner._split(SQL)


def test_four_statements_function_comment_and_the_one_time_pass():
    st = _stmts()
    assert len(st) == 4
    assert st[0].startswith("CREATE OR REPLACE FUNCTION public.refresh_asset_posture(p_asset_id text)")
    assert st[1].startswith("COMMENT ON FUNCTION public.refresh_asset_posture(text)")
    assert st[2] == "SELECT public.refresh_all_asset_posture()"
    assert st[3].startswith("UPDATE public.assets")


def test_the_function_only_delegates_to_the_trigger_rule():
    body = _stmts()[0]
    assert "RETURNS void" in body and "LANGUAGE sql" in body
    assert body.endswith("AS 'SELECT public.recompute_asset_current_risk_for(p_asset_id)'")
    assert "$$" not in SQL.split("END-META", 1)[1]          # the runner's splitter knows no $$


def test_one_time_pass_clears_only_the_old_info_text():
    up = " ".join(_stmts()[3].split())
    assert up == ("UPDATE public.assets SET current_risk_reason = NULL WHERE current_risk = 'UNKNOWN' "
                  "AND current_risk_reason = 'no open findings above INFO'")


def test_touches_no_finding_and_drops_nothing():
    low = " ".join(runner._split(SQL)).lower()
    for bad in ("findings set", "delete ", "drop ", "truncate", "alter table", "insert into"):
        assert bad not in low, bad


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta) and migration_meta.is_transactional(meta)


def test_maintenance_sql_carries_the_same_function():
    m = (DB / "maintenance.sql").read_text()
    assert FUNC_RE.search(m).group(0) == FUNC_RE.search(SQL).group(0)
    assert m.count("CREATE OR REPLACE FUNCTION public.refresh_asset_posture") == 1
    assert "CREATE OR REPLACE FUNCTION refresh_asset_posture(" not in m      # the old ladder is gone


def test_refresh_all_still_loops_over_it():
    m = (DB / "maintenance.sql").read_text()
    assert "PERFORM refresh_asset_posture(r.asset_id);" in m


# ── the hand-run paths follow the one rule ───────────────────────────────────
def test_posture_rollup_no_moderate_count_escalation():
    from cs_importers.posture_rollup import compute_asset_verdict
    four = [{"finding_id": f"x{i}", "severity": "MODERATE", "current_status": "open", "title": "t"} for i in range(4)]
    assert compute_asset_verdict(four)[0] == "MODERATE"
    modh = four + [{"finding_id": "y", "severity": "MODERATE-HIGH", "current_status": "open", "title": "t"}]
    assert compute_asset_verdict(modh)[0] == "MODERATE-HIGH"
    resolved = [{"finding_id": "z", "severity": "HIGH", "current_status": "remediated", "title": "t"}]
    risk, reason, _ = compute_asset_verdict(resolved)
    assert risk == "UNKNOWN" and reason == "All 1 previously-detected findings are resolved."
    assert compute_asset_verdict([])[0] == "UNKNOWN"


def test_import_jsonl_never_writes_a_rating_from_the_file():
    src = (DB / "import_jsonl.py").read_text()
    i = src.index("def load_assets(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert 'rec.get("current_risk")' not in body and 'rec.get("current_risk_reason")' not in body
    c = body.index("ON CONFLICT (asset_id) DO UPDATE SET")
    conflict = body[c:body.index('"""', c)]
    assert "current_risk" not in conflict
    assert "SELECT refresh_all_asset_posture()" in src                  # the refresh still sets it
