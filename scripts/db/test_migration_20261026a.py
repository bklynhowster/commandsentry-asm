"""(KB 12 job 3t, 2026-10-26) Migration M: "not responding", then it leaves — the one source.

Howie, 2026-10-26 07:00: "initially we let people know that it's not responding and then after a
certain amount of time we say that it's going off-line and out of the portal". Ruled 07:16 (D1-D7)
and 08:39 (D8-D10). Pinned here: the hold column; the view v_asset_reachability (owned assets;
its clock is the newest liveness ANSWER, never assets.last_alive_at; 24 h to "not responding";
fresh checks required; a held host is never flagged; leaves_on is NULL until the notice is
stamped, then greatest(notice, last answer) + 7 days); authenticated-only reads; the verdict
read policy (the portal could read none of the checks before); pm.unimacgraphics.com held and the
July test host retired, each audited once; the uncalled July function dropped; no dollar quotes
(the runner can't split them); the meta auto-applies. Proven on PostgreSQL 16 in the build note
(the view against a hand-built fleet, two applies, anon denied, a viewer sees what the owner sees).
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261026a_reachability.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _view() -> str:
    v = next(s for s in _stmts() if s.startswith("CREATE OR REPLACE VIEW public.v_asset_reachability"))
    return v


def test_the_statements_in_order():
    want = [
        "ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS dark_hold_reason text",
        "CREATE OR REPLACE VIEW public.v_asset_reachability WITH (security_invoker = true) AS",
        "GRANT SELECT ON public.v_asset_reachability TO authenticated",
        "REVOKE ALL ON public.v_asset_reachability FROM anon",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.v_asset_reachability FROM authenticated",
        "DROP POLICY IF EXISTS asset_liveness_verdict_role_select ON public.asset_liveness_verdict",
        "CREATE POLICY asset_liveness_verdict_role_select ON public.asset_liveness_verdict FOR SELECT TO authenticated USING (public.is_viewer_or_higher())",
        "UPDATE public.assets SET dark_hold_reason =",
        "INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details) SELECT NULL, 'dark_rule_hold',",
        "INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, after_state, details) SELECT NULL, 'retire_test_host',",
        "UPDATE public.assets SET discovery_status = 'retired', last_transition_at = now() WHERE asset_id = 'unreachable-detector-test.invalid'",
        "DROP FUNCTION IF EXISTS public.asset_dark_debounce_state(text)",
    ]
    st = _stmts()
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:120], w)
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_the_clock_is_the_newest_answer_not_the_scan_clock():
    v = _view()
    assert "max(v.probed_at) FILTER (WHERE v.any_port_responded) AS last_answer_at" in v
    assert "last_alive_at" not in v, "last_alive_at is the scan/import clock (Qwen MF1)"


def test_not_responding_is_24h_owned_live_unheld_and_fresh():
    v = _view()
    assert "a.discovery_status = 'confirmed_live' AND a.dark_hold_reason IS NULL" in v
    assert "f.newest_check > now() - interval '12 hours'" in v          # checks must be fresh
    assert "an.last_check_at IS NOT NULL" in v                          # an unprobed host is not flagged
    assert "an.last_answer_at < now() - interval '24 hours'" in v       # D1
    assert "WHERE coalesce(a.ownership, 'unknown') = 'owned'" in v


def test_reason_words_come_from_the_newest_check():
    v = _view()
    assert "WHEN nw.per_port_results ->> '_dns' = 'nxdomain' THEN 'name_gone'" in v
    assert "WHEN an.last_answer_at IS NULL THEN 'never_answered'" in v
    assert "ELSE 'no_answer'" in v
    assert "refused" not in v, "a refused connection is an answer (Howie, 2026-10-25 10:00)"


def test_leaves_on_waits_for_the_notice_and_counts_seven_days():
    v = _view()
    assert ("CASE WHEN a.fade_detected_at IS NULL THEN NULL ELSE greatest(a.fade_detected_at, "
            "coalesce(an.last_answer_at, a.fade_detected_at)) + make_interval(days => "
            "greatest(coalesce(a.dark_patience_override_days, 7), 7)) END AS leaves_on") in v
    # D2 (Qwen code review MF1): an override can lengthen the week, never shorten it
    assert "make_interval(days => coalesce(a.dark_patience_override_days, 7))" not in v


def test_the_hold_and_the_retirement_are_audited_once():
    st = _stmts()
    hold, aud_hold, aud_retire, retire = st[7], st[8], st[9], st[10]
    assert "WHERE asset_id = 'pm.unimacgraphics.com' AND dark_hold_reason IS NULL" in hold
    assert "AND NOT EXISTS (SELECT 1 FROM public.admin_audit_log l WHERE l.action = 'dark_rule_hold'" in aud_hold
    assert "a.discovery_status IS DISTINCT FROM 'retired'" in aud_retire
    assert "AND discovery_status IS DISTINCT FROM 'retired'" in retire


def test_meta_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
