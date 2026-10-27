"""(KB 12 job 3l round 5, 2026-10-27) Migration 20261027a: the daily's Slack half.

Howie, 08:46: two buttons, "Approve for email" and "Post to Slack", each its own decision.
08:47: the Slack post is a different piece of writing for a different audience.

Pinned here: the channel's own record (slack_told: RLS on, no policies, anon/authenticated
revoked; one row per finding, never shared with the email's digest_told); the Slack half on
digest_pending (nullable, additive, its own status with a CHECK, its own UNIQUE token hash);
the two portal functions are SECURITY DEFINER with an empty search_path, granted to anon and
authenticated only after PUBLIC is revoked; the Post button approves only a waiting, unexpired
post and says why not otherwise; no data changes; no dollar quotes; the meta auto-applies; the
file lands in BOTH databases (stated, plan v2 M5). Proven on PostgreSQL 16 in the build note.
"""
import pathlib
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261027a_digest_slack.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))
sys.path.insert(0, str(DB.parent / "alerter"))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402


def _stmts():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def test_the_statements_in_order():
    want = [
        "CREATE TABLE IF NOT EXISTS public.slack_told (",
        "COMMENT ON TABLE public.slack_told IS",
        "ALTER TABLE public.slack_told ENABLE ROW LEVEL SECURITY",
        "REVOKE ALL ON public.slack_told FROM anon, authenticated",
        "ALTER TABLE public.digest_pending ADD COLUMN IF NOT EXISTS slack_payload jsonb NULL,",
        "ALTER TABLE public.digest_pending DROP CONSTRAINT IF EXISTS digest_pending_slack_status_check",
        "ALTER TABLE public.digest_pending ADD CONSTRAINT digest_pending_slack_status_check CHECK (slack_status IN ('none', 'awaiting', 'approved', 'posting', 'posted', 'superseded', 'failed'))",
        "CREATE UNIQUE INDEX IF NOT EXISTS digest_pending_slack_token_hash_idx ON public.digest_pending (slack_token_hash)",
        "CREATE OR REPLACE FUNCTION public.digest_slack_preview(p_token text)",
        "CREATE OR REPLACE FUNCTION public.digest_slack_approve(p_token text)",
        "REVOKE ALL ON FUNCTION public.digest_slack_preview(text) FROM PUBLIC",
        "REVOKE ALL ON FUNCTION public.digest_slack_approve(text) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.digest_slack_preview(text) TO anon, authenticated",
        "GRANT EXECUTE ON FUNCTION public.digest_slack_approve(text) TO anon, authenticated",
    ]
    st = _stmts()
    assert len(st) == len(want), st
    for s, w in zip(st, want):
        assert s.startswith(w), (s[:160], w)
    assert "$$" not in SQL.split("END-META", 1)[1], "the runner is not dollar-quote aware"


def test_the_record_and_the_columns_are_what_the_alerter_reads_and_writes():
    st = _stmts()
    t = st[0].split("(", 1)[1].strip()
    assert t.startswith("finding_id text PRIMARY KEY, first_told_at timestamptz NOT NULL DEFAULT now(), "
                        "last_full_at timestamptz NOT NULL DEFAULT now(), reminders integer NOT NULL DEFAULT 0, "
                        "closed_seen_at timestamptz NULL, updated_at timestamptz NOT NULL DEFAULT now()")
    cols = st[4]
    for c in ("slack_payload jsonb NULL", "slack_status text NOT NULL DEFAULT 'none'", "slack_token_hash text NULL",
              "slack_approved_at timestamptz NULL", "slack_posted_at timestamptz NULL",
              "slack_attempts integer NOT NULL DEFAULT 0", "slack_error text NULL",
              "slack_finalize jsonb NOT NULL DEFAULT '{}'::jsonb"):
        assert c in cols, c
    assert "slack_token text" not in cols, "the token itself is never stored"
    import run_alerter as ra
    assert "SELECT finding_id, first_told_at, last_full_at, reminders, closed_seen_at FROM public.slack_told" in " ".join(ra.SQL_SLACK_TOLD_READ.split())
    ins = " ".join(ra.SQL_PENDING_INSERT_V2.split())
    assert "slack_payload, slack_status, slack_token_hash, slack_finalize)" in ins


def test_the_functions_run_as_owner_with_no_search_path_and_approve_once():
    st = _stmts()
    for s in st[8:10]:
        assert "SECURITY DEFINER SET search_path TO ''" in s, s[:200]
        assert "FROM public.digest_pending d" in s
    approve = st[9]
    assert "WHERE d.slack_token_hash = t.h AND d.slack_status = ''awaiting'' AND d.expires_at > now()" in approve
    assert "''already approved''" in approve and "''expired''" in approve and "''unknown''" in approve
    assert "status = ''approved''" not in approve.replace("slack_status", ""), "it never touches the email's status"


def test_nothing_deleted_no_data_no_policy():
    low = " ".join(_stmts()).lower()
    for bad in ("delete from", "drop table", "truncate", "insert into", "create policy", "grant all"):
        assert bad not in low, bad
    assert low.count("update public.digest_pending") == 1, "the only UPDATE is the Post button's own, on the Slack half"


def test_meta_is_valid_and_auto_applies():
    meta = migration_meta.parse_meta(SQL)
    assert meta["idempotent"] == "true" and meta["transactional"] == "true"
    assert meta["safe_auto_apply"] == "true" and meta["requires_backup"] == "false"
    assert migration_meta.validate_meta(meta, MIG.name) == []
