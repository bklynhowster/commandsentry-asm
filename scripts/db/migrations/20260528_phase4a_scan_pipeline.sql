-- ============================================================================
-- 20260528 — Phase 4a scan pipeline foundation
-- ============================================================================
--
-- Foundation for COMMANDsentry's transition from passive ASM (subdomain
-- discovery + service inventory) to active tiered scanning. This migration
-- creates the schema; the worker, GH Action, and portal UI follow in
-- subsequent commits.
--
-- This migration is ADDITIVE ONLY. No existing data is moved, modified, or
-- deleted. Every new column has a default or is nullable. The existing
-- ASM Discover workflow continues to function exactly as before.
--
-- WHAT THIS ADDS:
--   • 4 enums:  scan_intensity_t, scan_status_t, scan_source_t, scan_run_status_t
--   • 4 tables: scan_queue, scan_run, scan_run_artifacts, asset_auth_config
--   • 1 column: assets.scan_cadence_overrides (JSONB)
--   • Indexes for queue polling, artifact cleanup, and history lookups
--   • A partial unique index that enforces "one in-flight scan per asset"
--   • RLS policies wired through public.is_admin() and public.is_asset_owner()
--
-- WHAT THIS DOES NOT DO:
--   • Does not implement the worker (separate Python script in scripts/scanner/)
--   • Does not implement the GH Action (separate .github/workflows/scanner.yml)
--   • Does not implement the portal "Scan Now" button or admin auth-config UI
--   • Does not insert any seed data — empty queue / empty auth_config to start
--
-- Spec: Obsidian / COMMANDsentry / 48 - Phase 4a Spec and Context Handoff.md
-- Locked decisions: see "Locked decisions" section of the spec doc.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260528_phase4a_scan_pipeline.sql
--
-- Safe to re-run — every CREATE uses IF NOT EXISTS or a do-block guard.
-- ============================================================================

begin;

-- ----------------------------------------------------------------------------
-- ENUM: scan_intensity_t — the three tiers
-- ----------------------------------------------------------------------------
-- Drives which tool playbook the worker executes. Asset cadence policy
-- references these values via assets.scan_cadence_overrides JSONB.
--   • light  — passive HTTPS only (TLS cert, headers, common paths, DNS posture)
--   • medium — active recon (nuclei, nikto, ZAP Baseline, Schemathesis, etc.)
--   • heavy  — deep probe (wpscan, testssl, sqlmap, Akto, dalfox, ZAP Full Scan,
--              ysoserial.net, etc.)

do $$
begin
  if not exists (select 1 from pg_type where typname = 'scan_intensity_t') then
    create type public.scan_intensity_t as enum (
      'light',
      'medium',
      'heavy'
    );
  end if;
end $$;

-- ----------------------------------------------------------------------------
-- ENUM: scan_status_t — queue lifecycle states
-- ----------------------------------------------------------------------------
--   • queued    — sitting in scan_queue, waiting for the worker to claim
--   • running   — worker has claimed it, scan_run row exists, tools executing
--   • complete  — scan finished successfully (findings written, run closed out)
--   • failed    — scan errored before completing (error_message populated)
--   • canceled  — admin pulled the plug before completion

do $$
begin
  if not exists (select 1 from pg_type where typname = 'scan_status_t') then
    create type public.scan_status_t as enum (
      'queued',
      'running',
      'complete',
      'failed',
      'canceled'
    );
  end if;
end $$;

-- ----------------------------------------------------------------------------
-- ENUM: scan_source_t — what triggered the scan
-- ----------------------------------------------------------------------------
-- Lets us answer "did the cron miss anything", "who's firing the most ad-hoc
-- scans", and similar audit questions without parsing user metadata.

do $$
begin
  if not exists (select 1 from pg_type where typname = 'scan_source_t') then
    create type public.scan_source_t as enum (
      'manual',             -- user clicked "Scan Now" in the portal
      'cron',               -- scheduled cron tick (cadence-driven)
      'workflow_run',       -- chained after a successful ASM Discover run
      'workflow_dispatch'   -- manual fire from GH Actions UI / gh CLI
    );
  end if;
end $$;

-- ----------------------------------------------------------------------------
-- ENUM: scan_run_status_t — actual execution state (subset of scan_status_t)
-- ----------------------------------------------------------------------------
-- scan_run never sits 'queued' (it's created when the worker claims a queue
-- entry) and is never user-canceled the same way (canceling kills the queue
-- entry, the worker observes that and writes failed). So scan_run has its
-- own narrower enum.

do $$
begin
  if not exists (select 1 from pg_type where typname = 'scan_run_status_t') then
    create type public.scan_run_status_t as enum (
      'running',
      'complete',
      'failed'
    );
  end if;
end $$;

-- ============================================================================
-- TABLE: scan_queue
-- ============================================================================
-- The work queue. Insert here to request a scan; the worker polls every 5 min,
-- atomically claims the oldest 'queued' row (FOR UPDATE SKIP LOCKED), creates
-- a corresponding scan_run, executes, then closes out both rows.

create table if not exists public.scan_queue (
  queue_id             uuid primary key default gen_random_uuid(),
  asset_id             text not null references public.assets(asset_id) on delete cascade,
  intensity            public.scan_intensity_t not null,
  authenticated        boolean not null default false,
  triggered_by_user_id uuid references auth.users(id),
  triggered_at         timestamptz not null default now(),
  scheduled_for        timestamptz not null default now(),
  status               public.scan_status_t not null default 'queued',
  started_at           timestamptz,
  completed_at         timestamptz,
  duration_seconds     integer,
  error_message        text,
  findings_count       integer,
  scan_run_id          uuid,  -- populated once the worker creates the scan_run
  source               public.scan_source_t not null,
  notes                text,

  -- Light tier is passive HTTPS only — authenticated mode doesn't make sense.
  -- Authenticated scans only run at medium or heavy intensity.
  constraint scan_queue_authenticated_implies_active
    check (authenticated = false or intensity in ('medium', 'heavy')),

  -- Sanity: scheduled_for can be at or after triggered_at, never before.
  constraint scan_queue_scheduled_after_triggered
    check (scheduled_for >= triggered_at)
);

comment on table public.scan_queue is
  'Phase 4a scan request queue. Inserts here trigger scans; the worker polls '
  'every 5 min and atomically claims the oldest queued row. One row per scan '
  'request — completed rows are retained for audit, not deleted.';

comment on column public.scan_queue.asset_id is
  'Which asset to scan. Cascade-deletes if the asset is removed.';

comment on column public.scan_queue.intensity is
  'Tier of scan to run: light / medium / heavy. See scan_intensity_t comment.';

comment on column public.scan_queue.authenticated is
  'If true, the worker logs in via asset_auth_config before running the scan. '
  'Only valid for medium/heavy intensity (enforced by check constraint).';

comment on column public.scan_queue.triggered_by_user_id is
  'Which user triggered the scan. NULL for cron / workflow_run / workflow_dispatch.';

comment on column public.scan_queue.scheduled_for is
  'When this scan should run. Defaults to now() for immediate scans; can be '
  'set in the future to defer execution (e.g., off-hours scans).';

comment on column public.scan_queue.status is
  'Lifecycle: queued → running → (complete | failed | canceled).';

comment on column public.scan_queue.scan_run_id is
  'Populated by the worker after it creates the corresponding scan_run row. '
  'NULL while queued; non-NULL once running, complete, or failed.';

comment on column public.scan_queue.source is
  'How this scan was triggered: manual (Scan Now button) / cron / '
  'workflow_run (chained after ASM Discover) / workflow_dispatch.';

-- Index: worker polling — fast lookup of next queued row.
-- "Where status = 'queued'" makes this a partial index, keeping it small
-- even as completed rows accumulate forever.
create index if not exists scan_queue_polling_idx
  on public.scan_queue (scheduled_for)
  where status = 'queued';

-- Index: per-asset scan history lookup ("show all scans for this asset").
create index if not exists scan_queue_by_asset_idx
  on public.scan_queue (asset_id, triggered_at desc);

-- Partial unique index: ENFORCES one in-flight scan per asset.
-- The portal's "Scan Now" button greys out when this index would block a
-- new insert; the worker honors this when atomically claiming rows.
create unique index if not exists scan_queue_one_running_per_asset
  on public.scan_queue (asset_id)
  where status = 'running';

-- Index: admin view of all scans triggered by a specific user.
create index if not exists scan_queue_by_user_idx
  on public.scan_queue (triggered_by_user_id, triggered_at desc)
  where triggered_by_user_id is not null;

-- ============================================================================
-- TABLE: scan_run
-- ============================================================================
-- The execution record. Created by the worker when it claims a queue entry,
-- closed out when the scan finishes (success or failure). Separated from
-- scan_queue so that queue lifecycle (queued/canceled) is distinct from
-- execution lifecycle (running/complete/failed).

create table if not exists public.scan_run (
  scan_run_id       uuid primary key default gen_random_uuid(),
  queue_id          uuid references public.scan_queue(queue_id) on delete set null,
  asset_id          text not null references public.assets(asset_id) on delete cascade,
  intensity         public.scan_intensity_t not null,
  authenticated     boolean not null,
  started_at        timestamptz not null default now(),
  completed_at      timestamptz,
  duration_seconds  integer,
  tools_run         text[] not null default '{}',
  egress_ip         inet,
  vpn_config_used   text,
  github_run_id     text,
  status            public.scan_run_status_t not null default 'running',
  findings_added    integer not null default 0,
  findings_updated  integer not null default 0,
  error_message     text
);

comment on table public.scan_run is
  'Phase 4a scan execution record. One row per actual scan attempt (queue '
  'entry that was claimed by the worker). Retained forever for audit and '
  'historical analysis.';

comment on column public.scan_run.queue_id is
  'FK back to the scan_queue row that triggered this run. Nullable because '
  'queue rows can be deleted (e.g., GDPR scrub of triggering user) without '
  'losing the run history. ON DELETE SET NULL preserves the run record.';

comment on column public.scan_run.tools_run is
  'Array of tool names actually executed (e.g., {nmap, nuclei, nikto, zap}). '
  'Useful for debugging "why did this scan miss X" — if X tool is not in the '
  'array, it never ran on this asset/run.';

comment on column public.scan_run.egress_ip is
  'The egress IP observed at scan start (via curl ifconfig.me through the '
  'VPN tunnel). Required for audit — proves traffic origin if a target ever '
  'pushes back on "who scanned us".';

comment on column public.scan_run.vpn_config_used is
  'Name of the ExpressVPN .ovpn config that was active during this scan. '
  'For Heavy tier, this captures the FIRST config (rotation history is in '
  'the artifacts).';

comment on column public.scan_run.github_run_id is
  'GitHub Actions run ID — link back to the workflow logs for this scan. '
  'Format: https://github.com/bklynhowster/commandsentry-asm/actions/runs/{id}';

comment on column public.scan_run.findings_added is
  'Count of NEW finding rows inserted by this run (status flipped to '
  'detected via the upsert path).';

comment on column public.scan_run.findings_updated is
  'Count of EXISTING finding rows whose last_observed_at was bumped by this '
  'run (re-detected, no status change).';

-- Index: per-asset scan history ("show me every scan that ran on CCC").
create index if not exists scan_run_by_asset_idx
  on public.scan_run (asset_id, started_at desc);

-- Index: lookup by GH run ID (for debugging from a workflow link).
create index if not exists scan_run_by_github_run_idx
  on public.scan_run (github_run_id)
  where github_run_id is not null;

-- Index: queue → run join, for queue-side queries that need run details.
create index if not exists scan_run_by_queue_idx
  on public.scan_run (queue_id)
  where queue_id is not null;

-- ============================================================================
-- TABLE: scan_run_artifacts
-- ============================================================================
-- Raw scan tool outputs (nuclei JSONL, ZAP XML, sqlmap output, testssl JSON,
-- etc.). 90-day retention — long enough for forensic re-analysis, short
-- enough to avoid unbounded growth.
--
-- Storage strategy:
--   • content_jsonb        — inline if structured and < 1 MB
--   • content_storage_path — object storage path otherwise (S3, Supabase Storage)
-- Worker decides at upload time.

create table if not exists public.scan_run_artifacts (
  artifact_id           uuid primary key default gen_random_uuid(),
  scan_run_id           uuid not null references public.scan_run(scan_run_id) on delete cascade,
  tool_name             text not null,
  output_format         text not null,
  size_bytes            integer not null,
  created_at            timestamptz not null default now(),
  expires_at            timestamptz not null default (now() + interval '90 days'),
  content_jsonb         jsonb,
  content_storage_path  text,

  -- Exactly one storage mode populated.
  constraint scan_run_artifacts_one_storage_mode
    check (
      (content_jsonb is not null and content_storage_path is null)
      or (content_jsonb is null and content_storage_path is not null)
    )
);

comment on table public.scan_run_artifacts is
  'Raw scan tool outputs retained for 90 days. Daily cleanup job at 03:00 '
  'UTC deletes rows where expires_at < now(). Inline JSONB for small '
  'outputs, object storage paths for large ones (multi-MB ZAP reports etc.).';

comment on column public.scan_run_artifacts.output_format is
  'Tool-specific format: jsonl / json / xml / txt / log / html. Drives '
  'how the ingestion parser handles re-processing if a tool''s parser changes.';

comment on column public.scan_run_artifacts.size_bytes is
  'Original output size before any compression. Recorded even when inline-'
  'stored so we can compute total storage burden without scanning content.';

comment on column public.scan_run_artifacts.expires_at is
  'When the daily cleanup job will delete this row. Defaults to now() + 90d.';

-- Index: cleanup job scan ("delete where expires_at < now()").
-- Partial — only the rows not yet expired need to be sorted by expiry.
-- Actually no: cleanup needs the EXPIRED rows fast. Index without filter.
create index if not exists scan_run_artifacts_expires_idx
  on public.scan_run_artifacts (expires_at);

-- Index: lookup by scan_run for the UI ("show me every artifact this run produced").
create index if not exists scan_run_artifacts_by_run_idx
  on public.scan_run_artifacts (scan_run_id);

-- ============================================================================
-- TABLE: asset_auth_config
-- ============================================================================
-- Per-asset authenticated DAST configuration. One row per asset that has
-- authenticated scanning configured. The "enabled" flag is the runtime
-- gate — admin / owner must explicitly turn it on after setup completes.
--
-- Credentials NEVER live here. Only the names of GH Action repo secrets
-- that hold the actual username/password. The worker reads those secrets at
-- scan time via the env-var injection that GH Actions does naturally.

create table if not exists public.asset_auth_config (
  asset_id                  text primary key references public.assets(asset_id) on delete cascade,
  login_url                 text not null,
  username_field            text not null default 'Email',
  password_field            text not null default 'Password',
  username_credential_ref   text,
  password_credential_ref   text,
  post_login_check_url      text,
  auth_cookie_name          text,
  custom_login_script_path  text,
  enabled                   boolean not null default false,
  last_tested_at            timestamptz,
  last_test_status          text,
  created_at                timestamptz not null default now(),
  updated_at                timestamptz not null default now(),
  updated_by_user_id        uuid references auth.users(id)
);

comment on table public.asset_auth_config is
  'Per-asset authenticated DAST configuration. Credentials are NOT stored '
  'here — only the NAMES of GH Action repo secrets that hold them. The '
  '"enabled" flag must be explicitly turned on after setup; new rows default '
  'to false to prevent accidental runs against broken configs.';

comment on column public.asset_auth_config.login_url is
  'Full URL of the login form. Worker navigates here with Playwright before '
  'every authenticated scan.';

comment on column public.asset_auth_config.username_credential_ref is
  'NAME of the GH Action repo secret that holds the username (e.g., '
  '"CCC_AUTH_USER"). Worker reads via os.environ at scan time. Never store '
  'the actual credential value here.';

comment on column public.asset_auth_config.password_credential_ref is
  'NAME of the GH Action repo secret that holds the password (e.g., '
  '"CCC_AUTH_PASS"). Worker reads via os.environ at scan time. Never store '
  'the actual credential value here.';

comment on column public.asset_auth_config.post_login_check_url is
  'A URL that returns 200 only when authenticated. Worker fetches this after '
  'login to verify the session is valid before kicking off the scan tools.';

comment on column public.asset_auth_config.auth_cookie_name is
  'Name of the canonical session cookie (e.g., ".SCI.Session"). Used by the '
  'walker to confirm the session is being passed through to downstream tools.';

comment on column public.asset_auth_config.custom_login_script_path is
  'Optional path to a Playwright login script variant for assets with non-'
  'standard auth flows. NULL means use the generic Playwright script.';

comment on column public.asset_auth_config.enabled is
  'Runtime gate. New rows default to false; admin/owner must explicitly turn '
  'on after a successful "Test Login" run in the auth-config UI.';

comment on column public.asset_auth_config.last_tested_at is
  'When the admin last clicked "Test Login" in the auth-config UI.';

comment on column public.asset_auth_config.last_test_status is
  'Result of the last "Test Login" run. e.g., "success", "login_form_not_found", '
  '"credential_rejected", "post_login_check_failed".';

-- updated_at auto-update trigger
create or replace function public.asset_auth_config_touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_asset_auth_config_touch_updated_at
  on public.asset_auth_config;
create trigger trg_asset_auth_config_touch_updated_at
  before update on public.asset_auth_config
  for each row
  execute function public.asset_auth_config_touch_updated_at();

-- ============================================================================
-- ALTER: assets — add scan_cadence_overrides JSONB
-- ============================================================================
-- Per-asset cadence policy. NULL means "use defaults" (Light=daily,
-- Medium=weekly, Heavy=monthly). Non-NULL overrides per tier.
--
-- Schema (worker validates at read time, not enforced at DB level for
-- flexibility):
--   {
--     "light":               "daily" | "weekly" | "monthly" | "quarterly" | "never",
--     "medium":              "daily" | "weekly" | "monthly" | "quarterly" | "never",
--     "heavy":               "daily" | "weekly" | "monthly" | "quarterly" | "never",
--     "heavy_authenticated": "monthly" | "quarterly" | ...   -- only present if auth is configured + enabled
--   }
--
-- Example for CCC:
--   { "light": "daily", "medium": "weekly", "heavy": "monthly", "heavy_authenticated": "monthly" }

alter table public.assets
  add column if not exists scan_cadence_overrides jsonb;

comment on column public.assets.scan_cadence_overrides is
  'Per-asset cadence override. NULL = use defaults (Light=daily, Medium='
  'weekly, Heavy=monthly). Non-NULL specifies cadence per tier. Worker reads '
  'this on every cron tick to decide which tiers to fire on this asset.';

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================
-- Enable RLS on all four new tables and wire through the existing
-- public.is_admin() and public.is_asset_owner() helpers from migration
-- 20260521_user_roles_and_admin_audit.sql + 20260522_asset_owner_role_*.sql.

alter table public.scan_queue           enable row level security;
alter table public.scan_run             enable row level security;
alter table public.scan_run_artifacts   enable row level security;
alter table public.asset_auth_config    enable row level security;

-- ----------------------------------------------------------------------------
-- scan_queue policies
-- ----------------------------------------------------------------------------
-- SELECT: any authenticated user with a role can read (admin, asset_owner,
-- viewer). Worker uses service role and bypasses RLS.
-- INSERT: admins or asset_owners.
-- UPDATE: admins only (workers use service role). Owners can't update
-- to prevent them from manipulating status to bypass concurrency limits.
-- DELETE: no one via RLS — service role only (for GDPR scrubs etc.).

drop policy if exists scan_queue_select on public.scan_queue;
create policy scan_queue_select on public.scan_queue
  for select
  to authenticated
  using (public.has_role('admin') or public.has_role('asset_owner') or public.has_role('viewer'));

drop policy if exists scan_queue_insert on public.scan_queue;
create policy scan_queue_insert on public.scan_queue
  for insert
  to authenticated
  with check (public.is_admin() or public.is_asset_owner());

drop policy if exists scan_queue_update_admin on public.scan_queue;
create policy scan_queue_update_admin on public.scan_queue
  for update
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ----------------------------------------------------------------------------
-- scan_run policies
-- ----------------------------------------------------------------------------
-- Read-only for all roles. Worker writes via service role.

drop policy if exists scan_run_select on public.scan_run;
create policy scan_run_select on public.scan_run
  for select
  to authenticated
  using (public.has_role('admin') or public.has_role('asset_owner') or public.has_role('viewer'));

-- ----------------------------------------------------------------------------
-- scan_run_artifacts policies
-- ----------------------------------------------------------------------------
-- Admin-only SELECT — raw scan output can contain credentials, internal IPs,
-- or other sensitive data. Worker writes via service role. Owners/viewers
-- see the cleaned-up findings, not the raw artifacts.

drop policy if exists scan_run_artifacts_select_admin on public.scan_run_artifacts;
create policy scan_run_artifacts_select_admin on public.scan_run_artifacts
  for select
  to authenticated
  using (public.is_admin());

-- ----------------------------------------------------------------------------
-- asset_auth_config policies
-- ----------------------------------------------------------------------------
-- Admin-only for everything. Asset owners DO NOT manage their own auth
-- config — too sensitive (the credential_ref names are technically not
-- secret but the existence of authenticated scanning is itself a signal).
-- Only the ISMS lead / admin sets these up.

drop policy if exists asset_auth_config_select_admin on public.asset_auth_config;
create policy asset_auth_config_select_admin on public.asset_auth_config
  for select
  to authenticated
  using (public.is_admin());

drop policy if exists asset_auth_config_insert_admin on public.asset_auth_config;
create policy asset_auth_config_insert_admin on public.asset_auth_config
  for insert
  to authenticated
  with check (public.is_admin());

drop policy if exists asset_auth_config_update_admin on public.asset_auth_config;
create policy asset_auth_config_update_admin on public.asset_auth_config
  for update
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

drop policy if exists asset_auth_config_delete_admin on public.asset_auth_config;
create policy asset_auth_config_delete_admin on public.asset_auth_config
  for delete
  to authenticated
  using (public.is_admin());

-- ============================================================================
-- GRANTS
-- ============================================================================
-- Service role bypasses RLS entirely (that's how the worker writes to
-- findings + scan_run + scan_run_artifacts). authenticated role needs basic
-- SELECT grants on top of RLS to be able to read anything.

grant select                            on public.scan_queue           to authenticated;
grant insert (asset_id, intensity, authenticated, triggered_by_user_id, scheduled_for, source, notes)
                                        on public.scan_queue           to authenticated;
grant select                            on public.scan_run             to authenticated;
grant select                            on public.scan_run_artifacts   to authenticated;
grant select, insert, update, delete    on public.asset_auth_config    to authenticated;

commit;

-- ============================================================================
-- POST-APPLY VERIFICATION
-- ============================================================================
-- Run these queries after applying to verify the migration landed cleanly:
--
--   -- Enums exist
--   select typname from pg_type where typname like 'scan_%' order by typname;
--   -- Expected: scan_intensity_t, scan_run_status_t, scan_source_t, scan_status_t
--
--   -- Tables exist
--   select tablename from pg_tables
--     where schemaname = 'public' and tablename like 'scan_%' or tablename = 'asset_auth_config'
--     order by tablename;
--   -- Expected: asset_auth_config, scan_queue, scan_run, scan_run_artifacts
--
--   -- Cadence column on assets
--   select column_name from information_schema.columns
--     where table_name = 'assets' and column_name = 'scan_cadence_overrides';
--   -- Expected: 1 row
--
--   -- Partial unique index — one running scan per asset
--   select indexname from pg_indexes
--     where tablename = 'scan_queue' and indexname = 'scan_queue_one_running_per_asset';
--   -- Expected: 1 row
--
--   -- RLS enabled
--   select tablename, rowsecurity from pg_tables
--     where schemaname = 'public'
--       and tablename in ('scan_queue', 'scan_run', 'scan_run_artifacts', 'asset_auth_config');
--   -- Expected: rowsecurity = true on all 4
-- ============================================================================
