-- ============================================================================
-- 20260525a — User notification preferences
-- ============================================================================
--
-- New per-user table that holds notification preferences for the /account
-- page. JSONB blobs for vuln + ASM event prefs so we can grow the event
-- catalog without migrations every time we add an event type.
--
-- Full design spec: Obsidian / COMMANDsentry / 39 - Notification Preferences
-- Design Spec.md
--
-- v1 scope: table + RLS. The trigger logic for actually sending emails on
-- events ships in a follow-up.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE
-- ----------------------------------------------------------------------------

create table if not exists public.user_notification_prefs (
  user_id              uuid primary key
                       references auth.users(id) on delete cascade,

  -- One JSONB blob per section. Shape validated in app code (Zod). Default
  -- to '{}' so the app can fall back to sane role-based defaults when a
  -- key is missing.
  vuln_prefs           jsonb not null default '{}'::jsonb,
  asm_prefs            jsonb not null default '{}'::jsonb,

  -- Severity floor — vuln events below this severity are suppressed (except
  -- always-on events: regressions, KEV listings).
  severity_floor       text not null default 'MODERATE'
                       check (severity_floor in
                         ('CRITICAL', 'HIGH', 'MODERATE-HIGH',
                          'MODERATE', 'LOW', 'INFO')),

  -- Asset scope — 'all' assets the user can see (RLS-gated) vs 'specific'
  -- assets only. v1 only supports 'all'; 'specific' UI lands in a later
  -- session. specific_asset_ids is the future filter list.
  asset_scope          text not null default 'all'
                       check (asset_scope in ('all', 'specific')),
  specific_asset_ids   text[] not null default '{}',

  -- Last-edited tracking — for the audit log + the "you saved at <time>"
  -- confirmation on the /account page.
  updated_at           timestamptz not null default now(),
  updated_by           uuid references auth.users(id)
);

comment on table public.user_notification_prefs is
  'Per-user notification preferences. JSONB sections (vuln_prefs, asm_prefs) '
  'hold the per-event cadence map. Read by the email-send paths via '
  'shouldNotifyUser() to decide whether to actually send a given email.';

create index if not exists idx_user_notification_prefs_updated
  on public.user_notification_prefs (updated_at desc);

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
-- Rules:
--   - Authenticated user CAN read their own row
--   - Authenticated user CAN insert/update their own row
--   - Admin role CAN read ALL rows (for the future audit-log view)
--   - Admin role CANNOT edit other users' prefs (privacy boundary —
--     individuals own their notification settings, not admins)
--   - Anon has no access

alter table public.user_notification_prefs enable row level security;

-- SELECT: self OR admin
create policy "own_prefs_select"
  on public.user_notification_prefs
  for select
  to authenticated
  using (
    user_id = auth.uid()
    or exists (
      select 1 from public.user_roles
      where user_roles.user_id = auth.uid()
        and user_roles.role = 'admin'
    )
  );

-- INSERT: only self
create policy "own_prefs_insert"
  on public.user_notification_prefs
  for insert
  to authenticated
  with check (user_id = auth.uid());

-- UPDATE: only self
create policy "own_prefs_update"
  on public.user_notification_prefs
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- No DELETE policy — preferences are not deletable from the UI. If a user
-- is deleted from auth.users, ON DELETE CASCADE removes their row.

-- ----------------------------------------------------------------------------
-- HELPER FUNCTION: get_or_init_notification_prefs
-- ----------------------------------------------------------------------------
-- Returns the user's preferences row, creating it with sensible defaults
-- if it doesn't exist yet. The app calls this on first load of /account so
-- the user sees populated defaults instead of an empty form.
--
-- SECURITY DEFINER because the caller might not yet have an inserted row.
-- The function still enforces that user_id matches auth.uid().

create or replace function public.get_or_init_notification_prefs()
returns public.user_notification_prefs
language plpgsql
security definer
set search_path = public
as $$
declare
  result public.user_notification_prefs;
  caller uuid;
begin
  caller := auth.uid();
  if caller is null then
    raise exception 'auth.uid() is null — not signed in';
  end if;

  -- Try to load the row
  select * into result
  from public.user_notification_prefs
  where user_id = caller;

  -- Initialize on first call
  if not found then
    insert into public.user_notification_prefs (user_id, updated_by)
    values (caller, caller)
    returning * into result;
  end if;

  return result;
end;
$$;

revoke all on function public.get_or_init_notification_prefs() from public;
grant execute on function public.get_or_init_notification_prefs() to authenticated;

comment on function public.get_or_init_notification_prefs is
  'Returns the caller''s notification preferences row, creating it with '
  'database defaults on first call. Use from the /account page so the UI '
  'always has a row to bind to.';
