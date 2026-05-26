-- ============================================================================
-- 20260526b — Asset decomposition (system-per-subdomain)
-- ============================================================================
--
-- Foundation for Howie's "Flavor 1" architecture: each subdomain that
-- represents a distinct attack surface gets its own asset row, sibling
-- to every other asset in the dashboard list. The apex domain becomes a
-- property, not a parent.
--
-- This migration is ADDITIVE ONLY. No existing data is moved or deleted.
-- All current asset rows continue to work exactly as before. The split
-- itself runs as a separate script (scripts/db/split_assets_by_system.py)
-- with a dry-run mode for review.
--
-- Spec: Obsidian / COMMANDsentry / 43 - Asset Decomposition Design Spec.md
-- ============================================================================

-- ----------------------------------------------------------------------------
-- ENUM: asset_kind_t
-- ----------------------------------------------------------------------------
-- Classifies the kind of system this asset represents. Drives UI icon +
-- color in the asset list, and informs default scan playbooks (don't run
-- web scanners against a mail asset, etc.).

do $$
begin
  if not exists (select 1 from pg_type where typname = 'asset_kind_t') then
    create type public.asset_kind_t as enum (
      'web',       -- website / web app
      'portal',    -- customer-facing portal, often multi-tenant
      'api',       -- API endpoint
      'mail',      -- mail server (smtp, imap, mx)
      'ftp',       -- ftp / sftp
      'staging',   -- *-test / *-staging / *-dev / *-uat variant
      'infra',     -- vpn, jump host, hypervisor admin, etc.
      'unknown'    -- default — refined later
    );
  end if;
end $$;

-- ----------------------------------------------------------------------------
-- ALTER: assets — add new columns (additive, all nullable or defaulted)
-- ----------------------------------------------------------------------------
alter table public.assets
  add column if not exists apex_domain  text,
  add column if not exists kind         public.asset_kind_t not null default 'unknown',
  add column if not exists aliases      text[] not null default '{}',
  add column if not exists parent_apex  text;

comment on column public.assets.apex_domain is
  'The registrable apex this asset rolls up to (e.g., unimacgraphics.com '
  'for portal.unimacgraphics.com). Used for org-level filtering in the '
  'dashboard. NULL for IP-type assets where there is no apex.';

comment on column public.assets.kind is
  'What KIND of system this asset is. Web, portal, mail, ftp, staging, '
  'infra, or unknown. Used for default scan playbooks and UI icons.';

comment on column public.assets.aliases is
  'Alternative names that resolve to the same exact system (e.g., '
  'www.example.com is an alias of example.com). Aliases share findings, '
  'surface, and notification scope with the canonical asset.';

comment on column public.assets.parent_apex is
  'Reserved for edge cases where a subdomain belongs to a different org '
  'than its apex would imply. NULL in normal cases.';

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------
-- Apex filter is the primary new lookup pattern: "show me every asset
-- under unimacgraphics.com". Kind filter is secondary: "show me every
-- mail asset in the fleet".

create index if not exists idx_assets_apex
  on public.assets (apex_domain);

create index if not exists idx_assets_kind
  on public.assets (kind);

-- ----------------------------------------------------------------------------
-- BACKFILL: populate apex_domain for existing rows
-- ----------------------------------------------------------------------------
-- For all existing assets, derive apex_domain from the asset_id where
-- the asset_id is a domain name. IP-type assets get NULL (no apex).
--
-- This is a best-effort heuristic: take the last two dot-segments
-- (works for *.com, *.net, *.org, etc.). Multi-segment TLDs (.co.uk,
-- .com.au) are wrong here — we'll fix those manually if they exist.
-- Today's fleet has none.

update public.assets
set apex_domain =
  case
    when asset_id ~ '^[0-9.]+$' then null  -- IPv4
    when asset_id ~ ':' then null          -- IPv6
    when array_length(string_to_array(asset_id, '.'), 1) >= 2 then
      (string_to_array(asset_id, '.'))[array_length(string_to_array(asset_id, '.'), 1) - 1]
      || '.'
      || (string_to_array(asset_id, '.'))[array_length(string_to_array(asset_id, '.'), 1)]
    else asset_id
  end
where apex_domain is null;

-- ----------------------------------------------------------------------------
-- That's it for the migration. The actual decomposition (creating new
-- asset rows for each detected system) runs as a separate script with
-- dry-run + manual review:
--    scripts/db/split_assets_by_system.py --dry-run
-- ----------------------------------------------------------------------------
