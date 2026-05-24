#!/usr/bin/env python3
"""
asset_tech_profile_populator.py — populate assets.tech_profile from on-disk
scan artifacts.

Companion to scan_artifact_walker.py — same parsing logic, but the OUTPUT
goes to the per-asset tech_profile JSONB column (set up by migration
20260522d_asset_tech_profile.sql), not to per-finding columns.

Builds a snapshot like:

  {
    "platform": {
      "web_server": {"name": "nginx", "version": null, "sources": ["nuclei"]},
      "application": {"name": "WordPress", "version": "6.9.4", "sources": ["nuclei","plugin_versions"]}
    },
    "edge": {
      "waf": {"name": "nginxgeneric", "sources": ["nuclei"]}
    },
    "wordpress": {
      "core_version": "6.9.4",
      "plugins": [
        {"slug": "mega_main_menu", "display_name": "Mega Main Menu", "version": "2.2.1"},
        ...
      ]
    }
  }

Also writes a row to asset_tech_history for each observation (first_seen vs
version_changed) so the /assets/[id] page can show a change timeline.

Usage:
  python scripts/normalize/asset_tech_profile_populator.py --dry-run
  python scripts/normalize/asset_tech_profile_populator.py
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def _load_walker_module():
    """Import the walker module so we can reuse its parsers + plugin index."""
    walker_path = Path(__file__).parent / "scan_artifact_walker.py"
    spec = importlib.util.spec_from_file_location("walker", walker_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["walker"] = mod
    spec.loader.exec_module(mod)
    return mod


def build_tech_profile(idx, walker_mod) -> dict:
    """Serialize an ArtifactIndex into the tech_profile JSON shape."""
    profile: dict = {}

    # ── Platform: web server + application
    platform: dict = {}
    if idx.wp_version:
        platform["application"] = {
            "name": "WordPress",
            "version": idx.wp_version,
            "category": "CMS",
            "sources": ["nuclei", "plugin_versions"],
        }
    # Look for web-server hints in extra_tags
    web_server_hints = {"nginx", "apache", "iis", "lighttpd", "caddy"}
    for tag in idx.extra_tags:
        if tag in web_server_hints:
            platform["web_server"] = {"name": tag, "sources": ["nuclei"]}
            break
    if platform:
        profile["platform"] = platform

    # ── Edge: WAF
    if idx.waf:
        profile["edge"] = {"waf": {"name": idx.waf, "sources": ["nuclei"]}}

    # ── WordPress detail (when applicable)
    if idx.wp_version or any(walker_mod.normalize_slug(p.slug) for p in idx.plugins):
        wp: dict = {}
        if idx.wp_version:
            wp["core_version"] = idx.wp_version
        plugins_out: list = []
        for p in sorted(idx.plugins, key=lambda x: x.slug):
            plugins_out.append({
                "slug": p.slug,
                "display_name": walker_mod.display_name_for(p.slug),
                "version": p.version,
                "matched_url": p.matched_url,
                "source": p.source,
            })
        if plugins_out:
            wp["plugins"] = plugins_out
            wp["plugin_count"] = len(plugins_out)
        if wp:
            profile["wordpress"] = wp

    # ── Tags lifted to top level for fleet queries
    if idx.extra_tags:
        profile["tags"] = sorted(idx.extra_tags)

    return profile


def diff_profile(prior: dict, new: dict) -> list[dict]:
    """
    Return a list of asset_tech_history row payloads describing what changed
    between prior and new tech_profile. Each row covers one item.

    Detects:
      - 'first_seen'      — new key/value not in prior
      - 'version_changed' — same item, different version
      - 'removed'         — was in prior, missing from new
    """
    history: list[dict] = []

    # Compare WordPress core version
    prior_wp = (prior.get("wordpress") or {}).get("core_version")
    new_wp = (new.get("wordpress") or {}).get("core_version")
    if new_wp and not prior_wp:
        history.append({
            "category": "application",
            "item_key": "wordpress-core",
            "name": "WordPress",
            "version": new_wp,
            "prior_value": None,
            "new_value": {"version": new_wp},
            "change_type": "first_seen",
            "source": "nuclei",
        })
    elif new_wp and prior_wp and new_wp != prior_wp:
        history.append({
            "category": "application",
            "item_key": "wordpress-core",
            "name": "WordPress",
            "version": new_wp,
            "prior_value": {"version": prior_wp},
            "new_value": {"version": new_wp},
            "change_type": "version_changed",
            "source": "nuclei",
        })

    # Compare WAF
    prior_waf = ((prior.get("edge") or {}).get("waf") or {}).get("name")
    new_waf = ((new.get("edge") or {}).get("waf") or {}).get("name")
    if new_waf and not prior_waf:
        history.append({
            "category": "edge.waf",
            "name": new_waf,
            "prior_value": None,
            "new_value": {"name": new_waf},
            "change_type": "first_seen",
            "source": "nuclei",
        })
    elif new_waf and prior_waf and new_waf != prior_waf:
        history.append({
            "category": "edge.waf",
            "name": new_waf,
            "prior_value": {"name": prior_waf},
            "new_value": {"name": new_waf},
            "change_type": "version_changed",  # treat WAF swap as a version change
            "source": "nuclei",
        })

    # Compare plugins (by slug)
    prior_plugins = {
        p["slug"]: p
        for p in ((prior.get("wordpress") or {}).get("plugins") or [])
    }
    new_plugins = {
        p["slug"]: p
        for p in ((new.get("wordpress") or {}).get("plugins") or [])
    }
    for slug, p in new_plugins.items():
        if slug not in prior_plugins:
            history.append({
                "category": "wordpress.plugin",
                "item_key": slug,
                "name": p.get("display_name") or slug,
                "version": p.get("version"),
                "prior_value": None,
                "new_value": p,
                "change_type": "first_seen",
                "source": p.get("source") or "nuclei",
            })
        else:
            old = prior_plugins[slug]
            if (p.get("version") and old.get("version") and
                    p["version"] != old["version"]):
                history.append({
                    "category": "wordpress.plugin",
                    "item_key": slug,
                    "name": p.get("display_name") or slug,
                    "version": p.get("version"),
                    "prior_value": {"version": old.get("version")},
                    "new_value": {"version": p.get("version")},
                    "change_type": "version_changed",
                    "source": p.get("source") or "nuclei",
                })

    return history


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print proposed updates without writing.")
    parser.add_argument("--folder", help="Override: process this single scan folder. Requires --asset-id.")
    parser.add_argument("--asset-id", help="Asset ID to associate with --folder.")
    args = parser.parse_args()

    try:
        from supabase import create_client
    except ImportError:
        sys.exit("Install deps: pip install supabase  (or activate the .venv used by the synth script)")

    walker = _load_walker_module()
    repo_root = Path(__file__).resolve().parents[2]
    walker.load_env(repo_root)
    sb_url = os.environ.get("SUPABASE_URL", walker.DEFAULT_SUPABASE_URL)
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not sb_key:
        sys.exit("SUPABASE_SERVICE_ROLE_KEY not set (check .env)")
    sb = create_client(sb_url, sb_key)

    if args.folder:
        if not args.asset_id:
            sys.exit("--folder requires --asset-id")
        targets = [(Path(args.folder).expanduser(), args.asset_id)]
    else:
        targets = walker.discover_target_folders(walker.DEFAULT_SCAN_ROOT)

    if not targets:
        sys.exit("No target folders found.")

    print(f"Populator ({'DRY RUN' if args.dry_run else 'WRITING TO DB'}) — {len(targets)} target folder(s)")
    print("=" * 76)

    for folder, asset_id in targets:
        print(f"\n▸ {asset_id}")
        idx = walker.build_index(folder, asset_id)
        new_profile = build_tech_profile(idx, walker)

        # Fetch current profile for diff. maybe_single() in supabase-py can
        # return None (not a response with .data=None) when no row matches,
        # so guard the chain rather than assume .data is always reachable.
        resp = (
            sb.table("assets")
            .select("asset_id, tech_profile, tech_profile_sources")
            .eq("asset_id", asset_id)
            .maybe_single()
            .execute()
        )
        row = getattr(resp, "data", None) if resp is not None else None
        if not row:
            print(f"  ! asset_id not found in DB: {asset_id}")
            continue

        prior = row.get("tech_profile") or {}
        history_rows = diff_profile(prior, new_profile)

        print(f"  Plugins: {len(idx.plugins)} · WP: {idx.wp_version or '—'} · WAF: {idx.waf or '—'}")
        print(f"  History changes detected: {len(history_rows)}")
        for h in history_rows[:5]:
            print(f"    · {h['change_type']:18} {h['category']:25} {h.get('item_key','')} {h.get('version','')}")
        if len(history_rows) > 5:
            print(f"    · ... +{len(history_rows) - 5} more")

        if args.dry_run:
            print(f"  (dry-run — not writing)")
            continue

        # Surface wpvuln in the sources list when wpvulnerability.net data
        # contributed an installed_version for at least one plugin. That
        # signal is what feeds the asset preview's Stack tile "Sources"
        # line ("nuclei, plugin_versions, wpvuln").
        source_set = {"nuclei", "plugin_versions"}
        if any(p.source == "wpvulnerability.net" for p in idx.plugins):
            source_set.add("wpvuln")
        sources = sorted(source_set)
        sb.table("assets").update({
            "tech_profile": new_profile,
            "tech_profile_updated_at": datetime.now(timezone.utc).isoformat(),
            "tech_profile_sources": sources,
            "tech_profile_confidence": "medium",
        }).eq("asset_id", asset_id).execute()

        for h in history_rows:
            h["asset_id"] = asset_id
            sb.table("asset_tech_history").insert(h).execute()

        print(f"  ✓ tech_profile written + {len(history_rows)} history rows")

    print()
    print("=" * 76)
    print("Done." if not args.dry_run else "Done (dry-run).")


if __name__ == "__main__":
    main()
