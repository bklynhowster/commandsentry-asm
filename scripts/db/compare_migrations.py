#!/usr/bin/env python3
"""
compare_migrations.py — cross-instance migration-set divergence report (4.7 Q6, Phase 4).
See SCANNER_MIGRATION_LEDGER_SPEC.md.

Diffs THIS repo's scripts/db/migrations/*.sql against the OTHER instance's, classifies each
divergence against .migration-divergence.yaml, and reports:
   intentional_divergence  ○  accepted instance-first state (context, not action)
   todo_port               ->  queued to port to the other instance (action items)
   UNCLASSIFIED            !!  a migration diverged without being registered — decide: port it,
                              or add it to .migration-divergence.yaml.

Non-blocking visibility tool. Exit 1 ONLY on unclassified divergence, so CI can surface it; wire
the workflow step `continue-on-error: true` to keep it advisory (4.7 Q6).

The OTHER instance's migration list comes from a local checkout (--other-dir, for local runs with
both repos cloned) or the public GitHub contents API (--other-repo owner/repo, for CI). retired/ is
excluded (non-recursive glob).

Usage:
  compare_migrations.py --self-label command --other-label prodex \
      (--other-repo bklynhowster/prodexsentry-asm | --other-dir PATH) \
      [--self-dir scripts/db/migrations] [--divergence-file .migration-divergence.yaml]
Exit: 0 clean | 1 unclassified divergence | 2 usage/fetch error.
"""
import argparse, glob, json, os, sys, urllib.request


def local_migrations(d):
    return {os.path.basename(p) for p in glob.glob(os.path.join(d, "*.sql"))}


def github_migrations(repo):
    url = f"https://api.github.com/repos/{repo}/contents/scripts/db/migrations"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "compare-migrations"})
    with urllib.request.urlopen(req, timeout=25) as r:
        data = json.load(r)
    return {i["name"] for i in data if isinstance(i, dict) and i.get("name", "").endswith(".sql")}


def load_registry(path):
    if not os.path.exists(path):
        print(f"::warning::{path} not found — every divergence will read as UNCLASSIFIED", file=sys.stderr)
        return {}, {}, []
    try:
        import yaml
    except ImportError:
        print("::error::pyyaml required: pip install --break-system-packages pyyaml", file=sys.stderr)
        raise SystemExit(2)
    d = yaml.safe_load(open(path)) or {}
    idv = d.get("intentional_divergence") or {}
    return (idv.get("command_only") or {}), (idv.get("prodex_only") or {}), (d.get("todo_port") or [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-label", required=True, choices=["command", "prodex"])
    ap.add_argument("--other-label", required=True, choices=["command", "prodex"])
    ap.add_argument("--self-dir", default="scripts/db/migrations")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--other-dir")
    g.add_argument("--other-repo")
    ap.add_argument("--divergence-file", default=".migration-divergence.yaml")
    args = ap.parse_args()

    self_migs = local_migrations(args.self_dir)
    try:
        other_migs = local_migrations(args.other_dir) if args.other_dir else github_migrations(args.other_repo)
    except Exception as e:  # noqa
        print(f"::error::could not read the other instance's migrations: {e}", file=sys.stderr)
        return 2

    command_migs, prodex_migs = ((self_migs, other_migs) if args.self_label == "command"
                                 else (other_migs, self_migs))
    command_only = sorted(command_migs - prodex_migs)
    prodex_only = sorted(prodex_migs - command_migs)

    reg_cmd, reg_prx, todo = load_registry(args.divergence_file)
    todo_files = {t.get("migration") for t in todo if isinstance(t, dict)}

    def classify(files, registry):
        intentional, ported, unknown = [], [], []
        for f in files:
            if f in registry:
                intentional.append((f, registry[f]))
            elif f in todo_files:
                ported.append(f)
            else:
                unknown.append(f)
        return intentional, ported, unknown

    ci, cp, cu = classify(command_only, reg_cmd)
    pi, pp, pu = classify(prodex_only, reg_prx)

    print(f"== migration-set divergence: {len(command_only)} Command-only, {len(prodex_only)} Prodex-only "
          f"({len(command_migs & prodex_migs)} shared) ==")
    if ci or pi:
        print("\n  intentional (registered instance-first state):")
        for f, why in ci: print(f"    o command-only  {f}  — {why}")
        for f, why in pi: print(f"    o prodex-only   {f}  — {why}")
    if cp or pp:
        print("\n  -> todo_port (queued to port):")
        for f in cp + pp: print(f"    -> {f}")
    unclassified = cu + pu
    if unclassified:
        print("\n  !! UNCLASSIFIED divergence — port it, or register it in .migration-divergence.yaml:")
        for f in cu: print(f"    !! command-only  {f}")
        for f in pu: print(f"    !! prodex-only   {f}")
        print(f"::warning::{len(unclassified)} unregistered migration divergence(s) — "
              "port to the other instance, or register in .migration-divergence.yaml")
        return 1
    print("\nRESULT: all divergence is registered (intentional or todo_port) — no surprises.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
