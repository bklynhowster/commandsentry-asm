"""(KB 12, 2026-11-12) Migration 20261112a: the attack test is switched on for
pulse.uat.prodexlabs.com, and for nothing else.

Howie, 11:31: "Why in the world are there any circumstances where there's an asset that we see on
the site, yet it's not authorized to scan?" 11:50: look where the names point first. 11:55, to
switching this one on: "Yes". The switch is the one place a person confirms the server behind a
name is ours (D-064), so this file names one asset and leans on one fact: it shares its address
with uat.prodexlabs.com, which is already switched on.

Pinned here: one UPDATE, on public.assets, of exactly the two switches, to true; it can only match
the one asset id; only while that asset is owned and confirmed_live and a switch is still off; only
while uat.prodexlabs.com is owned with both switches on; ph-test and demo-tour are not touched and
ownership is never written; one audit row, written from the rows the UPDATE returned (so none when
nothing changed), carrying the old values, the batch, the reason, the evidence, the approval and
the undo; a guard that stops a second recording; nothing deleted, no schema change, no dollar
quotes; one transaction; the meta auto-applies. Proven on PostgreSQL 17.6 in the build note (today's
shape, each condition broken on purpose, one switch already on, a Command-like copy, the guard
tripped, two applies, by hand and through the repo runner).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261112a_pulse_uat_attack_test_on.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

ASSET = "pulse.uat.prodexlabs.com"
TWIN = "uat.prodexlabs.com"
BATCH = "20261112a-pulse-uat-attack-test-on"
ACTION = "change_asset_probe_authorization"


def _body():
    return runner._strip_comments(SQL)


def _flat():
    return " ".join(_body().split())


def _statements():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _update():
    f = _flat()
    return f[f.index("UPDATE public.assets a"):f.index("RETURNING")]


def test_two_statements_the_change_then_the_guard():
    st = [s for s in _statements() if s not in ("BEGIN", "COMMIT")]
    assert len(st) == 2
    assert st[0].startswith("WITH changed AS ( UPDATE public.assets a ")
    assert st[1].startswith("SELECT 1 / (CASE WHEN count(*) <= 1 THEN 1 ELSE 0 END) AS guard_recorded_at_most_once")


def test_one_update_of_exactly_the_two_switches_to_true():
    b = _body()
    assert b.count("UPDATE ") == 1
    u = _update()
    sets = u[u.index(" SET ") + 5:u.index(" FROM ")]
    assert [s.strip() for s in sets.split(",")] == ["active_probe_authorized = true",
                                                     "enforcement_probe_authorized = true"]
    for never in ("ownership =", "discovery_status =", "kind =", "= false"):
        assert never not in sets, never


def test_it_can_only_match_the_one_asset():
    u = _update()
    assert f"WHERE a.asset_id = '{ASSET}' AND old.asset_id = a.asset_id" in u
    # every asset id named anywhere in the statement is this one or the one it leans on
    assert set(re.findall(r"asset_id = '([^']+)'", _flat())) == {ASSET, TWIN}
    for other in ("ph-test", "demo-tour", "link.prodexlabs.com", " LIKE ", " IN (", "%"):
        assert other not in u, other


def test_only_while_it_is_ours_live_and_still_off():
    u = _update()
    assert "AND a.ownership = 'owned'" in u
    assert "AND a.discovery_status = 'confirmed_live'" in u
    assert "AND NOT (a.active_probe_authorized AND a.enforcement_probe_authorized)" in u


def test_only_while_the_site_it_shares_an_address_with_is_switched_on():
    u = _update()
    assert ("AND EXISTS (SELECT 1 FROM public.assets u "
            f"WHERE u.asset_id = '{TWIN}' AND u.ownership = 'owned' "
            "AND u.active_probe_authorized AND u.enforcement_probe_authorized)") in u


def test_one_audit_row_from_what_the_update_returned_with_the_old_values():
    f = _flat()
    assert f.count("INSERT INTO") == 1
    assert ("RETURNING a.asset_id, old.active_probe_authorized AS old_active, "
            "old.enforcement_probe_authorized AS old_enforcement )") in f
    ins = f[f.index("INSERT INTO public.admin_audit_log"):f.index("; SELECT 1 /") if "; SELECT 1 /" in f else len(f)]
    assert ins.startswith("INSERT INTO public.admin_audit_log (actor_user_id, action, before_state, "
                          f"after_state, details) SELECT NULL, '{ACTION}', ")
    assert ("jsonb_build_object('active_probe_authorized', c.old_active, "
            "'enforcement_probe_authorized', c.old_enforcement)") in ins
    assert ("jsonb_build_object('active_probe_authorized', true, "
            "'enforcement_probe_authorized', true)") in ins
    assert " FROM changed c" in ins and " VALUES " not in ins   # no row unless the UPDATE changed one
    for key in ("'asset_id', c.asset_id", f"'batch', '{BATCH}'", "'reason', '", "'evidence', '",
                "'approved_by', 'howie@prodexlabs.com (chat approval 2026-11-12 11:55 ET)'",
                "'changed_by', '", "'undo', '"):
        assert key in ins, key
    assert "136.69.87.98" in ins and TWIN in ins


def test_the_guard_counts_this_files_own_audit_rows():
    g = [s for s in _statements() if s.startswith("SELECT 1 /")][0]
    assert g.endswith(f"FROM public.admin_audit_log WHERE action = '{ACTION}' "
                      f"AND details ->> 'batch' = '{BATCH}'")
    b = _body()
    assert b.index("INSERT INTO public.admin_audit_log") < b.index("guard_recorded_at_most_once")


def test_nothing_else_is_touched():
    b = _body()
    for word in ("DELETE ", "DROP ", "TRUNCATE", "ALTER ", "CREATE ", "GRANT", "REVOKE",
                 "public.findings", "public.scan_queue", "public.asset_surface", "INSERT INTO public.assets"):
        assert word not in b, word
    assert "$$" not in SQL


def test_one_transaction_and_the_meta_auto_applies():
    b = _body()
    assert b.count("\nBEGIN;\n") == 1 and b.rstrip().endswith("COMMIT;")
    assert b.index("BEGIN;") < b.index("UPDATE public.assets") < b.index("COMMIT;")
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)
