"""(Prodex plan 2026-11-10) Migration 20261110b: public.cisa_mirror_addresses, the addresses on
ProDex's CISA Cyber Hygiene list that Sentry scans the way CISA does.

Howie, 2026-11-10 10:49: "forget about Command. This is a Prodex-only thing, so I don't want to
add anything to Command." Pinned here: one new table and nothing else (no asset, finding, view or
function touched, nothing deleted); an address column that takes one IPv4 address and nothing else;
a names list that can't be empty (the scanner's safety rail reads it); RLS on, nothing granted to
anon or authenticated; exactly the ten inbound addresses of the CISA sheet with their names, and
none of the ten outbound NAT addresses; the insert runs only where the owned Prodex apex exists
(so Command gets an empty table); a guard that stops on anything but 0 or 10 rows; the meta
auto-applies. Proven on PostgreSQL 16 in the build note (a Command-like and a Prodex-like copy,
two applies each, the CHECKs refusing a name, a range and an empty list, the guard tripped by a
stray row).
"""
import pathlib
import re
import sys

DB = pathlib.Path(__file__).resolve().parent
MIG = DB / "migrations" / "20261110b_cisa_mirror_addresses.sql"
SQL = MIG.read_text()
sys.path.insert(0, str(DB))

import apply_pending_migrations as runner  # noqa: E402
import migration_meta  # noqa: E402

INBOUND = {
    "136.81.173.196": {"prod", "bitec", "dass", "demo", "highcom", "l3h-ivs", "l3h-nh", "l3h-ss",
                       "littleleaffarms", "panthalassa", "time", "trial"},
    "136.81.178.35": {"staging"},
    "136.69.87.98": {"uat"},
    "34.54.236.210": {"preview"},
    "136.81.198.25": {"sandbox", "oidc-test"},
    "34.67.20.186": {"atlantis-gcp"},
    "34.36.153.196": {"tour"},
    "8.232.147.166": {"", "www", "cooked"},
    "136.81.194.166": {"prosalud"},
    "136.81.196.61": {"prosalud-staging"},
}
OUTBOUND_NAT = ("34.67.179.80", "34.58.206.165", "34.173.210.19", "34.63.170.7", "34.9.47.186",
                "34.152.17.216", "34.186.200.18", "34.95.18.119", "34.47.7.116", "34.19.236.175")


def _body():
    return runner._strip_comments(SQL)


def _statements():
    return [" ".join(s.split()) for s in runner._split(SQL) if s.strip()]


def _rows():
    vals = _body()[_body().index("FROM (VALUES"):_body().index(") AS v (address")]
    out = {}
    for m in re.finditer(r"\('([0-9.]+)',\s*ARRAY\[(.*?)\],\s*'(.*?)',\s*(true|false)\)", vals, re.S):
        names = re.findall(r"'([^']+)'", m.group(2))
        out[m.group(1)] = {"names": names, "what": m.group(3), "reserved": m.group(4) == "true"}
    return out


def test_exactly_the_ten_inbound_addresses_with_their_names():
    rows = _rows()
    assert set(rows) == set(INBOUND)
    for addr, short in INBOUND.items():
        want = {(s + ".prodexlabs.com") if s else "prodexlabs.com" for s in short}
        assert set(rows[addr]["names"]) == want, addr


def test_no_outbound_nat_address_and_only_atlantis_is_unreserved():
    for nat in OUTBOUND_NAT:
        assert nat not in SQL
    assert [a for a, r in _rows().items() if not r["reserved"]] == ["34.67.20.186"]


def test_the_rows_go_in_only_where_the_owned_prodex_apex_is():
    b = " ".join(_body().split())
    assert ("WHERE EXISTS (SELECT 1 FROM public.assets a WHERE a.asset_id = 'prodexlabs.com' "
            "AND a.ownership = 'owned') ON CONFLICT (address) DO NOTHING;") in b


def test_the_address_column_takes_one_ipv4_address_only():
    m = re.search(r"CHECK \(address ~ '(.*?)'\)", SQL)
    rx = re.compile(m.group(1))
    for ok in ("136.81.173.196", "8.232.147.166", "0.0.0.0", "255.255.255.255"):
        assert rx.search(ok), ok
    for bad in ("prod.prodexlabs.com", "256.1.1.1", "1.2.3.4/24", "1.2.3", "1.2.3.4.5", " 1.2.3.4", "01.2.3.4x"):
        assert not rx.search(bad), bad
    assert "CHECK (cardinality(names) > 0)" in SQL


def test_rls_on_and_nothing_granted():
    b = " ".join(_body().split())
    assert "ALTER TABLE public.cisa_mirror_addresses ENABLE ROW LEVEL SECURITY;" in b
    assert "REVOKE ALL ON public.cisa_mirror_addresses FROM anon, authenticated;" in b
    assert "GRANT" not in b and "CREATE POLICY" not in b


def test_one_table_and_nothing_else_is_touched():
    b = _body()
    for word in ("UPDATE ", "DELETE ", "DROP ", "TRUNCATE", "ALTER TYPE", "CREATE VIEW",
                 "CREATE OR REPLACE", "public.findings", "INSERT INTO public.assets"):
        assert word not in b, word
    assert b.count("CREATE TABLE") == 1
    assert b.count("INSERT INTO") == 1
    assert "$$" not in SQL


def test_the_guard_stops_on_anything_but_none_or_ten():
    assert ("SELECT 1 / (CASE WHEN (SELECT count(*) FROM public.cisa_mirror_addresses) IN (0, 10) "
            "THEN 1 ELSE 0 END) AS guard_none_or_ten") in _statements()


def test_one_transaction_and_the_meta_auto_applies():
    b = _body()
    assert b.count("\nBEGIN;\n") == 1 and b.rstrip().endswith("COMMIT;")
    assert b.index("BEGIN;") < b.index("CREATE TABLE") < b.index("COMMIT;")
    meta = migration_meta.parse_meta(SQL)
    assert migration_meta.validate_meta(meta, MIG.name) == []
    assert migration_meta.is_safe_auto_apply(meta)
    assert migration_meta.is_transactional(meta)

