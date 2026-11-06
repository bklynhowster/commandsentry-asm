"""Job 5a push 2 (plan v3 E): the one-time load of this instance's DNS history.

Pinned:
  * the history is read with the SAME pipeline the live importer uses (legacy readings,
    dns_changes, dns_event_rows) and gives the same fingerprint for the same change;
  * each row is dated by its own copy (observed_at = that copy's completed_at), tagged
    dns_backfill and marked loaded_from_history; it claims nothing about "now";
  * the history ENDS at the first copy that carries dns_readings (that copy included), where the
    live importer takes over: nothing twice, nothing between;
  * a rotating cloud name, a CNAME to the same target and an empty best-effort set give nothing;
  * it waits (writes nothing) while an enabled apex target has no copy with readings yet;
  * it writes nothing when already loaded, without the cloud classifier, over MAX_ROWS, on a dry
    run, or when any insert fails: one transaction, all the rows or none;
  * asm-discover.yml runs it after the importer, and a failure there never fails discovery;
  * through history_rows, this instance's replay fixture gives exactly the hand-written changes.

Run:  pytest scripts/db/test_dns_history_5a.py -q
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import load_dns_history as L  # noqa: E402
import surface_diff as sd  # noqa: E402

APEX = "example.com"


def sub(name, a=(), ports=(), cname=None, org="Org", cloud=None):
    s = {"name": name, "hosts": [{"ip": ip, "asn": "AS1", "asn_org": org} for ip in a],
         "services": [{"ip": a[0], "port": p, "protocol": "tcp"} for p in ports] if a else [],
         "dns": {"a": list(a), "aaaa": [], "cname": cname, "ns": [], "mx": [], "txt": []}}
    if cloud is not None:
        s["_cloud"] = cloud
    return s


def copy(at, *subs, readings=False, apex=APEX):
    b = {"asset": {"type": "apex", "value": apex}, "scan": {"completed_at": at}, "subdomains": list(subs)}
    if readings:
        b["dns_readings"] = {}
    return b


def fixture_classify(s):
    c = s.get("_cloud")
    return {"is_cloud_endpoint": c[0], "cloud_provider": c[1]} if c else {}


def rows_of(copies, have=None, aliases=(), classify=fixture_classify):
    have = have if have is not None else {APEX, "test." + APEX, "www." + APEX, "mail." + APEX}
    cs = [(f"c{i}", c["scan"]["completed_at"], c) for i, c in enumerate(copies)]
    return L.history_rows(cs, APEX, list(aliases), have, classify)


T = ["2026-06-01T00:00:00Z", "2026-06-01T06:00:00Z", "2026-06-01T12:00:00Z", "2026-06-01T18:00:00Z"]


# ── the history of one apex ────────────────────────────────────────────────────────────────────
def test_a_move_is_one_row_dated_by_its_own_copy_with_the_live_fingerprint():
    old = copy(T[0], sub(APEX, ["1.1.1.1"]), sub("test." + APEX, ["24.38.70.8"], [443]))
    new = copy(T[1], sub(APEX, ["1.1.1.1"]), sub("test." + APEX, ["52.119.65.6"], [22]))
    res = rows_of([old, new])
    assert res["ends_at"] is None and res["read"] == 2
    (r,) = res["rows"]
    assert r["event_type"] == "dns_address_changed" and r["host"] == "test." + APEX
    assert r["asset_id"] == "test." + APEX and r["source_tag"] == "dns_backfill"
    assert r["observed_at"] == T[1]
    assert r["prev_value"]["values"] == ["24.38.70.8"] and r["new_value"]["values"] == ["52.119.65.6"]
    assert r["prev_value"]["ports"] == [{"ip": "24.38.70.8", "port": 443, "proto": "tcp"}]
    assert r["new_value"]["ports"] == [{"ip": "52.119.65.6", "port": 22, "proto": "tcp"}]
    assert r["prev_value"]["last_seen"] == T[0]
    assert "owned_address_now" not in r["prev_value"]          # not a historical fact
    assert r["new_value"]["loaded_from_history"] == {"copy": "c1", "completed_at": T[1]}
    live = sd.dns_changes(sd.legacy_readings(old), sd.legacy_readings(new), {}, apex=APEX)
    assert r["new_value"]["fingerprint"] == sd.change_fingerprint(live[0])


def test_the_history_ends_at_the_first_copy_with_readings_that_copy_included():
    cs = [copy(T[0], sub("test." + APEX, ["10.0.0.1"])),
          copy(T[1], sub("test." + APEX, ["10.0.0.2"]), readings=True),
          copy(T[2], sub("test." + APEX, ["10.0.0.3"]), readings=True)]
    res = rows_of(cs)
    assert res["ends_at"] == "c1" and res["read"] == 2
    assert [(r["prev_value"]["values"], r["new_value"]["values"]) for r in res["rows"]] == [(["10.0.0.1"], ["10.0.0.2"])]


def test_the_last_legacy_copy_is_compared_with_the_first_readings_copy_and_nothing_after():
    cs = [copy(T[0], sub("test." + APEX, ["10.0.0.1"])),
          copy(T[1], sub("test." + APEX, ["10.0.0.1"]), readings=True)]
    res = rows_of(cs)
    assert res["ends_at"] == "c1" and res["rows"] == []


def test_a_rotating_cloud_name_and_a_cname_to_the_same_target_give_nothing():
    az = (True, "azure")
    cs = [copy(T[i], sub("mail." + APEX, [f"52.96.0.{i}"], cloud=az),
               sub("www." + APEX, [f"75.2.0.{i}"], cname="sites.mintlify.dev")) for i in range(4)]
    assert rows_of(cs)["rows"] == []


def test_a_cloud_name_whose_provider_changes_is_a_move():
    cs = [copy(T[0], sub("mail." + APEX, ["52.96.0.1"], cloud=(True, "azure"))),
          copy(T[1], sub("mail." + APEX, ["34.1.1.1"], cloud=(True, "gcp")))]
    assert [r["event_type"] for r in rows_of(cs)["rows"]] == ["dns_address_changed"]


def test_a_name_missing_from_a_copy_keeps_its_last_reading_and_its_ports():
    cs = [copy(T[0], sub(APEX, ["1.1.1.1"]), sub("test." + APEX, ["24.38.70.8"], [443])),
          copy(T[1], sub(APEX, ["1.1.1.1"])),
          copy(T[2], sub(APEX, ["1.1.1.1"]), sub("test." + APEX, ["52.119.65.6"]))]
    (r,) = rows_of(cs)["rows"]
    assert r["prev_value"]["ports"] == [{"ip": "24.38.70.8", "port": 443, "proto": "tcp"}]
    assert r["observed_at"] == T[2]
    # dated by the copy that really showed the old address, never by T1, which did not
    assert r["prev_value"]["last_seen"] == T[0] and r["prev_value"]["read_at"] == T[0]


def test_an_empty_record_in_a_middle_copy_keeps_the_last_observed_value_and_its_date():
    cs = [copy(T[0], sub("test." + APEX, ["24.38.70.8"], [443], cname="a.host.net")),
          copy(T[1], sub("test." + APEX, [])),
          copy(T[2], sub("test." + APEX, ["52.119.65.6"], cname="b.host.net"))]
    rows = {r["event_type"]: r for r in rows_of(cs)["rows"]}
    assert sorted(rows) == ["dns_address_changed", "dns_cname_changed"]
    mv = rows["dns_address_changed"]["prev_value"]
    assert mv["values"] == ["24.38.70.8"] and mv["last_seen"] == T[0] and mv["read_at"] == T[0]
    assert mv["ports"] == [{"ip": "24.38.70.8", "port": 443, "proto": "tcp"}]
    cn = rows["dns_cname_changed"]["prev_value"]
    assert cn["values"] == ["a.host.net"] and cn["read_at"] == T[0] and "last_seen" not in cn


def test_a_name_whose_ports_closed_before_it_moved_carries_no_old_ports():
    cs = [copy(T[0], sub("test." + APEX, ["24.38.70.8"], [443])),
          copy(T[1], sub("test." + APEX, ["24.38.70.8"], [])),
          copy(T[2], sub("test." + APEX, ["52.119.65.6"]))]
    (r,) = rows_of(cs)["rows"]
    assert r["prev_value"]["ports"] == []


def test_an_empty_best_effort_set_is_never_a_removal_or_gone():
    cs = [copy(T[0], sub("test." + APEX, ["24.38.70.8"])), copy(T[1], sub("test." + APEX, [])),
          copy(T[2], sub("test." + APEX, [])), copy(T[3], sub("test." + APEX, ["24.38.70.8"]))]
    assert rows_of(cs)["rows"] == []


def test_names_without_an_asset_row_are_skipped_and_reported_and_www_goes_to_the_apex():
    cs = [copy(T[0], sub("ghost." + APEX, ["10.0.0.1"]), sub("www." + APEX, ["10.0.0.5"])),
          copy(T[1], sub("ghost." + APEX, ["10.0.0.2"]), sub("www." + APEX, ["10.0.0.6"]))]
    res = rows_of(cs, have={APEX})
    assert res["skipped"] == ["ghost." + APEX]
    assert [(r["asset_id"], r["host"]) for r in res["rows"]] == [(APEX, "www." + APEX)]


def test_an_unreadable_copy_is_skipped_and_counted():
    cs = [("c0", T[0], copy(T[0], sub("test." + APEX, ["10.0.0.1"]))), ("c1", T[1], None),
          ("c2", T[2], copy(T[2], sub("test." + APEX, ["10.0.0.2"])))]
    res = L.history_rows(cs, APEX, [], {"test." + APEX}, fixture_classify)
    assert res["unreadable"] == 1 and res["read"] == 2 and len(res["rows"]) == 1


def test_a_copy_without_completed_at_is_dated_by_its_commit():
    c1 = copy(T[1], sub("test." + APEX, ["10.0.0.2"]))
    del c1["scan"]["completed_at"]
    cs = [("c0", T[0], copy(T[0], sub("test." + APEX, ["10.0.0.1"]))), ("c1", "2026-06-02T00:00:00+00:00", c1)]
    (r,) = L.history_rows(cs, APEX, [], {"test." + APEX}, fixture_classify)["rows"]
    assert r["observed_at"] == "2026-06-02T00:00:00+00:00"


# ── the load: a real git repository and a stand-in database ───────────────────────────────────
def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def make_repo(tmp_path, history, targets=("example",), extra_targets=()):
    """history: {file stem: [blob, ...]} committed in order, one commit per step."""
    repo = tmp_path / "r"
    (repo / "data" / "assets").mkdir(parents=True)
    git(repo, "init", "-q")
    tl = [{"id": t, "type": "apex", "value": f"{t}.com"} for t in targets] + list(extra_targets)
    (repo / "data" / "targets.yml").write_text(json.dumps({"targets": tl}))   # JSON is YAML
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "targets")
    steps = max(len(v) for v in history.values())
    for i in range(steps):
        for stem, blobs in history.items():
            if i < len(blobs):
                (repo / "data" / "assets" / f"{stem}.json").write_text(json.dumps(blobs[i]))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", f"copy {i}")
    return repo


class Cur:
    def __init__(self, db):
        self.db, self.last = db, ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.last = " ".join(str(sql).split())
        self.db.calls.append(self.last)

    def executemany(self, sql, rows):
        rows = list(rows)
        if self.db.fail_insert:
            raise RuntimeError("insert refused")
        self.db.pending.extend(rows)

    def fetchone(self):
        if "count(*)" in self.last:
            return (self.db.already, "2026-11-06 12:00:00+00" if self.db.already else None)
        if self.last.startswith("SELECT aliases"):
            return (self.db.aliases,)
        return None

    def fetchall(self):
        if self.last.startswith("SELECT asset_id FROM public.assets"):
            return [(a,) for a in sorted(self.db.have)]
        return []


class DB:
    def __init__(self, have, already=0, fail_insert=False, aliases=None):
        self.have, self.already, self.fail_insert = set(have), already, fail_insert
        self.aliases = aliases or []
        self.calls, self.pending, self.written, self.rolled_back = [], [], [], 0

    def cursor(self):
        return Cur(self)

    def commit(self):
        self.written.extend(self.pending)
        self.pending = []

    def rollback(self):
        self.pending = []
        self.rolled_back += 1


HAVE = {"example.com", "test.example.com"}


def moving_history(readings_at=2):
    return [copy(T[i], sub("example.com", ["1.1.1.1"]), sub("test.example.com", [f"10.0.0.{i}"]),
                 readings=i >= readings_at, apex="example.com") for i in range(4)]


def run(repo, db, **kw):
    lines = []
    code = L.run(db, repo, classify=kw.pop("classify", fixture_classify), out=lines.append, **kw)
    return code, "\n".join(lines)


def test_loads_every_row_in_one_commit_dated_by_each_copy(tmp_path):
    repo = make_repo(tmp_path, {"example": moving_history()})
    db = DB(HAVE)
    code, log = run(repo, db)
    assert code == 0 and "loaded: 2 history row(s)" in log
    assert [(r["host"], r["observed_at"]) for r in db.written] == [("test.example.com", T[1]), ("test.example.com", T[2])]
    assert all(r["source_tag"] == "dns_backfill" for r in db.written)
    assert all(hasattr(r["new_value"], "obj") for r in db.written)          # wrapped as JSON for psycopg
    assert db.calls[0].startswith("SELECT pg_advisory_xact_lock")
    assert "observed_at)s::timestamptz" in L.INSERT_HISTORY_SQL


def test_already_loaded_stops_after_one_query_and_reads_no_history(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"example": moving_history()})
    monkeypatch.setattr(L, "plan_load", lambda *a, **k: pytest.fail("history read after already loaded"))
    db = DB(HAVE, already=2)
    code, log = run(repo, db)
    assert code == 0 and "already loaded" in log and db.written == []


def test_waits_while_an_enabled_apex_target_has_no_copy_with_readings(tmp_path):
    repo = make_repo(tmp_path, {"example": moving_history(readings_at=99)})
    db = DB(HAVE)
    code, log = run(repo, db)
    assert code == 0 and "waiting" in log and "example" in log and db.written == []


def test_ip_targets_are_ignored_and_a_stale_apex_is_read_whole(tmp_path):
    ipcopy = {"asset": {"type": "ip", "value": "24.157.51.70"}, "scan": {"completed_at": T[0]},
              "subdomains": [{"name": "24.157.51.70", "dns": {"a": []}}]}
    stale = [copy(T[i], sub("test.old.com", [f"10.1.0.{i}"]), apex="old.com") for i in range(3)]
    repo = make_repo(tmp_path, {"example": moving_history(), "24-157-51-70": [ipcopy, ipcopy],
                                "old": stale},
                     extra_targets=[{"id": "24-157-51-70", "type": "ip", "value": "24.157.51.70"}])
    db = DB(HAVE | {"test.old.com"})
    code, log = run(repo, db)
    assert code == 0 and "24-157-51-70" not in log
    assert sorted(r["host"] for r in db.written) == ["test.example.com"] * 2 + ["test.old.com"] * 2


def test_a_failed_insert_writes_nothing_and_exits_1(tmp_path):
    repo = make_repo(tmp_path, {"example": moving_history()})
    db = DB(HAVE, fail_insert=True)
    code, log = run(repo, db)
    assert code == 1 and "FAILED (nothing written)" in log and db.written == [] and db.rolled_back


def test_refuses_without_the_cloud_classifier(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"example": moving_history()})
    monkeypatch.setattr(L.imp, "_classify_cloud", None)
    db = DB(HAVE)
    code, log = run(repo, db, classify=None)
    assert code == 1 and "cloud classifier" in log and db.written == [] and db.calls == []


def test_refuses_over_max_rows(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"example": moving_history()})
    monkeypatch.setattr(L, "MAX_ROWS", 1)
    db = DB(HAVE)
    code, log = run(repo, db)
    assert code == 1 and "REFUSED" in log and db.written == []


def test_dry_run_writes_nothing(tmp_path):
    repo = make_repo(tmp_path, {"example": moving_history()})
    db = DB(HAVE)
    code, log = run(repo, db, dry_run=True)
    assert code == 0 and "dry run: 2 row(s)" in log and db.written == []


def test_no_changes_writes_nothing_and_says_so(tmp_path):
    flat = [copy(T[i], sub("test.example.com", ["10.0.0.1"]), readings=i >= 1, apex="example.com") for i in range(3)]
    repo = make_repo(tmp_path, {"example": flat})
    db = DB(HAVE)
    code, log = run(repo, db)
    assert code == 0 and "no changes" in log and db.written == []


def test_git_copies_yields_every_version_oldest_first_one_at_a_time(tmp_path):
    repo = make_repo(tmp_path, {"example": moving_history()})
    got = L.git_copies(repo, "data/assets/example.json")
    assert not isinstance(got, list)                                         # a generator
    ats = [b["scan"]["completed_at"] for _, _, b in got]
    assert ats == T


# ── the workflow step ──────────────────────────────────────────────────────────────────────────
def test_discovery_runs_the_load_after_the_importer_and_never_fails_on_it():
    import yaml
    wf = yaml.safe_load((HERE.parents[1] / ".github" / "workflows" / "asm-discover.yml").read_text())
    steps = next(iter(wf["jobs"].values()))["steps"]
    names = [s.get("name", "") for s in steps]
    imp_i = next(i for i, s in enumerate(steps) if "import_asm_to_surface.py" in (s.get("run") or ""))
    load_i = next(i for i, s in enumerate(steps) if "load_dns_history.py" in (s.get("run") or ""))
    assert load_i == imp_i + 1, names
    st = steps[load_i]
    assert st.get("continue-on-error") is True
    assert "mode != 'skipped'" in st.get("if", "")
    assert "SUPABASE_DSN" in (st.get("env") or {})
    assert "--dry-run" not in st["run"]
    # the load needs every saved copy: the job checks out the whole history, before the load
    co = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/checkout")]
    assert co and co[0] < load_i
    assert all(int((steps[i].get("with") or {}).get("fetch-depth", 1)) == 0 for i in co)


def test_a_shallow_checkout_is_refused_and_writes_nothing(tmp_path):
    full = make_repo(tmp_path, {"example": moving_history()})
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{full}", str(shallow)], check=True,
                   capture_output=True)
    assert L.is_shallow(shallow) and not L.is_shallow(full)
    db = DB(HAVE)
    code, log = run(shallow, db)
    assert code == 1 and "shallow" in log and db.written == []
    assert L.is_shallow(tmp_path / "not-a-repo-at-all")


# ── the replay gate, through the loader's own path ────────────────────────────────────────────
FIXTURE = HERE / "fixtures" / "dns_history_5a.json"


def test_this_instances_fixture_gives_exactly_the_hand_written_changes_through_history_rows():
    fx = json.loads(FIXTURE.read_text())
    for name in sorted(fx["names"]):
        entry = fx["names"][name]
        cs = []
        for i, c in enumerate(entry["copies"]):
            s = {"name": name, "_cloud": tuple(c["cloud"]),
                 "dns": {"a": c["a"], "aaaa": c["aaaa"], "cname": c["cname"], "ns": c["ns"]},
                 "hosts": [{"ip": ip, "asn_org": org} for ip, org in c["owners"].items()]}
            cs.append((f"c{i}", c["at"], {"asset": {"type": "apex", "value": entry["apex"]},
                                          "scan": {"completed_at": c["at"]}, "subdomains": [s]}))
        res = L.history_rows(cs, entry["apex"], [], {name, entry["apex"]}, fixture_classify)  # www goes to the apex
        got = [[ch["at"], ch["kind"], ch["old"].get("values"), ch["new"].get("values")] for ch in res["changes"]]
        assert got == fx["expect"][name], name
        assert len(res["rows"]) == len(got)
