"""(KB 12 job 4, plan v1.3 step 3(b), 2026-11-04) A row closed because its name stopped being
deep-scanned comes back when a scan finds it again.

Migration 20261104b closes, as closed_reclassified tagged 'job4-name-retired', the rows only a deep
scan of a site's other name wrote (the site is now shown and deep-scanned under the name the
browser lands on, Howie D6). A later scan of that name (one started by hand, or a site whose face
changes) must reopen exactly those rows; every other closed_reclassified row stays closed
(20260827a, 20261103a). Pinned in both findings upserts: the quick scan's (run_light.py) and the
shared one in run_medium.py that the deep scan reuses. Proven on PostgreSQL 16 in the build note.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_light  # noqa: E402
import run_medium  # noqa: E402

REOPEN = ("current_status = CASE WHEN findings.current_status = 'closed_reclassified' "
          "AND 'job4-name-retired' = ANY (coalesce(findings.tags, '{}'::text[])) THEN 'detected' "
          "WHEN findings.current_status IN ( 'remediated', 'validated_remediated', "
          "'false_positive', 'wont_fix', 'accepted_risk',")


def _flat(sql):
    return " ".join(line.split("--", 1)[0] for line in sql.splitlines()).split()


def test_both_upserts_reopen_only_the_tagged_rows_first():
    for sql in (run_light.UPSERT_FINDING_SQL, run_medium.UPSERT_FINDING_SQL):
        flat = " ".join(_flat(sql))
        assert REOPEN in flat
        assert flat.count("'job4-name-retired'") == 1


def test_every_other_closed_status_stays_closed():
    light = " ".join(_flat(run_light.UPSERT_FINDING_SQL))
    assert ("WHEN findings.current_status IN ( 'remediated', 'validated_remediated', 'false_positive', "
            "'wont_fix', 'accepted_risk', 'closed_reclassified' ) THEN findings.current_status ELSE 'detected' END") in light
    medium = " ".join(_flat(run_medium.UPSERT_FINDING_SQL))
    assert ("'false_positive', 'wont_fix', 'accepted_risk', 'closed_reclassified', 'regressed' ) "
            "THEN findings.current_status ELSE 'detected' END") in medium


def test_the_deep_scan_uses_the_shared_upsert():
    src = (Path(__file__).resolve().parent / "run_heavy.py").read_text()
    assert "from run_medium import UPSERT_FINDING_SQL" in src
