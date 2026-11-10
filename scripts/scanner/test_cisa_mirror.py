"""The address scan that copies CISA's Cyber Hygiene scanning: the logic (cisa_mirror.py).

Prodex plan 2026-11-10. Every number here is CISA's, from its published code:
cisagov/cyhy-commander (netscan1.sh, netscan2.sh), cisagov/cyhy-core (scheduler.py),
cisagov/cyhy-reports (RISKY_SERVICES_MAP), and nmap's nmap-services for port names.

    python3 -m pytest scripts/scanner/test_cisa_mirror.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

import cisa_mirror as cm  # noqa: E402


# ── CISA's ping lists ────────────────────────────────────────────────────────────────

def test_the_first_ping_is_cisas_30_ports_in_cisas_order():
    assert len(cm.PING_PORTS_FIRST) == 30 == len(set(cm.PING_PORTS_FIRST))
    assert cm.PING_PORTS_FIRST[:6] == (443, 80, 1720, 22, 49152, 21)
    assert cm.PING_PORTS_FIRST[-1] == 9886


def test_the_second_ping_is_970_more_and_repeats_none():
    assert len(cm.PING_PORTS_SECOND) == 970 == len(set(cm.PING_PORTS_SECOND))
    assert not set(cm.PING_PORTS_FIRST) & set(cm.PING_PORTS_SECOND)
    assert cm.PING_PORTS_SECOND[:4] == (23, 143, 8443, 631)
    assert len(cm.PING_PORTS) == 1000


# ── 1. up or down, as CISA's ping decides ────────────────────────────────────────────

def test_an_icmp_reply_is_up():
    assert cm.cisa_sees_up(True, {})


def test_a_refusal_on_a_ping_port_is_up_the_way_nmap_counts_a_reset():
    assert cm.cisa_sees_up(False, {443: "refused"})
    assert cm.cisa_sees_up(False, {9886: "open"})


def test_a_service_only_on_a_port_cisa_never_knocks_on_looks_down_to_cisa():
    # CISA would never port-scan this address: nothing answered its 1,000 ping ports.
    assert 44444 not in cm.PING_PORTS
    assert not cm.cisa_sees_up(False, {44444: "open", 443: "silent", 80: "silent"})


def test_silence_everywhere_and_no_icmp_is_down():
    assert not cm.cisa_sees_up(False, {p: "silent" for p in cm.PING_PORTS_FIRST})


# ── 2. every port: one pass vs what answers again ────────────────────────────────────

def test_split_ports_keeps_what_reanswered_and_names_the_phantoms():
    s = cm.split_ports([443, 80, 8888, 2000], [443, 80])
    assert s == {"one_pass": [80, 443, 2000, 8888], "reanswered": [80, 443], "phantom": [2000, 8888]}


def test_a_reanswer_not_in_the_one_pass_list_is_ignored():
    assert cm.split_ports([443], [443, 22])["reanswered"] == [443]


def test_the_sweep_is_every_tcp_port_by_connect_on_an_address_only():
    cmd = cm.sweep_command("136.81.173.196", 250)
    assert cmd[:3] == ["naabu", "-host", "136.81.173.196"]
    assert cmd[cmd.index("-p") + 1] == "-"
    assert cmd[cmd.index("-scan-type") + 1] == "CONNECT"
    for bad in ("prod.prodexlabs.com", "136.81.173.0/24", "136.81.173.196; id"):
        with pytest.raises(ValueError):
            cm.sweep_command(bad, 250)


# ── CISA's risky services ────────────────────────────────────────────────────────────

def test_rdp_smb_telnet_sql_are_on_cisas_list_by_port():
    assert cm.risky_category(3389) == "rdp"
    assert cm.risky_category(445) == "smb"
    assert cm.risky_category(23) == "telnet"
    assert cm.risky_category(1433) == "sql"
    assert cm.risky_category(135) == "rpc"
    assert cm.risky_category(88) == "kerberos"


def test_web_ssh_and_mysql_are_not_on_cisas_list():
    # CISA's list keys on nmap names: 3306 is "mysql", which the list doesn't name.
    for port in (80, 443, 22, 3306, 5432, 8080):
        assert cm.risky_category(port) is None


def test_a_greeting_beats_the_port_name_like_nmap_sv():
    assert cm.nmap_name(21) == "ftp" and cm.risky_category(21) == "ftp"
    assert cm.nmap_name(21, "ssh") == "ssh"
    assert cm.risky_category(21, "ssh") is None
    assert cm.risky_category(2121, "ftp") == "ftp"


def test_the_risky_finding_is_info_like_cisas_and_says_why():
    f = cm.risky_service_finding("136.81.173.196", 3389)
    assert f["severity"] == "INFO"
    assert f["key"] == "cisa-risky-service-rdp-3389-tcp"
    assert "Remote Desktop (RDP)" in f["title"] and "3389/tcp" in f["title"]
    assert "CISA" in f["description"]
    assert cm.risky_service_finding("136.81.173.196", 443) is None


def test_every_risky_port_name_is_a_name_on_cisas_list():
    assert set(cm.RISKY_PORT_NAMES.values()) <= set(cm.RISKY_SERVICES)
    assert set(cm.RISKY_SERVICES.values()) <= set(cm.CATEGORY_WORDS)


# ── CISA's rescan schedule ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("priority,hours", [
    (1, 2160), (0, 336), (-1, 168), (-2, 144), (-3, 120), (-4, 96),
    (-6, 60), (-8, 24), (-12, 18), (-16, 12), (-40, 12), (9, 2160),
])
def test_interval_hours_are_cisas_anchors_and_straight_lines_between(priority, hours):
    assert cm.interval_hours(priority) == pytest.approx(hours)


def test_the_fact_sheet_times_fall_out_of_the_scheduler():
    lv = cm.SEVERITY_PRIORITY
    assert cm.interval_hours(lv[4]) == 12          # Critical (and KEV)
    assert cm.interval_hours(lv[3]) == 24          # High
    assert cm.interval_hours(lv[2]) == 96          # Medium: 4 days
    assert cm.interval_hours(lv[1]) == 144         # Low: 6 days
    assert cm.interval_hours(cm.RESTING_UP_PRIORITY) == 168   # nothing found: 7 days


def test_a_new_address_that_never_answers_backs_off_to_90_days():
    p = cm.START_PRIORITY
    p = cm.next_priority(p, up=False, max_level=0, kev_count=0)
    assert p == 1 and cm.interval_hours(p) == 2160
    assert cm.next_priority(p, up=False, max_level=0, kev_count=0) == 1


def test_a_finding_jumps_straight_to_its_time_and_recovery_is_one_step_a_scan():
    p = cm.next_priority(-1, up=True, max_level=3, kev_count=0)
    assert p == -8                                     # High: straight to 24 hours
    p = cm.next_priority(p, up=True, max_level=1, kev_count=0)
    assert p == -7                                     # now only Low: one step back
    assert cm.next_priority(-2, up=True, max_level=1, kev_count=0) == -2


def test_a_kev_is_the_critical_time_whatever_its_grade():
    assert cm.next_priority(-1, up=True, max_level=1, kev_count=1) == -16


def test_nothing_found_decays_to_seven_days_and_a_returning_address_starts_there():
    assert cm.next_priority(-5, up=True, max_level=0, kev_count=0) == -4
    assert cm.next_priority(1, up=True, max_level=0, kev_count=0) == -1
    assert cm.next_priority(-1, up=True, max_level=0, kev_count=0) == -1


def test_sentry_grades_on_cisas_scale():
    assert cm.worst_level(["LOW", "MODERATE", "INFO"]) == 2
    assert cm.worst_level(["MODERATE-HIGH"]) == 3
    assert cm.worst_level(["INFO"]) == 0
    assert cm.worst_level([]) == 0


# ── the safety rail ─────────────────────────────────────────────────────────────────

def test_only_names_that_still_point_at_the_address_count():
    dns = {"prod.prodexlabs.com": ["136.81.173.196"],
           "trial.prodexlabs.com": ["136.81.173.196", "136.81.173.197"],
           "atlantis-gcp.prodexlabs.com": ["34.67.20.200"]}
    names = ["prod.prodexlabs.com", "trial.prodexlabs.com", "atlantis-gcp.prodexlabs.com", "gone.prodexlabs.com"]

    def resolve(n):
        if n not in dns:
            raise OSError("NXDOMAIN")
        return dns[n]

    assert cm.names_pointing_here("136.81.173.196", names, resolve) == ["prod.prodexlabs.com", "trial.prodexlabs.com"]
    assert cm.names_pointing_here("34.67.20.186", names, resolve) == []
    assert cm.names_pointing_here("34.67.20.186", [], resolve) == []


def test_a_cvss_score_decides_the_cisa_grade_the_way_nessus_grades():
    assert cm.cisa_level("LOW", 9.8) == 4
    assert cm.cisa_level("MODERATE", 7.0) == 3
    assert cm.cisa_level("HIGH", 6.9) == 2
    assert cm.cisa_level("INFO", 0.1) == 1
    assert cm.cisa_level("MODERATE", None) == 2
    assert cm.cisa_level("INFO", None) == 0
    assert cm.cisa_level("MODERATE", "n/a") == 2
    assert cm.CISA_LEVEL_WORDS[cm.cisa_level("HIGH")] == "High"
