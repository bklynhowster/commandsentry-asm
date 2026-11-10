#!/usr/bin/env python3
"""cisa_mirror.py — scan an address the way CISA's Cyber Hygiene scanning does. Logic only.

Prodex plan 2026-11-10 ("a separate address area in PRODEXsentry, scanned the way CISA
does", Howie 10:48-10:49, go 12:27). CISA scans each static public IPv4 address on an
organization's authorization. Its published code (GitHub, cisagov) does three things:

  1. Is it up?  nmap ping: ICMP echo and timestamp, and a TCP knock on 30 ports; if
     nothing answers, a second knock on 970 more. An address that answers neither is
     "down" and is NOT port-scanned (cyhy_commander/jobs/netscan1.sh, netscan2.sh).
  2. Every TCP port, 1-65535: nmap SYN scan, -sV service names, OS guess, reverse DNS,
     up to 4 hours per address (portscan.sh). TCP only.
  3. Nessus on the open ports only, safe checks on, Denial of Service off (vulnscan.py,
     extras/policy.xml).

It reports Nessus's Critical, High, Medium and Low; Informational results are dropped,
except a "potentially risky service" (RDP, Telnet, SMB, ...) is reported just for being
open (cyhy-reports, RISKY_SERVICES_MAP). A Known Exploited Vulnerability (KEV) sets the
address to the Critical rescan time. The rescan time moves one step per scan
(cyhy-core, cyhy/db/scheduler.py): see next_priority() and interval_hours().

Sentry's differences, on purpose: a CONNECT scan, not SYN (the scan runs through the
VPN, which can't send raw packets; same open-or-closed answer); an ICMP echo only, no ICMP
timestamp request (nothing in the scanner image sends one), so an address that answers
only a timestamp request looks down here and up to CISA; no Nessus (Sentry's own safe
checks run instead); nothing is sent to a non-web service (no logins of any kind, the
job-4l rule), so a service is named by its port unless it greets us first.

What CISA's code says is the code they publish; what they run today may differ.
Standard library only. Pure functions: the scanner and the scheduler call them.
"""
from __future__ import annotations

import ipaddress

# CISA's first ping: ICMP echo and timestamp, plus a TCP knock on these 30 ports
# (cisagov/cyhy-commander, cyhy_commander/jobs/netscan1.sh, nmap -PS list, in CISA's order).
PING_PORTS_FIRST = (
    443, 80, 1720, 22, 49152, 21, 53, 61001, 3479, 25, 62078, 3389, 8080, 8008, 8081, 9100,
    8010, 4000, 1248, 248, 175, 8087, 9010, 9004, 8111, 4502, 10800, 7776, 2770, 9886,
)

# CISA's second ping, only for an address that did not answer the first: 970 more ports
# (netscan2.sh, nmap -PS list, in CISA's order). None repeats a first-ping port.
PING_PORTS_SECOND = (
    23, 143, 8443, 631, 389, 515, 636, 6001, 9000, 1503, 9101, 7778, 8001, 9001, 9443, 10001,
    10443, 56241, 56242, 17001, 56240, 3601, 6011, 7780, 8305, 8122, 3082, 11898, 14001, 7782,
    3201, 6577, 21443, 17500, 1723, 49154, 5900, 264, 548, 8088, 49153, 8082, 88, 179, 111, 17,
    4500, 18264, 10000, 646, 44, 49155, 4030, 18080, 4110, 7310, 1352, 280, 5357, 554, 420,
    3689, 57621, 8020, 5001, 3910, 1947, 427, 8009, 500, 2105, 6068, 14000, 2107, 2103, 1801,
    51708, 3580, 60699, 52230, 5061, 497, 311, 2701, 49156, 2869, 5000, 8000, 9112, 993, 2049,
    7070, 81, 639, 59158, 843, 7474, 5800, 49157, 3911, 5060, 9116, 10243, 2002, 50001, 9113,
    9115, 3306, 7627, 9114, 7100, 1025, 110, 587, 59160, 49162, 6137, 6139, 6136, 135, 4786,
    2968, 119, 52311, 1755, 995, 7000, 1027, 8085, 49158, 10224, 465, 7001, 18231, 4122, 49159,
    9220, 8086, 6646, 4443, 47989, 902, 9002, 3582, 4002, 1026, 5985, 2001, 6002, 541, 5051,
    139, 47984, 8187, 16720, 27036, 5355, 161, 47001, 9080, 36515, 50060, 50000, 445, 9999,
    10002, 912, 9876, 8089, 15000, 5666, 444, 9290, 49160, 26143, 6000, 24, 8888, 407, 49161,
    1935, 10247, 2010, 861, 7547, 2020, 7777, 593, 1028, 2343, 5222, 5003, 82, 990, 13782, 4823,
    8296, 830, 7002, 256, 259, 49163, 4009, 5989, 50248, 2776, 5005, 5230, 7112, 6839, 9102,
    664, 625, 1024, 5228, 3011, 59111, 7435, 59110, 8291, 2777, 1688, 5229, 5405, 1689, 49872,
    7, 1099, 1782, 49164, 15328, 4001, 1719, 873, 15332, 8083, 3390, 801, 1433, 1022, 3268,
    15331, 1521, 9110, 8084, 27000, 15330, 1783, 32003, 1677, 1727, 1030, 1676, 20, 1718, 8090,
    522, 7676, 9090, 83, 7190, 1700, 900, 1769, 1618, 1772, 20121, 1737, 2797, 1796, 49167,
    15333, 59112, 15329, 1654, 1728, 1627, 1640, 585, 1791, 1600, 1787, 8649, 1778, 1760, 4899,
    1648, 1776, 1641, 1609, 1638, 1650, 32771, 1792, 1686, 1705, 1731, 1604, 1722, 32004, 1726,
    32001, 1645, 1608, 1663, 1773, 1696, 1714, 1622, 7113, 1344, 1666, 1715, 7103, 9500, 7181,
    1661, 3800, 1611, 1659, 898, 1673, 1746, 1798, 464, 5064, 1029, 1614, 2179, 7937, 1709,
    1711, 50003, 1716, 1712, 1706, 1494, 1311, 1911, 1780, 1788, 1789, 1793, 1794, 1797, 514,
    1766, 1765, 1764, 53048, 1759, 491, 51001, 1754, 1750, 49, 2070, 1743, 1741, 2222, 2271,
    2272, 1732, 51100, 1730, 1417, 1779, 1675, 1682, 1691, 1690, 32772, 32006, 32005, 32002,
    32000, 1684, 28780, 123, 1683, 1610, 1693, 1664, 1612, 1613, 1615, 16993, 1668, 1679, 1619,
    7101, 7031, 11526, 7186, 32459, 1628, 1652, 1644, 1629, 1630, 49165, 1634, 1601, 7938, 1631,
    1646, 1647, 1632, 1633, 1636, 2000, 162, 1643, 1669, 1749, 544, 1637, 7111, 1665, 1751,
    1753, 1786, 7102, 7191, 1758, 1757, 1649, 1771, 7187, 1767, 1626, 1657, 1655, 1625, 1660,
    1812, 1670, 7205, 1762, 1761, 1662, 7180, 1623, 1768, 1748, 1704, 1747, 417, 1725, 1671,
    115, 1721, 1607, 1605, 1717, 1694, 419, 1602, 49166, 1729, 49168, 1695, 1710, 1697, 1708,
    1420, 1707, 1419, 1701, 1702, 33434, 8110, 1740, 1687, 1733, 4172, 1620, 1744, 1418, 1616,
    1745, 1734, 1672, 1680, 1699, 1642, 1698, 1674, 1775, 1752, 1621, 1703, 1763, 1742, 1651,
    1756, 1653, 1681, 1739, 1738, 1606, 1736, 1770, 1031, 54921, 1624, 1658, 1692, 1724, 3001,
    5004, 396, 38996, 32773, 32007, 5308, 23000, 4567, 421, 422, 9111, 3128, 3269, 2746, 7150,
    220, 7183, 1795, 1790, 1785, 1784, 54922, 54923, 1713, 5009, 7199, 79, 1781, 48080, 1603,
    1685, 1678, 1667, 6129, 1656, 1617, 1635, 7185, 59686, 50002, 55914, 3221, 1774, 56409,
    8796, 1735, 3071, 1639, 52345, 12345, 1777, 49170, 59152, 13724, 4242, 1799, 623, 1886,
    9400, 1023, 9389, 16995, 8651, 6783, 8652, 13, 8295, 7123, 8289, 8100, 52577, 52578, 992,
    49173, 60000, 11000, 1021, 55001, 56789, 8016, 1039, 1033, 57616, 5672, 3260, 5916, 5938,
    5631, 51700, 6112, 3000, 9997, 9295, 42, 9091, 5120, 5050, 5042, 4445, 55000, 2811, 5121,
    12489, 10050, 16001, 7443, 49174, 4509, 32774, 37395, 44516, 37, 49169, 54320, 51289, 5432,
    4510, 3031, 8172, 64337, 5200, 62602, 5667, 9107, 5122, 3079, 50010, 8989, 4353, 55656,
    1048, 8092, 49178, 49180, 1032, 30005, 2598, 49171, 10008, 12346, 52000, 6003, 49200, 210,
    1041, 57282, 1049, 56790, 56729, 56819, 7004, 1047, 6259, 1241, 59822, 54400, 6667, 9,
    59778, 53974, 53946, 5223, 6067, 53700, 6036, 5500, 5901, 61116, 1017, 8834, 59278, 51080,
    22350, 30718, 49172, 53101, 53100, 53025, 52869, 13783, 2492, 2067, 2098, 51234, 57594,
    51125, 19996, 50004, 53211, 302, 300, 8570, 513, 59002, 9022, 9200, 8292, 51579, 51508,
    53192, 51928, 1034, 56293, 52195, 51400, 1046, 51339, 51333, 52374, 51233, 51225, 1056,
    1060, 51155, 1080, 52324, 52543, 53208, 52465, 53200, 53158, 53133, 56265, 56072, 56020,
    55987, 55964, 56268, 1865, 56274, 53000, 52913, 55898, 52899, 52687, 52685, 52658, 53181,
    51118, 55088, 51053, 53390, 2525, 50104, 50077, 50038, 49201, 49177, 53628, 53602, 53566,
    53556, 53407, 44442, 55557, 31865, 16509, 13000, 10011, 9501, 6481, 6501, 6556, 9007, 8676,
    8200, 54075, 54090, 50182, 50184, 55530, 55448, 55403, 55172, 8091, 55044, 50991, 50988,
    50882, 50844, 50795, 50764, 5013, 54698, 50593, 54579, 50490, 2443, 54435, 50458, 50363,
    50200, 50185, 50341, 1, 57905, 57272, 59043, 56660, 57199, 59842, 56646, 58038, 304, 56967,
    57574, 63, 56697, 56733, 57585, 666, 59909, 59334, 58769, 56882, 59703, 56606, 57878, 56827,
    57181, 59195, 64327, 57130, 57458, 58276, 58578, 56952, 57093, 57151, 57436, 62319, 57856,
    59517, 59824, 59357, 57022, 54637, 54604, 58798, 54591, 16888, 54597, 53201, 53177, 54657,
    54587, 51200, 58288, 16012, 54611, 58833, 58835, 17729, 58820, 54617, 57955, 16386, 52762,
    54514, 53207, 58699, 56901, 57894, 51104, 51102, 51098, 51095, 54387, 54385, 54377, 51089,
    54337, 47546, 54318, 54313, 58624, 57915, 53311, 56891, 53297, 57944, 22939, 58770, 27019,
    54521, 51152, 16000, 51143, 54502, 53266, 54488, 58730, 51130, 54475, 54473, 51235, 54811,
    54719, 58001, 59024, 59023, 57999, 52927, 55072, 55071, 55067, 52935, 52958, 52962, 51373,
    9600, 52989, 55035, 55030, 51392, 58005, 9998, 58245, 52778, 55315, 52783, 51476, 52809,
    51447, 52839, 9014, 52840, 55206, 55192, 9067, 59069, 59066, 59063, 57998, 55010, 51241,
    51320, 54861, 51311, 54846, 54834, 54833, 54820, 53102, 57845, 54781, 53118, 57966, 54750,
    51248, 54727, 58841, 54866, 58912, 56856, 54884, 53018, 54998, 54985, 58966,
)

# CISA's "potentially risky services": nmap service name -> the category CISA reports
# (cisagov/cyhy-reports, cyhy_report/customer/generate_report.py, RISKY_SERVICES_MAP).
RISKY_SERVICES = {
    'ms-wbt-server': 'rdp',
    'telnet': 'telnet',
    'rtelnet': 'telnet',
    'microsoft-ds': 'smb',
    'smbdirect': 'smb',
    'ldap': 'ldap',
    'netbios-ns': 'netbios',
    'netbios-dgm': 'netbios',
    'netbios-ssn': 'netbios',
    'ftp': 'ftp',
    'rsftp': 'ftp',
    'ni-ftp': 'ftp',
    'tftp': 'ftp',
    'bftp': 'ftp',
    'msrpc': 'rpc',
    'sqlnet': 'sql',
    'sqlserv': 'sql',
    'sql-net': 'sql',
    'sqlsrv': 'sql',
    'msql': 'sql',
    'mini-sql': 'sql',
    'mysql-cluster': 'sql',
    'ms-sql-s': 'sql',
    'ms-sql-m': 'sql',
    'irc': 'irc',
    'kerberos-sec': 'kerberos',
    'kpasswd5': 'kerberos',
    'klogin': 'kerberos',
    'kshell': 'kerberos',
    'kerberos-adm': 'kerberos',
    'kerberos': 'kerberos',
    'kerberos_master': 'kerberos',
    'krb_prop': 'kerberos',
    'krbupdate': 'kerberos',
    'kpasswd': 'kerberos',
}

# The TCP port nmap names each of those services by when it can't tell from the service
# itself (nmap's nmap-services file). CISA's port scan runs nmap -sV, which names a service
# from what it answers and falls back to this name; Sentry sends nothing to a service, so
# it goes by the port, overridden by a greeting the server sends unasked.
RISKY_PORT_NAMES = {
    21: 'ftp',
    23: 'telnet',
    26: 'rsftp',
    47: 'ni-ftp',
    66: 'sqlnet',
    69: 'tftp',
    88: 'kerberos-sec',
    107: 'rtelnet',
    118: 'sqlserv',
    135: 'msrpc',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    150: 'sql-net',
    152: 'bftp',
    156: 'sqlsrv',
    194: 'irc',
    389: 'ldap',
    445: 'microsoft-ds',
    464: 'kpasswd5',
    529: 'irc',
    543: 'klogin',
    544: 'kshell',
    749: 'kerberos-adm',
    750: 'kerberos',
    754: 'krb_prop',
    760: 'krbupdate',
    761: 'kpasswd',
    1112: 'msql',
    1114: 'mini-sql',
    1186: 'mysql-cluster',
    1433: 'ms-sql-s',
    1434: 'ms-sql-m',
    3389: 'ms-wbt-server',
    4333: 'msql',
    5445: 'smbdirect',
    6665: 'irc',
    6666: 'irc',
    6667: 'irc',
    6668: 'irc',
    6669: 'irc',
    6670: 'irc',
}

# A greeting the server sends unasked (service_greeting.protocol_of) beats the port's
# name, the way nmap -sV names what answers: SSH on port 21 is "ssh", not "ftp".
GREETING_NAMES = {"ssh": "ssh", "ftp": "ftp", "smtp": "smtp", "pop3": "pop3", "imap": "imap"}

# What a category is, in plain words, for the finding and the address page.
CATEGORY_WORDS = {
    "rdp": "Remote Desktop (RDP)",
    "telnet": "Telnet (unencrypted remote login)",
    "smb": "Windows file sharing (SMB)",
    "ldap": "a directory service (LDAP)",
    "netbios": "Windows NetBIOS",
    "ftp": "file transfer (FTP or TFTP)",
    "rpc": "Microsoft RPC",
    "sql": "a database (SQL)",
    "irc": "chat (IRC)",
    "kerberos": "Kerberos sign-in",
}

# ── CISA's rescan schedule (cyhy-core, cyhy/db/scheduler.py) ─────────────────────────
# A priority number per address; lower is sooner. New addresses start at 0.
START_PRIORITY = 0
RESTING_DOWN_PRIORITY = 1        # an address that keeps not answering ends at 90 days
RESTING_UP_PRIORITY = -1         # an address that answers with nothing found: 7 days
SEVERITY_PRIORITY = {1: -2, 2: -4, 3: -8, 4: -16}   # Low, Medium, High, Critical
KEV_PRIORITY = SEVERITY_PRIORITY[4]
_ANCHOR_HOURS = {1: 90 * 24, 0: 14 * 24, -1: 7 * 24, -4: 4 * 24, -8: 1 * 24, -16: 12}

# Sentry's grades on CISA's 1-4 scale (Nessus: 1 Low, 2 Medium, 3 High, 4 Critical).
# MODERATE-HIGH sits between Medium and High; it goes up, so the address is rescanned
# sooner rather than later. INFO is not a CISA ticket (0).
SENTRY_TO_CISA_LEVEL = {"CRITICAL": 4, "HIGH": 3, "MODERATE-HIGH": 3, "MODERATE": 2, "LOW": 1, "INFO": 0}


def interval_hours(priority: int) -> float:
    """Hours until the next scan at this priority: CISA's anchors, straight lines between
    them (pandas interpolate, linear), clamped to 1 .. -16."""
    p = max(-16, min(1, int(priority)))
    if p in _ANCHOR_HOURS:
        return float(_ANCHOR_HOURS[p])
    hi = min(k for k in _ANCHOR_HOURS if k > p)      # nearer zero
    lo = max(k for k in _ANCHOR_HOURS if k < p)      # more urgent
    frac = (hi - p) / (hi - lo)
    return _ANCHOR_HOURS[hi] + (_ANCHOR_HOURS[lo] - _ANCHOR_HOURS[hi]) * frac


def next_priority(priority: int, up: bool, max_level: int, kev_count: int) -> int:
    """CISA's DefaultScheduler.schedule(), one scan's step."""
    p = int(priority)
    if not up:
        return p + 1 if p < RESTING_DOWN_PRIORITY else p
    if max_level > 0:
        if kev_count > 0:
            return KEV_PRIORITY
        want = SEVERITY_PRIORITY[max(1, min(4, int(max_level)))]
        if want == p:
            return p
        if want < p:
            return want
        return p + 1                     # recovering from something worse: one step a scan
    if p < RESTING_UP_PRIORITY:
        return p + 1
    if p > RESTING_UP_PRIORITY:
        return RESTING_UP_PRIORITY
    return p


def cisa_level(severity: str | None, cvss_score=None) -> int:
    """The grade CISA would likely give, 0-4. Nessus grades by CVSS base score (Critical
    9.0+, High 7.0+, Medium 4.0+, Low above 0), so a finding with a score goes by the
    score; one without goes by Sentry's own grade (SENTRY_TO_CISA_LEVEL)."""
    if cvss_score is not None:
        try:
            v = float(cvss_score)
        except (TypeError, ValueError):
            v = None
        if v is not None:
            return 4 if v >= 9.0 else 3 if v >= 7.0 else 2 if v >= 4.0 else 1 if v > 0 else 0
    return SENTRY_TO_CISA_LEVEL.get(str(severity or "").upper(), 0)


CISA_LEVEL_WORDS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "not reported"}


def worst_level(grades) -> int:
    """The worst open grade on CISA's scale; 0 when nothing would be a CISA ticket."""
    return max((SENTRY_TO_CISA_LEVEL.get(str(g).upper(), 0) for g in grades), default=0)


# ── 1. Is it up? ─────────────────────────────────────────────────────────────────────
PING_PORTS = frozenset(PING_PORTS_FIRST) | frozenset(PING_PORTS_SECOND)


def cisa_sees_up(icmp_answered: bool, knock: dict) -> bool:
    """Would CISA's ping call this address up? knock maps port -> 'open' | 'refused' |
    'silent'. An nmap TCP ping counts a refusal (a reset) as an answer, the same as a
    port that opens; only silence on every ping port, and no ICMP reply, is "down"."""
    if icmp_answered:
        return True
    return any(state in ("open", "refused") for port, state in knock.items() if int(port) in PING_PORTS)


# ── 2. Every port: what a one-pass scan lists, and what re-answers ────────────────────
def split_ports(one_pass, reanswered) -> dict:
    """one_pass: the ports a single sweep found open (what CISA's one-pass nmap lists).
    reanswered: those that opened again on a re-check from the same exit. Only these
    become findings; the rest are phantoms (a cloud edge accepting a connection nothing
    stands behind; Sentry's cloud gate, July 2026)."""
    seen = sorted({int(p) for p in one_pass})
    again = sorted({int(p) for p in reanswered} & set(seen))
    return {"one_pass": seen, "reanswered": again, "phantom": sorted(set(seen) - set(again))}


# ── Service names and CISA's risky list ──────────────────────────────────────────────
def nmap_name(port: int, greeting_protocol: str | None = None) -> str | None:
    """The name nmap would most likely give the service: a greeting first, else the
    port's name for CISA's risky services. None: not one this table knows."""
    if greeting_protocol in GREETING_NAMES:
        return GREETING_NAMES[greeting_protocol]
    return RISKY_PORT_NAMES.get(int(port))


def risky_category(port: int, greeting_protocol: str | None = None) -> str | None:
    """CISA's category ('rdp', 'smb', ...) when CISA would list this service as
    potentially risky; None otherwise."""
    name = nmap_name(port, greeting_protocol)
    return RISKY_SERVICES.get(name) if name else None


def risky_service_finding(address: str, port: int, greeting_protocol: str | None = None) -> dict | None:
    """The fields of the finding for a risky service CISA would list, or None. INFO, as
    CISA grades it (its only Informational tickets are these); the address page shows it
    under CISA's heading."""
    cat = risky_category(port, greeting_protocol)
    if not cat:
        return None
    name = nmap_name(port, greeting_protocol)
    what = CATEGORY_WORDS.get(cat, cat)
    return {
        "key": f"cisa-risky-service-{cat}-{int(port)}-tcp",
        "title": f"Open to the internet: {what} on {int(port)}/tcp (CISA lists it as a potentially risky service)",
        "severity": "INFO",
        "category": "recon",
        "description": (f"{address} accepts connections on {int(port)}/tcp, which nmap names "
                        f"'{name}'. CISA's Cyber Hygiene report lists {what} as a potentially "
                        f"risky service whenever it is open to the internet, whatever its version."),
        "port": int(port),
        "protocol": "tcp",
    }


# ── The safety rail: scan an address only while one of its names still points at it ──
def names_pointing_here(address: str, names, resolve) -> list[str]:
    """The names (from the address's list) whose current DNS answers include it.
    resolve(name) -> iterable of address strings; a lookup that fails counts as not
    pointing. Empty: do not scan (the address may now belong to someone else)."""
    want = ipaddress.ip_address(address)
    out = []
    for n in names or ():
        try:
            got = {ipaddress.ip_address(a) for a in resolve(n)}
        except Exception:
            continue
        if want in got:
            out.append(n)
    return out


def sweep_command(address: str, rate: int) -> list[str]:
    """naabu over every TCP port, CONNECT (no raw packets over the VPN), JSON lines."""
    ipaddress.ip_address(address)        # an address, never a name or a range
    return ["naabu", "-host", address, "-p", "-", "-rate", str(int(rate)),
            "-scan-type", "CONNECT", "-silent", "-json"]
