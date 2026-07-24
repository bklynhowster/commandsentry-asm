"""Tests for extended liveness (Obsidian 161 step 5 / 4.7 Q5+Q7).

_reachability_verdict is the pure core: (live, ext_live, nonhttp_ports_hit). Old httpx-only `live`
stays authoritative in shadow-mode; the extended verdict ALSO counts a confirmed non-HTTP service
(SSH/SFTP, FTPS, mail) so a correctly-hardened plaintext-killed box stops reading dead.
"""
from normalize import _reachability_verdict as V, _NONHTTP_LIVE_PORTS


def test_http_status_is_live_including_auth_gate():
    # any HTTP status = live in BOTH modes (401/403 already counted before this change)
    assert V(200, set(), False) == (True, True, [])
    assert V(401, set(), False) == (True, True, [])          # auth-gated 443 is alive
    assert V(403, set(), False) == (True, True, [])


def test_sftp_only_diverges_shadow_keeps_old_flip_makes_alive():
    # the ftp.unimacgraphics.com / SFTP-only shape: 22 open, no HTTP response
    assert V(None, {22}, False) == (False, True, [22])       # SHADOW: authoritative=old(dead), ext=alive
    assert V(None, {22}, True) == (True, True, [22])         # FLIPPED: authoritative=ext(alive)


def test_nonhttp_ports_reported_even_when_http_live():
    # nonhttp list is informational — populated regardless of http; no divergence when both live
    assert V(200, {22}, False) == (True, True, [22])
    assert V(200, {22, 990}, False) == (True, True, [22, 990])


def test_ftps_and_mail_ports_count_https_port_does_not():
    # 990 FTPS + 22 SSH count; 443 is HTTP (caught by httpx path), not in the non-http set
    assert V(None, {22, 990, 443}, False) == (False, True, [22, 990])
    assert V(None, {465, 993, 995}, True) == (True, True, [465, 993, 995])   # mail-hardened box, flipped


def test_genuinely_dead_and_non_prove_ports():
    assert V(None, set(), False) == (False, False, [])
    assert V(None, {3306}, False) == (False, False, [])      # mysql is NOT a prove-alive port
    assert V(None, None, False) == (False, False, [])        # tolerate None ports


def test_nonhttp_live_port_set_is_the_hardening_suite():
    # SSH/SFTP + FTP(S) + mail — the services a plaintext-killed box legitimately answers on
    assert {22, 21, 990} <= _NONHTTP_LIVE_PORTS
    assert {25, 465, 587, 993, 995, 110, 143} <= _NONHTTP_LIVE_PORTS
    assert 443 not in _NONHTTP_LIVE_PORTS and 80 not in _NONHTTP_LIVE_PORTS   # HTTP handled by httpx
