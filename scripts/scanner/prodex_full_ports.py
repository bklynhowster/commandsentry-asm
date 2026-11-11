#!/usr/bin/env python3
"""Prodex-only every-port scope and bounded application proof.

Scope is authorization data, not a target list or host classification. Command has no
scope file and never takes this path. Network functions are injectable for tests.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import socket
import ssl
import time
from pathlib import Path
import service_greeting as sg

SCOPE_PATH = Path(__file__).resolve().parents[2] / "data" / "prodex_port_scope.json"
MAX_PROOF_PORTS = 12
PROOF_BUDGET_S = 90.0
CONTROL_PORTS = (65431, 65432, 65433)
SWEEP_TIMEOUT_S = 1200
# Scheduling only; responses, not this list, identify services.
PRIORITY_PORTS = (22, 21, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                  1433, 1521, 3306, 3389, 5432, 8080, 8443)


def load_scope(path=None) -> dict:
    """Validated {IPv4: record}; absent/malformed scope means no authorization."""
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8") if path else
                          SCOPE_PATH.read_text(encoding="utf-8"))["addresses"]
        out = {}
        for row in rows:
            address = str(ipaddress.ip_address(row["address"]))
            names = sorted({str(n).lower().rstrip(".") for n in row["names"] if str(n).strip()})
            if names:
                out[address] = {**row, "address": address, "names": names}
        return out
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def resolve_ipv4(host: str, resolver=None) -> list[str]:
    try:
        resolver = resolver or (lambda h: [a[4][0] for a in socket.getaddrinfo(h, None, socket.AF_INET)])
        return sorted({str(ipaddress.ip_address(a)) for a in resolver(host)
                       if ipaddress.ip_address(a).version == 4})
    except (OSError, ValueError, TypeError):
        return []


def authorized_address(host: str, *, scope=None, resolver=None, path=None) -> str | None:
    """The authorized current address for this exact expected name, else None."""
    scope = load_scope(path) if scope is None else scope
    host, resolved = host.lower().rstrip("."), set(resolve_ipv4(host, resolver))
    for address, row in scope.items():
        if host in row["names"] and address in resolved:
            return address
    return None


def sweep_command(host: str, rate: int) -> list[str]:
    return ["naabu", "-host", host, "-p", "-", "-rate", str(int(rate)),
            "-scan-type", "CONNECT", "-silent", "-json"]


def candidate_order(ports, scan_id: str) -> list[int]:
    """Familiar services first, then stable scan-ID rotation of the other ports."""
    values = sorted({int(p) for p in ports})
    first = [p for p in PRIORITY_PORTS if p in values]
    rest = [p for p in values if p not in PRIORITY_PORTS]
    if rest:
        shift = int(hashlib.sha256(str(scan_id).encode()).hexdigest()[:8], 16) % len(rest)
        rest = rest[shift:] + rest[:shift]
    return first + rest


def _fingerprint(value) -> str | None:
    if not value:
        return None
    return value if isinstance(value, str) else hashlib.sha256(str(value).encode()).hexdigest()


def prove_ports(host: str, raw_ports, scan_id: str, *, reconfirm, probe,
                clock=time.monotonic, max_ports=MAX_PROOF_PORTS,
                budget_s=PROOF_BUDGET_S) -> dict:
    """Bound recheck + proof. probe returns kind/fingerprint/default_fingerprint."""
    start = clock()
    raw = sorted({int(p) for p in raw_ports})
    candidates = candidate_order(raw, scan_id)
    attempted, overflow = candidates[:max_ports], candidates[max_ports:]
    defaults, control_open, entries = set(), [], []
    budget_exhausted = False

    def time_left():
        return budget_s - (clock() - start)

    for port in CONTROL_PORTS:
        if time_left() <= 0:
            budget_exhausted = True
            break
        try:
            if reconfirm(host, port):
                control_open.append(port)
                answer = probe(host, port, False) or {}
                fp = _fingerprint(answer.get("fingerprint"))
                if fp:
                    defaults.add(fp)
        except Exception:
            pass
    for port in attempted:
        if time_left() <= 0:
            budget_exhausted = True
            break
        entry = {"port": port, "status": "unproven", "kind": None, "fingerprint": None}
        try:
            if not reconfirm(host, port):
                entry["status"] = "phantom"
            else:
                answer = probe(host, port, True) or {}
                fp = _fingerprint(answer.get("fingerprint"))
                default_fp = _fingerprint(answer.get("default_fingerprint"))
                entry.update(kind=answer.get("kind"), fingerprint=fp)
                if fp and fp not in defaults and fp != default_fp:
                    entry["status"] = "proven"
                elif fp:
                    entry["status"] = "default_response"
        except Exception as exc:
            entry.update(status="proof_error", error=type(exc).__name__)
        entries.append(entry)
    attempted_set = {e["port"] for e in entries}
    overflow = sorted(set(overflow) | (set(attempted) - attempted_set))
    proven = [e["port"] for e in entries if e["status"] == "proven"]
    if time_left() < 0:
        budget_exhausted = True
    complete = not overflow and not budget_exhausted
    return {
        "one_pass": raw, "attempted": sorted(attempted_set), "proof_overflow": overflow,
        "reanswered": [e["port"] for e in entries if e["status"] != "phantom"],
        "proven": proven,
        "unproven": [e["port"] for e in entries if e["status"] != "proven"],
        "control_ports_open": control_open,
        "accept_all_controls": len(control_open) == len(CONTROL_PORTS),
        "proof_complete": complete, "budget_exhausted": budget_exhausted,
        "max_proof_ports": max_ports, "proof_budget_s": budget_s, "results": entries,
    }


def _tls_answer(host: str, port: int, named: bool, timeout: float) -> str | None:
    """Certificate hash only; no application data or authentication is sent."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with context.wrap_socket(raw, server_hostname=host if named else None) as conn:
            cert = conn.getpeercert(binary_form=True)
            return hashlib.sha256(cert).hexdigest() if cert else None


def _http_answer(host: str, port: int, named: bool, timeout: float) -> str | None:
    """An ordinary HEAD request; retain only a bounded body/status fingerprint."""
    if named:
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
    else:
        request = b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(request)
        chunks, size = [], 0
        while size < 4096:
            block = conn.recv(min(1024, 4096 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
    raw = b"".join(chunks)
    if not raw:
        return None
    body = raw.partition(b"\r\n\r\n")[2] or raw.split(b"\r\n", 1)[0]
    return hashlib.sha256(body).hexdigest()


def probe_application(host: str, port: int, named: bool, timeout: float = 3.0) -> dict | None:
    """Greeting, TLS hello, or plain web HEAD; only kind and hashes leave this function."""
    try:
        greeting = sg.read_greeting(host, port, connect_s=timeout, read_s=timeout)
        if greeting.get("greeting"):
            return {"kind": greeting.get("protocol") or "greeting",
                    "fingerprint": hashlib.sha256(greeting["greeting"].encode()).hexdigest(),
                    "default_fingerprint": None}
    except (OSError, ValueError):
        pass
    try:
        fingerprint = _tls_answer(host, port, named, timeout)
        if fingerprint:
            default = None if named else fingerprint
            if named:
                try:
                    default = _tls_answer(host, port, False, timeout)
                except (OSError, ValueError, ssl.SSLError):
                    pass
            return {"kind": "https", "fingerprint": fingerprint, "default_fingerprint": default}
    except (OSError, ValueError, ssl.SSLError):
        pass
    try:
        fingerprint = _http_answer(host, port, named, timeout)
        if fingerprint:
            default = None if named else fingerprint
            if named:
                try:
                    default = _http_answer(host, port, False, timeout)
                except OSError:
                    pass
            return {"kind": "http", "fingerprint": fingerprint, "default_fingerprint": default}
    except OSError:
        pass
    return None

