"""Concurrent TCP connect scanning and lightweight banner grabbing."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from .models import Service
from .services import HTTP_PORTS, TLS_PORTS, identify_service

MAX_BANNER = 1024

# Telnet IAC (Interpret As Command) sequences: 0xFF followed by a command byte
# and, for WILL/WONT/DO/DONT, an option byte.
IAC = 0xFF


def strip_telnet_negotiation(data: bytes) -> tuple[bytes, bool]:
    """Remove telnet option negotiation; return (clean bytes, saw_iac)."""
    out = bytearray()
    saw_iac = False
    i = 0
    while i < len(data):
        b = data[i]
        if b == IAC and i + 1 < len(data):
            saw_iac = True
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL WONT DO DONT
                i += 3
                continue
            if cmd == 0xFA:  # sub-negotiation until IAC SE
                end = data.find(bytes([IAC, 0xF0]), i + 2)
                i = len(data) if end == -1 else end + 2
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out), saw_iac


def clean_banner(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    printable = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)
    return printable.strip()[:MAX_BANNER]


def _http_probe(host: str) -> bytes:
    return (
        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: lan-auditor\r\nConnection: close\r\n\r\n"
    ).encode()


def _recv(sock: socket.socket, limit: int = MAX_BANNER) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(limit - total)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        # Most banners are one line or one response; stop after a short pause.
        sock.settimeout(0.3)
    return b"".join(chunks)


def is_port_open(ip: str, port: int, timeout: float = 0.75) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Service:
    """Connect to an open port and fingerprint what answers.

    Strategy: (1) wait briefly for a volunteered banner (SSH, FTP, SMTP,
    telnet...), (2) on TLS ports, complete a handshake and send an HTTP HEAD,
    (3) on HTTP ports, send an HTTP HEAD in plaintext.
    """
    svc = Service(port=port)
    data = b""
    saw_iac = False

    if port in TLS_PORTS:
        data = _grab_tls(ip, port, timeout)
        if data is not None:
            svc.tls = True
        else:
            data = b""

    if not svc.tls:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(min(timeout, 1.5))
                data = _recv(sock)
                if not data and port in HTTP_PORTS | {8443, 443}:
                    sock.settimeout(timeout)
                    sock.sendall(_http_probe(ip))
                    data = _recv(sock)
        except OSError:
            data = b""
        data, saw_iac = strip_telnet_negotiation(data)

    svc.banner = clean_banner(data)
    svc.service = identify_service(port, svc.banner, svc.tls)
    if saw_iac and svc.service not in ("ssh", "http", "https"):
        svc.service = "telnet"
    return svc


def _grab_tls(ip: str, port: int, timeout: float) -> bytes | None:
    """Return the HTTP response (possibly empty) over TLS, or None if not TLS."""
    ctx = ssl.create_default_context()
    # We fingerprint, we do not trust: home devices nearly always use
    # self-signed certificates, so verification is intentionally disabled.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                if port in (443, 5001, 8443):
                    tls.sendall(_http_probe(ip))
                tls.settimeout(min(timeout, 1.5))
                return _recv(tls)
    except (OSError, ssl.SSLError):
        return None


def scan_host(
    ip: str,
    ports: list[int],
    *,
    timeout: float = 0.75,
    banner_timeout: float = 2.0,
    workers: int = 64,
    grab: bool = True,
) -> list[Service]:
    """Scan ``ports`` on ``ip`` concurrently and fingerprint the open ones."""
    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        flags = list(pool.map(lambda p: is_port_open(ip, p, timeout), ports))
    open_ports = [p for p, ok in zip(ports, flags, strict=True) if ok]
    if not grab:
        return [Service(port=p, service=identify_service(p)) for p in open_ports]
    if not open_ports:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(open_ports))) as pool:
        return list(pool.map(lambda p: grab_banner(ip, p, banner_timeout), open_ports))
