"""Host discovery: ARP, ICMP and TCP "ping" sweeps.

Each method returns the set of IPs it found alive. ARP (via scapy) needs root
and is optional; ICMP uses the system ``ping`` binary so no raw sockets or
privileges are required; TCP ping uses ordinary connect() calls, where both a
completed handshake and an explicit refusal (RST) prove the host is up.
"""

from __future__ import annotations

import errno
import platform
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

from .oui import normalize_mac

# Ports that most home devices answer on (or actively refuse).
TCP_PING_PORTS = (80, 443, 22, 445, 139, 8080, 53, 62078, 8008, 554)

_REFUSED = {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", 10061)}


# --------------------------------------------------------------------------- ICMP


def _ping_command(ip: str, timeout: float) -> list[str] | None:
    exe = shutil.which("ping")
    if not exe:
        return None
    system = platform.system()
    if system == "Windows":
        return [exe, "-n", "1", "-w", str(int(timeout * 1000)), ip]
    if system == "Darwin":
        return [exe, "-c", "1", "-W", str(int(timeout * 1000)), ip]
    return [exe, "-c", "1", "-W", str(max(1, round(timeout))), ip]


def icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    cmd = _ping_command(ip, timeout)
    if cmd is None:
        return False
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


# --------------------------------------------------------------------------- TCP


def tcp_ping(ip: str, ports: Iterable[int] = TCP_PING_PORTS, timeout: float = 0.5) -> bool:
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
        except OSError:
            continue
        finally:
            sock.close()
        if code == 0 or code in _REFUSED:
            return True
    return False


# --------------------------------------------------------------------------- ARP


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except Exception:  # pragma: no cover - depends on environment
        return False
    return True


def arp_sweep(cidr_or_ips: str | list[str], timeout: float = 2.0) -> dict[str, str]:
    """Active ARP sweep with scapy. Returns ``{ip: mac}``. Needs root."""
    from scapy.all import ARP, Ether, conf, srp  # type: ignore

    conf.verb = 0
    pdst = cidr_or_ips if isinstance(cidr_or_ips, str) else list(cidr_or_ips)
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst), timeout=timeout, retry=1)
    return {rcv.psrc: normalize_mac(rcv.hwsrc) or rcv.hwsrc for _, rcv in answered}


_ARP_LINE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<mac>[0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})"
)


def parse_arp_output(text: str) -> dict[str, str]:
    """Parse ``/proc/net/arp``, ``arp -an`` or Windows ``arp -a`` output."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        m = _ARP_LINE.search(line)
        if not m:
            continue
        # Pad single-digit octets that macOS prints (e.g. "0:1b:63:...").
        parts = re.split(r"[:-]", m.group("mac"))
        mac = normalize_mac("".join(p.zfill(2) for p in parts))
        if mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            table[m.group("ip")] = mac
    return table


def read_arp_cache() -> dict[str, str]:
    """Read the operating system's ARP cache without sending any packets."""
    try:
        with open("/proc/net/arp", encoding="ascii") as fh:
            return parse_arp_output(fh.read())
    except OSError:
        pass
    exe = shutil.which("arp")
    if not exe:
        return {}
    args = [exe, "-a"] if platform.system() == "Windows" else [exe, "-an"]
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            args, capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp_output(out)


# --------------------------------------------------------------------------- DNS


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return name if name != ip else None


# --------------------------------------------------------------------------- sweep


def sweep(
    ips: list[str],
    probe: Callable[[str], bool],
    workers: int = 128,
) -> set[str]:
    """Run ``probe`` against every IP concurrently; return the ones that answered."""
    if not ips:
        return set()
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as pool:
        results = pool.map(probe, ips)
        return {ip for ip, alive in zip(ips, results, strict=True) if alive}
