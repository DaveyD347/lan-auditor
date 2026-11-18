"""Port lists and service identification."""

from __future__ import annotations

import re

# Well-known ports seen on home networks, mapped to the expected service.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "smb",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1883: "mqtt",
    1900: "upnp",
    2049: "nfs",
    2323: "telnet",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp",
    5001: "https",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5900: "vnc",
    5901: "vnc",
    6379: "redis",
    7547: "tr-069",
    8000: "http",
    8008: "http",
    8009: "ajp",
    8080: "http",
    8081: "http",
    8443: "https",
    8883: "mqtts",
    8888: "http",
    9000: "http",
    9100: "jetdirect",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    32400: "plex",
    49152: "upnp",
    62078: "iphone-sync",
}

DEFAULT_PORTS: list[int] = sorted(COMMON_PORTS)

# Ports where we should actively speak HTTP if nothing is volunteered.
HTTP_PORTS = {80, 81, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8888, 9000, 32400, 49152}
# Ports where we should attempt a TLS handshake.
TLS_PORTS = {443, 993, 995, 5001, 8443, 8883}

# (regex, service) pairs applied to the banner, first match wins.
BANNER_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^SSH-\d", re.I), "ssh"),
    (re.compile(r"^HTTP/\d", re.I), "http"),
    (re.compile(r"^220[ -].*\b(ftp|filezilla|vsftpd|proftpd|pure-ftpd)\b", re.I), "ftp"),
    (re.compile(r"^220[ -].*\b(smtp|esmtp|postfix|exim|sendmail)\b", re.I), "smtp"),
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
    (re.compile(r"^RFB \d{3}\.\d{3}", re.I), "vnc"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    (re.compile(r"^-ERR.*redis|^\$\d+\r?\n# Server", re.I), "redis"),
    (re.compile(r"\b(login|username|password)\s*:", re.I), "telnet"),
]


def identify_service(port: int, banner: str = "", tls: bool = False) -> str:
    """Best guess at the service on ``port`` given its banner."""
    for pattern, name in BANNER_SIGNATURES:
        if banner and pattern.search(banner):
            if name == "http" and tls:
                return "https"
            return name
    guess = COMMON_PORTS.get(port, "unknown")
    if tls and guess == "http":
        return "https"
    return guess


def parse_ports(spec: str) -> list[int]:
    """Parse ``"22,80,8000-8100"`` or the keywords ``default`` / ``all``."""
    spec = spec.strip().lower()
    if spec in ("", "default", "common"):
        return list(DEFAULT_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port out of range: {bad[0]}")
    return sorted(ports)
