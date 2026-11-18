"""Risk rules: flag unencrypted, legacy or commonly-misconfigured services.

Rules are deliberately conservative and explainable. Each finding says *why*
the service is a concern so a home-lab user can decide what to do about it.
These are indicators, not proof of a vulnerability.
"""

from __future__ import annotations

import re

from .models import Finding, Host, Service, Severity

# service name -> (rule id, severity, title, detail)
SERVICE_RULES: dict[str, tuple[str, Severity, str, str]] = {
    "telnet": (
        "LAN-TELNET",
        Severity.HIGH,
        "Telnet service exposed",
        "Telnet sends usernames, passwords and session data in cleartext and is a "
        "favourite target of IoT botnets such as Mirai. Disable it and use SSH.",
    ),
    "ftp": (
        "LAN-FTP",
        Severity.MEDIUM,
        "Plaintext FTP service",
        "FTP transmits credentials and files unencrypted. Prefer SFTP or FTPS, and "
        "check that anonymous login is disabled.",
    ),
    "adb": (
        "LAN-ADB",
        Severity.CRITICAL,
        "Android Debug Bridge over network",
        "ADB on TCP 5555 usually grants an unauthenticated root or shell session on "
        "Android devices and TV boxes. Turn off network debugging.",
    ),
    "vnc": (
        "LAN-VNC",
        Severity.HIGH,
        "VNC remote desktop exposed",
        "VNC is often configured with weak or no passwords and the classic protocol "
        "is unencrypted. Restrict it or tunnel it over SSH/VPN.",
    ),
    "rdp": (
        "LAN-RDP",
        Severity.MEDIUM,
        "Remote Desktop (RDP) exposed",
        "RDP is a common brute-force and exploit target. Ensure Network Level "
        "Authentication is on, the host is patched, and it is not port-forwarded.",
    ),
    "smb": (
        "LAN-SMB",
        Severity.LOW,
        "SMB file sharing available",
        "SMB shares are normal on a LAN but should require authentication. Make "
        "sure SMBv1 is disabled and the port is never forwarded to the internet.",
    ),
    "netbios-ssn": (
        "LAN-NETBIOS",
        Severity.LOW,
        "NetBIOS session service available",
        "Legacy NetBIOS can leak host and user names. Disable it if unused.",
    ),
    "redis": (
        "LAN-REDIS",
        Severity.HIGH,
        "Redis exposed on the network",
        "Redis has historically shipped with no authentication; an open instance "
        "can lead to data theft or remote code execution. Bind it to localhost or "
        "require a password.",
    ),
    "mongodb": (
        "LAN-MONGODB",
        Severity.HIGH,
        "MongoDB exposed on the network",
        "Older MongoDB defaults allowed unauthenticated access. Enable auth and "
        "bind to localhost unless remote access is required.",
    ),
    "memcached": (
        "LAN-MEMCACHED",
        Severity.HIGH,
        "Memcached exposed on the network",
        "Memcached has no authentication by default. Bind it to localhost.",
    ),
    "elasticsearch": (
        "LAN-ELASTIC",
        Severity.HIGH,
        "Elasticsearch HTTP API exposed",
        "Older Elasticsearch versions expose all data without authentication.",
    ),
    "mysql": (
        "LAN-MYSQL",
        Severity.MEDIUM,
        "MySQL/MariaDB exposed on the network",
        "Database ports should not normally be reachable from other LAN devices.",
    ),
    "postgresql": (
        "LAN-POSTGRES",
        Severity.MEDIUM,
        "PostgreSQL exposed on the network",
        "Database ports should not normally be reachable from other LAN devices.",
    ),
    "mqtt": (
        "LAN-MQTT",
        Severity.MEDIUM,
        "Plaintext MQTT broker",
        "MQTT on 1883 is unencrypted and frequently allows anonymous clients to "
        "read and publish smart-home messages. Use 8883 with TLS and auth.",
    ),
    "tr-069": (
        "LAN-TR069",
        Severity.MEDIUM,
        "TR-069 / CWMP management interface",
        "ISP remote-management (TR-069) has a history of serious router "
        "vulnerabilities. Check your router firmware is current.",
    ),
    "upnp": (
        "LAN-UPNP",
        Severity.LOW,
        "UPnP service detected",
        "UPnP lets devices open ports on your router automatically. Consider "
        "disabling UPnP on the router if you do not need it.",
    ),
    "rtsp": (
        "LAN-RTSP",
        Severity.LOW,
        "RTSP video stream service",
        "Camera streams over RTSP are often unauthenticated. Verify a password is "
        "required to view the stream.",
    ),
    "jetdirect": (
        "LAN-JETDIRECT",
        Severity.LOW,
        "Raw printing port (JetDirect) open",
        "Port 9100 accepts unauthenticated print jobs and sometimes printer "
        "commands. Fine on a trusted LAN; never expose it externally.",
    ),
    "rsync": (
        "LAN-RSYNC",
        Severity.MEDIUM,
        "rsync daemon exposed",
        "rsync modules may be readable without authentication.",
    ),
    "nfs": (
        "LAN-NFS",
        Severity.MEDIUM,
        "NFS export service exposed",
        "Check exports are restricted to specific hosts.",
    ),
    "pop3": (
        "LAN-POP3",
        Severity.LOW,
        "Plaintext POP3",
        "POP3 on port 110 sends credentials unencrypted unless STARTTLS is enforced.",
    ),
    "imap": (
        "LAN-IMAP",
        Severity.LOW,
        "Plaintext IMAP",
        "IMAP on port 143 sends credentials unencrypted unless STARTTLS is enforced.",
    ),
    "socks": (
        "LAN-SOCKS",
        Severity.MEDIUM,
        "SOCKS proxy exposed",
        "An open proxy can be abused to pivot through your network.",
    ),
}

_ADMIN_HINTS = re.compile(
    r"router|gateway|admin|login|management|webui|web ui|lighttpd|goahead|"
    r"boa/|mini_httpd|micro_httpd|rompager|hikvision|dvr|nvr|ipcam|camera|"
    r"openwrt|luci|dd-wrt|tomato|netgear|tp-link|linksys|asus|d-link|zyxel|"
    r"ubiquiti|unifi|synology|qnap|printer",
    re.I,
)
_BASIC_AUTH = re.compile(r"^www-authenticate:\s*basic", re.I | re.M)
_OPENSSH = re.compile(r"OpenSSH[_-](\d+)\.(\d+)", re.I)


def _http_findings(svc: Service) -> list[Finding]:
    if svc.tls or svc.service not in ("http",):
        return []
    banner = svc.banner
    if _BASIC_AUTH.search(banner):
        return [
            Finding(
                "LAN-HTTP-BASIC",
                Severity.HIGH,
                "HTTP Basic auth over plaintext",
                "This interface asks for a username and password using HTTP Basic "
                "auth without TLS, so credentials cross the network base64-encoded "
                "(effectively cleartext). Enable HTTPS on the device.",
                svc.port,
            )
        ]
    if banner.startswith("HTTP/") and (
        _ADMIN_HINTS.search(banner) or re.search(r"^HTTP/\S+\s+401", banner, re.M)
    ):
        return [
            Finding(
                "LAN-HTTP-ADMIN",
                Severity.MEDIUM,
                "Unencrypted HTTP management interface",
                "This looks like a device admin page served over plain HTTP. "
                "Anyone on the network can sniff the login. Enable HTTPS if the "
                "device supports it.",
                svc.port,
            )
        ]
    return [
        Finding(
            "LAN-HTTP",
            Severity.LOW,
            "Unencrypted HTTP service",
            "A web service is reachable over plain HTTP. If it has a login or settings page, prefer HTTPS.",
            svc.port,
        )
    ]


def _ssh_findings(svc: Service) -> list[Finding]:
    if svc.service != "ssh":
        return []
    if re.match(r"SSH-1\.(?!99)", svc.banner):
        return [
            Finding(
                "LAN-SSH-V1",
                Severity.HIGH,
                "SSH protocol version 1 supported",
                "SSHv1 has known cryptographic weaknesses. Upgrade the device.",
                svc.port,
            )
        ]
    m = _OPENSSH.search(svc.banner)
    if m and (int(m.group(1)), int(m.group(2))) < (7, 4):
        return [
            Finding(
                "LAN-SSH-OLD",
                Severity.MEDIUM,
                f"Outdated OpenSSH {m.group(1)}.{m.group(2)}",
                "OpenSSH older than 7.4 is long out of support and affected by "
                "several published vulnerabilities. Update the firmware or OS.",
                svc.port,
            )
        ]
    return []


def evaluate_service(svc: Service) -> list[Finding]:
    findings: list[Finding] = []
    rule = SERVICE_RULES.get(svc.service)
    if rule:
        rule_id, severity, title, detail = rule
        findings.append(Finding(rule_id, severity, title, detail, svc.port))
    findings.extend(_http_findings(svc))
    findings.extend(_ssh_findings(svc))
    return findings


def evaluate_host(host: Host) -> list[Finding]:
    """Compute and attach findings for ``host``; returns them sorted by severity."""
    findings: list[Finding] = []
    for svc in host.services:
        findings.extend(evaluate_service(svc))
    findings.sort(key=lambda f: (-f.severity, f.port or 0))
    host.findings = findings
    return findings
