# lan-auditor

**Home network LAN auditor and device fingerprinter.** Find every device on your
network, see which ports and services they expose, and get plain-English flags
for the risky ones: Telnet, plaintext HTTP admin pages, network ADB, open Redis
and more.

Pure Python, no required dependencies, runs on Linux, macOS and Windows.

[![CI](https://github.com/DaveyD347/lan-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/DaveyD347/lan-auditor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> [!WARNING]
> **Only scan networks you own or have explicit written permission to test.**
> Port scanning someone else's network may be illegal where you live and will
> likely violate your ISP's or employer's terms. By default lan-auditor refuses
> to scan anything outside private address ranges (10/8, 172.16/12,
> 192.168/16, link-local and loopback).

## Features

| Area | What it does |
|---|---|
| **Host discovery** | ARP sweep (scapy, optional), ICMP ping sweep (system `ping`, no root needed) and TCP "ping" (a SYN-ACK *or* an RST both prove a host is up), all run concurrently |
| **Port scanning** | Concurrent TCP connect scan of ~55 home-network ports by default, or any list/range you choose |
| **Banner grabbing** | Reads volunteered banners (SSH, FTP, SMTP, VNC), sends `HEAD /` to web ports, completes TLS handshakes on TLS ports, and strips Telnet option negotiation to reveal login prompts |
| **Device fingerprinting** | MAC vendor (OUI) lookup from a built-in table or the full IEEE registry, reverse DNS names, and detection of randomised "private" MACs used by modern phones |
| **Risk flags** | 25+ explainable rules with severities, from `LOW` (plain HTTP) to `CRITICAL` (network ADB), and a 0-100 risk score per host |
| **Output** | Coloured terminal report, JSON for scripting, Markdown for sharing; `--fail-on` exit codes for cron or CI |

## Install

```bash
git clone https://github.com/DaveyD347/lan-auditor.git
cd lan-auditor
python -m pip install .            # core, zero dependencies
python -m pip install ".[arp]"     # optional: active ARP sweeps via scapy
```

Or run it without installing: `python -m lanaudit` from the `src` directory.

## Usage

```bash
# Scan your local /24 (auto-detected)
lan-auditor

# Scan a specific subnet, range or host
lan-auditor 192.168.1.0/24
lan-auditor 192.168.1.10-50,192.168.1.200

# Pick ports
lan-auditor 192.168.1.0/24 -p 22,23,80,443,8000-8100
lan-auditor 192.168.1.1 -p all

# Skip discovery (treat hosts as up, like nmap -Pn)
lan-auditor 192.168.1.1 -Pn

# Reports
lan-auditor -f json -o scan.json
lan-auditor -f markdown -o report.md

# Exit with status 2 if anything HIGH or worse is found (cron / CI friendly)
lan-auditor --fail-on high -q

# Download the full IEEE MAC vendor database (~38k vendors) once
lan-auditor update-oui

# Active ARP sweep (finds devices that ignore ping); needs root + scapy
sudo lan-auditor 192.168.1.0/24
```

Run `lan-auditor scan --help` for every option.

### Example output

```text
lan-auditor report  target=192.168.1.0/24  started=2026-11-18T22:10:35+00:00
254 address(es) probed, 9 host(s) up, 14.2s

IP              MAC                VENDOR                      HOSTNAME                   OPEN  RISK
----------------------------------------------------------------------------------------------------
192.168.1.1     F0:9F:C2:12:34:56  Ubiquiti                    router.lan                    4   20 MEDIUM
192.168.1.23    C0:56:E3:AA:BB:CC  Hikvision                   -                             3   75 HIGH
192.168.1.40    DA:A1:19:01:02:03  (randomised / locally adm…  pixel-8.lan                   0    0
...

192.168.1.23 - Hikvision
  23/tcp    telnet          BusyBox v1.19 login:
  80/tcp    http            HTTP/1.0 401 Unauthorized
  554/tcp   rtsp
    [HIGH] HTTP Basic auth over plaintext (port 80) LAN-HTTP-BASIC
      This interface asks for a username and password using HTTP Basic auth without TLS ...
    [HIGH] Telnet service exposed (port 23) LAN-TELNET
      Telnet sends usernames, passwords and session data in cleartext ...
    [LOW] RTSP video stream service (port 554) LAN-RTSP
      Camera streams over RTSP are often unauthenticated ...

Findings  CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 3
```

## How it works

```
targets ──► discovery ──────────────► port scan ──► banner grab ──► risk rules ──► report
            ARP (scapy, root)         TCP connect   passive read    service rules   text
            ICMP (system ping)        thread pool   HTTP HEAD       HTTP heuristics json
            TCP ping (SYN-ACK/RST)                  TLS handshake   SSH versions    markdown
            OS ARP cache ─► MACs ─► OUI vendor      telnet IAC
```

1. **Discovery.** Each method runs in a thread pool. ICMP shells out to the
   system `ping` so no raw sockets or root are needed. TCP ping tries a handful
   of ports that home devices commonly answer on; a refused connection counts
   as "alive" because only a live host sends an RST. Probing fills the
   kernel's ARP cache, which is then read (`/proc/net/arp` or `arp -a`) to
   learn MAC addresses without needing root.
2. **Port scan.** Plain `connect()` calls, `--port-workers` at a time per host
   and up to 8 hosts in parallel.
3. **Banner grabbing.** For each open port: wait briefly for the server to
   speak first; on TLS ports complete a handshake (certificate verification is
   deliberately off, as home devices almost always self-sign); on web ports
   send `HEAD /`. Telnet IAC negotiation bytes are stripped and their presence
   is itself a fingerprint.
4. **Risk rules** live in [`src/lanaudit/risk.py`](src/lanaudit/risk.py) as a
   simple table plus a few heuristics (HTTP Basic auth over plaintext,
   router/camera admin pages, outdated OpenSSH, SSHv1).

## Risk rules

| Rule | Severity | Trigger |
|---|---|---|
| `LAN-ADB` | CRITICAL | Android Debug Bridge on 5555 |
| `LAN-TELNET` | HIGH | Telnet (23/2323 or IAC negotiation seen) |
| `LAN-HTTP-BASIC` | HIGH | `WWW-Authenticate: Basic` over plain HTTP |
| `LAN-VNC` | HIGH | VNC remote desktop |
| `LAN-REDIS` / `LAN-MONGODB` / `LAN-MEMCACHED` / `LAN-ELASTIC` | HIGH | Datastores that historically default to no auth |
| `LAN-SSH-V1` | HIGH | SSH protocol 1.x |
| `LAN-HTTP-ADMIN` | MEDIUM | Router/camera/NAS admin page over plain HTTP |
| `LAN-FTP` | MEDIUM | Plaintext FTP |
| `LAN-SSH-OLD` | MEDIUM | OpenSSH older than 7.4 |
| `LAN-RDP`, `LAN-MQTT`, `LAN-TR069`, `LAN-MYSQL`, `LAN-POSTGRES`, `LAN-RSYNC`, `LAN-NFS`, `LAN-SOCKS` | MEDIUM | Exposed remote access, plaintext IoT messaging, ISP management, databases |
| `LAN-HTTP`, `LAN-SMB`, `LAN-NETBIOS`, `LAN-UPNP`, `LAN-RTSP`, `LAN-JETDIRECT`, `LAN-POP3`, `LAN-IMAP` | LOW | Worth knowing about, usually fine on a trusted LAN |

Findings are **indicators, not proof**: lan-auditor never logs in, brute-forces
or exploits anything. Use it to decide what to look at next.

## Scheduled scans

Run nightly and keep a Markdown report:

```cron
0 3 * * * /usr/local/bin/lan-auditor 192.168.1.0/24 -q -f markdown -o /var/log/lan-audit/$(date +\%F).md
```

## Development

```bash
python -m pip install -e ".[dev]"
pytest          # tests spin up fake SSH/HTTP/Telnet servers on localhost
ruff check .
```

The test suite never touches your real network.

## Limitations and roadmap

- IPv4 and TCP only for now (no UDP services such as SNMP or SSDP yet).
- The built-in vendor table is small; run `lan-auditor update-oui` for full coverage.
- Ideas: UDP/mDNS/SSDP discovery, diffing two scans to spot new devices,
  HTML report, CVE lookup from banners.

## License

[MIT](LICENSE)
