"""High-level orchestration: discover hosts, scan them, evaluate risk."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import discovery
from .models import Host
from .oui import OUILookup
from .risk import evaluate_host
from .scanner import scan_host


@dataclass
class ScanOptions:
    ports: list[int]
    methods: tuple[str, ...] = ("arp", "icmp", "tcp")
    timeout: float = 0.75
    banner_timeout: float = 2.0
    workers: int = 128
    port_workers: int = 64
    grab_banners: bool = True
    resolve_names: bool = True
    skip_discovery: bool = False


@dataclass
class ScanResult:
    target: str
    started: str
    duration: float
    hosts: list[Host] = field(default_factory=list)
    hosts_scanned: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started": self.started,
            "duration_seconds": round(self.duration, 2),
            "hosts_scanned": self.hosts_scanned,
            "hosts_up": len(self.hosts),
            "notes": self.notes,
            "hosts": [h.to_dict() for h in self.hosts],
        }


Progress = Callable[[str], None]


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def discover(ips: list[str], opts: ScanOptions, notes: list[str], progress: Progress) -> dict[str, Host]:
    hosts: dict[str, Host] = {}

    def add(ip: str, method: str, mac: str | None = None) -> None:
        host = hosts.setdefault(ip, Host(ip=ip))
        if method not in host.discovered_by:
            host.discovered_by.append(method)
        if mac and not host.mac:
            host.mac = mac

    if opts.skip_discovery:
        for ip in ips:
            add(ip, "assumed")
        return hosts

    if "arp" in opts.methods:
        if discovery.scapy_available() and _is_root():
            progress(f"ARP sweep of {len(ips)} addresses")
            try:
                for ip, mac in discovery.arp_sweep(ips).items():
                    add(ip, "arp", mac)
            except Exception as exc:  # pragma: no cover - environment dependent
                notes.append(f"ARP sweep failed: {exc}")
        else:
            notes.append(
                "Active ARP sweep skipped (needs root and `pip install lan-auditor[arp]`); "
                "MAC addresses come from the OS ARP cache instead."
            )

    if "icmp" in opts.methods:
        progress(f"ICMP ping sweep of {len(ips)} addresses")
        icmp_timeout = max(1.0, opts.timeout)
        for ip in discovery.sweep(ips, lambda i: discovery.icmp_ping(i, icmp_timeout), opts.workers):
            add(ip, "icmp")

    if "tcp" in opts.methods:
        remaining = [ip for ip in ips if ip not in hosts]
        progress(f"TCP ping sweep of {len(remaining)} addresses")

        def probe(ip: str) -> bool:
            return discovery.tcp_ping(ip, timeout=opts.timeout)

        for ip in discovery.sweep(remaining, probe, opts.workers):
            add(ip, "tcp")

    # ICMP/TCP probes populate the kernel ARP cache, so read it afterwards.
    wanted = set(ips)
    for ip, mac in discovery.read_arp_cache().items():
        if ip in wanted:
            if ip in hosts:
                hosts[ip].mac = hosts[ip].mac or mac
            elif "arp" in opts.methods:
                add(ip, "arp-cache", mac)
    return hosts


def run_audit(
    target: str,
    ips: list[str],
    opts: ScanOptions,
    oui: OUILookup | None = None,
    progress: Progress | None = None,
) -> ScanResult:
    progress = progress or (lambda _msg: None)
    oui = oui or OUILookup.load()
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.monotonic()
    notes: list[str] = []

    hosts = discover(ips, opts, notes, progress)
    progress(f"{len(hosts)} host(s) up; scanning {len(opts.ports)} port(s) each")

    def enrich(host: Host) -> Host:
        host.vendor = oui.lookup(host.mac)
        if opts.resolve_names:
            host.hostname = discovery.reverse_dns(host.ip)
        host.services = scan_host(
            host.ip,
            opts.ports,
            timeout=opts.timeout,
            banner_timeout=opts.banner_timeout,
            workers=opts.port_workers,
            grab=opts.grab_banners,
        )
        evaluate_host(host)
        progress(f"  {host.ip}: {len(host.services)} open, {len(host.findings)} finding(s)")
        return host

    ordered = sorted(hosts.values(), key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    if ordered:
        with ThreadPoolExecutor(max_workers=min(8, len(ordered))) as pool:
            ordered = list(pool.map(enrich, ordered))

    return ScanResult(
        target=target,
        started=started,
        duration=time.monotonic() - t0,
        hosts=ordered,
        hosts_scanned=len(ips),
        notes=notes,
    )
