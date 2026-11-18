"""Target parsing and local-network detection."""

from __future__ import annotations

import ipaddress
import socket

MAX_HOSTS_DEFAULT = 4096


class TargetError(ValueError):
    """Raised when a target specification is invalid or unsafe."""


def _expand_range(spec: str) -> list[ipaddress.IPv4Address]:
    """Expand ``192.168.1.10-50`` or ``192.168.1.10-192.168.1.50``."""
    start_s, end_s = spec.split("-", 1)
    start = ipaddress.IPv4Address(start_s.strip())
    end_s = end_s.strip()
    if "." in end_s:
        end = ipaddress.IPv4Address(end_s)
    else:
        prefix = str(start).rsplit(".", 1)[0]
        end = ipaddress.IPv4Address(f"{prefix}.{end_s}")
    if int(end) < int(start):
        raise TargetError(f"range end is before range start: {spec}")
    return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]


def parse_targets(
    spec: str,
    *,
    allow_public: bool = False,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Turn a target spec into a sorted, de-duplicated list of IPv4 strings.

    Accepts comma-separated CIDRs (``192.168.1.0/24``), single addresses and
    dash ranges (``192.168.1.10-50``). By default only private, loopback and
    link-local addresses are allowed, as a guard against accidentally scanning
    networks you do not own.
    """
    addrs: set[ipaddress.IPv4Address] = set()
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.IPv4Network(part, strict=False)
                if net.num_addresses > max_hosts + 2:
                    raise TargetError(
                        f"{part} has {net.num_addresses} addresses; "
                        f"limit is {max_hosts} (use --max-hosts to raise it)"
                    )
                addrs.update(net.hosts() if net.num_addresses > 2 else net)
            elif "-" in part:
                addrs.update(_expand_range(part))
            else:
                addrs.add(ipaddress.IPv4Address(part))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
            if isinstance(exc, TargetError):
                raise
            raise TargetError(f"invalid target '{part}': {exc}") from exc

    if not addrs:
        raise TargetError("no targets given")
    if len(addrs) > max_hosts:
        raise TargetError(
            f"{len(addrs)} hosts exceeds the limit of {max_hosts} (use --max-hosts to raise it)"
        )
    if not allow_public:
        public = sorted(a for a in addrs if not (a.is_private or a.is_loopback or a.is_link_local))
        if public:
            raise TargetError(
                f"{public[0]} is not a private address. lan-auditor is meant for "
                "networks you own; pass --allow-public only if you are authorised "
                "to scan it."
            )
    return [str(a) for a in sorted(addrs)]


def local_ip() -> str | None:
    """Best-effort primary local IPv4 address (no packets are actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def guess_local_network(prefix: int = 24) -> str | None:
    """Guess the local subnet as ``<local ip>/<prefix>``."""
    ip = local_ip()
    if not ip or ip.startswith("127."):
        return None
    return str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
