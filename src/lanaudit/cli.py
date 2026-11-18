"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .auditor import ScanOptions, run_audit
from .models import Severity
from .oui import OUILookup, default_cache_path, update_cache
from .report import render_json, render_markdown, render_text
from .services import parse_ports
from .targets import MAX_HOSTS_DEFAULT, TargetError, guess_local_network, parse_targets

BANNER = """\
Only scan networks you own or have explicit permission to test.
Unauthorised scanning may be illegal where you live."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lan-auditor",
        description="Discover devices on your LAN, fingerprint their services and flag insecure ones.",
        epilog=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="scan a network (default command)",
        epilog=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "target",
        nargs="?",
        help="CIDR, IP, or range, comma separated (e.g. 192.168.1.0/24, "
        "10.0.0.5, 192.168.1.10-50). Defaults to your local /24.",
    )
    scan.add_argument(
        "-p",
        "--ports",
        default="default",
        help="ports to scan: 'default' (~55 common), 'all', or e.g. '22,80,8000-8100'",
    )
    scan.add_argument(
        "-m",
        "--methods",
        default="arp,icmp,tcp",
        help="discovery methods, comma separated from arp,icmp,tcp (default: all)",
    )
    scan.add_argument(
        "-Pn",
        "--skip-discovery",
        action="store_true",
        help="treat every target as up and go straight to port scanning",
    )
    scan.add_argument(
        "-t", "--timeout", type=float, default=0.75, help="connect/probe timeout in seconds (default 0.75)"
    )
    scan.add_argument(
        "--banner-timeout", type=float, default=2.0, help="banner grab timeout in seconds (default 2.0)"
    )
    scan.add_argument(
        "-w", "--workers", type=int, default=128, help="concurrent discovery probes (default 128)"
    )
    scan.add_argument(
        "--port-workers", type=int, default=64, help="concurrent port probes per host (default 64)"
    )
    scan.add_argument("--no-banners", action="store_true", help="skip banner grabbing")
    scan.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    scan.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="output format (default text)",
    )
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    scan.add_argument(
        "--oui-file", type=Path, help="extra OUI database (IEEE oui.csv/oui.txt or Wireshark manuf)"
    )
    scan.add_argument(
        "--allow-public", action="store_true", help="permit non-private targets (only if you are authorised!)"
    )
    scan.add_argument(
        "--max-hosts",
        type=int,
        default=MAX_HOSTS_DEFAULT,
        help=f"refuse targets larger than this (default {MAX_HOSTS_DEFAULT})",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity if s > Severity.INFO],
        help="exit with status 2 if any finding is at or above this severity",
    )

    oui = sub.add_parser("update-oui", help="download the full IEEE MAC vendor registry")
    oui.add_argument(
        "--dest", type=Path, default=None, help=f"where to save it (default {default_cache_path()})"
    )
    return parser


def _cmd_update_oui(args: argparse.Namespace) -> int:
    try:
        path, count = update_cache(args.dest)
    except Exception as exc:  # network errors, HTTP errors, etc.
        print(f"error: could not download OUI registry: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {count} vendor prefixes to {path}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    target = args.target or guess_local_network()
    if not target:
        print(
            "error: could not detect your local network; pass a target such as 192.168.1.0/24",
            file=sys.stderr,
        )
        return 1
    try:
        ips = parse_targets(target, allow_public=args.allow_public, max_hosts=args.max_hosts)
        ports = parse_ports(args.ports)
    except (TargetError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    methods = tuple(m.strip() for m in args.methods.split(",") if m.strip())
    unknown = set(methods) - {"arp", "icmp", "tcp"}
    if unknown:
        print(f"error: unknown discovery method(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1

    opts = ScanOptions(
        ports=ports,
        methods=methods,
        timeout=args.timeout,
        banner_timeout=args.banner_timeout,
        workers=max(1, args.workers),
        port_workers=max(1, args.port_workers),
        grab_banners=not args.no_banners,
        resolve_names=not args.no_dns,
        skip_discovery=args.skip_discovery,
    )

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"[*] {msg}", file=sys.stderr, flush=True)

    if not args.quiet:
        print(BANNER.splitlines()[0], file=sys.stderr)
    progress(f"Target {target}: {len(ips)} address(es), {len(ports)} port(s)")
    try:
        result = run_audit(target, ips, opts, OUILookup.load(args.oui_file), progress)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    if args.format == "json":
        text = render_json(result)
    elif args.format == "markdown":
        text = render_markdown(result)
    else:
        color = not args.no_color and args.output is None and sys.stdout.isatty()
        text = render_text(result, color=color)

    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        progress(f"Report written to {args.output}")
    else:
        print(text)

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for h in result.hosts for f in h.findings):
            return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `lan-auditor 192.168.1.0/24` is shorthand for `lan-auditor scan 192.168.1.0/24`.
    if not argv or argv[0] not in ("scan", "update-oui", "-h", "--help", "--version"):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    if args.command == "update-oui":
        return _cmd_update_oui(args)
    return _cmd_scan(args)
