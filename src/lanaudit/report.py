"""Output formatting: coloured terminal table, JSON and Markdown."""

from __future__ import annotations

import json

from .auditor import ScanResult
from .models import Severity

_COLORS = {
    Severity.INFO: "\033[37m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;41;97m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _sev(sev: Severity, color: bool) -> str:
    label = sev.name
    return f"{_COLORS[sev]}{label}{_RESET}" if color else label


def _truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _first_line(banner: str) -> str:
    return banner.splitlines()[0] if banner else ""


def render_text(result: ScanResult, color: bool = True) -> str:
    b = _BOLD if color else ""
    d = _DIM if color else ""
    r = _RESET if color else ""
    lines: list[str] = []
    lines.append(f"{b}lan-auditor report{r}  target={result.target}  started={result.started}")
    lines.append(
        f"{d}{result.hosts_scanned} address(es) probed, {len(result.hosts)} host(s) up, "
        f"{result.duration:.1f}s{r}"
    )
    for note in result.notes:
        lines.append(f"{d}note: {note}{r}")
    lines.append("")

    if not result.hosts:
        lines.append("No live hosts found.")
        return "\n".join(lines)

    header = f"{'IP':<16}{'MAC':<19}{'VENDOR':<28}{'HOSTNAME':<26}{'OPEN':>5}  RISK"
    lines.append(f"{b}{header}{r}")
    lines.append("-" * len(header))
    for h in result.hosts:
        risk = f"{h.risk_score:>3} " + (_sev(h.max_severity, color) if h.findings else "")
        lines.append(
            f"{h.ip:<16}{(h.mac or '-'):<19}{_truncate(h.vendor or '-', 26):<28}"
            f"{_truncate(h.hostname or '-', 24):<26}{len(h.services):>5}  {risk}"
        )

    for h in result.hosts:
        if not h.services:
            continue
        lines.append("")
        title = h.ip + (f" ({h.hostname})" if h.hostname else "") + (f" - {h.vendor}" if h.vendor else "")
        lines.append(f"{b}{title}{r}")
        for s in h.services:
            proto = f"{s.port}/{s.protocol}"
            tls = " tls" if s.tls else ""
            lines.append(f"  {proto:<10}{s.service + tls:<16}{d}{_truncate(_first_line(s.banner), 60)}{r}")
        for f in h.findings:
            lines.append(f"    [{_sev(f.severity, color)}] {f.title} (port {f.port}) {d}{f.rule_id}{r}")
            lines.append(f"      {d}{f.detail}{r}")

    total = [f for h in result.hosts for f in h.findings]
    lines.append("")
    counts = {s: sum(1 for f in total if f.severity == s) for s in Severity if s > Severity.INFO}
    summary = ", ".join(f"{_sev(s, color)}: {n}" for s, n in sorted(counts.items(), reverse=True))
    lines.append(f"{b}Findings{r}  {summary}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    out: list[str] = [
        "# LAN Audit Report",
        "",
        f"- **Target:** `{result.target}`",
        f"- **Started:** {result.started}",
        f"- **Hosts up:** {len(result.hosts)} of {result.hosts_scanned} probed",
        f"- **Duration:** {result.duration:.1f}s",
        "",
    ]
    for note in result.notes:
        out.append(f"> {note}")
    if result.notes:
        out.append("")
    out += [
        "## Hosts",
        "",
        "| IP | MAC | Vendor | Hostname | Open ports | Risk |",
        "|---|---|---|---|---|---|",
    ]
    for h in result.hosts:
        ports = ", ".join(str(s.port) for s in h.services) or "-"
        risk = f"{h.risk_score} ({h.max_severity.name})" if h.findings else "0"
        out.append(
            f"| {h.ip} | {h.mac or '-'} | {_md_escape(h.vendor or '-')} | "
            f"{_md_escape(h.hostname or '-')} | {ports} | {risk} |"
        )
    findings = [(h, f) for h in result.hosts for f in h.findings]
    out += ["", "## Findings", ""]
    if not findings:
        out.append("No findings.")
    else:
        out += ["| Severity | Host | Port | Finding | Rule |", "|---|---|---|---|---|"]
        for h, f in sorted(findings, key=lambda hf: -hf[1].severity):
            out.append(f"| {f.severity.name} | {h.ip} | {f.port} | {_md_escape(f.title)} | {f.rule_id} |")
        out += ["", "### Details", ""]
        seen: set[str] = set()
        for _, f in findings:
            if f.rule_id in seen:
                continue
            seen.add(f.rule_id)
            out.append(f"- **{f.rule_id}** ({f.severity.name}): {f.detail}")
    out.append("")
    return "\n".join(out)
