import json

from lanaudit import cli
from lanaudit.auditor import ScanOptions, ScanResult, run_audit
from lanaudit.models import Host, Service
from lanaudit.oui import OUILookup
from lanaudit.report import render_markdown, render_text
from lanaudit.risk import evaluate_host


def sample_result() -> ScanResult:
    host = Host(
        ip="192.168.1.10",
        mac="B8:27:EB:00:00:01",
        vendor="Raspberry Pi Foundation",
        hostname="pi.lan",
        discovered_by=["icmp"],
        services=[
            Service(port=23, service="telnet", banner="login:"),
            Service(port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.6"),
        ],
    )
    evaluate_host(host)
    return ScanResult(
        target="192.168.1.0/24",
        started="2026-01-01T00:00:00+00:00",
        duration=1.2,
        hosts=[host],
        hosts_scanned=254,
    )


def test_render_text_plain():
    out = render_text(sample_result(), color=False)
    assert "192.168.1.10" in out and "Raspberry Pi" in out
    assert "[HIGH] Telnet service exposed" in out
    assert "\033[" not in out


def test_render_markdown():
    md = render_markdown(sample_result())
    assert md.startswith("# LAN Audit Report")
    assert "| HIGH | 192.168.1.10 | 23 | Telnet service exposed | LAN-TELNET |" in md


def test_run_audit_against_localhost(fake_server):
    srv = fake_server(greeting=bytes([0xFF, 0xFB, 0x01]) + b"BusyBox login: ")
    opts = ScanOptions(ports=[srv.port], skip_discovery=True, resolve_names=False, timeout=0.5)
    result = run_audit("127.0.0.1", ["127.0.0.1"], opts, OUILookup({}))
    (host,) = result.hosts
    assert host.services[0].service == "telnet"
    assert host.findings[0].rule_id == "LAN-TELNET"


def test_cli_json_and_fail_on(fake_server, capsys):
    srv = fake_server(greeting=b"\xff\xfb\x01login: ")
    code = cli.main(
        ["127.0.0.1", "-Pn", "-p", str(srv.port), "--no-dns", "-q", "-f", "json", "--fail-on", "high"]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == 2
    assert data["hosts"][0]["findings"][0]["rule_id"] == "LAN-TELNET"


def test_cli_writes_file(fake_server, tmp_path):
    srv = fake_server(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
    out = tmp_path / "report.md"
    code = cli.main(
        [
            "scan",
            "127.0.0.1",
            "-Pn",
            "-p",
            str(srv.port),
            "--no-dns",
            "-q",
            "-f",
            "markdown",
            "-o",
            str(out),
            "--fail-on",
            "high",
        ]
    )
    assert code == 0
    assert "No findings." in out.read_text()


def test_cli_refuses_public_target(capsys):
    assert cli.main(["8.8.8.8", "-q"]) == 1
    assert "not a private address" in capsys.readouterr().err


def test_cli_rejects_bad_method(capsys):
    assert cli.main(["127.0.0.1", "-m", "smoke"]) == 1
