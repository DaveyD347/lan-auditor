from lanaudit.models import Host, Service, Severity
from lanaudit.risk import evaluate_host, evaluate_service


def ids(findings):
    return [f.rule_id for f in findings]


def test_telnet_is_high():
    (f,) = evaluate_service(Service(port=23, service="telnet"))
    assert f.rule_id == "LAN-TELNET" and f.severity == Severity.HIGH and f.port == 23


def test_adb_is_critical():
    assert evaluate_service(Service(port=5555, service="adb"))[0].severity == Severity.CRITICAL


def test_http_basic_auth_plaintext():
    svc = Service(
        port=80, service="http", banner='HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="x"'
    )
    assert ids(evaluate_service(svc)) == ["LAN-HTTP-BASIC"]


def test_http_admin_interface():
    svc = Service(port=80, service="http", banner="HTTP/1.1 200 OK\r\nServer: lighttpd/1.4")
    assert ids(evaluate_service(svc)) == ["LAN-HTTP-ADMIN"]


def test_plain_http_low():
    svc = Service(port=8000, service="http", banner="HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6")
    (f,) = evaluate_service(svc)
    assert f.rule_id == "LAN-HTTP" and f.severity == Severity.LOW


def test_https_not_flagged():
    assert evaluate_service(Service(port=443, service="https", tls=True, banner="HTTP/1.1 200 OK")) == []


def test_old_openssh():
    svc = Service(port=22, service="ssh", banner="SSH-2.0-OpenSSH_6.6.1p1")
    assert ids(evaluate_service(svc)) == ["LAN-SSH-OLD"]
    assert evaluate_service(Service(port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.6")) == []


def test_sshv1():
    assert ids(evaluate_service(Service(port=22, service="ssh", banner="SSH-1.5-old"))) == ["LAN-SSH-V1"]
    assert evaluate_service(Service(port=22, service="ssh", banner="SSH-1.99-OpenSSH_9.0")) == []


def test_host_score_and_ordering():
    host = Host(
        ip="192.168.1.5",
        services=[
            Service(port=445, service="smb"),
            Service(port=23, service="telnet"),
            Service(port=5555, service="adb"),
        ],
    )
    findings = evaluate_host(host)
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    assert host.risk_score == 50 + 30 + 5
    assert host.max_severity == Severity.CRITICAL


def test_score_capped():
    host = Host(ip="x", services=[Service(port=p, service="adb") for p in range(5)])
    evaluate_host(host)
    assert host.risk_score == 100
