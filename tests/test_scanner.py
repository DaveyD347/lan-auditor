from lanaudit import scanner
from lanaudit.scanner import clean_banner, grab_banner, scan_host, strip_telnet_negotiation


def test_strip_telnet_negotiation():
    raw = bytes([0xFF, 0xFD, 0x18, 0xFF, 0xFB, 0x01]) + b"login: "
    clean, saw = strip_telnet_negotiation(raw)
    assert clean == b"login: "
    assert saw


def test_clean_banner_replaces_control_chars():
    assert clean_banner(b"abc\x00\x01def\r\n") == "abc..def"


def test_scan_finds_open_port_only(fake_server, closed_port):
    srv = fake_server(greeting=b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu\r\n")
    services = scan_host("127.0.0.1", [srv.port, closed_port], timeout=0.5, banner_timeout=1)
    assert [s.port for s in services] == [srv.port]
    assert services[0].service == "ssh"
    assert services[0].banner.startswith("SSH-2.0-OpenSSH_6.6")


def test_scan_without_banners(fake_server):
    srv = fake_server()
    services = scan_host("127.0.0.1", [srv.port], grab=False)
    assert services[0].banner == ""


def test_http_probe_on_http_port(fake_server, monkeypatch):
    reply = (
        b'HTTP/1.0 401 Unauthorized\r\nServer: GoAhead-Webs\r\nWWW-Authenticate: Basic realm="router"\r\n\r\n'
    )
    srv = fake_server(reply_to_request=reply)
    monkeypatch.setattr(scanner, "HTTP_PORTS", {srv.port})
    svc = grab_banner("127.0.0.1", srv.port, timeout=2)
    assert svc.service == "http"
    assert "WWW-Authenticate: Basic" in svc.banner


def test_telnet_detected_from_iac(fake_server):
    srv = fake_server(greeting=bytes([0xFF, 0xFD, 0x01]) + b"\r\nWelcome\r\n")
    svc = grab_banner("127.0.0.1", srv.port, timeout=2)
    assert svc.service == "telnet"
    assert svc.banner == "Welcome"
