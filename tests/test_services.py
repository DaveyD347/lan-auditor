import pytest

from lanaudit.services import DEFAULT_PORTS, identify_service, parse_ports


def test_parse_ports_mixed():
    assert parse_ports("80, 22,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_keywords():
    assert parse_ports("default") == DEFAULT_PORTS
    assert len(parse_ports("all")) == 65535


def test_parse_ports_out_of_range():
    with pytest.raises(ValueError):
        parse_ports("0,70000")


@pytest.mark.parametrize(
    "port,banner,tls,expected",
    [
        (2222, "SSH-2.0-OpenSSH_9.6", False, "ssh"),
        (9999, "HTTP/1.1 200 OK", False, "http"),
        (9999, "HTTP/1.1 200 OK", True, "https"),
        (2121, "220 (vsFTPd 3.0.3)", False, "ftp"),
        (23, "", False, "telnet"),
        (5900, "RFB 003.008", False, "vnc"),
        (12345, "", False, "unknown"),
        (8080, "", True, "https"),
        (4000, "BusyBox login: ", False, "telnet"),
    ],
)
def test_identify_service(port, banner, tls, expected):
    assert identify_service(port, banner, tls) == expected
