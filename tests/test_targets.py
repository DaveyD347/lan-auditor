import pytest

from lanaudit.targets import TargetError, guess_local_network, parse_targets


def test_cidr_excludes_network_and_broadcast():
    ips = parse_targets("192.168.1.0/30")
    assert ips == ["192.168.1.1", "192.168.1.2"]


def test_single_and_short_range_and_dedupe():
    ips = parse_targets("10.0.0.5, 10.0.0.4-6")
    assert ips == ["10.0.0.4", "10.0.0.5", "10.0.0.6"]


def test_full_range():
    assert parse_targets("172.16.0.254-172.16.1.1") == [
        "172.16.0.254",
        "172.16.0.255",
        "172.16.1.0",
        "172.16.1.1",
    ]


def test_sorted_numerically():
    assert parse_targets("192.168.1.10,192.168.1.9") == ["192.168.1.9", "192.168.1.10"]


def test_public_address_refused_by_default():
    with pytest.raises(TargetError, match="not a private address"):
        parse_targets("8.8.8.8")


def test_public_address_allowed_with_flag():
    assert parse_targets("8.8.8.8", allow_public=True) == ["8.8.8.8"]


def test_too_many_hosts():
    with pytest.raises(TargetError, match="limit"):
        parse_targets("10.0.0.0/16", max_hosts=1024)


@pytest.mark.parametrize("bad", ["", "999.1.1.1", "192.168.1.0/40", "192.168.1.50-10", "abc"])
def test_invalid(bad):
    with pytest.raises(TargetError):
        parse_targets(bad)


def test_guess_local_network_shape():
    net = guess_local_network()
    assert net is None or net.endswith("/24")
