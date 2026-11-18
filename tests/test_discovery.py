import sys

from lanaudit import discovery

PROC_NET_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         b8:27:eb:11:22:33     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
"""

MAC_ARP = """\
? (192.168.1.1) at 0:1b:63:a:b:c on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""

WIN_ARP = """\
Interface: 192.168.1.50 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           b8-27-eb-11-22-33     dynamic
"""


def test_parse_linux_arp():
    assert discovery.parse_arp_output(PROC_NET_ARP) == {"192.168.1.1": "B8:27:EB:11:22:33"}


def test_parse_macos_arp_pads_octets():
    assert discovery.parse_arp_output(MAC_ARP) == {"192.168.1.1": "00:1B:63:0A:0B:0C"}


def test_parse_windows_arp():
    assert discovery.parse_arp_output(WIN_ARP) == {"192.168.1.1": "B8:27:EB:11:22:33"}


def test_tcp_ping_open_and_refused(fake_server, closed_port):
    srv = fake_server()
    assert discovery.tcp_ping("127.0.0.1", ports=[srv.port])
    # A refused connection (RST) still proves the host is alive. Windows
    # retries refused SYNs for ~2s, longer than the probe timeout, so skip it there.
    if sys.platform != "win32":
        assert discovery.tcp_ping("127.0.0.1", ports=[closed_port])


def test_sweep_runs_probe_concurrently():
    alive = discovery.sweep(["a", "b", "c"], lambda ip: ip != "b", workers=3)
    assert alive == {"a", "c"}
    assert discovery.sweep([], lambda ip: True) == set()
