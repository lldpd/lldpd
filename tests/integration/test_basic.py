import time
import pytest
import pyroute2


def test_one_neighbor(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out['lldp.eth0.age'].startswith('0 day, 00:00:')
        assert out['lldp.eth0.chassis.descr'].startswith(
            "Spectacular GNU/Linux 2016 Linux")
        assert 'lldp.eth0.chassis.Router.enabled' in out
        assert 'lldp.eth0.chassis.Station.enabled' in out
        del out['lldp.eth0.age']
        del out['lldp.eth0.chassis.descr']
        del out['lldp.eth0.chassis.Router.enabled']
        del out['lldp.eth0.chassis.Station.enabled']
        assert out == {"lldp.eth0.via": "LLDP",
                       "lldp.eth0.rid": "1",
                       "lldp.eth0.chassis.mac": "00:00:00:00:00:02",
                       "lldp.eth0.chassis.name": "ns-2.example.com",
                       "lldp.eth0.chassis.mgmt-ip": "fe80::200:ff:fe00:2",
                       "lldp.eth0.chassis.Bridge.enabled": "off",
                       "lldp.eth0.chassis.Wlan.enabled": "off",
                       "lldp.eth0.port.mac": "00:00:00:00:00:02",
                       "lldp.eth0.port.descr": "eth1"}


@pytest.mark.parametrize("neighbors", (5, 10, 50))
def test_several_neighbors(lldpd, lldpcli, links, namespaces, neighbors):
    for i in range(2, neighbors + 1):
        links(namespaces(1), namespaces(i))
    for i in range(1, neighbors + 1):
        with namespaces(i):
            lldpd(sleep=(i == 1 and 2 or 0),
                  silent=True)
    time.sleep(2)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        for i in range(2, neighbors + 1):
            assert out['lldp.eth{}.chassis.name'.format((i - 2)*2)] == \
                'ns-{}.example.com'.format(i)


def test_overrided_description(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-S", "Modified description")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out['lldp.eth0.chassis.descr'] == "Modified description"


def test_hide_kernel(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-k")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.descr"] == \
            "Spectacular GNU/Linux 2016"


def test_listen_only(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-r")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}


def test_forced_management_address(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-m", "2001:db8::47")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "2001:db8::47"


def test_management_address(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        ipr = pyroute2.IPRoute()
        idx = ipr.link_lookup(ifname="eth1")[0]
        ipr.addr('add', index=idx, address="192.168.14.2", mask=24)
        ipr.addr('add', index=idx, address="172.25.21.47", mask=24)
        lldpd("-m", "172.25.*")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "172.25.21.47"
