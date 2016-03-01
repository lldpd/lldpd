import pytest
import pyroute2


@pytest.mark.skipif('CDP' not in pytest.config.lldpd.protocols,
                    reason="CDP not supported")
@pytest.mark.parametrize("argument, expected", [
    ("-cc", "CDPv1"),
    ("-ccc", "CDPv2")])
def test_cdp(lldpd, lldpcli, links, namespaces,
             argument, expected):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-c", "-ll", "-r")
    with namespaces(2):
        lldpd(argument, "-ll")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out["lldp.eth0.via"] == expected
        assert out["lldp.eth0.chassis.local"] == "ns-2.example.com"
        assert out["lldp.eth0.chassis.name"] == "ns-2.example.com"
        assert out["lldp.eth0.chassis.descr"].startswith(
            "Linux running on Spectacular GNU/Linux 2016")
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "eth1"


@pytest.mark.skipif('FDP' not in pytest.config.lldpd.protocols,
                    reason="FDP not supported")
def test_fdp(lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-f", "-ll", "-r")
    with namespaces(2):
        lldpd("-ff", "-ll")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out["lldp.eth0.via"] == "FDP"
        assert out["lldp.eth0.chassis.local"] == "ns-2.example.com"
        assert out["lldp.eth0.chassis.name"] == "ns-2.example.com"
        assert out["lldp.eth0.chassis.descr"].startswith(
            "Linux running on Spectacular GNU/Linux 2016")
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "eth1"


@pytest.mark.skipif('EDP' not in pytest.config.lldpd.protocols,
                    reason="EDP not supported")
def test_edp(lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-e", "-ll", "-r")
    with namespaces(2):
        lldpd("-ee", "-ll")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out["lldp.eth0.via"] == "EDP"
        assert out["lldp.eth0.chassis.mac"] == "00:00:00:00:00:02"
        assert out["lldp.eth0.chassis.name"] == "ns-2.example.com"
        assert out["lldp.eth0.chassis.descr"] == \
            "EDP enabled device, version 7.6.4.99"
        assert out["lldp.eth0.port.ifname"] == "1/2"
        assert out["lldp.eth0.port.descr"] == "Slot 1 / Port 2"


@pytest.mark.skipif('SONMP' not in pytest.config.lldpd.protocols,
                    reason="SONMP not supported")
def test_sonmp(lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-s", "-ll", "-r")
    with namespaces(2):
        ipr = pyroute2.IPRoute()
        idx = ipr.link_lookup(ifname="eth1")[0]
        ipr.addr('add', index=idx, address="192.168.14.2", mask=24)
        lldpd("-ss", "-ll")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out["lldp.eth0.via"] == "SONMP"
        assert out["lldp.eth0.chassis.name"] == "192.168.14.2"
        assert out["lldp.eth0.chassis.descr"] == "unknown (via SONMP)"
        assert out["lldp.eth0.port.local"] == "00-00-02"
        assert out["lldp.eth0.port.descr"] == "port 2"
