import time
import pytest
import pyroute2
import scapy.all
import scapy.contrib.lldp


def test_one_neighbor(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.age"].startswith("0 day, 00:00:")
        assert out["lldp.eth0.chassis.descr"].startswith(
            "Spectacular GNU/Linux 2016 Linux"
        )
        assert "lldp.eth0.chassis.Router.enabled" in out
        assert "lldp.eth0.chassis.Station.enabled" in out
        del out["lldp.eth0.age"]
        del out["lldp.eth0.chassis.descr"]
        del out["lldp.eth0.chassis.Router.enabled"]
        del out["lldp.eth0.chassis.Station.enabled"]
        assert out == {
            "lldp.eth0.via": "LLDP",
            "lldp.eth0.rid": "1",
            "lldp.eth0.chassis.mac": "00:00:00:00:00:02",
            "lldp.eth0.chassis.name": "ns-2.example.com",
            "lldp.eth0.chassis.mgmt-ip": "fe80::200:ff:fe00:2",
            "lldp.eth0.chassis.mgmt-iface": "2",
            "lldp.eth0.chassis.Bridge.enabled": "off",
            "lldp.eth0.chassis.Wlan.enabled": "off",
            "lldp.eth0.port.mac": "00:00:00:00:00:02",
            "lldp.eth0.port.descr": "eth1",
            "lldp.eth0.port.ttl": "120",
        }


@pytest.mark.parametrize("neighbors", (5, 10, 20))
def test_several_neighbors(lldpd, lldpcli, links, namespaces, neighbors):
    for i in range(2, neighbors + 1):
        links(namespaces(1), namespaces(i))
    for i in range(1, neighbors + 1):
        with namespaces(i):
            lldpd(sleep=(i == 1 and 2 or 0), silent=True)
    time.sleep(10)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        for i in range(2, neighbors + 1):
            assert out[
                "lldp.eth{}.chassis.name".format((i - 2) * 2)
            ] == "ns-{}.example.com".format(i)


def test_one_interface(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "interfaces")
        assert out["lldp.eth0.chassis.descr"].startswith(
            "Spectacular GNU/Linux 2016 Linux"
        )
        assert "lldp.eth0.chassis.Router.enabled" in out
        assert "lldp.eth0.chassis.Station.enabled" in out
        del out["lldp.eth0.chassis.descr"]
        del out["lldp.eth0.chassis.Router.enabled"]
        del out["lldp.eth0.chassis.Station.enabled"]
        assert out == {
            "lldp.eth0.status": "RX and TX",
            "lldp.eth0.chassis.mac": "00:00:00:00:00:01",
            "lldp.eth0.chassis.name": "ns-1.example.com",
            "lldp.eth0.chassis.mgmt-ip": "fe80::200:ff:fe00:1",
            "lldp.eth0.chassis.mgmt-iface": "3",
            "lldp.eth0.chassis.Bridge.enabled": "off",
            "lldp.eth0.chassis.Wlan.enabled": "off",
            "lldp.eth0.port.mac": "00:00:00:00:00:01",
            "lldp.eth0.port.descr": "eth0",
            "lldp.eth0.ttl.ttl": "120",
        }


@pytest.mark.parametrize("interfaces", (5, 10, 20))
def test_several_interfaces(lldpd, lldpcli, links, namespaces, interfaces):
    for i in range(2, interfaces + 1):
        links(namespaces(1), namespaces(i))
    for i in range(1, interfaces + 1):
        with namespaces(i):
            lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "interfaces")
        for i in range(2, interfaces + 1):
            assert (
                out["lldp.eth{}.chassis.mac".format((i - 2) * 2)] == "00:00:00:00:00:01"
            )
            assert out[
                "lldp.eth{}.port.mac".format((i - 2) * 2)
            ] == "00:00:00:00:00:{num:02x}".format(num=(i - 2) * 2 + 1)


def test_different_mtu(lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2), mtu=1500)
    links(namespaces(1), namespaces(2), mtu=9000)
    with namespaces(1):
        lldpd()
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "interfaces")
        assert out["lldp.eth0.chassis.mac"] == "00:00:00:00:00:01"
        assert out["lldp.eth2.chassis.mac"] == "00:00:00:00:00:01"


def test_overrided_description(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-S", "Modified description")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.descr"] == "Modified description"


def test_overrided_description2(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "system", "description", "Modified description")
        lldpcli("update")
        time.sleep(1)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.descr"] == "Modified description"


def test_overrided_chassisid(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "system", "chassisid", "Modified chassis ID")
        lldpcli("update")
        time.sleep(1)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.local"] == "Modified chassis ID"


def test_overrided_chassisid_kept(lldpd1, lldpd, lldpcli, namespaces, links):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "system", "chassisid", "Modified chassis ID")
        links.down("eth1")
        time.sleep(1)
        links.up("eth1")
        time.sleep(1)
        lldpcli("update")
        time.sleep(1)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.local"] == "Modified chassis ID"


def test_overrided_chassisid_reverse(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "system", "chassisid", "Modified chassis ID")
        lldpcli("unconfigure", "system", "chassisid")
        lldpcli("update")
        time.sleep(1)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mac"] == "00:00:00:00:00:02"


def test_hide_kernel(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-k")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.descr"] == "Spectacular GNU/Linux 2016"


def test_listen_only(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-r")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}


def test_forced_unknown_management_address(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd("-m", "2001:db8::47")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "2001:db8::47"
        assert "lldp.eth0.chassis.mgmt-iface" not in out


def test_forced_known_management_address(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
        lldpd("-m", "192.168.14.2")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "192.168.14.2"
        assert out["lldp.eth0.chassis.mgmt-iface"] == "2"


def test_management_address(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
            ipr.addr("add", index=idx, address="172.25.21.47", prefixlen=24)
        lldpd("-m", "172.25.*")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "172.25.21.47"
        assert out["lldp.eth0.chassis.mgmt-iface"] == "2"


def test_negative_management_address(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
            ipr.addr("add", index=idx, address="172.25.21.47", prefixlen=24)
        lldpd("-m", "!192.168.14.2,!*:*")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "172.25.21.47"
        assert out["lldp.eth0.chassis.mgmt-iface"] == "2"


def test_negative_unknown_management_address(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
            ipr.addr("add", index=idx, address="172.25.21.47", prefixlen=24)
        lldpd("-m", "!192.168.14.2,!*:*,192.0.2.15")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert "lldp.eth0.chassis.mgmt-ip" not in out
        assert "lldp.eth0.chassis.mgmt-iface" not in out


def test_management_interface(lldpd1, lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2), 4)
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
            idx = ipr.link_lookup(ifname="eth3")[0]
            ipr.addr("add", index=idx, address="172.25.21.47", prefixlen=24)
        lldpd("-m", "eth3")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == [
            "172.25.21.47",
            "fe80::200:ff:fe00:4",
        ]
        assert out["lldp.eth0.chassis.mgmt-iface"] == ["4", "4"]


def test_change_management_address(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
        lldpd("-m", "192.168.*")
        # We need a short TX interval as updating the IP address
        # doesn't trigger a resend.
        lldpcli("configure", "lldp", "tx-interval", "2")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "192.168.14.2"
        assert out["lldp.eth0.chassis.mgmt-iface"] == "2"
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            ipr.addr("del", index=idx, address="192.168.14.2", prefixlen=24)
            ipr.addr("add", index=idx, address="192.168.14.5", prefixlen=24)
        time.sleep(5)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mgmt-ip"] == "192.168.14.5"
        assert out["lldp.eth0.chassis.mgmt-iface"] == "2"


def test_portid_subtype_ifname(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "lldp", "portidsubtype", "ifname")
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "eth1"


def test_portid_subtype_with_alias(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.link("set", index=idx, ifalias="alias of eth1")
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "alias of eth1"


def test_portid_subtype_macaddress(lldpd1, lldpd, lldpcli, links, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.link("set", index=idx, ifalias="alias of eth1")
        lldpd()
        lldpcli("configure", "lldp", "portidsubtype", "macaddress")
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.mac"] == "00:00:00:00:00:02"
        assert out["lldp.eth0.port.descr"] == "eth1"


def test_portid_subtype_local(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "lldp", "portidsubtype", "local", "localname")
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.local"] == "localname"
        assert out["lldp.eth0.port.descr"] == "eth1"


def test_portid_subtype_local_with_description(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli(
            "configure",
            "lldp",
            "portidsubtype",
            "local",
            "localname",
            "description",
            "localdescription",
        )
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.local"] == "localname"
        assert out["lldp.eth0.port.descr"] == "localdescription"


def test_portdescription(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        lldpd()
        lldpcli("configure", "lldp", "portdescription", "localdescription")
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.descr"] == "localdescription"


def test_portid_subtype_local_with_alias(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.link("set", index=idx, ifalias="alias of eth1")
        lldpd()
        lldpcli("configure", "lldp", "portidsubtype", "local", "localname")
        time.sleep(3)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.port.local"] == "localname"
        assert out["lldp.eth0.port.descr"] == "alias of eth1"


def test_port_status_txonly(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd()
        lldpcli("configure", "lldp", "status", "tx-only")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}
        lldpcli("update")
    with namespaces(2):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth1.chassis.mac"] == "00:00:00:00:00:01"


def test_port_status_rxonly(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd()
        lldpcli("configure", "lldp", "status", "rx-only")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mac"] == "00:00:00:00:00:02"
        lldpcli("update")
    with namespaces(2):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}


def test_port_status_rxandtx(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd()
        lldpcli("configure", "lldp", "status", "rx-and-tx")  # noop
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.chassis.mac"] == "00:00:00:00:00:02"
        lldpcli("update")
    with namespaces(2):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth1.chassis.mac"] == "00:00:00:00:00:01"


def test_port_status_disabled(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd()
        lldpcli("configure", "lldp", "status", "disabled")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}
        lldpcli("update")
    with namespaces(2):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out == {}


def test_port_vlan_tx(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(1):
        lldpd()
        lldpcli(
            "configure",
            "ports",
            "eth0",
            "lldp",
            "vlan-tx",
            "100",
            "priority",
            "5",
            "dei",
            "1",
        )
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "ports", "eth0")
        assert out["lldp.eth0.port.vlanTX.id"] == "100"
        assert out["lldp.eth0.port.vlanTX.prio"] == "5"
        assert out["lldp.eth0.port.vlanTX.dei"] == "1"
        # unconfigure VLAN TX
        lldpcli("unconfigure", "ports", "eth0", "lldp", "vlan-tx")
        out = lldpcli("-f", "keyvalue", "show", "interfaces", "ports", "eth0")
        assert "lldp.eth0.port.vlanTX.id" not in out
        assert "lldp.eth0.port.vlanTX.prio" not in out
        assert "lldp.eth0.port.vlanTX.dei" not in out


def test_set_interface_alias(lldpd1, lldpd, lldpcli, namespaces):
    with namespaces(1):
        lldpcli("configure", "system", "interface", "description")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        with pyroute2.IPRoute() as ipr:
            link = ipr.link("get", ifname="eth0")[0]
            assert (
                link.get_attr("IFLA_IFALIAS") == "lldpd: connected to ns-2.example.com"
            )


def test_lldpdu_shutdown(lldpd, lldpcli, namespaces, links):
    links(namespaces(1), namespaces(2))
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd()
    # From https://github.com/lldpd/lldpd/issues/348
    frm_fa01 = (
        scapy.all.Ether(
            src="04:fe:7f:00:00:01", dst=scapy.contrib.lldp.LLDP_NEAREST_BRIDGE_MAC
        )
        / scapy.contrib.lldp.LLDPDUChassisID(
            subtype=scapy.contrib.lldp.LLDPDUChassisID.SUBTYPE_MAC_ADDRESS,
            id=b"\x04\xfe\x7f\x00\x00\x00",
        )
        / scapy.contrib.lldp.LLDPDUPortID(
            subtype=scapy.contrib.lldp.LLDPDUPortID.SUBTYPE_INTERFACE_NAME, id="Fa0/1"
        )
        / scapy.contrib.lldp.LLDPDUTimeToLive(ttl=65535)
        / scapy.contrib.lldp.LLDPDUSystemName(
            system_name="this info should not disappear"
        )
        / scapy.contrib.lldp.LLDPDUEndOfLLDPDU()
    )
    frm_fa01 = frm_fa01.build()
    frm_fa01 = scapy.all.Ether(frm_fa01)

    frm_fa02 = (
        scapy.all.Ether(
            src="04:fe:7f:00:00:02", dst=scapy.contrib.lldp.LLDP_NEAREST_BRIDGE_MAC
        )
        / scapy.contrib.lldp.LLDPDUChassisID(
            subtype=scapy.contrib.lldp.LLDPDUChassisID.SUBTYPE_MAC_ADDRESS,
            id=b"\x04\xfe\x7f\x00\x00\x00",
        )
        / scapy.contrib.lldp.LLDPDUPortID(
            subtype=scapy.contrib.lldp.LLDPDUPortID.SUBTYPE_INTERFACE_NAME, id="Fa0/2"
        )
        / scapy.contrib.lldp.LLDPDUTimeToLive(ttl=65535)
        / scapy.contrib.lldp.LLDPDUSystemName(
            system_name="this info should not disappear"
        )
        / scapy.contrib.lldp.LLDPDUEndOfLLDPDU()
    )
    frm_fa02 = frm_fa02.build()
    frm_fa02 = scapy.all.Ether(frm_fa02)

    frm_shut_fa01 = (
        scapy.all.Ether(
            src="04:fe:7f:00:00:01", dst=scapy.contrib.lldp.LLDP_NEAREST_BRIDGE_MAC
        )
        / scapy.contrib.lldp.LLDPDUChassisID(
            subtype=scapy.contrib.lldp.LLDPDUChassisID.SUBTYPE_MAC_ADDRESS,
            id=b"\x04\xfe\x7f\x00\x00\x00",
        )
        / scapy.contrib.lldp.LLDPDUPortID(
            subtype=scapy.contrib.lldp.LLDPDUPortID.SUBTYPE_INTERFACE_NAME, id="Fa0/1"
        )
        / scapy.contrib.lldp.LLDPDUTimeToLive(ttl=0)
        / scapy.contrib.lldp.LLDPDUEndOfLLDPDU()
    )
    frm_shut_fa01 = frm_shut_fa01.build()
    frm_shut_fa01 = scapy.all.Ether(frm_shut_fa01)

    with namespaces(2):
        scapy.all.sendp(frm_fa01, iface="eth1")
        scapy.all.sendp(frm_fa02, iface="eth3")
        time.sleep(2)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        del out["lldp.eth0.age"]
        del out["lldp.eth2.age"]
        assert out == {
            "lldp.eth0.via": "LLDP",
            "lldp.eth0.rid": "1",
            "lldp.eth0.chassis.mac": "04:fe:7f:00:00:00",
            "lldp.eth0.chassis.name": "this info should not disappear",
            "lldp.eth0.port.ifname": "Fa0/1",
            "lldp.eth0.port.ttl": "65535",
            "lldp.eth2.via": "LLDP",
            "lldp.eth2.rid": "1",
            "lldp.eth2.chassis.mac": "04:fe:7f:00:00:00",
            "lldp.eth2.chassis.name": "this info should not disappear",
            "lldp.eth2.port.ifname": "Fa0/2",
            "lldp.eth2.port.ttl": "65535",
        }
    with namespaces(2):
        scapy.all.sendp(frm_shut_fa01, iface="eth1")
        time.sleep(2)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        del out["lldp.eth2.age"]
        assert out == {
            "lldp.eth2.via": "LLDP",
            "lldp.eth2.rid": "1",
            "lldp.eth2.chassis.mac": "04:fe:7f:00:00:00",
            "lldp.eth2.chassis.name": "this info should not disappear",
            "lldp.eth2.port.ifname": "Fa0/2",
            "lldp.eth2.port.ttl": "65535",
        }
