import struct
import time

import pytest
import pyroute2
import scapy.all
import scapy.contrib.lldp


@pytest.mark.skipif("'CDP' not in config.lldpd.protocols", reason="CDP not supported")
@pytest.mark.parametrize("argument, expected", [("-cc", "CDPv1"), ("-ccc", "CDPv2")])
def test_cdp(lldpd, lldpcli, links, namespaces, argument, expected):
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
            "Linux running on Spectacular GNU/Linux 2016"
        )
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "eth1"


@pytest.mark.skipif("'CDP' not in config.lldpd.protocols", reason="CDP not supported")
def test_smart_filter_cdp_versions(lldpd, lldpcli, links, namespaces):
    """CDPv1 and CDPv2 should be counted as a single protocol.

    With two LLDP, one CDPv1 and one CDPv2 neighbors on the same port,
    the smart filter has a tie between LLDP and CDP and selects LLDP.
    Counting CDP versions separately would select CDPv1 instead and
    incorrectly hide the LLDP neighbors.
    """
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-c", "-r")

    def lldp_frame(src, chassis, port, name):
        return (
            scapy.all.Ether(src=src, dst=scapy.contrib.lldp.LLDP_NEAREST_BRIDGE_MAC)
            / scapy.contrib.lldp.LLDPDUChassisID(
                subtype=scapy.contrib.lldp.LLDPDUChassisID.SUBTYPE_MAC_ADDRESS,
                id=chassis,
            )
            / scapy.contrib.lldp.LLDPDUPortID(
                subtype=scapy.contrib.lldp.LLDPDUPortID.SUBTYPE_INTERFACE_NAME,
                id=port,
            )
            / scapy.contrib.lldp.LLDPDUTimeToLive(ttl=120)
            / scapy.contrib.lldp.LLDPDUSystemName(system_name=name)
            / scapy.contrib.lldp.LLDPDUEndOfLLDPDU()
        )

    def cdp_frame(src, version, device, port, software):
        payload = struct.pack("!BBH", version, 180, 0)
        for tlv_type, value in (
            (0x0001, device),  # Device ID
            (0x0003, port),  # Port ID
            (0x0004, struct.pack("!I", 0x09)),  # Capabilities
            (0x0005, software),  # Software
        ):
            payload += struct.pack("!HH", tlv_type, len(value) + 4) + value
        llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
        return scapy.all.Ether(
            src=src, dst="01:00:0c:cc:cc:cc", type=len(llc) + len(payload)
        ) / scapy.all.Raw(llc + payload)

    with namespaces(2):
        for frame in (
            lldp_frame(
                "04:fe:7f:00:00:01",
                b"\x04\xfe\x7f\x00\x00\x01",
                "Gi0/1",
                "dlink-switch",
            ),
            lldp_frame(
                "04:fe:7f:00:00:02",
                b"\x04\xfe\x7f\x00\x00\x02",
                "eth0",
                "windows-endpoint",
            ),
            cdp_frame("04:fe:7f:00:00:03", 1, b"mikrotik", b"ether1", b"RouterOS"),
            cdp_frame("04:fe:7f:00:00:04", 2, b"fanvil-phone", b"WAN", b"Fanvil"),
        ):
            scapy.all.sendp(frame, iface="eth1", verbose=False)
        time.sleep(2)
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors")
        assert out["lldp.eth0.via"] == ["LLDP", "LLDP"]
        assert out["lldp.eth0.chassis.name"] == [
            "dlink-switch",
            "windows-endpoint",
        ]


@pytest.mark.skipif("'FDP' not in config.lldpd.protocols", reason="FDP not supported")
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
            "Linux running on Spectacular GNU/Linux 2016"
        )
        assert out["lldp.eth0.port.ifname"] == "eth1"
        assert out["lldp.eth0.port.descr"] == "eth1"


@pytest.mark.skipif("'EDP' not in config.lldpd.protocols", reason="EDP not supported")
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
        assert out["lldp.eth0.chassis.descr"] == "EDP enabled device, version 7.6.4.99"
        assert out["lldp.eth0.port.ifname"] == "1/2"
        assert out["lldp.eth0.port.descr"] == "Slot 1 / Port 2"


@pytest.mark.skipif(
    "'SONMP' not in config.lldpd.protocols", reason="SONMP not supported"
)
def test_sonmp(lldpd, lldpcli, links, namespaces):
    links(namespaces(1), namespaces(2))
    with namespaces(1):
        lldpd("-s", "-ll", "-r")
    with namespaces(2):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="eth1")[0]
            ipr.addr("add", index=idx, address="192.168.14.2", prefixlen=24)
        lldpd("-ss", "-ll")
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        assert out["lldp.eth0.via"] == "SONMP"
        assert out["lldp.eth0.chassis.name"] == "192.168.14.2"
        assert out["lldp.eth0.chassis.descr"] == "unknown (via SONMP)"
        port = out["lldp.eth0.port.local"][-1]
        assert out["lldp.eth0.port.local"] == "00-00-0{}".format(port)
        assert out["lldp.eth0.port.descr"] == "port {}".format(port)
