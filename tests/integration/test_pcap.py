import pytest
import socket
import struct


def send_pcap(location, interface):
    """Send a PCAP file to the given interface. It is assumed that all
    pcap files are little-endian."""
    with open(location, 'rb') as f:
        hdr = f.read(24)
        magic, major, minor, _, _, _, network = struct.unpack("<IHHiIII",
                                                              hdr)
        assert(magic == 0xa1b2c3d4)
        assert(major == 2)
        assert(minor == 4)
        assert(network == 1)
        hdr = f.read(16)
        _, _, ilen, olen = struct.unpack("<IIII", hdr)
        assert(ilen == olen)
        content = f.read(ilen)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
        s.send(content)


class TestPcapCaptures(object):

    def test_cisco_sg200(self, lldpd1, lldpcli, namespaces):
        with namespaces(2):
            send_pcap('data/sg200.pcap', 'eth1')
        with namespaces(1):
            out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
            assert out['lldp.eth0.age'].startswith('0 day, 00:00:')
            del out['lldp.eth0.age']
            expected = {
                "lldp.eth0.via": "LLDP",
                "lldp.eth0.rid": "1",
                "lldp.eth0.chassis.mac": "00:35:35:35:35:35",
                "lldp.eth0.chassis.ttl": "120",
                "lldp.eth0.port.ifname": "g1",
                "lldp.eth0.port.auto-negotiation.supported": "yes",
                "lldp.eth0.port.auto-negotiation.enabled": "yes",
                "lldp.eth0.port.auto-negotiation.1000Base-T.hd": "no",
                "lldp.eth0.port.auto-negotiation.1000Base-T.fd": "yes",
                "lldp.eth0.port.auto-negotiation.current": "unknown",
            }
            if 'LLDP-MED' in pytest.config.lldpd.features:
                expected.update({
                    "lldp.eth0.lldp-med.device-type":
                    "Network Connectivity Device",
                    "lldp.eth0.lldp-med.Capabilities.available": "yes",
                    "lldp.eth0.lldp-med.Policy.available": "yes",
                    "lldp.eth0.lldp-med.Location.available": "yes",
                    "lldp.eth0.lldp-med.MDI/PSE.available": "yes",
                    "lldp.eth0.lldp-med.Inventory.available": "yes",
                    "lldp.eth0.lldp-med.Civic address.country": "DE",
                    "lldp.eth0.lldp-med.Civic address.city": "Berlin",
                    "lldp.eth0.lldp-med.Civic address.street":
                    "Karl-Liebknecht-Strase",
                    "lldp.eth0.lldp-med.Civic address.building": "42",
                    "lldp.eth0.lldp-med.inventory.hardware": "V02",
                    "lldp.eth0.lldp-med.inventory.software": "1.0.8.3",
                    "lldp.eth0.lldp-med.inventory.firmware": "1.0.8.3",
                    "lldp.eth0.lldp-med.inventory.serial": "XXX11111ZZZ",
                    "lldp.eth0.lldp-med.inventory.manufacturer": "0xbc00",
                    "lldp.eth0.lldp-med.inventory.model": "SG 200-08P",
                    "lldp.eth0.lldp-med.inventory.asset": "1"
                })
            assert out == expected
