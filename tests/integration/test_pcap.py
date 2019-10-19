import scapy.all


def send_pcap(location, interface):
    packets = scapy.all.rdpcap(location)
    print(packets)
    scapy.all.sendp(packets, iface=interface)


def test_cisco_sg200(request, lldpd1, lldpcli, namespaces):
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
            "lldp.eth0.port.ttl": "120",
            "lldp.eth0.port.ifname": "g1",
        }
        if 'Dot3' in request.config.lldpd.features:
            expected.update({
                "lldp.eth0.port.auto-negotiation.supported": "yes",
                "lldp.eth0.port.auto-negotiation.enabled": "yes",
                "lldp.eth0.port.auto-negotiation.1000Base-T.hd": "no",
                "lldp.eth0.port.auto-negotiation.1000Base-T.fd": "yes",
                "lldp.eth0.port.auto-negotiation.current": "unknown",
            })
        if 'LLDP-MED' in request.config.lldpd.features:
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
