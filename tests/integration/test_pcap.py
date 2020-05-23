import pytest


def test_cisco_sg200(request, lldpd1, lldpcli, namespaces):
    with namespaces(2):
        pytest.helpers.send_pcap('data/sg200.pcap', 'eth1')
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


@pytest.mark.skipif("'Dot3' not in config.lldpd.features",
                    readon="Dot3 not supported")
def test_8023bt(lldpd1, lldpcli, namespaces):
    with namespaces(2):
        pytest.helpers.send_pcap('data/8023bt.pcap', 'eth1')
    with namespaces(1):
        out = lldpcli("-f", "keyvalue", "show", "neighbors", "details")
        for k in list(out.keys()):
            if not k.startswith("lldp.eth0.port.power."):
                del out[k]
        assert out == {
            'lldp.eth0.port.power.supported': 'yes',
            'lldp.eth0.port.power.enabled': 'yes',
            'lldp.eth0.port.power.paircontrol': 'yes',
            'lldp.eth0.port.power.device-type': 'PSE',
            'lldp.eth0.port.power.pairs': 'signal',
            'lldp.eth0.port.power.class': 'class 4',
            'lldp.eth0.port.power.power-type': '2',
            'lldp.eth0.port.power.source': 'PSE',
            'lldp.eth0.port.power.priority': 'low',
            'lldp.eth0.port.power.requested': '71000',
            'lldp.eth0.port.power.allocated': '51000',
            'lldp.eth0.port.power.requested-a': '35500',
            'lldp.eth0.port.power.requested-b': '35500',
            'lldp.eth0.port.power.allocated-a': '25500',
            'lldp.eth0.port.power.allocated-b': '25500',
            'lldp.eth0.port.power.pse-powering-status':
            '4-pair powering single-signature PD',
            'lldp.eth0.port.power.pd-powering-status': 'Unknown',
            'lldp.eth0.port.power.power-pairs-ext': 'Both alternatives',
            'lldp.eth0.port.power.power-class-ext-a': 'Class 4',
            'lldp.eth0.port.power.power-class-ext-b': 'Class 4',
            'lldp.eth0.port.power.power-class-ext': 'Dual-signature PD',
            'lldp.eth0.port.power.power-type-ext': 'Type 3 PSE',
            'lldp.eth0.port.power.pd-load':
            ('PD is single- or dual-signature and power '
             'is not electrically isolated'),
            'lldp.eth0.port.power.max-power': '51000'
        }
