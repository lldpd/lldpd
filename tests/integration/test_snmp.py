import pytest

pytestmark = pytest.mark.skipif("not config.lldpd.snmp", reason="no SNMP support")


def test_snmp_register(snmpd, snmpwalk, lldpd, namespaces):
    with namespaces(1):
        snmpd()
        lldpd("-x")
        out = snmpwalk(".1.3.6.1.2.1.1.9.1.3")
        assert 'STRING: "lldpMIB implementation by lldpd"' in out.values()


def test_snmp_one_neighbor(snmpd, snmpwalk, lldpd, namespaces):
    with namespaces(1):
        snmpd()
        lldpd("-x")
    with namespaces(2):
        lldpd()
    with namespaces(1):
        out = snmpwalk(".1.0.8802.1.1.2.1")
        assert out[".1.0.8802.1.1.2.1.2.1.0"].startswith("Timeticks: ")
        assert out[".1.0.8802.1.1.2.1.3.2.0"] == 'STRING: "ns-1.example.com"'
        assert out[".1.0.8802.1.1.2.1.3.3.0"] == 'STRING: "ns-1.example.com"'
        assert out[".1.0.8802.1.1.2.1.3.4.0"].startswith(
            'STRING: "Spectacular GNU/Linux 2016 Linux'
        )


def test_snmp_empty_sysname(snmpd, snmpwalk, lldpd, links, namespaces):
    # See https://github.com/lldpd/lldpd/issues/392
    links(namespaces(1), namespaces(2))
    links(namespaces(1), namespaces(3))
    links(namespaces(1), namespaces(4))
    with namespaces(1):
        snmpd()
        lldpd("-x")
    with namespaces(2):
        lldpd()
    with namespaces(3):
        # Packet without sysName
        lldpd("-r")
        pytest.helpers.send_pcap("data/connectx.pcap", "eth3")
    with namespaces(4):
        lldpd()
    with namespaces(1):
        out = snmpwalk(".1.0.8802.1.1.2.1.4.1.1.9")  # lldpRemSysName
        # We should get something like:
        # .1.0.8802.1.1.2.1.4.1.1.9.400.3.1 STRING: "ns-2.example.com"
        # .1.0.8802.1.1.2.1.4.1.1.9.700.5.2 (not present)
        # .1.0.8802.1.1.2.1.4.1.1.9.1000.7.3 STRING: "ns-4.example.com"
        print(out)
        assert list(out.values()) == [
            'STRING: "ns-2.example.com"',
            'STRING: "ns-4.example.com"',
        ]
        oids = list(out.keys())
        assert oids[0].endswith(".3.1")
        assert oids[1].endswith(".7.3")
